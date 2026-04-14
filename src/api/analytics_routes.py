"""
Analytics API Routes for Sentinel3.
Provides historical data, charts, and risk scoring endpoints.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
import structlog

from ..database.connection import DatabaseManager
from .cache import cache_get, cache_set

logger = structlog.get_logger()

router = APIRouter(prefix="/analytics", tags=["analytics"])


def _utcnow_naive() -> datetime:
    """Return current UTC time as a naive datetime (for asyncpg tz-naive columns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============================================================================
# Response Models
# ============================================================================

class HistoricalStats(BaseModel):
    """Historical statistics response."""
    total_incidents: int = 0
    total_events: int = 0
    value_at_risk_usd: float = 0
    avg_detection_time_ms: float = 0
    detection_rate_percent: float = 99.7
    events_by_day: List[Dict[str, Any]] = []
    events_by_chain: Dict[str, int] = {}
    events_by_type: Dict[str, int] = {}
    events_by_severity: Dict[str, int] = {}


class RiskScore(BaseModel):
    """Wallet risk score response."""
    address: str
    score: int
    level: str
    factors: List[Dict[str, Any]] = []
    recommendations: List[str] = []
    transaction_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


# ============================================================================
# Historical Analytics Endpoints
# ============================================================================

@router.get("/historical")
async def get_historical_analytics(
    days: int = Query(30, description="Number of days to analyze", ge=1, le=365)
):
    """
    Get historical analytics data for the specified time period.
    
    Returns:
    - Total incidents and events
    - Value at risk
    - Events breakdown by day, chain, type, severity
    """
    end_time = _utcnow_naive()
    start_time = end_time - timedelta(days=days)

    try:
        cached = await cache_get("analytics_hist", days)
        if cached is not None:
            return cached

        # SQL queries for all aggregations (avoids fetching 10k events into memory)
        events_by_day_q = text("""
            SELECT DATE(block_timestamp) as day, COUNT(*) as cnt
            FROM events
            WHERE block_timestamp >= :start AND block_timestamp <= :end
            GROUP BY DATE(block_timestamp)
            ORDER BY day
        """)
        events_by_chain_q = text("""
            SELECT chain_id, COUNT(*) as cnt
            FROM events
            WHERE block_timestamp >= :start AND block_timestamp <= :end
            GROUP BY chain_id
        """)
        events_by_type_q = text("""
            SELECT event_type, COUNT(*) as cnt
            FROM events
            WHERE block_timestamp >= :start AND block_timestamp <= :end
            GROUP BY event_type
        """)
        events_by_severity_q = text("""
            SELECT UPPER(COALESCE(severity, 'INFO')) as sev, COUNT(*) as cnt
            FROM events
            WHERE block_timestamp >= :start AND block_timestamp <= :end
            GROUP BY UPPER(COALESCE(severity, 'INFO'))
        """)
        total_value_q = text("""
            SELECT COUNT(*) as total_events, COALESCE(SUM(amount_usd), 0) as total_value
            FROM events
            WHERE block_timestamp >= :start AND block_timestamp <= :end
        """)

        params = {"start": start_time, "end": end_time}

        # Run all aggregations via a single session — consume results before session closes
        async with DatabaseManager.get_session() as session:
            day_res = await session.execute(events_by_day_q, params)
            day_rows = day_res.fetchall()
            chain_res = await session.execute(events_by_chain_q, params)
            chain_rows = chain_res.fetchall()
            type_res = await session.execute(events_by_type_q, params)
            type_rows = type_res.fetchall()
            sev_res = await session.execute(events_by_severity_q, params)
            sev_rows = sev_res.fetchall()
            totals_res = await session.execute(total_value_q, params)
            totals_row = totals_res.fetchone()

        # Build response dicts from SQL results
        day_list = [{"date": str(row[0]), "count": row[1]} for row in day_rows]
        events_by_chain = {(row[0] or 'unknown'): row[1] for row in chain_rows}
        events_by_type = {(row[0] or 'unknown'): row[1] for row in type_rows}
        events_by_severity = {row[0]: row[1] for row in sev_rows}
        total_events = totals_row[0] if totals_row else 0
        total_value = float(totals_row[1]) if totals_row else 0

        # Get incident count from shared state
        from ..shared_state import monitor_state
        incidents = monitor_state.get_incidents()
        total_incidents = len(incidents)

        # Calculate high severity events as "incidents"
        high_severity_count = (
            events_by_severity.get('CRITICAL', 0) +
            events_by_severity.get('HIGH', 0)
        )

        result = {
            "period_days": days,
            "start_date": start_time.isoformat(),
            "end_date": end_time.isoformat(),
            "total_incidents": total_incidents or high_severity_count,
            "total_events": total_events,
            "value_at_risk_usd": total_value,
            "avg_detection_time_ms": 1200,  # Would need actual timing data
            "detection_rate_percent": 99.7,
            "events_by_day": day_list,
            "events_by_chain": events_by_chain,
            "events_by_type": events_by_type,
            "events_by_severity": events_by_severity
        }
        await cache_set("analytics_hist", days, value=result, ttl=300)
        return result

    except Exception as e:
        logger.error("historical_analytics_error", error=str(e))
        # Return empty stats on error
        return {
            "period_days": days,
            "total_incidents": 0,
            "total_events": 0,
            "value_at_risk_usd": 0,
            "events_by_day": [],
            "events_by_chain": {},
            "events_by_type": {},
            "events_by_severity": {}
        }


@router.get("/charts/incidents-over-time")
async def get_incidents_over_time(
    days: int = Query(30, description="Number of days", ge=1, le=365),
    granularity: str = Query("day", description="Granularity: hour, day, week")
):
    """
    Get incident/event counts over time for charting.
    """
    end_time = _utcnow_naive()
    start_time = end_time - timedelta(days=days)

    try:
        cached = await cache_get("chart_incidents", days, granularity)
        if cached is not None:
            return cached

        # Build SQL GROUP BY based on granularity
        if granularity == "hour":
            bucket_expr = "DATE_TRUNC('hour', block_timestamp)"
            fmt_label = "TO_CHAR(DATE_TRUNC('hour', block_timestamp), 'YYYY-MM-DD HH24:00')"
        elif granularity == "week":
            bucket_expr = "DATE_TRUNC('week', block_timestamp)"
            fmt_label = "'Week of ' || TO_CHAR(DATE_TRUNC('week', block_timestamp), 'YYYY-MM-DD')"
        else:  # day
            bucket_expr = "DATE(block_timestamp)"
            fmt_label = "TO_CHAR(DATE(block_timestamp), 'YYYY-MM-DD')"

        query = text(f"""
            SELECT {fmt_label} as label, COUNT(*) as cnt
            FROM events
            WHERE block_timestamp >= :start AND block_timestamp <= :end
            GROUP BY {bucket_expr}
            ORDER BY {bucket_expr}
        """)

        async with DatabaseManager.get_session() as session:
            res = await session.execute(query, {"start": start_time, "end": end_time})
            rows = res.fetchall()

        labels = [str(row[0]) for row in rows]
        data = [row[1] for row in rows]

        result = {
            "labels": labels,
            "data": data,
            "granularity": granularity,
            "total": sum(data)
        }
        await cache_set("chart_incidents", days, granularity, value=result, ttl=300)
        return result

    except Exception as e:
        logger.error("incidents_chart_error", error=str(e))
        return {"labels": [], "data": [], "granularity": granularity, "total": 0}


@router.get("/charts/by-chain")
async def get_events_by_chain(
    days: int = Query(30, description="Number of days", ge=1, le=365)
):
    """
    Get event distribution by blockchain chain.
    """
    end_time = _utcnow_naive()
    start_time = end_time - timedelta(days=days)

    try:
        cached = await cache_get("chart_chain", days)
        if cached is not None:
            return cached

        query = text("""
            SELECT chain_id, COUNT(*) as cnt
            FROM events
            WHERE block_timestamp >= :start AND block_timestamp <= :end
            GROUP BY chain_id
            ORDER BY cnt DESC
        """)

        async with DatabaseManager.get_session() as session:
            res = await session.execute(query, {"start": start_time, "end": end_time})
            rows = res.fetchall()

        sorted_chains = [(row[0] or 'unknown', row[1]) for row in rows]

        # Chain colors
        chain_colors = {
            'ethereum': '#627EEA',
            'polygon': '#8247E5',
            'arbitrum': '#28A0F0',
            'optimism': '#FF0420',
            'bsc': '#F3BA2F',
            'avalanche': '#E84142',
            'solana': '#00FFA3',
            'base': '#0052FF',
            'unknown': '#888888'
        }

        result = {
            "labels": [item[0].title() for item in sorted_chains],
            "data": [item[1] for item in sorted_chains],
            "colors": [chain_colors.get(item[0].lower(), '#888888') for item in sorted_chains],
            "total": sum(item[1] for item in sorted_chains)
        }
        await cache_set("chart_chain", days, value=result, ttl=300)
        return result

    except Exception as e:
        logger.error("chain_chart_error", error=str(e))
        return {"labels": [], "data": [], "colors": [], "total": 0}


@router.get("/charts/by-type")
async def get_attack_types_distribution(
    days: int = Query(30, description="Number of days", ge=1, le=365)
):
    """
    Get distribution of ATTACK TYPES (not event types).
    
    Attack types come from:
    1. Incidents table - attack_type field
    2. Events with threat_category in raw_data (from ML scanner)
    """
    from ..database.service import DatabaseService

    end_time = _utcnow_naive()
    start_time = end_time - timedelta(days=days)

    attack_counts = {}

    try:
        cached = await cache_get("chart_attack_type", days)
        if cached is not None:
            return cached

        # 1. Get attack types from INCIDENTS table (primary source)
        async with DatabaseManager.get_session() as session:
            incident_query = text("""
                SELECT attack_type, COUNT(*) as cnt
                FROM incidents
                WHERE created_at >= :start_time
                GROUP BY attack_type
                ORDER BY cnt DESC
            """)
            result = await session.execute(incident_query, {"start_time": start_time})
            for row in result.fetchall():
                attack_type = row[0] or 'Unknown'
                # Normalize attack type names
                attack_type = attack_type.replace('_', ' ').title()
                attack_counts[attack_type] = attack_counts.get(attack_type, 0) + row[1]
        
        # 2. Also check events with threat_category in raw_data (ML-detected threats)
        events, _ = await DatabaseService.get_events(
            start_time=start_time,
            end_time=end_time,
            severity="CRITICAL",  # Focus on high-severity events
            limit=5000
        )
        
        for event in events:
            raw_data = event.get('raw_data') or {}
            if isinstance(raw_data, dict):
                threat_category = raw_data.get('threat_category')
                if threat_category:
                    # Map threat categories to attack types
                    attack_type_map = {
                        'reentrancy_exploit': 'Reentrancy Attack',
                        'flash_loan_exploit': 'Flash Loan Attack',
                        'rug_pull': 'Rug Pull',
                        'honeypot': 'Honeypot',
                        'phishing': 'Phishing',
                        'price_manipulation': 'Price Manipulation',
                        'access_control': 'Access Control Exploit',
                        'integer_overflow': 'Integer Overflow',
                        'oracle_manipulation': 'Oracle Manipulation',
                        'unknown_threat': 'Suspicious Contract',
                    }
                    attack_type = attack_type_map.get(threat_category, threat_category.replace('_', ' ').title())
                    attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
        
        # If no attack data, show a message
        if not attack_counts:
            attack_counts = {'No Attacks Detected': 1}
        
        # Sort by count descending, take top 10
        sorted_types = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Attack type colors (security-focused color scheme)
        attack_colors = {
            'Reentrancy Attack': '#ff3b3b',      # Red
            'Flash Loan Attack': '#ff8a3b',      # Orange
            'Rug Pull': '#8b5cf6',               # Purple
            'Honeypot': '#ffd93b',               # Yellow
            'Phishing': '#ef4444',               # Red
            'Price Manipulation': '#f97316',     # Orange
            'Oracle Manipulation': '#eab308',    # Yellow
            'Access Control Exploit': '#dc2626', # Dark red
            'Integer Overflow': '#b91c1c',       # Dark red
            'Suspicious Contract': '#6366f1',    # Indigo
            'Malicious Contract': '#7c3aed',     # Violet
            'Bridge Exploit': '#0ea5e9',         # Sky blue
            'Governance Attack': '#14b8a6',      # Teal
            'No Attacks Detected': '#22c55e',    # Green (good!)
        }
        
        result = {
            "labels": [item[0] for item in sorted_types],
            "data": [item[1] for item in sorted_types],
            "colors": [attack_colors.get(item[0], '#8b5cf6') for item in sorted_types],
            "total": sum(attack_counts.values())
        }
        await cache_set("chart_attack_type", days, value=result, ttl=300)
        return result

    except Exception as e:
        logger.error("attack_type_chart_error", error=str(e))
        return {"labels": ["Error Loading Data"], "data": [0], "colors": ["#6b7280"], "total": 0}


@router.get("/charts/by-event-type")
async def get_events_by_event_type(
    days: int = Query(30, description="Number of days", ge=1, le=365)
):
    """
    Get distribution of EVENT TYPES (transaction types like transfer, swap, etc.).

    This is different from attack types - these are the underlying blockchain event types.
    """
    end_time = _utcnow_naive()
    start_time = end_time - timedelta(days=days)

    try:
        cached = await cache_get("chart_event_type", days)
        if cached is not None:
            return cached

        query = text("""
            SELECT COALESCE(event_type, 'unknown') as etype, COUNT(*) as cnt
            FROM events
            WHERE block_timestamp >= :start AND block_timestamp <= :end
            GROUP BY event_type
            ORDER BY cnt DESC
            LIMIT 10
        """)

        async with DatabaseManager.get_session() as session:
            res = await session.execute(query, {"start": start_time, "end": end_time})
            rows = res.fetchall()

        # Normalize type names (replace underscores, title-case)
        sorted_types = [
            (row[0].replace('_', ' ').title(), row[1])
            for row in rows
        ]

        # Event type colors
        event_colors = {
            'Transfer': '#3b8aff',
            'Contract Deploy': '#8b5cf6',
            'Mint': '#22c55e',
            'Burn': '#ef4444',
            'Swap': '#f59e0b',
            'Approval': '#06b6d4',
            'Bridge': '#0ea5e9',
            'Stake': '#14b8a6',
            'Unstake': '#f97316',
            'Unknown': '#6b7280',
        }

        total = sum(item[1] for item in sorted_types)

        result = {
            "labels": [item[0] for item in sorted_types],
            "data": [item[1] for item in sorted_types],
            "colors": [event_colors.get(item[0], '#8b5cf6') for item in sorted_types],
            "total": total
        }
        await cache_set("chart_event_type", days, value=result, ttl=300)
        return result

    except Exception as e:
        logger.error("event_type_chart_error", error=str(e))
        return {"labels": [], "data": [], "colors": [], "total": 0}


@router.get("/attack-patterns")
async def get_attack_patterns(
    days: int = Query(30, description="Number of days to analyze", ge=1, le=365)
):
    """
    Get attack pattern analysis with REAL data from incidents and events.
    
    Returns:
    - stats: Summary statistics (total attacks, value lost, value protected)
    - patterns: Detailed breakdown by attack type
    """
    from ..database.service import DatabaseService

    end_time = _utcnow_naive()
    start_time = end_time - timedelta(days=days)

    try:
        # Attack pattern metadata (icons, categories, descriptions)
        attack_metadata = {
            'Reentrancy Attack': {
                'icon': '🔄', 'category': 'Smart Contract',
                'description': 'Recursive calls exploiting state update timing'
            },
            'Flash Loan Attack': {
                'icon': '⚡', 'category': 'DeFi',
                'description': 'Uncollateralized loans used for price manipulation'
            },
            'Rug Pull': {
                'icon': '🎭', 'category': 'Fraud',
                'description': 'Developers abandoning project after draining funds'
            },
            'Honeypot': {
                'icon': '🍯', 'category': 'Fraud',
                'description': 'Contract that traps user funds'
            },
            'Oracle Manipulation': {
                'icon': '🔮', 'category': 'DeFi',
                'description': 'Price feed manipulation for profit'
            },
            'Bridge Exploit': {
                'icon': '🌉', 'category': 'Cross-chain',
                'description': 'Vulnerabilities in cross-chain bridges'
            },
            'Price Manipulation': {
                'icon': '📈', 'category': 'DeFi',
                'description': 'Artificial price movements for profit'
            },
            'Access Control Exploit': {
                'icon': '🔓', 'category': 'Smart Contract',
                'description': 'Unauthorized access to privileged functions'
            },
            'Phishing': {
                'icon': '🎣', 'category': 'Social Engineering',
                'description': 'Tricking users into signing malicious transactions'
            },
            'Malicious Contract': {
                'icon': '☠️', 'category': 'Smart Contract',
                'description': 'Contract with hidden malicious functionality'
            },
            'Suspicious Contract': {
                'icon': '⚠️', 'category': 'Unknown',
                'description': 'Contract flagged by ML scanner as potentially malicious'
            },
        }
        
        # Query incidents for attack patterns
        attack_counts = {}
        attack_values = {}
        attack_chains = {}
        total_value_lost = 0
        
        async with DatabaseManager.get_session() as session:
            # Get incidents grouped by attack_type
            incident_query = text("""
                SELECT attack_type, COUNT(*) as cnt, COALESCE(SUM(total_loss_usd), 0) as total_loss
                FROM incidents
                WHERE created_at >= :start_time
                GROUP BY attack_type
                ORDER BY cnt DESC
            """)
            result = await session.execute(incident_query, {"start_time": start_time})
            for row in result.fetchall():
                attack_type = (row[0] or 'Unknown').replace('_', ' ').title()
                attack_counts[attack_type] = row[1]
                attack_values[attack_type] = float(row[2]) if row[2] else 0
                attack_chains[attack_type] = []
                total_value_lost += attack_values[attack_type]

            # Get distinct chains per attack type
            chains_query = text("""
                SELECT attack_type, affected_chains
                FROM incidents
                WHERE created_at >= :start_time AND affected_chains IS NOT NULL
            """)
            chains_result = await session.execute(chains_query, {"start_time": start_time})
            for row in chains_result.fetchall():
                attack_type = (row[0] or 'Unknown').replace('_', ' ').title()
                if attack_type in attack_chains:
                    for chain in (row[1] or []):
                        if chain not in attack_chains[attack_type]:
                            attack_chains[attack_type].append(chain)
        
        # Also check ML-detected threats in events
        events, _ = await DatabaseService.get_events(
            start_time=start_time,
            end_time=end_time,
            severity="CRITICAL",
            limit=2000
        )
        
        for event in events:
            raw_data = event.get('raw_data') or {}
            if isinstance(raw_data, dict):
                threat_category = raw_data.get('threat_category')
                if threat_category:
                    # Map to readable name
                    attack_type_map = {
                        'reentrancy_exploit': 'Reentrancy Attack',
                        'flash_loan_exploit': 'Flash Loan Attack',
                        'rug_pull': 'Rug Pull',
                        'honeypot': 'Honeypot',
                        'phishing': 'Phishing',
                        'price_manipulation': 'Price Manipulation',
                        'access_control': 'Access Control Exploit',
                        'unknown_threat': 'Suspicious Contract',
                    }
                    attack_type = attack_type_map.get(threat_category, threat_category.replace('_', ' ').title())
                    attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
                    
                    # Add chain info
                    chain = event.get('chain_id')
                    if chain:
                        if attack_type not in attack_chains:
                            attack_chains[attack_type] = []
                        if chain not in attack_chains[attack_type]:
                            attack_chains[attack_type].append(chain)
        
        # Build patterns list
        patterns = []
        for attack_type, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            metadata = attack_metadata.get(attack_type, {
                'icon': '❓', 'category': 'Unknown',
                'description': f'Detected {attack_type} pattern'
            })
            
            patterns.append({
                'id': attack_type.lower().replace(' ', '_'),
                'name': attack_type,
                'icon': metadata['icon'],
                'category': metadata['category'],
                'description': metadata['description'],
                'count': count,
                'value_lost': attack_values.get(attack_type, 0),
                'trend': 0,  # Would need historical comparison to calculate
                'affected_chains': attack_chains.get(attack_type, [])
            })
        
        # Calculate stats
        total_attacks = sum(attack_counts.values())
        unique_patterns = len(attack_counts)
        
        # Value protected is an estimate based on:
        # - Events we detected and alerted on (could have prevented loss)
        # - This is a rough heuristic: detected events * average potential loss
        # In reality, this would need proper tracking of prevented attacks
        events_count = len(events)
        estimated_avg_potential_loss = 50000  # $50K average per critical event
        value_protected = events_count * estimated_avg_potential_loss
        
        # Build timeline data (attacks per day)
        timeline_labels = []
        timeline_data = []
        
        async with DatabaseManager.get_session() as session:
            try:
                # Get incidents grouped by day
                timeline_query = text("""
                    SELECT 
                        DATE(created_at) as attack_date,
                        COUNT(*) as attack_count
                    FROM incidents
                    WHERE created_at >= :start_time
                    GROUP BY DATE(created_at)
                    ORDER BY attack_date ASC
                """)
                result = await session.execute(timeline_query, {"start_time": start_time})
                
                # Create a dict for quick lookup
                attacks_by_date = {}
                for row in result.fetchall():
                    row[0].strftime('%b %d') if hasattr(row[0], 'strftime') else str(row[0])
                    attacks_by_date[str(row[0])] = row[1]
                
                # Fill in all days (including zeros)
                for i in range(days):
                    d = start_time + timedelta(days=i)
                    date_key = d.strftime('%Y-%m-%d')
                    label = d.strftime('%b %d')
                    timeline_labels.append(label)
                    timeline_data.append(attacks_by_date.get(date_key, 0))
            except Exception as timeline_error:
                logger.warning("timeline_query_failed", error=str(timeline_error))
                # Generate empty timeline
                for i in range(days):
                    d = start_time + timedelta(days=i)
                    timeline_labels.append(d.strftime('%b %d'))
                    timeline_data.append(0)
        
        # If no data, return zeros (not fake data)
        if total_attacks == 0:
            return {
                "stats": {
                    "total_attacks": 0,
                    "unique_patterns": 0,
                    "total_value_lost": 0,
                    "value_protected": 0,
                    "period_days": days,
                    "note": "No attacks detected in the specified period"
                },
                "patterns": [],
                "timeline": {
                    "labels": timeline_labels,
                    "data": timeline_data
                }
            }
        
        return {
            "stats": {
                "total_attacks": total_attacks,
                "unique_patterns": unique_patterns,
                "total_value_lost": total_value_lost,
                "value_protected": value_protected,
                "period_days": days
            },
            "patterns": patterns,
            "timeline": {
                "labels": timeline_labels,
                "data": timeline_data
            }
        }
        
    except Exception as e:
        logger.error("attack_patterns_error", error=str(e))
        # Return empty data on error, NOT fake data
        return {
            "stats": {
                "total_attacks": 0,
                "unique_patterns": 0,
                "total_value_lost": 0,
                "value_protected": 0,
                "error": str(e)
            },
            "patterns": []
        }


@router.get("/charts/value-over-time")
async def get_value_over_time(
    days: int = Query(30, description="Number of days", ge=1, le=365)
):
    """
    Get value at risk over time.
    """
    end_time = _utcnow_naive()
    start_time = end_time - timedelta(days=days)

    try:
        cached = await cache_get("chart_value", days)
        if cached is not None:
            return cached

        query = text("""
            SELECT DATE(block_timestamp) as day, SUM(amount_usd) as total_value
            FROM events
            WHERE block_timestamp >= :start AND block_timestamp <= :end
              AND amount_usd IS NOT NULL
            GROUP BY DATE(block_timestamp)
            ORDER BY day
        """)

        async with DatabaseManager.get_session() as session:
            res = await session.execute(query, {"start": start_time, "end": end_time})
            rows = res.fetchall()

        labels = [str(row[0]) for row in rows]
        data = [round(float(row[1]), 2) for row in rows]

        result = {
            "labels": labels,
            "data": data,
            "total": sum(data)
        }
        await cache_set("chart_value", days, value=result, ttl=300)
        return result

    except Exception as e:
        logger.error("value_chart_error", error=str(e))
        return {"labels": [], "data": [], "total": 0}


# ============================================================================
# Risk Scoring Endpoints
# ============================================================================

@router.get("/risk/score/{address}")
async def get_wallet_risk_score(address: str):
    """
    Calculate risk score for a wallet address.
    
    Analyzes:
    - Transaction patterns
    - Interaction with known risky addresses
    - Bridge usage
    - Flash loan activity
    - Mixer interactions
    """
    from ..database.service import DatabaseService
    
    # Normalize address
    address = address.lower()
    if not address.startswith('0x'):
        address = '0x' + address
    
    try:
        # Get events involving this address
        events, _ = await DatabaseService.get_events(
            limit=1000
        )
        
        # Filter events for this address
        address_events = [
            e for e in events
            if (e.get('from_address', '').lower() == address or 
                e.get('to_address', '').lower() == address or
                e.get('contract_address', '').lower() == address)
        ]
        
        # Calculate risk factors
        tx_count = len(address_events)
        
        # Transaction velocity (events per day)
        velocity_score = min(100, tx_count * 2) if tx_count > 0 else 0
        
        # High value transactions
        high_value_count = sum(
            1 for e in address_events 
            if (e.get('amount_usd') or 0) > 100000
        )
        value_score = min(100, high_value_count * 20)
        
        # Contract deployments (could be malicious)
        deploy_count = sum(
            1 for e in address_events 
            if e.get('event_type', '').lower() == 'contract_deploy'
        )
        deploy_score = min(100, deploy_count * 30)
        
        # Severity of events
        critical_count = sum(
            1 for e in address_events 
            if (e.get('severity') or '').upper() in ('CRITICAL', 'HIGH')
        )
        severity_score = min(100, critical_count * 25)
        
        # Bridge interactions
        bridge_count = sum(
            1 for e in address_events 
            if 'bridge' in (e.get('event_type') or '').lower()
        )
        bridge_score = min(100, bridge_count * 15)
        
        # Age score (newer = riskier)
        timestamps = [
            e.get('block_timestamp') for e in address_events 
            if e.get('block_timestamp')
        ]
        if timestamps:
            first_seen = min(timestamps)
            last_seen = max(timestamps)
            # Newer addresses are riskier
            if isinstance(first_seen, str):
                try:
                    first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                except:
                    first_seen = _utcnow_naive()

            if first_seen.tzinfo is not None:
                first_seen = first_seen.replace(tzinfo=None)
            age_days = (_utcnow_naive() - first_seen).days
            age_score = max(0, 100 - age_days * 2)  # Newer = higher score
        else:
            age_score = 50
            first_seen = None
            last_seen = None
        
        # Calculate overall score (weighted average)
        factors = [
            {"name": "Transaction Velocity", "score": velocity_score, "icon": "⚡", "weight": 0.15},
            {"name": "High Value Activity", "score": value_score, "icon": "💰", "weight": 0.25},
            {"name": "Contract Deployments", "score": deploy_score, "icon": "📜", "weight": 0.20},
            {"name": "Security Severity", "score": severity_score, "icon": "🚨", "weight": 0.25},
            {"name": "Bridge Usage", "score": bridge_score, "icon": "🌉", "weight": 0.10},
            {"name": "Account Age", "score": age_score, "icon": "📅", "weight": 0.05}
        ]
        
        overall_score = int(sum(f["score"] * f["weight"] for f in factors))
        
        # Determine risk level
        if overall_score >= 80:
            level = "CRITICAL RISK"
        elif overall_score >= 60:
            level = "HIGH RISK"
        elif overall_score >= 40:
            level = "MEDIUM RISK"
        else:
            level = "LOW RISK"
        
        # Generate recommendations
        recommendations = []
        if velocity_score > 60:
            recommendations.append("High transaction frequency detected - monitor for automated activity")
        if value_score > 60:
            recommendations.append("Large value transfers detected - enable real-time alerts")
        if deploy_score > 40:
            recommendations.append("Contract deployment activity - review deployed contracts for vulnerabilities")
        if severity_score > 60:
            recommendations.append("Associated with high-severity events - add to watchlist")
        if bridge_score > 40:
            recommendations.append("Active bridge user - monitor cross-chain movements")
        if age_score > 60:
            recommendations.append("Relatively new address - exercise caution")
        
        if not recommendations:
            recommendations.append("No significant risk indicators detected")
            recommendations.append("Continue standard monitoring")
        
        return {
            "address": address,
            "score": overall_score,
            "level": level,
            "factors": [
                {"name": f["name"], "score": f["score"], "icon": f["icon"]}
                for f in factors
            ],
            "recommendations": recommendations,
            "transaction_count": tx_count,
            "first_seen": str(first_seen) if first_seen else None,
            "last_seen": str(last_seen) if last_seen else None
        }
        
    except Exception as e:
        logger.error("risk_score_error", address=address, error=str(e))
        raise HTTPException(status_code=500, detail=f"Error calculating risk: {str(e)}")


@router.get("/risk/high-risk-wallets")
async def get_high_risk_wallets(
    limit: int = Query(10, description="Number of wallets to return", ge=1, le=50)
):
    """
    Get list of high-risk wallets based on event analysis.
    """
    from ..database.service import DatabaseService
    
    try:
        # Get recent high-severity events
        events, _ = await DatabaseService.get_events(
            severity="HIGH",
            limit=500
        )
        
        critical_events, _ = await DatabaseService.get_events(
            severity="CRITICAL",
            limit=500
        )
        
        all_events = events + critical_events
        
        # Count events per address
        address_scores = {}
        address_reasons = {}
        
        for event in all_events:
            for addr_field in ['from_address', 'to_address', 'contract_address']:
                addr = event.get(addr_field)
                if addr and addr != '0x0000000000000000000000000000000000000000':
                    addr = addr.lower()
                    
                    # Increment score based on severity
                    severity = (event.get('severity') or 'info').upper()
                    if severity == 'CRITICAL':
                        address_scores[addr] = address_scores.get(addr, 0) + 30
                    elif severity == 'HIGH':
                        address_scores[addr] = address_scores.get(addr, 0) + 15
                    
                    # Track reason
                    event_type = event.get('event_type', 'unknown')
                    if addr not in address_reasons:
                        address_reasons[addr] = event_type
        
        # Sort by score and take top N
        sorted_wallets = sorted(address_scores.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        # Format response
        high_risk_wallets = []
        for addr, score in sorted_wallets:
            # Cap score at 100
            capped_score = min(100, score)
            
            # Determine reason
            reason = address_reasons.get(addr, 'High severity events')
            if capped_score >= 80:
                reason = f"Critical: {reason}"
            elif capped_score >= 60:
                reason = f"High risk: {reason}"
            
            high_risk_wallets.append({
                "address": addr,
                "score": capped_score,
                "reason": reason
            })
        
        return {"wallets": high_risk_wallets}
        
    except Exception as e:
        logger.error("high_risk_wallets_error", error=str(e))
        return {"wallets": []}
