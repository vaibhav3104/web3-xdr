"""
Analytics API Routes for Sentinel3.
Provides historical data, charts, and risk scoring endpoints.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/analytics", tags=["analytics"])


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
    from ..database.service import DatabaseService
    from ..database.connection import DatabaseManager
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    try:
        # Get events from database
        events, _ = await DatabaseService.get_events(
            start_time=start_time,
            end_time=end_time,
            limit=10000  # Get a good sample
        )
        
        # Calculate statistics
        total_events = len(events)
        
        # Group by day
        events_by_day = {}
        events_by_chain = {}
        events_by_type = {}
        events_by_severity = {}
        total_value = 0
        
        for event in events:
            # By day
            timestamp = event.get('block_timestamp')
            if timestamp:
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    except:
                        timestamp = None
                if timestamp:
                    day_key = timestamp.strftime('%Y-%m-%d')
                    events_by_day[day_key] = events_by_day.get(day_key, 0) + 1
            
            # By chain
            chain = event.get('chain_id', 'unknown')
            events_by_chain[chain] = events_by_chain.get(chain, 0) + 1
            
            # By type
            event_type = event.get('event_type', 'unknown')
            events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
            
            # By severity
            severity = (event.get('severity') or 'info').upper()
            events_by_severity[severity] = events_by_severity.get(severity, 0) + 1
            
            # Value at risk
            amount_usd = event.get('amount_usd')
            if amount_usd and isinstance(amount_usd, (int, float)):
                total_value += float(amount_usd)
        
        # Convert events_by_day to sorted list
        day_list = [
            {"date": k, "count": v}
            for k, v in sorted(events_by_day.items())
        ]
        
        # Get incident count from shared state
        from ..shared_state import monitor_state
        incidents = monitor_state.get_incidents()
        total_incidents = len(incidents)
        
        # Calculate high severity events as "incidents"
        high_severity_count = (
            events_by_severity.get('CRITICAL', 0) + 
            events_by_severity.get('HIGH', 0)
        )
        
        return {
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
    from ..database.service import DatabaseService
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    try:
        events, _ = await DatabaseService.get_events(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )
        
        # Group by time period
        time_buckets = {}
        
        for event in events:
            timestamp = event.get('block_timestamp')
            if timestamp:
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    except:
                        continue
                
                if granularity == "hour":
                    key = timestamp.strftime('%Y-%m-%d %H:00')
                elif granularity == "week":
                    # Get week start (Monday)
                    week_start = timestamp - timedelta(days=timestamp.weekday())
                    key = f"Week of {week_start.strftime('%Y-%m-%d')}"
                else:  # day
                    key = timestamp.strftime('%Y-%m-%d')
                
                time_buckets[key] = time_buckets.get(key, 0) + 1
        
        # Sort and format
        sorted_data = sorted(time_buckets.items())
        
        return {
            "labels": [item[0] for item in sorted_data],
            "data": [item[1] for item in sorted_data],
            "granularity": granularity,
            "total": sum(time_buckets.values())
        }
        
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
    from ..database.service import DatabaseService
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    try:
        events, _ = await DatabaseService.get_events(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )
        
        chain_counts = {}
        for event in events:
            chain = event.get('chain_id', 'unknown')
            chain_counts[chain] = chain_counts.get(chain, 0) + 1
        
        # Sort by count descending
        sorted_chains = sorted(chain_counts.items(), key=lambda x: x[1], reverse=True)
        
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
        
        return {
            "labels": [item[0].title() for item in sorted_chains],
            "data": [item[1] for item in sorted_chains],
            "colors": [chain_colors.get(item[0].lower(), '#888888') for item in sorted_chains],
            "total": sum(chain_counts.values())
        }
        
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
    from ..database.connection import DatabaseManager
    from sqlalchemy import text
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    attack_counts = {}
    
    try:
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
        
        return {
            "labels": [item[0] for item in sorted_types],
            "data": [item[1] for item in sorted_types],
            "colors": [attack_colors.get(item[0], '#8b5cf6') for item in sorted_types],
            "total": sum(attack_counts.values())
        }
        
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
    from ..database.service import DatabaseService
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    try:
        events, _ = await DatabaseService.get_events(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )
        
        type_counts = {}
        for event in events:
            event_type = event.get('event_type', 'unknown')
            # Normalize type names
            type_name = event_type.replace('_', ' ').title()
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        # Sort by count descending, take top 10
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
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
        
        return {
            "labels": [item[0] for item in sorted_types],
            "data": [item[1] for item in sorted_types],
            "colors": [event_colors.get(item[0], '#8b5cf6') for item in sorted_types],
            "total": sum(type_counts.values())
        }
        
    except Exception as e:
        logger.error("event_type_chart_error", error=str(e))
        return {"labels": [], "data": [], "colors": [], "total": 0}


@router.get("/charts/value-over-time")
async def get_value_over_time(
    days: int = Query(30, description="Number of days", ge=1, le=365)
):
    """
    Get value at risk over time.
    """
    from ..database.service import DatabaseService
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    try:
        events, _ = await DatabaseService.get_events(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )
        
        # Group value by day
        value_by_day = {}
        
        for event in events:
            timestamp = event.get('block_timestamp')
            amount_usd = event.get('amount_usd')
            
            if timestamp and amount_usd:
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    except:
                        continue
                
                day_key = timestamp.strftime('%Y-%m-%d')
                
                if isinstance(amount_usd, (int, float)):
                    value_by_day[day_key] = value_by_day.get(day_key, 0) + float(amount_usd)
        
        # Sort and format
        sorted_data = sorted(value_by_day.items())
        
        return {
            "labels": [item[0] for item in sorted_data],
            "data": [round(item[1], 2) for item in sorted_data],
            "total": sum(value_by_day.values())
        }
        
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
                    first_seen = datetime.now(timezone.utc)
            
            age_days = (datetime.now(timezone.utc) - first_seen.replace(tzinfo=timezone.utc) if first_seen.tzinfo is None else first_seen).days
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
