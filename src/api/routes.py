"""
API Routes for Web3 XDR Dashboard.
Connected to real-time monitor data.
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger()

router = APIRouter()


# ============================================================================
# Pydantic Models for API
# ============================================================================

class IncidentSummary(BaseModel):
    """Summary of an incident for list view."""
    id: str
    title: str
    severity: str
    status: str
    attack_type: str
    confidence: float
    total_loss_usd: float
    affected_chains: List[str]
    created_at: datetime
    event_count: int = 0  # Phase 4: Number of events
    
    class Config:
        from_attributes = True


class TimelineEntry(BaseModel):
    """Timeline entry for incident details."""
    timestamp: datetime
    chain: str
    tx_hash: str
    description: str
    event_id: Optional[str] = None
    severity: Optional[str] = None


class IncidentDetail(BaseModel):
    """Full incident details with timeline and explanation."""
    id: str
    incident_id: str
    cluster_key: str
    title: str
    summary: str
    severity: str
    status: str
    attack_type: str
    confidence: float
    total_loss_usd: float
    event_count: int
    affected_chains: List[str]
    affected_contracts: Optional[List[str]] = None
    affected_addresses: Optional[List[str]] = None
    created_at: datetime
    updated_at: datetime
    first_event_time: Optional[datetime] = None
    last_event_time: Optional[datetime] = None
    
    # Phase 4: Timeline and explanation
    timeline: List[TimelineEntry] = []
    explanation: Optional[dict] = None  # Structured explanation JSON
    
    class Config:
        from_attributes = True


class EventSummary(BaseModel):
    """Security event summary."""
    event_id: str
    chain_id: str
    block_number: int
    tx_hash: str
    event_type: str
    severity: str
    timestamp: datetime


class EventDetail(BaseModel):
    """Full event details for log explorer."""
    id: str
    chain: str
    event_type: str
    tx_hash: str
    block: int
    contract: str
    severity: str
    timestamp: datetime
    data: dict = {}


class StatsResponse(BaseModel):
    """Statistics response."""
    total_events: int
    total_incidents: int
    active_incidents: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    blocks_scanned: int
    events_by_chain: dict
    events_by_type: dict
    uptime_seconds: int


class ChainStatus(BaseModel):
    """Chain status information."""
    chain_id: str
    chain_name: str
    head_height: int
    processed_height: int
    lag_blocks: int
    confirmed_height: int
    status: str  # healthy, lagging, error
    last_update: Optional[datetime]


class ChainsStatusResponse(BaseModel):
    """Chains status response."""
    chains: List[ChainStatus]
    total_chains: int
    healthy_chains: int
    lagging_chains: int


# ============================================================================
# Routes - Connected to Monitor State
# ============================================================================

@router.get("/incidents", response_model=List[IncidentSummary])
async def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, le=100, description="Max results"),
):
    """
    List all incidents with optional filtering.
    Only shows real incidents (from monitor or attack simulator).
    """
    from ..shared_state import monitor_state
    
    incidents = monitor_state.get_incidents()
    
    # Convert real incidents to response format
    all_incidents = [
        IncidentSummary(
            id=i.id,
            title=i.title,
            severity=i.severity.lower() if i.severity else "medium",
            status=i.status.lower() if i.status else "open",
            attack_type=i.attack_type,
            confidence=i.confidence,
            total_loss_usd=i.total_loss_usd,
            affected_chains=i.affected_chains,
            created_at=i.created_at,
        )
        for i in incidents
    ]
    
    # Filter by severity
    if severity:
        all_incidents = [i for i in all_incidents if i.severity == severity.lower()]
    
    # Filter by status
    if status:
        all_incidents = [i for i in all_incidents if i.status == status.lower()]
    
    # Sort by severity (critical first) then by created_at descending
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_incidents.sort(key=lambda i: (severity_order.get(i.severity, 4), -i.created_at.timestamp() if i.created_at else 0))
    
    return all_incidents[:limit]


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
async def get_incident_details(incident_id: str):
    """
    Get full incident details including timeline and structured explanation.
    
    Phase 4: Returns complete incident information with:
    - Timeline of all events
    - Structured explanation (summary, technical context, evidence)
    - Recommended actions
    """
    from ..shared_state import monitor_state
    
    # Get incident from monitor state
    incidents = monitor_state.get_incidents()
    incident = next((i for i in incidents if i.id == incident_id or getattr(i, 'incident_id', '') == incident_id), None)
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Build timeline from incident data
    timeline = []
    if hasattr(incident, 'timeline') and incident.timeline:
        timeline = [
            TimelineEntry(
                timestamp=entry.get('timestamp', incident.created_at) if isinstance(entry, dict) else entry.timestamp,
                chain=entry.get('chain', 'unknown') if isinstance(entry, dict) else entry.chain,
                tx_hash=entry.get('tx_hash', '') if isinstance(entry, dict) else entry.tx_hash,
                description=entry.get('description', '') if isinstance(entry, dict) else entry.description,
                event_id=entry.get('event_id') if isinstance(entry, dict) else getattr(entry, 'event_id', None),
                severity=entry.get('severity') if isinstance(entry, dict) else getattr(entry, 'severity', None)
            )
            for entry in incident.timeline
        ]
    else:
        # Fallback: create timeline from event_ids
        timeline = [
            TimelineEntry(
                timestamp=incident.created_at,
                chain=chain,
                tx_hash="",
                description=f"Event on {chain}",
                severity=incident.severity.lower() if incident.severity else "medium"
            )
            for chain in incident.affected_chains
        ]
    
    # Get explanation (if available)
    explanation = None
    if hasattr(incident, 'explanation_json') and incident.explanation_json:
        explanation = incident.explanation_json
    elif hasattr(incident, 'summary'):
        # Generate basic explanation from summary
        explanation = {
            "summary": incident.summary,
            "recommended_action": "INVESTIGATE",
            "confidence": incident.confidence
        }
    
    return IncidentDetail(
        id=incident.id,
        incident_id=getattr(incident, 'incident_id', incident.id),
        cluster_key=getattr(incident, 'cluster_key', ''),
        title=incident.title,
        summary=incident.summary,
        severity=incident.severity.lower() if incident.severity else "medium",
        status=incident.status.lower() if incident.status else "open",
        attack_type=incident.attack_type,
        confidence=incident.confidence,
        total_loss_usd=incident.total_loss_usd,
        event_count=getattr(incident, 'event_count', len(incident.affected_chains)),
        affected_chains=incident.affected_chains,
        affected_contracts=getattr(incident, 'affected_contracts', None),
        affected_addresses=getattr(incident, 'affected_addresses', None),
        created_at=incident.created_at,
        updated_at=getattr(incident, 'updated_at', incident.created_at),
        first_event_time=getattr(incident, 'first_event_time', None),
        last_event_time=getattr(incident, 'last_event_time', None),
        timeline=timeline,
        explanation=explanation
    )


@router.get("/events")
async def list_events(
    chain_id: Optional[str] = Query(None, description="Filter by chain"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by event status (e.g., PENDING, CONFIRMED)"),
    start_time: Optional[str] = Query(None, description="Start time ISO format"),
    end_time: Optional[str] = Query(None, description="End time ISO format"),
    cursor: Optional[str] = Query(None, description="Cursor for pagination"),
    include_total: bool = Query(False, description="Include total count (expensive)"),
    search: Optional[str] = Query(None, description="Simple text search"),
    query: Optional[str] = Query(None, description="Lucene query (e.g., chain:ethereum AND severity:critical)"),
    limit: int = Query(500, le=1000, description="Max results"),
):
    """
    List security events with full details for log explorer.
    
    Reads from PostgreSQL database (not in-memory state) so API and Worker
    can run in separate containers.
    
    Supports:
    - Basic filters: chain_id, event_type, severity, time range
    - Simple text search: search parameter
    - Advanced Lucene queries: query parameter
    
    Lucene Query Examples:
    - chain:ethereum AND severity:critical
    - event_type:Transfer AND amount:[1000 TO *]
    - (chain:ethereum OR chain:polygon) AND NOT severity:info
    """
    from ..database.service import DatabaseService
    from ..database.connection import DatabaseManager
    from ..query.lucene_parser import execute_lucene_query
    
    # Parse time filters
    start_dt = None
    end_dt = None
    if start_time:
        try:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        except:
            pass
    if end_time:
        try:
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        except:
            pass
    
    # Query events from PostgreSQL database
    logger.info("api_querying_database_for_events", 
                chain_id=chain_id, 
                event_type=event_type, 
                severity=severity,
                status=status,
                start_time=str(start_dt) if start_dt else None,
                end_time=str(end_dt) if end_dt else None,
                limit=limit,
                cursor=cursor is not None)
    try:
        # Get actual total count from database (only if requested - expensive operation)
        # Skip if it times out - don't block the API response
        total_count = None
        if include_total:
            try:
                total_count = await DatabaseService.get_events_count(
                    chain_id=chain_id,
                    event_type=event_type,
                    severity=severity,
                    start_time=start_dt,
                    end_time=end_dt
                )
                # If None, count query timed out - that's OK, we'll just not include total
            except Exception as e:
                logger.warning("count_query_failed", error=str(e))
                total_count = None
        
        # Fetch events with cursor pagination (preferred) or offset (backward compat)
        db_events, next_cursor = await DatabaseService.get_events(
            chain_id=chain_id,
            event_type=event_type,
            severity=severity,
            status=status,
            start_time=start_dt,
            end_time=end_dt,
            limit=limit,
            offset=0,  # Not used if cursor provided
            cursor=cursor
        )
        logger.info("api_database_query_successful", events_count=len(db_events), total_in_db=total_count, has_next_cursor=next_cursor is not None)
    except Exception as e:
        logger.error("database_query_failed", error=str(e), exc_info=True)
        # Fallback to empty result
        total_count = None
        db_events = []
        next_cursor = None
    
    # Convert events to dict format expected by frontend
    # get_events now returns dicts directly, so just format them
    event_dicts = []
    for e in db_events:
        # e is already a dict from get_events
        block_timestamp = e.get('block_timestamp')
        if isinstance(block_timestamp, datetime):
            # Ensure timezone-aware
            if block_timestamp.tzinfo is None:
                from datetime import timezone
                block_timestamp = block_timestamp.replace(tzinfo=timezone.utc)
            timestamp_str = block_timestamp.isoformat()
        elif isinstance(block_timestamp, str):
            # If string, ensure it has timezone info
            if not block_timestamp.endswith('Z') and '+' not in block_timestamp:
                timestamp_str = block_timestamp + '+00:00'
            else:
                timestamp_str = block_timestamp
        else:
            timestamp_str = None
        
        event_dict = {
            "id": e.get('id'),
            "event_id": e.get('event_id'),
            "chain": e.get('chain_id'),
            "chain_id": e.get('chain_id'),
            "event_type": e.get('event_type'),
            "tx_hash": e.get('tx_hash'),
            "block": e.get('block_number'),
            "block_number": e.get('block_number'),
            "contract": e.get('contract_address'),
            "contract_address": e.get('contract_address'),
            "from_address": e.get('from_address'),
            "to_address": e.get('to_address'),
            "severity": (e.get('severity') or 'LOW').lower(),
            "timestamp": timestamp_str,
            "amount": e.get('amount'),
            "amount_usd": e.get('amount_usd'),
            "data": e.get('raw_data') or {},
            **(e.get('raw_data') or {})  # Flatten raw_data fields for searching
        }
        event_dicts.append(event_dict)
    
    # Apply Lucene query if provided
    if query and query.strip():
        event_dicts = execute_lucene_query(query, event_dicts)
    
    # Fall back to simple text search
    elif search:
        search_lower = search.lower()
        event_dicts = [
            e for e in event_dicts 
            if any(
                search_lower in str(v).lower() 
                for v in e.values() 
                if v is not None
            )
        ]
    
    # Limit results
    event_dicts = event_dicts[:limit]
    
    # Return full event details with cursor pagination
    response = {
        "returned": len(event_dicts),  # Number of events actually returned
        "query_used": query if query else (f"text:{search}" if search else None),
        "events": [
            {
                "id": e.get("id"),
                "chain": e.get("chain"),
                "event_type": e.get("event_type"),
                "tx_hash": e.get("tx_hash"),
                "block": e.get("block"),
                "contract": e.get("contract"),
                "severity": e.get("severity"),
                "timestamp": e.get("timestamp"),
                "data": e.get("data", {})
            }
            for e in event_dicts
        ]
    }
    
    # Add total count if requested
    if include_total and total_count is not None:
        response["total"] = total_count
    
    # Add next cursor if available
    if next_cursor:
        response["next_cursor"] = next_cursor
    
    return response


@router.get("/events/query-help")
async def get_query_help():
    """
    Get help documentation for Lucene query syntax.
    """
    from ..query.lucene_parser import get_query_syntax_help
    return get_query_syntax_help()


@router.get("/stats")
async def get_statistics():
    """
    Get real-time system statistics and metrics.
    Only counts real incidents (no simulated demos).
    """
    from ..shared_state import monitor_state
    
    stats = monitor_state.get_stats()
    incidents = monitor_state.get_incidents()
    
    uptime = 0
    if stats["start_time"]:
        uptime = int((datetime.utcnow() - stats["start_time"]).total_seconds())
    
    # Count real incidents only
    total_incidents = len(incidents)
    active_incidents = len([i for i in incidents if i.status.lower() in ("open", "investigating")])
    critical_count = len([i for i in incidents if i.severity.upper() == "CRITICAL"])
    high_count = len([i for i in incidents if i.severity.upper() == "HIGH"])
    medium_count = len([i for i in incidents if i.severity.upper() == "MEDIUM"])
    low_count = len([i for i in incidents if i.severity.upper() == "LOW"])
    
    return {
        "total_events": stats["total_events"],
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "critical_alerts": critical_count,
        "high_alerts": high_count,
        "medium_alerts": medium_count,
        "low_alerts": low_count,
        "blocks_scanned": stats["blocks_scanned"],
        "events_by_chain": stats["events_by_chain"],
        "events_by_type": stats["events_by_type"],
        "uptime_seconds": uptime,
        "last_event_time": stats["last_event_time"].isoformat() if stats["last_event_time"] else None,
    }


@router.get("/chains")
async def list_chains():
    """
    List monitored chains and their status.
    """
    from ..shared_state import monitor_state
    
    stats = monitor_state.get_stats()
    chains_data = stats.get("events_by_chain", {})
    
    chains = []
    for chain_id, event_count in chains_data.items():
        chains.append({
            "id": chain_id,
            "name": chain_id.title(),
            "status": "active",
            "events_detected": event_count
        })
    
    # Add default chains if not seen yet
    for chain_id in ["ethereum", "polygon", "arbitrum"]:
        if chain_id not in chains_data:
            chains.append({
                "id": chain_id,
                "name": chain_id.title(),
                "status": "connected",
                "events_detected": 0
            })
    
    return {"chains": chains}


@router.get("/bridges")
async def list_bridges():
    """
    List monitored bridges and their status.
    """
    return {
        "bridges": [
            {
                "id": "wormhole_eth",
                "name": "Wormhole (Ethereum)",
                "source_chain": "ethereum",
                "dest_chain": "solana",
                "status": "monitored"
            },
            {
                "id": "polygon_pos",
                "name": "Polygon PoS Bridge",
                "source_chain": "ethereum",
                "dest_chain": "polygon",
                "status": "monitored"
            }
        ]
    }


# ============================================================================
# Storage & Maintenance Routes
# ============================================================================

@router.get("/storage/stats")
async def get_storage_stats():
    """
    Get storage statistics (PostgreSQL).
    Shows event counts, oldest/newest events, and breakdown by chain.
    """
    try:
        from ..database.sync_service import get_storage_stats
        return get_storage_stats()
    except ImportError:
        return {"error": "Database module not available", "storage": "in-memory"}


@router.get("/chains/debug-logs")
async def get_debug_logs():
    """
    Get recent debug logs for non-EVM chain initialization.
    """
    from ..shared_state import monitor_state
    
    chain_status = monitor_state.get_chain_status()
    
    # Get all chains including failed ones
    all_chains = []
    for chain_id, status in chain_status.items():
        all_chains.append({
            "chain_id": chain_id,
            "chain_type": status.get("chain_type", "unknown"),
            "status": status.get("status", "unknown"),
            "last_block": status.get("last_block", 0),
            "last_update": status.get("last_update"),
            "error": status.get("error"),
        })
    
    return {
        "total_tracked": len(all_chains),
        "connected": len([c for c in all_chains if c["status"] == "connected"]),
        "failed": len([c for c in all_chains if c["status"] in ["failed", "error"]]),
        "chains": sorted(all_chains, key=lambda x: x["chain_id"])
    }


@router.get("/chains/test-rpc")
async def test_rpc_connections():
    """
    Test non-EVM RPC connections directly.
    Useful for debugging connection issues.
    """
    import aiohttp
    
    results = {}
    
    # Test Cosmos RPCs
    cosmos_rpcs = [
        ("cosmos", "https://cosmos-rpc.polkachu.com/status"),
        ("osmosis", "https://osmosis-rpc.polkachu.com/status"),
        ("injective", "https://injective-rpc.polkachu.com/status"),
    ]
    
    # Test Move RPCs
    move_rpcs = [
        ("aptos", "https://fullnode.mainnet.aptoslabs.com/v1"),
    ]
    
    # Test Near RPCs
    near_rpcs = [
        ("near", "https://rpc.mainnet.near.org"),
    ]
    
    async with aiohttp.ClientSession() as session:
        # Test Cosmos
        for chain, url in cosmos_rpcs:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        height = data.get("result", {}).get("sync_info", {}).get("latest_block_height", "N/A")
                        results[chain] = {"status": "connected", "block": height}
                    else:
                        results[chain] = {"status": "error", "code": resp.status}
            except Exception as e:
                results[chain] = {"status": "failed", "error": str(e)[:100]}
        
        # Test Aptos
        for chain, url in move_rpcs:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        version = data.get("ledger_version", "N/A")
                        results[chain] = {"status": "connected", "version": version}
                    else:
                        results[chain] = {"status": "error", "code": resp.status}
            except Exception as e:
                results[chain] = {"status": "failed", "error": str(e)[:100]}
        
        # Test Near
        for chain, url in near_rpcs:
            try:
                async with session.post(
                    url, 
                    json={"jsonrpc": "2.0", "id": "test", "method": "status", "params": []},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        height = data.get("result", {}).get("sync_info", {}).get("latest_block_height", "N/A")
                        results[chain] = {"status": "connected", "block": height}
                    else:
                        results[chain] = {"status": "error", "code": resp.status}
            except Exception as e:
                results[chain] = {"status": "failed", "error": str(e)[:100]}
    
    return results


@router.get("/chains/status")
async def get_chains_status():
    """
    Get connection status of all blockchain listeners.
    Shows EVM and non-EVM chain connection health.
    """
    from ..shared_state import monitor_state
    
    chain_status = monitor_state.get_chain_status()
    events_by_chain = monitor_state.stats.get("events_by_chain", {})
    
    # Categorize chains
    evm_chains = []
    non_evm_chains = []
    
    evm_types = ["ethereum", "polygon", "arbitrum", "optimism", "base", "avalanche", "bsc"]
    non_evm_types = ["cosmos", "osmosis", "injective", "aptos", "sui", "near", "solana"]
    
    for chain_id, status in chain_status.items():
        status["events_count"] = events_by_chain.get(chain_id, 0)
        
        if status.get("chain_type") == "evm" or chain_id.lower() in evm_types:
            evm_chains.append(status)
        else:
            non_evm_chains.append(status)
    
    # Add any chains with events but not in status tracking
    for chain_id, count in events_by_chain.items():
        if chain_id not in chain_status:
            entry = {
                "chain_id": chain_id,
                "chain_type": "evm" if chain_id.lower() in evm_types else "non-evm",
                "status": "connected",
                "events_count": count,
                "last_update": None
            }
            if chain_id.lower() in evm_types:
                evm_chains.append(entry)
            else:
                non_evm_chains.append(entry)
    
    return {
        "summary": {
            "total_chains": len(evm_chains) + len(non_evm_chains),
            "evm_chains": len(evm_chains),
            "non_evm_chains": len(non_evm_chains),
            "chains_with_events": len([c for c in evm_chains + non_evm_chains if c.get("events_count", 0) > 0])
        },
        "evm_chains": sorted(evm_chains, key=lambda x: x.get("events_count", 0), reverse=True),
        "non_evm_chains": sorted(non_evm_chains, key=lambda x: x.get("events_count", 0), reverse=True)
    }


@router.get("/chains/status", response_model=ChainsStatusResponse)
async def get_chains_status():
    """
    Get status of all monitored chains.
    Reports head height, processed height, and lag.
    Queries Prometheus metrics from worker.
    """
    import os
    import yaml
    from pathlib import Path
    import httpx
    
    # Load chain config
    config_path = Path(__file__).resolve().parent.parent.parent / "config" / "chains.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    # Try to fetch metrics from worker (if available)
    metrics_text = None
    worker_url = os.getenv("WORKER_METRICS_URL", "http://localhost:9090/metrics")
    
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(worker_url)
            if response.status_code == 200:
                metrics_text = response.text
    except Exception:
        pass  # Worker may not be running
    
    # Parse metrics
    metrics_data = {}
    if metrics_text:
        from prometheus_client.parser import text_string_to_metric_families
        for family in text_string_to_metric_families(metrics_text):
            for sample in family.samples:
                if sample.name.startswith("sentinel3_"):
                    # Extract labels
                    chain = sample.labels.get("chain", "")
                    key = f"{sample.name}:{chain}"
                    metrics_data[key] = sample.value
    
    chains_status = []
    healthy_count = 0
    lagging_count = 0
    
    for chain_config in config.get("chains", []):
        chain_id = chain_config.get("chain_id", "")
        chain_name = chain_config.get("chain_name", chain_id)
        
        # Get metrics
        head_height = int(metrics_data.get(f"sentinel3_chain_head_height:{chain_id}", 0))
        processed_height = int(metrics_data.get(f"sentinel3_worker_processed_height:{chain_id}", 0))
        lag_blocks = int(metrics_data.get(f"sentinel3_head_lag_blocks:{chain_id}", 0))
        confirmed_height = int(metrics_data.get(f"sentinel3_finality_confirmed_blocks:{chain_id}", 0))
        
        # Determine status
        if lag_blocks > 100:
            status = "lagging"
            lagging_count += 1
        elif head_height == 0:
            status = "error"
        else:
            status = "healthy"
            healthy_count += 1
        
        chains_status.append(ChainStatus(
            chain_id=chain_id,
            chain_name=chain_name,
            head_height=head_height,
            processed_height=processed_height,
            lag_blocks=lag_blocks,
            confirmed_height=confirmed_height,
            status=status,
            last_update=datetime.now()
        ))
    
    return ChainsStatusResponse(
        chains=chains_status,
        total_chains=len(chains_status),
        healthy_chains=healthy_count,
        lagging_chains=lagging_count
    )


@router.post("/maintenance/purge")
async def purge_old_data(
    hours: int = Query(24, ge=1, le=720, description="Delete data older than X hours"),
    confirm: bool = Query(False, description="Must be true to execute purge"),
):
    """
    Purge events and resolved incidents older than specified hours.
    Default: 24 hours. Maximum: 720 hours (30 days).
    
    ⚠️ This action is irreversible! Set confirm=true to execute.
    
    Called automatically by Cloud Scheduler every 24 hours.
    """
    if not confirm:
        return {
            "message": "Dry run - set confirm=true to execute",
            "would_purge_data_older_than_hours": hours,
            "warning": "This action is irreversible!"
        }
    
    try:
        from ..database.sync_service import purge_old_events
        result = purge_old_events(hours=hours)
        return {
            "status": "success",
            "purge_result": result,
            "hours_threshold": hours
        }
    except ImportError:
        return {"error": "Database module not available", "status": "failed"}
    except Exception as e:
        return {"error": str(e), "status": "failed"}


@router.get("/maintenance/verify-schema")
async def verify_schema(user_info: dict = Depends(lambda: __import__("src.api.maintenance_auth", fromlist=["require_maintenance_access"]).require_maintenance_access())):
    """
    Verify database schema - check if status column exists.
    Requires maintenance access (admin role or MAINTENANCE_TOKEN).
    """
    from ..api.maintenance_auth import log_maintenance_action, require_maintenance_access
    try:
        from sqlalchemy import text
        from ..database.connection import DatabaseManager
        
        await DatabaseManager.initialize()
        
        async with DatabaseManager.get_session() as session:
            # Check if status column exists
            result = await session.execute(text("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns 
                WHERE table_name = 'events' AND column_name = 'status'
            """))
            status_col = result.fetchone()
            
            # Get all columns
            result = await session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'events'
                ORDER BY ordinal_position
            """))
            all_cols = [row[0] for row in result.fetchall()]
            
            return {
                "status": "success",
                "status_column_exists": status_col is not None,
                "status_column_details": {
                    "name": status_col[0] if status_col else None,
                    "type": status_col[1] if status_col else None,
                    "nullable": status_col[2] if status_col else None,
                    "default": status_col[3] if status_col else None,
                } if status_col else None,
                "all_columns": all_cols,
                "total_columns": len(all_cols)
            }
        
        # Log audit
        await log_maintenance_action(
            action_type="VERIFY_SCHEMA",
            user_info=user_info,
            payload={},
            outcome="success"
        )
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        # Log audit
        await log_maintenance_action(
            action_type="VERIFY_SCHEMA",
            user_info=user_info,
            payload={},
            outcome="error",
            error_message=str(e)
        )
        return {
            "status": "error",
            "error": str(e)
        }

@router.post("/maintenance/migrate-events")
async def migrate_events_table(user_info: dict = Depends(lambda: __import__("src.api.maintenance_auth", fromlist=["require_maintenance_access"]).require_maintenance_access())):
    """
    Migrate events table to add missing columns (status, block_hash, etc.).
    This fixes the schema mismatch between EventModel and the database table.
    
    Requires maintenance access (admin role or MAINTENANCE_TOKEN).
    
    Handles all edge cases:
    - Creates columns only if they don't exist
    - Creates indexes separately (can't be in DO blocks)
    - Handles NULL values in unique index
    - Provides detailed error reporting
    """
    from ..api.maintenance_auth import log_maintenance_action
    try:
        from sqlalchemy import text
        from ..database.connection import DatabaseManager
        
        await DatabaseManager.initialize()
        
        columns_added = []
        indexes_created = []
        
        async with DatabaseManager.get_session() as session:
            # Add status column (with index creation in separate statement)
            result = await session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'events' AND column_name = 'status'
            """))
            if not result.fetchone():
                await session.execute(text("ALTER TABLE events ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'PENDING'"))
                columns_added.append("status")
            
            # Add other missing columns
            column_defs = [
                ("block_hash", "VARCHAR(128)", True),
                ("canonical_event_hash", "VARCHAR(128)", True),
                ("confirmed_at", "TIMESTAMP WITH TIME ZONE", False),
                ("log_index", "INTEGER", False),
                ("topics", "VARCHAR(128)[]", False),
                ("asset_type", "VARCHAR(32)", False),
                ("asset_address", "VARCHAR(128)", False),
            ]
            
            for col_name, col_def, needs_index in column_defs:
                result = await session.execute(text(f"""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'events' AND column_name = '{col_name}'
                """))
                if not result.fetchone():
                    await session.execute(text(f"ALTER TABLE events ADD COLUMN {col_name} {col_def}"))
                    columns_added.append(col_name)
            
            # Create indexes separately (must be outside DO blocks)
            # Check if indexes exist before creating
            index_checks = [
                ("ix_events_status", "CREATE INDEX IF NOT EXISTS ix_events_status ON events(status, chain_id) WHERE status IS NOT NULL"),
                ("ix_events_block_hash", "CREATE INDEX IF NOT EXISTS ix_events_block_hash ON events(block_hash) WHERE block_hash IS NOT NULL"),
                ("ix_events_canonical_event_hash", "CREATE INDEX IF NOT EXISTS ix_events_canonical_event_hash ON events(canonical_event_hash) WHERE canonical_event_hash IS NOT NULL"),
                ("ix_events_unique_key", "CREATE UNIQUE INDEX IF NOT EXISTS ix_events_unique_key ON events(chain_id, tx_hash, COALESCE(log_index, -1))"),
            ]
            
            for index_name, create_sql in index_checks:
                # Check if index exists
                result = await session.execute(text(f"""
                    SELECT indexname 
                    FROM pg_indexes 
                    WHERE tablename = 'events' AND indexname = '{index_name}'
                """))
                if not result.fetchone():
                    try:
                        await session.execute(text(create_sql))
                        indexes_created.append(index_name)
                    except Exception as idx_error:
                        # Index might fail if column doesn't exist or constraint conflict
                        # Log but don't fail the migration
                        logger.warning(f"index_creation_failed", index=index_name, error=str(idx_error))
            
            await session.commit()
            
            return {
                "status": "success",
                "message": "Events table migration completed successfully",
                "columns_added": columns_added,
                "indexes_created": indexes_created,
                "summary": f"Added {len(columns_added)} columns and {len(indexes_created)} indexes"
            }
    except Exception as e:
        import traceback
        error_details = {
            "error": str(e),
            "type": type(e).__name__,
        }
        logger.error("migration_failed", **error_details, exc_info=True)
        
        # Log audit
        await log_maintenance_action(
            action_type="MIGRATE_EVENTS",
            user_info=user_info,
            payload={},
            outcome="error",
            error_message=str(e)
        )
        
        return {
            "status": "error",
            **error_details
        }

@router.post("/maintenance/init-db")
async def initialize_database():
    """
    Initialize database tables.
    Safe to call multiple times (uses CREATE IF NOT EXISTS).
    """
    try:
        from ..database.sync_service import ensure_tables_exist
        success = ensure_tables_exist()
        return {
            "status": "success" if success else "failed",
            "message": "Database tables initialized" if success else "Failed to initialize tables"
        }
    except ImportError:
        return {"error": "Database module not available", "status": "failed"}
    except Exception as e:
        return {"error": str(e), "status": "failed"}

@router.post("/maintenance/create-indexes")
async def create_performance_indexes():
    """
    Create performance indexes on events table.
    Safe to call multiple times (uses CREATE INDEX IF NOT EXISTS).
    """
    try:
        from ..database.connection import DatabaseManager
        from sqlalchemy import text
        import asyncio
        
        await DatabaseManager.initialize()
        
        results = {}
        async with DatabaseManager.get_session() as session:
            # Index 1: Timeline sorting
            try:
                await asyncio.wait_for(
                    session.execute(text(
                        "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);"
                    )),
                    timeout=60.0
                )
                results["idx_events_created_at"] = "created"
            except asyncio.TimeoutError:
                results["idx_events_created_at"] = "timeout"
            except Exception as e:
                results["idx_events_created_at"] = f"error: {str(e)}"
            
            # Index 2: Chain + timestamp
            try:
                await asyncio.wait_for(
                    session.execute(text(
                        "CREATE INDEX IF NOT EXISTS idx_events_chain_timestamp ON events(chain_id, block_timestamp DESC);"
                    )),
                    timeout=60.0
                )
                results["idx_events_chain_timestamp"] = "created"
            except asyncio.TimeoutError:
                results["idx_events_chain_timestamp"] = "timeout"
            except Exception as e:
                results["idx_events_chain_timestamp"] = f"error: {str(e)}"
            
            # Index 3: Chain + event_type
            try:
                await asyncio.wait_for(
                    session.execute(text(
                        "CREATE INDEX IF NOT EXISTS idx_events_chain_type ON events(chain_id, event_type);"
                    )),
                    timeout=60.0
                )
                results["idx_events_chain_type"] = "created"
            except asyncio.TimeoutError:
                results["idx_events_chain_type"] = "timeout"
            except Exception as e:
                results["idx_events_chain_type"] = f"error: {str(e)}"
        
        return {
            "status": "success",
            "indexes": results
        }
    except Exception as e:
        logger.error("create_indexes_failed", error=str(e), exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }

@router.get("/maintenance/db-status")
async def get_database_status():
    """
    Check database status: events count, indexes, and table statistics.
    Uses simpler queries to avoid timeouts.
    """
    try:
        from ..database.connection import DatabaseManager
        from sqlalchemy import text
        import asyncio
        
        async with DatabaseManager.get_session() as session:
            status_info = {}
            
            # Step 1: Check if table exists (fast)
            try:
                result = await asyncio.wait_for(
                    session.execute(text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'events')")),
                    timeout=5.0
                )
                table_exists = result.scalar()
                status_info["table_exists"] = table_exists
                
                if not table_exists:
                    return {
                        "status": "success",
                        "message": "Events table does not exist",
                        **status_info
                    }
            except asyncio.TimeoutError:
                return {"status": "error", "error": "Timeout checking if table exists"}
            except Exception as e:
                status_info["table_check_error"] = str(e)
            
            # Step 2: Get indexes (fast - uses system catalog)
            try:
                result = await asyncio.wait_for(
                    session.execute(text("""
                        SELECT indexname 
                        FROM pg_indexes 
                        WHERE tablename = 'events' 
                        ORDER BY indexname
                    """)),
                    timeout=5.0
                )
                indexes = [row[0] for row in result.fetchall()]
                status_info["indexes"] = indexes
                status_info["performance_indexes"] = {
                    "idx_events_created_at": "idx_events_created_at" in indexes,
                    "idx_events_chain_timestamp": "idx_events_chain_timestamp" in indexes
                }
            except asyncio.TimeoutError:
                status_info["index_check_timeout"] = True
            except Exception as e:
                status_info["index_check_error"] = str(e)
            
            # Step 3: Try to get approximate count (may timeout)
            try:
                result = await asyncio.wait_for(
                    session.execute(text("SELECT COUNT(*) FROM events LIMIT 1")),
                    timeout=10.0
                )
                # Actually get full count
                result = await asyncio.wait_for(
                    session.execute(text("SELECT COUNT(*) FROM events")),
                    timeout=30.0
                )
                event_count = result.scalar()
                status_info["event_count"] = event_count
            except asyncio.TimeoutError:
                status_info["count_timeout"] = True
                status_info["event_count"] = "timeout"
            except Exception as e:
                status_info["count_error"] = str(e)
            
            # Step 4: Try to get a sample (fast with LIMIT)
            try:
                result = await asyncio.wait_for(
                    session.execute(text("SELECT chain_id, event_type FROM events LIMIT 5")),
                    timeout=10.0
                )
                samples = [{"chain": row[0], "type": row[1]} for row in result.fetchall()]
                status_info["sample_events"] = samples
            except asyncio.TimeoutError:
                status_info["sample_timeout"] = True
            except Exception as e:
                status_info["sample_error"] = str(e)
            
            return {
                "status": "success",
                **status_info
            }
    except Exception as e:
        logger.error("db_status_check_failed", error=str(e), error_type=type(e).__name__, exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "error_type": type(e).__name__
        }
