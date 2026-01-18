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
    # Contract and address info for ML-detected threats
    affected_contracts: Optional[List[str]] = None
    affected_addresses: Optional[List[str]] = None
    summary: Optional[str] = None
    recommended_actions: Optional[List[str]] = None
    
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
    Fetches from both in-memory state and database.
    """
    from ..shared_state import monitor_state
    from ..database.service import DatabaseService
    
    all_incidents = []
    seen_ids = set()
    
    # 1. Get incidents from in-memory state (simulator, etc.)
    memory_incidents = monitor_state.get_incidents()
    for i in memory_incidents:
        if i.id not in seen_ids:
            seen_ids.add(i.id)
            all_incidents.append(IncidentSummary(
                id=i.id,
                title=i.title,
                severity=i.severity.lower() if i.severity else "medium",
                status=i.status.lower() if i.status else "open",
                attack_type=i.attack_type,
                confidence=i.confidence,
                total_loss_usd=i.total_loss_usd,
                affected_chains=i.affected_chains,
                created_at=i.created_at,
                affected_contracts=getattr(i, 'affected_contracts', None),
                affected_addresses=getattr(i, 'affected_addresses', None),
                summary=getattr(i, 'summary', None),
                recommended_actions=getattr(i, 'recommended_actions', None),
            ))
    
    # 2. Get incidents from database (worker-created)
    try:
        db_incidents = await DatabaseService.get_incidents(
            severity=severity,
            status=status,
            limit=limit * 2  # Fetch more to account for overlap
        )
        for inc in db_incidents:
            if inc["id"] not in seen_ids:
                seen_ids.add(inc["id"])
                all_incidents.append(IncidentSummary(
                    id=inc["id"],
                    title=inc["title"] or "Security Incident",
                    severity=inc["severity"],
                    status=inc["status"],
                    attack_type=inc["attack_type"],
                    confidence=inc["confidence"],
                    total_loss_usd=inc["total_loss_usd"],
                    affected_chains=inc["affected_chains"],
                    created_at=inc["created_at"],
                    affected_contracts=inc.get("affected_contracts"),
                    affected_addresses=inc.get("affected_addresses"),
                    summary=inc.get("summary"),
                    recommended_actions=inc.get("recommended_actions"),
                ))
    except Exception as e:
        logger.warning("db_incidents_fetch_failed", error=str(e))
    
    # Filter by severity (for in-memory incidents)
    if severity:
        all_incidents = [i for i in all_incidents if i.severity == severity.lower()]
    
    # Filter by status (for in-memory incidents)
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


class IncidentStatusUpdate(BaseModel):
    """Request body for updating incident status."""
    status: str


@router.post("/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(incident_id: str):
    """
    Acknowledge an incident.
    
    This marks the incident as acknowledged, indicating that
    a security analyst has reviewed it.
    """
    from ..shared_state import monitor_state
    from ..database.service import DatabaseService
    
    logger.info("acknowledge_incident_request", incident_id=incident_id)
    
    # Try to update in database first
    try:
        updated = await DatabaseService.update_incident_status(
            incident_id=incident_id,
            status="ACKNOWLEDGED"
        )
        if updated:
            logger.info("incident_acknowledged_in_db", incident_id=incident_id)
            return {"status": "acknowledged", "incident_id": incident_id, "source": "database"}
    except Exception as e:
        logger.warning("db_acknowledge_failed", incident_id=incident_id, error=str(e))
    
    # Fallback to in-memory update
    incidents = monitor_state.get_incidents()
    for incident in incidents:
        if incident.id == incident_id or getattr(incident, 'incident_id', '') == incident_id:
            incident.status = "ACKNOWLEDGED"
            logger.info("incident_acknowledged_in_memory", incident_id=incident_id)
            return {"status": "acknowledged", "incident_id": incident_id, "source": "memory"}
    
    raise HTTPException(status_code=404, detail="Incident not found")


@router.put("/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, body: IncidentStatusUpdate):
    """
    Update the status of an incident.
    
    Valid statuses: OPEN_PENDING, ACKNOWLEDGED, INVESTIGATING, RESOLVED, CLOSED
    """
    from ..shared_state import monitor_state
    from ..database.service import DatabaseService
    
    valid_statuses = ["OPEN_PENDING", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"]
    new_status = body.status.upper()
    
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    logger.info("update_incident_status_request", incident_id=incident_id, new_status=new_status)
    
    # Try to update in database first
    try:
        updated = await DatabaseService.update_incident_status(
            incident_id=incident_id,
            status=new_status
        )
        if updated:
            logger.info("incident_status_updated_in_db", incident_id=incident_id, status=new_status)
            return {"status": new_status, "incident_id": incident_id, "source": "database"}
    except Exception as e:
        logger.warning("db_status_update_failed", incident_id=incident_id, error=str(e))
    
    # Fallback to in-memory update
    incidents = monitor_state.get_incidents()
    for incident in incidents:
        if incident.id == incident_id or getattr(incident, 'incident_id', '') == incident_id:
            incident.status = new_status
            logger.info("incident_status_updated_in_memory", incident_id=incident_id, status=new_status)
            return {"status": new_status, "incident_id": incident_id, "source": "memory"}
    
    raise HTTPException(status_code=404, detail="Incident not found")


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
    
    # ========== DEBUG: Log all incoming parameters ==========
    logger.info("DEBUG_API_EVENTS_REQUEST_RECEIVED",
                raw_params={
                    "chain_id": chain_id,
                    "event_type": event_type,
                    "severity": severity,
                    "status": status,
                    "start_time": start_time,
                    "end_time": end_time,
                    "cursor": cursor,
                    "include_total": include_total,
                    "search": search,
                    "query": query,
                    "limit": limit
                })
    
    # Parse time filters
    start_dt = None
    end_dt = None
    if start_time:
        try:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            logger.info("DEBUG_PARSED_START_TIME", raw=start_time, parsed=str(start_dt))
        except Exception as e:
            logger.warning("DEBUG_START_TIME_PARSE_FAILED", raw=start_time, error=str(e))
    if end_time:
        try:
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            logger.info("DEBUG_PARSED_END_TIME", raw=end_time, parsed=str(end_dt))
        except Exception as e:
            logger.warning("DEBUG_END_TIME_PARSE_FAILED", raw=end_time, error=str(e))
    
    # Query events from PostgreSQL database
    logger.info("DEBUG_CALLING_DATABASE_SERVICE", 
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
        logger.info("DEBUG_BEFORE_GET_EVENTS_CALL")
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
        logger.info("DEBUG_AFTER_GET_EVENTS_CALL", 
                    events_count=len(db_events), 
                    total_in_db=total_count, 
                    has_next_cursor=next_cursor is not None,
                    first_event_sample=db_events[0] if db_events else None)
    except Exception as e:
        import traceback
        logger.error("DEBUG_DATABASE_QUERY_FAILED", 
                     error=str(e), 
                     error_type=type(e).__name__,
                     traceback=traceback.format_exc()[-1000:])
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
                "event_id": e.get("event_id"),
                "chain": e.get("chain"),
                "chain_id": e.get("chain_id"),
                "event_type": e.get("event_type"),
                "tx_hash": e.get("tx_hash"),
                "block": e.get("block"),
                "block_number": e.get("block_number"),
                "contract": e.get("contract"),
                "contract_address": e.get("contract_address"),
                "from_address": e.get("from_address"),
                "to_address": e.get("to_address"),
                "severity": e.get("severity"),
                "timestamp": e.get("timestamp"),
                "amount": e.get("amount"),
                "amount_usd": e.get("amount_usd"),
                "raw_data": e.get("data", {}),
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


@router.get("/debug/events")
async def debug_events():
    """
    DEBUG ENDPOINT: Direct database check for events.
    
    This endpoint bypasses all filtering and directly queries the database
    to verify data existence. Use this to debug the read path.
    """
    from ..database.connection import DatabaseManager
    from sqlalchemy import text
    import traceback
    
    debug_info = {
        "timestamp": datetime.utcnow().isoformat(),
        "database_connected": False,
        "total_events_in_db": 0,
        "sample_events": [],
        "events_by_chain": {},
        "events_by_severity": {},
        "latest_event_time": None,
        "oldest_event_time": None,
        "errors": []
    }
    
    try:
        async with DatabaseManager.get_session() as session:
            debug_info["database_connected"] = True
            
            # 1. Get total count
            count_result = await session.execute(text("SELECT COUNT(*) FROM events"))
            total_count = count_result.scalar()
            debug_info["total_events_in_db"] = total_count
            logger.info("DEBUG_ENDPOINT_TOTAL_COUNT", count=total_count)
            
            # 2. Get events by chain
            chain_result = await session.execute(text("""
                SELECT chain_id, COUNT(*) as cnt 
                FROM events 
                GROUP BY chain_id 
                ORDER BY cnt DESC
            """))
            for row in chain_result.fetchall():
                debug_info["events_by_chain"][row[0]] = row[1]
            
            # 3. Get events by severity
            severity_result = await session.execute(text("""
                SELECT severity, COUNT(*) as cnt 
                FROM events 
                GROUP BY severity 
                ORDER BY cnt DESC
            """))
            for row in severity_result.fetchall():
                debug_info["events_by_severity"][row[0]] = row[1]
            
            # 4. Get time range
            time_result = await session.execute(text("""
                SELECT 
                    MIN(block_timestamp) as oldest_block_time,
                    MAX(block_timestamp) as newest_block_time,
                    MIN(created_at) as oldest_created,
                    MAX(created_at) as newest_created
                FROM events
            """))
            time_row = time_result.fetchone()
            if time_row:
                debug_info["oldest_event_time"] = str(time_row[0]) if time_row[0] else None
                debug_info["latest_event_time"] = str(time_row[1]) if time_row[1] else None
                debug_info["oldest_created_at"] = str(time_row[2]) if time_row[2] else None
                debug_info["latest_created_at"] = str(time_row[3]) if time_row[3] else None
            
            # 5. Get 5 sample events (most recently ingested by created_at)
            sample_result = await session.execute(text("""
                SELECT id, event_id, chain_id, event_type, tx_hash, block_number, 
                       block_timestamp, severity, contract_address
                FROM events 
                ORDER BY created_at DESC NULLS LAST
                LIMIT 5
            """))
            for row in sample_result.fetchall():
                debug_info["sample_events"].append({
                    "id": str(row[0]),
                    "event_id": row[1],
                    "chain_id": row[2],
                    "event_type": row[3],
                    "tx_hash": row[4][:20] + "..." if row[4] and len(row[4]) > 20 else row[4],
                    "block_number": row[5],
                    "block_timestamp": str(row[6]) if row[6] else None,
                    "severity": row[7],
                    "contract_address": row[8][:20] + "..." if row[8] and len(row[8]) > 20 else row[8]
                })
            
            logger.info("DEBUG_ENDPOINT_COMPLETE", 
                        total=total_count, 
                        chains=len(debug_info["events_by_chain"]),
                        sample_count=len(debug_info["sample_events"]))
                        
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        debug_info["errors"].append(error_msg)
        debug_info["errors"].append(traceback.format_exc()[-500:])
        logger.error("DEBUG_ENDPOINT_ERROR", error=error_msg)
    
    return debug_info


@router.get("/debug/incidents")
async def debug_incidents():
    """
    DEBUG ENDPOINT: Direct database check for incidents.
    Shows raw incident data including affected_contracts and affected_addresses.
    """
    from ..database.connection import DatabaseManager
    from sqlalchemy import text
    import traceback
    
    debug_info = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_incidents": 0,
        "sample_incidents": [],
        "incidents_by_severity": {},
        "errors": []
    }
    
    try:
        async with DatabaseManager.get_session() as session:
            # Get total count
            count_result = await session.execute(text("SELECT COUNT(*) FROM incidents"))
            debug_info["total_incidents"] = count_result.scalar() or 0
            
            # Get sample incidents with all fields
            sample_result = await session.execute(text("""
                SELECT incident_id, title, severity, status, attack_type, confidence,
                       affected_chains, affected_contracts, affected_addresses, 
                       summary, recommended_actions, created_at
                FROM incidents 
                ORDER BY created_at DESC 
                LIMIT 5
            """))
            for row in sample_result.fetchall():
                debug_info["sample_incidents"].append({
                    "incident_id": row[0],
                    "title": row[1],
                    "severity": row[2],
                    "status": row[3],
                    "attack_type": row[4],
                    "confidence": float(row[5]) if row[5] else None,
                    "affected_chains": row[6],
                    "affected_contracts": row[7],
                    "affected_addresses": row[8],
                    "summary": row[9][:200] if row[9] else None,
                    "recommended_actions": row[10],
                    "created_at": str(row[11])
                })
            
            # Get incidents by severity
            severity_result = await session.execute(text("""
                SELECT severity, COUNT(*) as cnt 
                FROM incidents 
                GROUP BY severity 
                ORDER BY cnt DESC
            """))
            for row in severity_result.fetchall():
                debug_info["incidents_by_severity"][row[0]] = row[1]
                
    except Exception as e:
        debug_info["errors"].append(f"{type(e).__name__}: {str(e)}")
        debug_info["errors"].append(traceback.format_exc()[-500:])
        logger.error("DEBUG_INCIDENTS_ERROR", error=str(e))
    
    return debug_info


@router.get("/debug/incident/{incident_id}")
async def debug_incident_details(incident_id: str):
    """
    DEBUG ENDPOINT: Get full details for a specific incident by ID.
    
    Returns all incident data including:
    - Full incident record
    - Associated events with raw_data
    - ML analysis details (for ML-triggered incidents)
    
    Example: /api/debug/incident/inc_ml_polygon_0x24a7c517_1768742361
    """
    from ..database.connection import DatabaseManager
    from sqlalchemy import text
    import traceback
    import json
    
    debug_info = {
        "timestamp": datetime.utcnow().isoformat(),
        "incident_id": incident_id,
        "found": False,
        "incident": None,
        "associated_events": [],
        "ml_analysis": None,
        "errors": []
    }
    
    try:
        async with DatabaseManager.get_session() as session:
            # Get full incident record
            incident_result = await session.execute(text("""
                SELECT 
                    id, incident_id, cluster_key, title, summary,
                    severity, status, attack_type, confidence, total_loss_usd,
                    event_count, affected_chains, affected_contracts, affected_addresses,
                    event_ids, violation_ids, rule_ids, recommended_actions,
                    explanation_json, created_at, updated_at
                FROM incidents 
                WHERE incident_id = :incident_id
            """), {"incident_id": incident_id})
            
            row = incident_result.fetchone()
            if row:
                debug_info["found"] = True
                debug_info["incident"] = {
                    "id": str(row[0]),
                    "incident_id": row[1],
                    "cluster_key": row[2],
                    "title": row[3],
                    "summary": row[4],
                    "severity": row[5],
                    "status": row[6],
                    "attack_type": row[7],
                    "confidence": float(row[8]) if row[8] else None,
                    "total_loss_usd": float(row[9]) if row[9] else 0.0,
                    "event_count": row[10],
                    "affected_chains": row[11],
                    "affected_contracts": row[12],
                    "affected_addresses": row[13],
                    "event_ids": row[14],
                    "violation_ids": row[15],
                    "rule_ids": row[16],
                    "recommended_actions": row[17],
                    "explanation_json": row[18],
                    "created_at": str(row[19]),
                    "updated_at": str(row[20]),
                }
                
                # Get associated events
                event_ids = row[14] or []
                if event_ids:
                    # Build a query to get events by their IDs
                    events_result = await session.execute(text("""
                        SELECT 
                            event_id, chain_id, block_number, block_timestamp,
                            tx_hash, event_type, severity, from_address, to_address,
                            contract_address, amount, amount_usd, raw_data
                        FROM events 
                        WHERE event_id = ANY(:event_ids)
                        ORDER BY block_timestamp DESC
                    """), {"event_ids": event_ids})
                    
                    for evt_row in events_result.fetchall():
                        raw_data = evt_row[12]
                        # Parse raw_data if it's a string
                        if isinstance(raw_data, str):
                            try:
                                raw_data = json.loads(raw_data)
                            except:
                                pass
                        
                        event_data = {
                            "event_id": evt_row[0],
                            "chain_id": evt_row[1],
                            "block_number": evt_row[2],
                            "block_timestamp": str(evt_row[3]) if evt_row[3] else None,
                            "tx_hash": evt_row[4],
                            "event_type": evt_row[5],
                            "severity": evt_row[6],
                            "from_address": evt_row[7],
                            "to_address": evt_row[8],
                            "contract_address": evt_row[9],
                            "amount": evt_row[10],
                            "amount_usd": evt_row[11],
                            "raw_data": raw_data,
                        }
                        debug_info["associated_events"].append(event_data)
                        
                        # Extract ML analysis from raw_data if present
                        if raw_data and isinstance(raw_data, dict):
                            if "threat_category" in raw_data or "risk_score" in raw_data:
                                debug_info["ml_analysis"] = {
                                    "threat_category": raw_data.get("threat_category"),
                                    "risk_score": raw_data.get("risk_score"),
                                    "confidence": raw_data.get("confidence"),
                                    "is_threat": raw_data.get("is_threat"),
                                    "alerts": raw_data.get("alerts", []),
                                    "bytecode_size": raw_data.get("bytecode_size"),
                                    "source": raw_data.get("source"),
                                }
                
                # If no events found by ID, try to find by contract address
                if not debug_info["associated_events"]:
                    contracts = row[12] or []
                    if contracts:
                        contract_events_result = await session.execute(text("""
                            SELECT 
                                event_id, chain_id, block_number, block_timestamp,
                                tx_hash, event_type, severity, from_address, to_address,
                                contract_address, amount, amount_usd, raw_data
                            FROM events 
                            WHERE contract_address = ANY(:contracts)
                            ORDER BY block_timestamp DESC
                            LIMIT 10
                        """), {"contracts": contracts})
                        
                        for evt_row in contract_events_result.fetchall():
                            raw_data = evt_row[12]
                            if isinstance(raw_data, str):
                                try:
                                    raw_data = json.loads(raw_data)
                                except:
                                    pass
                            
                            event_data = {
                                "event_id": evt_row[0],
                                "chain_id": evt_row[1],
                                "block_number": evt_row[2],
                                "block_timestamp": str(evt_row[3]) if evt_row[3] else None,
                                "tx_hash": evt_row[4],
                                "event_type": evt_row[5],
                                "severity": evt_row[6],
                                "from_address": evt_row[7],
                                "to_address": evt_row[8],
                                "contract_address": evt_row[9],
                                "amount": evt_row[10],
                                "amount_usd": evt_row[11],
                                "raw_data": raw_data,
                            }
                            debug_info["associated_events"].append(event_data)
                            
                            # Extract ML analysis
                            if raw_data and isinstance(raw_data, dict):
                                if "threat_category" in raw_data or "risk_score" in raw_data:
                                    debug_info["ml_analysis"] = {
                                        "threat_category": raw_data.get("threat_category"),
                                        "risk_score": raw_data.get("risk_score"),
                                        "confidence": raw_data.get("confidence"),
                                        "is_threat": raw_data.get("is_threat"),
                                        "alerts": raw_data.get("alerts", []),
                                        "bytecode_size": raw_data.get("bytecode_size"),
                                        "source": raw_data.get("source"),
                                    }
            else:
                debug_info["errors"].append(f"Incident not found: {incident_id}")
                
    except Exception as e:
        debug_info["errors"].append(f"{type(e).__name__}: {str(e)}")
        debug_info["errors"].append(traceback.format_exc()[-500:])
        logger.error("DEBUG_INCIDENT_DETAILS_ERROR", error=str(e), incident_id=incident_id)
    
    return debug_info


@router.get("/debug/db-connection")
async def debug_db_connection():
    """
    DEBUG ENDPOINT: Test database connection directly.
    """
    from ..database.connection import DatabaseManager
    from sqlalchemy import text
    import traceback
    import os
    
    debug_info = {
        "timestamp": datetime.utcnow().isoformat(),
        "connection_successful": False,
        "env_vars": {
            "DATABASE_URL_set": bool(os.getenv("DATABASE_URL")),
            "CLOUDSQL_INSTANCE": os.getenv("CLOUDSQL_INSTANCE"),
            "POSTGRES_HOST": os.getenv("POSTGRES_HOST"),
            "POSTGRES_DB": os.getenv("POSTGRES_DB"),
        },
        "test_query_result": None,
        "errors": []
    }
    
    try:
        async with DatabaseManager.get_session() as session:
            # Simple test query
            result = await session.execute(text("SELECT 1 as test, NOW() as current_time"))
            row = result.fetchone()
            debug_info["connection_successful"] = True
            debug_info["test_query_result"] = {
                "test": row[0],
                "current_time": str(row[1])
            }
            logger.info("DEBUG_DB_CONNECTION_SUCCESS")
    except Exception as e:
        debug_info["errors"].append(f"{type(e).__name__}: {str(e)}")
        debug_info["errors"].append(traceback.format_exc()[-500:])
        logger.error("DEBUG_DB_CONNECTION_FAILED", error=str(e))
    
    return debug_info


# Cache for stats with TTL
_stats_cache = {
    "data": None,
    "timestamp": None,
    "ttl_seconds": 30  # Cache for 30 seconds
}

@router.get("/stats")
async def get_statistics():
    """
    Get real-time system statistics and metrics.
    
    ENHANCED: Hybrid stats from database + in-memory with 30-second caching.
    - Database provides persistent historical stats
    - In-memory provides real-time counters
    - Cache reduces database load
    """
    from ..shared_state import monitor_state
    from ..database.service import DatabaseService
    from ..database.connection import DatabaseManager
    from sqlalchemy import text
    import time
    
    # Check cache
    cache_valid = (
        _stats_cache["data"] is not None and 
        _stats_cache["timestamp"] is not None and
        (time.time() - _stats_cache["timestamp"]) < _stats_cache["ttl_seconds"]
    )
    
    if cache_valid:
        logger.debug("stats_cache_hit")
        return _stats_cache["data"]
    
    logger.debug("stats_cache_miss_fetching")
    
    # Get in-memory stats (real-time counters)
    memory_stats = monitor_state.get_stats()
    memory_incidents = monitor_state.get_incidents()
    
    # Calculate uptime
    uptime = 0
    if memory_stats["start_time"]:
        uptime = int((datetime.utcnow() - memory_stats["start_time"]).total_seconds())
    
    # Initialize counters
    total_events = memory_stats.get("total_events", 0)
    events_by_chain = dict(memory_stats.get("events_by_chain", {}))
    events_by_type = dict(memory_stats.get("events_by_type", {}))
    events_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    last_event_time = memory_stats.get("last_event_time")
    blocks_scanned = memory_stats.get("blocks_scanned", 0)
    
    # If blocks_scanned is 0, estimate from database
    # This provides a reasonable estimate when worker hasn't reported yet
    
    # Query database for persistent stats
    try:
        async with DatabaseManager.get_session() as session:
            # Total events count
            count_result = await session.execute(text("SELECT COUNT(*) FROM events"))
            db_total_events = count_result.scalar() or 0
            
            # Events by chain
            chain_result = await session.execute(text("""
                SELECT chain_id, COUNT(*) as cnt 
                FROM events 
                GROUP BY chain_id
            """))
            for row in chain_result.fetchall():
                chain_id = row[0]
                count = row[1]
                events_by_chain[chain_id] = count
            
            # Events by type
            type_result = await session.execute(text("""
                SELECT event_type, COUNT(*) as cnt 
                FROM events 
                GROUP BY event_type
            """))
            for row in type_result.fetchall():
                event_type = row[0] or "unknown"
                count = row[1]
                events_by_type[event_type] = count
            
            # Events by severity
            severity_result = await session.execute(text("""
                SELECT UPPER(severity), COUNT(*) as cnt 
                FROM events 
                WHERE severity IS NOT NULL
                GROUP BY UPPER(severity)
            """))
            for row in severity_result.fetchall():
                sev = row[0] or "INFO"
                count = row[1]
                if sev in events_by_severity:
                    events_by_severity[sev] = count
            
            # Latest event time
            time_result = await session.execute(text("""
                SELECT MAX(block_timestamp) FROM events
            """))
            db_last_event = time_result.scalar()
            if db_last_event:
                if last_event_time is None or db_last_event > last_event_time:
                    last_event_time = db_last_event
            
            # Estimate blocks scanned from database if not tracked in memory
            if blocks_scanned == 0:
                try:
                    # Get unique block count per chain and sum them
                    blocks_result = await session.execute(text("""
                        SELECT SUM(block_range) as total_blocks FROM (
                            SELECT chain_id, MAX(block_number) - MIN(block_number) + 1 as block_range
                            FROM events 
                            GROUP BY chain_id
                        ) as chain_blocks
                    """))
                    estimated_blocks = blocks_result.scalar()
                    if estimated_blocks and estimated_blocks > 0:
                        blocks_scanned = int(estimated_blocks)
                except Exception as e:
                    logger.debug("blocks_estimate_failed", error=str(e))
            
            # Use database total (more accurate than in-memory)
            total_events = db_total_events
            
            logger.debug("stats_db_query_success", total_events=total_events, chains=len(events_by_chain))
    except Exception as e:
        logger.warning("stats_db_query_failed", error=str(e))
        # Fall back to in-memory stats only
    
    # Count incidents from memory
    total_incidents = len(memory_incidents)
    active_incidents = len([i for i in memory_incidents if i.status.lower() in ("open", "investigating")])
    critical_incidents = len([i for i in memory_incidents if i.severity.upper() == "CRITICAL"])
    high_incidents = len([i for i in memory_incidents if i.severity.upper() == "HIGH"])
    medium_incidents = len([i for i in memory_incidents if i.severity.upper() == "MEDIUM"])
    low_incidents = len([i for i in memory_incidents if i.severity.upper() == "LOW"])
    
    # Also count database incidents
    try:
        db_incident_stats = await DatabaseService.get_incident_stats()
        total_incidents += db_incident_stats.get("total", 0)
        active_incidents += db_incident_stats.get("active", 0)
        by_severity = db_incident_stats.get("by_severity", {})
        critical_incidents += by_severity.get("CRITICAL", 0)
        high_incidents += by_severity.get("HIGH", 0)
        medium_incidents += by_severity.get("MEDIUM", 0)
        low_incidents += by_severity.get("LOW", 0)
    except Exception as e:
        logger.warning("db_incident_stats_failed", error=str(e))
    
    # Build response
    response = {
        "total_events": total_events,
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "critical_alerts": critical_incidents,
        "high_alerts": high_incidents,
        "medium_alerts": medium_incidents,
        "low_alerts": low_incidents,
        "blocks_scanned": blocks_scanned,
        "events_by_chain": events_by_chain,
        "events_by_type": events_by_type,
        "events_by_severity": events_by_severity,
        "uptime_seconds": uptime,
        "last_event_time": last_event_time.isoformat() if last_event_time else None,
        "cache_ttl_seconds": _stats_cache["ttl_seconds"],
    }
    
    # Update cache
    _stats_cache["data"] = response
    _stats_cache["timestamp"] = time.time()
    
    logger.info("stats_fetched", total_events=total_events, total_incidents=total_incidents)
    
    return response


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

@router.get("/maintenance/check-schema")
async def check_table_schema():
    """
    Check the actual database table schema.
    """
    try:
        from ..database.connection import DatabaseManager
        from sqlalchemy import text
        import asyncio
        
        async with DatabaseManager.get_session() as session:
            # Get column information
            result = await asyncio.wait_for(
                session.execute(text("""
                    SELECT 
                        column_name, 
                        data_type, 
                        is_nullable,
                        column_default
                    FROM information_schema.columns 
                    WHERE table_name = 'events' 
                    ORDER BY ordinal_position
                """)),
                timeout=10.0
            )
            columns = result.fetchall()
            
            schema_info = []
            for col in columns:
                schema_info.append({
                    "name": col[0],
                    "type": col[1],
                    "nullable": col[2] == "YES",
                    "default": col[3]
                })
            
            # Check constraints
            result = await asyncio.wait_for(
                session.execute(text("""
                    SELECT 
                        conname as constraint_name,
                        contype as constraint_type,
                        pg_get_constraintdef(oid) as definition
                    FROM pg_constraint
                    WHERE conrelid = 'events'::regclass
                """)),
                timeout=10.0
            )
            constraints = result.fetchall()
            
            constraint_info = []
            for con in constraints:
                constraint_info.append({
                    "name": con[0],
                    "type": con[1],
                    "definition": con[2]
                })
            
            return {
                "status": "success",
                "columns": schema_info,
                "constraints": constraint_info
            }
    except Exception as e:
        logger.error("check_schema_failed", error=str(e), exc_info=True)
        return {"status": "error", "error": str(e)}

@router.get("/maintenance/check-events")
async def check_events_in_database():
    """
    Simple check to see if any events exist in the database.
    Uses the simplest possible query.
    """
    try:
        from ..database.connection import DatabaseManager
        from sqlalchemy import text
        import asyncio
        
        async with DatabaseManager.get_session() as session:
            # Simplest possible query - just get one row
            try:
                result = await asyncio.wait_for(
                    session.execute(text("SELECT COUNT(*) as cnt FROM events")),
                    timeout=10.0
                )
                count = result.scalar()
                
                # If count > 0, get a sample
                sample = None
                if count and count > 0:
                    result = await asyncio.wait_for(
                        session.execute(text("SELECT chain_id, event_type, block_number, created_at FROM events ORDER BY created_at DESC LIMIT 1")),
                        timeout=10.0
                    )
                    row = result.fetchone()
                    if row:
                        sample = {
                            "chain": row[0],
                            "event_type": row[1],
                            "block": row[2],
                            "created_at": str(row[3]) if row[3] else None
                        }
                
                return {
                    "status": "success",
                    "event_count": count or 0,
                    "sample_event": sample
                }
            except asyncio.TimeoutError:
                return {"status": "timeout", "error": "Query timed out"}
            except Exception as e:
                return {"status": "error", "error": str(e), "error_type": type(e).__name__}
    except Exception as e:
        logger.error("check_events_failed", error=str(e), exc_info=True)
        return {"status": "error", "error": str(e)}

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
