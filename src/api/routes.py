"""
API Routes for Sentinel3 Dashboard.
Connected to real-time monitor data.
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

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


@router.get("/events")
async def list_events(
    chain_id: Optional[str] = Query(None, description="Filter by chain"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    start_time: Optional[str] = Query(None, description="Start time ISO format"),
    end_time: Optional[str] = Query(None, description="End time ISO format"),
    search: Optional[str] = Query(None, description="Search query"),
    limit: int = Query(500, le=1000, description="Max results"),
):
    """
    List security events with full details for log explorer.
    Supports filtering by chain, event type, severity, and time range.
    """
    from ..shared_state import monitor_state
    
    events = monitor_state.get_events(limit=1000)
    
    # Apply filters
    if chain_id:
        events = [e for e in events if e.chain == chain_id]
    
    if event_type:
        events = [e for e in events if e.event_type == event_type]
    
    if severity:
        events = [e for e in events if e.severity == severity]
    
    if start_time:
        try:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            events = [e for e in events if e.timestamp >= start_dt]
        except:
            pass
    
    if end_time:
        try:
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            events = [e for e in events if e.timestamp <= end_dt]
        except:
            pass
    
    if search:
        search_lower = search.lower()
        events = [
            e for e in events 
            if search_lower in e.id.lower() 
            or search_lower in e.chain.lower()
            or search_lower in e.event_type.lower()
            or search_lower in e.tx_hash.lower()
            or search_lower in e.contract.lower()
        ]
    
    events = events[:limit]
    
    # Return full event details
    return {
        "total": len(events),
        "events": [
            {
                "id": e.id,
                "chain": e.chain,
                "event_type": e.event_type,
                "tx_hash": e.tx_hash,
                "block": e.block,
                "contract": e.contract,
                "severity": e.severity,
                "timestamp": e.timestamp.isoformat(),
                "data": e.data or {}
            }
            for e in events
        ]
    }


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
