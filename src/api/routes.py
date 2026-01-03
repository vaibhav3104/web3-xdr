"""
API Routes for Web3 XDR Dashboard.
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


@router.get("/events", response_model=List[EventSummary])
async def list_events(
    chain_id: Optional[str] = Query(None, description="Filter by chain"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(100, le=500, description="Max results"),
):
    """
    List recent security events from real-time monitoring.
    """
    from ..shared_state import monitor_state
    
    events = monitor_state.get_events(limit=500)
    
    if chain_id:
        events = [e for e in events if e.chain == chain_id]
    
    if event_type:
        events = [e for e in events if e.event_type == event_type]
    
    events = events[:limit]
    
    return [
        EventSummary(
            event_id=e.id,
            chain_id=e.chain,
            block_number=e.block,
            tx_hash=e.tx_hash,
            event_type=e.event_type,
            severity=e.severity,
            timestamp=e.timestamp,
        )
        for e in events
    ]


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
