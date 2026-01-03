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
    include_simulated: bool = Query(True, description="Include simulated attack demos"),
):
    """
    List all incidents with optional filtering.
    """
    from ..shared_state import monitor_state
    
    incidents = monitor_state.get_incidents()
    
    # Add simulated attack incidents for demo purposes
    if include_simulated:
        simulated_attacks = [
            IncidentSummary(
                id="SIM-WORMHOLE-001",
                title="🔴 CRITICAL: Wormhole Unbacked Mint ($145M)",
                severity="critical",
                status="open",
                attack_type="unbacked_mint",
                confidence=0.95,
                total_loss_usd=145156044.0,
                affected_chains=["solana", "ethereum"],
                created_at=datetime.utcnow()
            ),
            IncidentSummary(
                id="SIM-FLASHLOAN-005",
                title="🔴 CRITICAL: Flash Loan Bridge Exploit ($39M)",
                severity="critical",
                status="open",
                attack_type="flash_loan_exploit",
                confidence=0.97,
                total_loss_usd=39099817.0,
                affected_chains=["ethereum"],
                created_at=datetime.utcnow()
            ),
            IncidentSummary(
                id="SIM-LAUNDERING-004",
                title="🔴 CRITICAL: Cross-chain Money Laundering ($42M)",
                severity="critical",
                status="investigating",
                attack_type="money_laundering",
                confidence=0.92,
                total_loss_usd=42700793.0,
                affected_chains=["ethereum", "polygon", "arbitrum", "bsc"],
                created_at=datetime.utcnow()
            ),
            IncidentSummary(
                id="SIM-STARGATE-003",
                title="🟠 HIGH: Stargate Liquidity Drain ($21M)",
                severity="high",
                status="open",
                attack_type="liquidity_drain",
                confidence=0.85,
                total_loss_usd=21771041.0,
                affected_chains=["ethereum", "arbitrum", "polygon"],
                created_at=datetime.utcnow()
            ),
            IncidentSummary(
                id="SIM-LAYERZERO-002",
                title="🟠 HIGH: LayerZero Message Forgery (Blocked)",
                severity="high",
                status="resolved",
                attack_type="message_forgery",
                confidence=0.88,
                total_loss_usd=0.0,
                affected_chains=["arbitrum"],
                created_at=datetime.utcnow()
            ),
        ]
    else:
        simulated_attacks = []
    
    # Convert real incidents to response format
    real_incidents = [
        IncidentSummary(
            id=i.id,
            title=i.title,
            severity=i.severity,
            status=i.status,
            attack_type=i.attack_type,
            confidence=i.confidence,
            total_loss_usd=i.total_loss_usd,
            affected_chains=i.affected_chains,
            created_at=i.created_at,
        )
        for i in incidents
    ]
    
    # Combine simulated + real incidents
    all_incidents = simulated_attacks + real_incidents
    
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
    """
    from ..shared_state import monitor_state
    
    stats = monitor_state.get_stats()
    real_incidents = monitor_state.get_incidents()
    
    uptime = 0
    if stats["start_time"]:
        uptime = int((datetime.utcnow() - stats["start_time"]).total_seconds())
    
    # Simulated attacks (same as in /incidents endpoint)
    simulated_attacks = [
        {"severity": "critical", "status": "open"},      # Wormhole
        {"severity": "critical", "status": "open"},      # Flash Loan
        {"severity": "critical", "status": "investigating"},  # Laundering
        {"severity": "high", "status": "open"},          # Stargate
        {"severity": "high", "status": "resolved"},      # LayerZero
    ]
    
    # Count real incidents
    real_active = len([i for i in real_incidents if i.status == "open"])
    real_critical = len([i for i in real_incidents if i.severity == "critical"])
    real_high = len([i for i in real_incidents if i.severity == "high"])
    
    # Count simulated
    sim_active = len([s for s in simulated_attacks if s["status"] in ["open", "investigating"]])
    sim_critical = len([s for s in simulated_attacks if s["severity"] == "critical"])
    sim_high = len([s for s in simulated_attacks if s["severity"] == "high"])
    
    # Total counts
    total_incidents = len(real_incidents) + len(simulated_attacks)
    active_incidents = real_active + sim_active
    
    return {
        "total_events": stats["total_events"],
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "critical_alerts": real_critical + sim_critical,
        "high_alerts": real_high + sim_high,
        "medium_alerts": stats["medium_alerts"],
        "low_alerts": stats["low_alerts"],
        "blocks_scanned": stats["blocks_scanned"],
        "events_by_chain": stats["events_by_chain"],
        "events_by_type": stats["events_by_type"],
        "uptime_seconds": uptime,
        "last_event_time": stats["last_event_time"].isoformat() if stats["last_event_time"] else None,
        "simulated_attacks": {
            "count": 5,
            "total_value_at_risk": 248727695,
            "attacks": ["Wormhole Unbacked Mint", "Flash Loan Exploit", "Cross-chain Laundering", "Stargate Drain", "LayerZero Forgery"]
        }
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
