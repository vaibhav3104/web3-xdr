"""
Cross-Chain Correlation API Routes
==================================

REST API endpoints for cross-chain correlation:
1. Correlation statistics
2. Pending correlations
3. Violations
4. Bridge health
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import structlog

from ..correlation.cross_chain import (
    cross_chain_correlator,
    CrossChainViolation,
    ViolationType,
    CorrelationStatus
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/cross-chain", tags=["cross-chain"])


# =============================================================================
# Response Models
# =============================================================================

class ViolationResponse(BaseModel):
    """Cross-chain violation response."""
    id: str
    violation_type: str
    severity: str
    bridge_id: str
    source_chain: str
    dest_chain: str
    timestamp: str
    lock_amount: float
    mint_amount: float
    amount_difference: float
    estimated_loss_usd: float
    description: str
    acknowledged: bool
    resolved: bool
    evidence: Dict[str, Any]


class CorrelationStatsResponse(BaseModel):
    """Cross-chain correlation statistics."""
    events_processed: int
    locks_received: int
    mints_received: int
    correlations_matched: int
    violations_detected: int
    orphan_mints: int
    orphan_locks: int
    pending_locks: int
    pending_mints: int
    total_correlations: int
    critical_violations: int


class PendingCorrelationsResponse(BaseModel):
    """Pending correlations awaiting match."""
    pending_locks: int
    pending_mints: int
    locks_by_bridge: Dict[str, int]
    mints_by_bridge: Dict[str, int]


class BridgeHealthResponse(BaseModel):
    """Health status for a bridge."""
    bridge_id: str
    events_last_hour: int
    locks_last_hour: int
    mints_last_hour: int
    matched_correlations: int
    violations_24h: int
    health_score: int
    status: str  # healthy, warning, critical


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("/stats", response_model=CorrelationStatsResponse)
async def get_correlation_stats():
    """
    Get cross-chain correlation statistics.
    
    Shows:
    - Total events processed
    - Lock/mint counts
    - Matched correlations
    - Violations detected
    - Orphan events (potential attacks)
    """
    stats = cross_chain_correlator.get_stats()
    
    return CorrelationStatsResponse(
        events_processed=stats.get("events_processed", 0),
        locks_received=stats.get("locks_received", 0),
        mints_received=stats.get("mints_received", 0),
        correlations_matched=stats.get("correlations_matched", 0),
        violations_detected=stats.get("violations_detected", 0),
        orphan_mints=stats.get("orphan_mints", 0),
        orphan_locks=stats.get("orphan_locks", 0),
        pending_locks=stats.get("pending_locks", 0),
        pending_mints=stats.get("pending_mints", 0),
        total_correlations=stats.get("total_correlations", 0),
        critical_violations=stats.get("critical_violations", 0)
    )


@router.get("/pending", response_model=PendingCorrelationsResponse)
async def get_pending_correlations():
    """
    Get pending correlations awaiting match.
    
    Locks waiting for mint = potential stuck funds
    Mints waiting for lock = potential attack in progress!
    """
    pending = cross_chain_correlator.get_pending_correlations()
    
    return PendingCorrelationsResponse(
        pending_locks=pending.get("pending_locks", 0),
        pending_mints=pending.get("pending_mints", 0),
        locks_by_bridge=pending.get("locks_by_bridge", {}),
        mints_by_bridge=pending.get("mints_by_bridge", {})
    )


@router.get("/violations", response_model=List[ViolationResponse])
async def get_violations(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    bridge_id: Optional[str] = Query(None, description="Filter by bridge ID"),
    limit: int = Query(100, ge=1, le=500, description="Maximum violations to return")
):
    """
    Get detected cross-chain violations.
    
    Violation types:
    - mint_without_lock: CRITICAL - Wormhole-style attack
    - lock_without_mint: HIGH - Funds stuck
    - amount_mismatch: HIGH - Different amounts
    - replay_attack: CRITICAL - Same message processed twice
    - time_anomaly: CRITICAL - Mint before lock (impossible!)
    """
    violations = cross_chain_correlator.get_violations(
        severity=severity,
        bridge_id=bridge_id,
        limit=limit
    )
    
    return [
        ViolationResponse(
            id=v.id,
            violation_type=v.violation_type.value,
            severity=v.severity,
            bridge_id=v.bridge_id,
            source_chain=v.source_chain,
            dest_chain=v.dest_chain,
            timestamp=v.timestamp.isoformat(),
            lock_amount=v.lock_amount,
            mint_amount=v.mint_amount,
            amount_difference=v.amount_difference,
            estimated_loss_usd=v.estimated_loss_usd,
            description=v.description,
            acknowledged=v.acknowledged,
            resolved=v.resolved,
            evidence=v.evidence
        )
        for v in violations
    ]


@router.get("/violations/critical", response_model=List[ViolationResponse])
async def get_critical_violations():
    """
    Get CRITICAL violations only.
    
    These are potential active attacks:
    - Mint without lock (Wormhole-style)
    - Replay attacks
    - Time anomalies
    """
    violations = cross_chain_correlator.get_violations(severity="critical")
    
    return [
        ViolationResponse(
            id=v.id,
            violation_type=v.violation_type.value,
            severity=v.severity,
            bridge_id=v.bridge_id,
            source_chain=v.source_chain,
            dest_chain=v.dest_chain,
            timestamp=v.timestamp.isoformat(),
            lock_amount=v.lock_amount,
            mint_amount=v.mint_amount,
            amount_difference=v.amount_difference,
            estimated_loss_usd=v.estimated_loss_usd,
            description=v.description,
            acknowledged=v.acknowledged,
            resolved=v.resolved,
            evidence=v.evidence
        )
        for v in violations
    ]


@router.post("/violations/{violation_id}/acknowledge")
async def acknowledge_violation(violation_id: str):
    """Acknowledge a violation (mark as reviewed)."""
    for v in cross_chain_correlator.violations:
        if v.id == violation_id:
            v.acknowledged = True
            return {"status": "acknowledged", "violation_id": violation_id}
    
    raise HTTPException(status_code=404, detail="Violation not found")


@router.post("/violations/{violation_id}/resolve")
async def resolve_violation(violation_id: str):
    """Mark a violation as resolved."""
    for v in cross_chain_correlator.violations:
        if v.id == violation_id:
            v.resolved = True
            return {"status": "resolved", "violation_id": violation_id}
    
    raise HTTPException(status_code=404, detail="Violation not found")


@router.get("/bridges/health")
async def get_bridges_health():
    """
    Get health status for all monitored bridges.
    
    Calculates health score based on:
    - Recent violations
    - Orphan events
    - Correlation success rate
    """
    stats = cross_chain_correlator.get_stats()
    violations = cross_chain_correlator.get_violations()
    
    # Group by bridge
    bridge_stats = {}
    
    for v in violations:
        if v.bridge_id not in bridge_stats:
            bridge_stats[v.bridge_id] = {
                "violations_24h": 0,
                "critical_violations": 0
            }
        bridge_stats[v.bridge_id]["violations_24h"] += 1
        if v.severity == "critical":
            bridge_stats[v.bridge_id]["critical_violations"] += 1
    
    # Calculate health for each bridge
    health_results = []
    
    known_bridges = ["wormhole", "layerzero", "stargate", "across", "hop", "synapse", "celer"]
    
    for bridge_id in known_bridges:
        bridge_data = bridge_stats.get(bridge_id, {"violations_24h": 0, "critical_violations": 0})
        
        # Calculate health score
        health_score = 100
        
        if bridge_data["critical_violations"] > 0:
            health_score -= 50 * bridge_data["critical_violations"]
        
        health_score -= 5 * bridge_data["violations_24h"]
        
        health_score = max(0, health_score)
        
        # Determine status
        if health_score >= 80:
            status = "healthy"
        elif health_score >= 50:
            status = "warning"
        else:
            status = "critical"
        
        health_results.append({
            "bridge_id": bridge_id,
            "events_last_hour": 0,  # Would need time-series data
            "locks_last_hour": 0,
            "mints_last_hour": 0,
            "matched_correlations": stats.get("correlations_matched", 0),
            "violations_24h": bridge_data["violations_24h"],
            "health_score": health_score,
            "status": status
        })
    
    return health_results


@router.get("/incidents/by-address/{address}")
async def get_incidents_by_address(address: str):
    """
    Get all incidents involving a given address across any chain.

    Useful for tracing a single attacker who operates on multiple chains —
    e.g. the same EOA exploiting Ethereum and Arbitrum in the same hour.
    """
    from ..correlation.incident_builder import IncidentBuilder

    # Use the global incident builder if one exists, otherwise return empty.
    # In production the builder lives on the worker; here we try a shared instance.
    builder: Optional[IncidentBuilder] = getattr(cross_chain_correlator, "_incident_builder", None)
    if not builder:
        return {
            "address": address,
            "incidents": [],
            "message": "Incident builder not initialised on this process"
        }

    incidents = builder.get_incidents_by_address(address.lower())
    return {
        "address": address,
        "incident_count": len(incidents),
        "incidents": [inc.to_dict() for inc in incidents],
    }


@router.get("/incidents/cross-chain-groups")
async def get_cross_chain_groups():
    """
    Return groups of incidents linked by shared addresses across >1 chain.

    Each group represents a likely single attacker operating on multiple chains.
    """
    from ..correlation.incident_builder import IncidentBuilder

    builder: Optional[IncidentBuilder] = getattr(cross_chain_correlator, "_incident_builder", None)
    if not builder:
        return {"groups": [], "message": "Incident builder not initialised on this process"}

    groups = builder.get_cross_chain_incidents()
    return {
        "group_count": len(groups),
        "groups": [
            {
                "shared_addresses": list(
                    set.intersection(*(inc.affected_addresses for inc in group)) if group else set()
                ),
                "chains": list({inc.source_chain for inc in group}),
                "incidents": [inc.to_dict() for inc in group],
            }
            for group in groups
        ],
    }


@router.get("/dashboard")
async def get_cross_chain_dashboard():
    """
    Get complete cross-chain dashboard data.
    
    Combines:
    - Overall stats
    - Pending correlations
    - Recent violations
    - Bridge health
    """
    stats = cross_chain_correlator.get_stats()
    pending = cross_chain_correlator.get_pending_correlations()
    violations = cross_chain_correlator.get_violations(limit=10)
    
    return {
        "stats": {
            "events_processed": stats.get("events_processed", 0),
            "correlations_matched": stats.get("correlations_matched", 0),
            "violations_detected": stats.get("violations_detected", 0),
            "critical_violations": stats.get("critical_violations", 0),
            "orphan_mints": stats.get("orphan_mints", 0),
            "orphan_locks": stats.get("orphan_locks", 0)
        },
        "pending": {
            "locks": pending.get("pending_locks", 0),
            "mints": pending.get("pending_mints", 0)
        },
        "recent_violations": [
            {
                "id": v.id,
                "type": v.violation_type.value,
                "severity": v.severity,
                "bridge": v.bridge_id,
                "loss_usd": v.estimated_loss_usd,
                "timestamp": v.timestamp.isoformat()
            }
            for v in violations
        ],
        "alerts": {
            "critical": stats.get("critical_violations", 0),
            "high": len([v for v in cross_chain_correlator.violations if v.severity == "high"]),
            "pending_review": len([v for v in cross_chain_correlator.violations if not v.acknowledged])
        }
    }

