"""
Protocol Monitoring API Routes
==============================

REST API endpoints for protocol-specific monitoring:
1. Protocol metrics (TVL, volume, rates)
2. Protocol alerts (liquidations, large txs)
3. Protocol health status
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
import structlog

from ..protocols.aave import aave_monitor
from ..protocols.uniswap import uniswap_monitor
from ..protocols.compound import compound_monitor

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/protocols", tags=["protocols"])


# =============================================================================
# Response Models
# =============================================================================

class ProtocolMetricsResponse(BaseModel):
    """Protocol metrics response."""
    protocol_id: str
    protocol_name: str
    chain_id: str
    timestamp: str
    
    # TVL
    tvl_usd: float = 0.0
    tvl_change_24h_percent: float = 0.0
    
    # Volume
    volume_24h_usd: float = 0.0
    
    # Lending-specific
    total_borrowed_usd: float = 0.0
    total_supplied_usd: float = 0.0
    utilization_rate: float = 0.0
    
    # Activity
    liquidations_24h_count: int = 0
    liquidations_24h_usd: float = 0.0


class ProtocolAlertResponse(BaseModel):
    """Protocol alert response."""
    alert_id: str
    protocol_id: str
    protocol_name: str
    chain_id: str
    alert_type: str
    severity: str
    timestamp: str
    
    title: str
    description: str
    value_usd: float = 0.0
    
    tx_hash: Optional[str] = None
    affected_address: Optional[str] = None
    affected_pool: Optional[str] = None


class ProtocolHealthResponse(BaseModel):
    """Protocol health status."""
    protocol_id: str
    protocol_name: str
    status: str  # healthy, warning, critical
    health_score: int = Field(..., ge=0, le=100)
    
    # Metrics summary
    chains_monitored: int = 0
    events_processed_24h: int = 0
    alerts_generated_24h: int = 0
    liquidations_24h: int = 0
    
    # Issues
    issues: List[str] = Field(default_factory=list)


class ProtocolListResponse(BaseModel):
    """List of supported protocols."""
    protocols: List[Dict[str, Any]]
    total: int


# =============================================================================
# Supported Protocols
# =============================================================================

PROTOCOL_MONITORS = {
    "aave_v3": aave_monitor,
    "uniswap": uniswap_monitor,
    "compound": compound_monitor,
}

PROTOCOL_INFO = {
    "aave_v3": {
        "id": "aave_v3",
        "name": "Aave V3",
        "type": "lending",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "base"],
        "description": "Decentralized lending protocol",
        "website": "https://aave.com",
    },
    "uniswap": {
        "id": "uniswap",
        "name": "Uniswap",
        "type": "dex",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "base"],
        "description": "Decentralized exchange (AMM)",
        "website": "https://uniswap.org",
    },
    "compound": {
        "id": "compound",
        "name": "Compound",
        "type": "lending",
        "chains": ["ethereum", "polygon", "arbitrum", "base"],
        "description": "Algorithmic money market protocol",
        "website": "https://compound.finance",
    },
}


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("/", response_model=ProtocolListResponse)
async def list_protocols():
    """
    List all supported protocols.
    
    Returns protocol info including:
    - Protocol ID and name
    - Type (lending, dex, etc.)
    - Supported chains
    """
    protocols = list(PROTOCOL_INFO.values())
    return ProtocolListResponse(
        protocols=protocols,
        total=len(protocols)
    )


@router.get("/{protocol_id}/metrics", response_model=ProtocolMetricsResponse)
async def get_protocol_metrics(
    protocol_id: str,
    chain_id: str = Query("ethereum", description="Chain to get metrics for")
):
    """
    Get real-time metrics for a protocol.
    
    Metrics include:
    - TVL and 24h change
    - Volume
    - Borrowing/lending stats (for lending protocols)
    - Liquidation activity
    """
    if protocol_id not in PROTOCOL_MONITORS:
        raise HTTPException(status_code=404, detail=f"Protocol {protocol_id} not found")
    
    monitor = PROTOCOL_MONITORS[protocol_id]
    
    if chain_id not in monitor.config.chains:
        raise HTTPException(
            status_code=400,
            detail=f"Chain {chain_id} not supported for {protocol_id}"
        )
    
    metrics = await monitor.get_metrics(chain_id)
    
    return ProtocolMetricsResponse(
        protocol_id=protocol_id,
        protocol_name=monitor.config.protocol_name,
        chain_id=chain_id,
        timestamp=metrics.timestamp.isoformat(),
        tvl_usd=metrics.tvl_usd,
        tvl_change_24h_percent=metrics.tvl_change_24h_percent,
        volume_24h_usd=metrics.volume_24h_usd,
        total_borrowed_usd=metrics.total_borrowed_usd,
        total_supplied_usd=metrics.total_supplied_usd,
        utilization_rate=metrics.utilization_rate,
        liquidations_24h_count=metrics.liquidations_24h_count,
        liquidations_24h_usd=metrics.liquidations_24h_usd,
    )


@router.get("/{protocol_id}/alerts", response_model=List[ProtocolAlertResponse])
async def get_protocol_alerts(
    protocol_id: str,
    chain_id: Optional[str] = Query(None, description="Filter by chain"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200)
):
    """
    Get recent alerts for a protocol.
    
    Alert types:
    - liquidation: Position liquidated
    - large_transaction: Large swap/borrow/supply
    - price_impact: High price impact trade
    - tvl_drop: Significant TVL decrease
    - rate_spike: Interest rate spike
    """
    if protocol_id not in PROTOCOL_MONITORS:
        raise HTTPException(status_code=404, detail=f"Protocol {protocol_id} not found")
    
    # In production, would fetch from database
    # For now, return empty list
    return []


@router.get("/{protocol_id}/health", response_model=ProtocolHealthResponse)
async def get_protocol_health(protocol_id: str):
    """
    Get health status for a protocol monitor.
    
    Health is determined by:
    - Recent event processing success
    - Alert generation rate
    - Liquidation activity
    """
    if protocol_id not in PROTOCOL_MONITORS:
        raise HTTPException(status_code=404, detail=f"Protocol {protocol_id} not found")
    
    monitor = PROTOCOL_MONITORS[protocol_id]
    stats = monitor.get_stats()
    
    # Calculate health score
    health_score = 100
    issues = []
    
    # Check for high liquidation rate
    if stats.get("liquidations_detected", 0) > 10:
        health_score -= 20
        issues.append(f"High liquidation activity: {stats['liquidations_detected']} detected")
    
    # Check for low event processing
    if stats.get("events_processed", 0) == 0:
        health_score -= 30
        issues.append("No events processed - check RPC connections")
    
    # Determine status
    if health_score >= 80:
        status = "healthy"
    elif health_score >= 50:
        status = "warning"
    else:
        status = "critical"
    
    return ProtocolHealthResponse(
        protocol_id=protocol_id,
        protocol_name=monitor.config.protocol_name,
        status=status,
        health_score=max(0, health_score),
        chains_monitored=len(monitor.config.chains),
        events_processed_24h=stats.get("events_processed", 0),
        alerts_generated_24h=stats.get("alerts_generated", 0),
        liquidations_24h=stats.get("liquidations_detected", 0),
        issues=issues,
    )


@router.get("/{protocol_id}/liquidations")
async def get_protocol_liquidations(
    protocol_id: str,
    chain_id: Optional[str] = Query(None, description="Filter by chain"),
    min_value_usd: float = Query(0, description="Minimum liquidation value"),
    limit: int = Query(50, ge=1, le=200)
):
    """
    Get recent liquidations for a lending protocol.
    
    Returns:
    - Liquidated address
    - Collateral seized
    - Debt repaid
    - Liquidator address
    """
    if protocol_id not in PROTOCOL_MONITORS:
        raise HTTPException(status_code=404, detail=f"Protocol {protocol_id} not found")
    
    monitor = PROTOCOL_MONITORS[protocol_id]
    
    if monitor.config.protocol_type.value != "lending":
        raise HTTPException(
            status_code=400,
            detail=f"{protocol_id} is not a lending protocol"
        )
    
    # In production, would fetch from database
    return {"liquidations": [], "total": 0}


@router.get("/dashboard")
async def get_protocols_dashboard():
    """
    Get dashboard summary for all protocols.
    
    Includes:
    - Health status for each protocol
    - Recent alerts
    - Aggregate metrics
    """
    protocols_status = []
    total_alerts = 0
    total_liquidations = 0
    
    for protocol_id, monitor in PROTOCOL_MONITORS.items():
        stats = monitor.get_stats()
        
        # Calculate health
        health_score = 100
        if stats.get("liquidations_detected", 0) > 10:
            health_score -= 20
        if stats.get("events_processed", 0) == 0:
            health_score -= 30
        
        if health_score >= 80:
            status = "healthy"
        elif health_score >= 50:
            status = "warning"
        else:
            status = "critical"
        
        protocols_status.append({
            "protocol_id": protocol_id,
            "name": monitor.config.protocol_name,
            "type": monitor.config.protocol_type.value,
            "status": status,
            "health_score": max(0, health_score),
            "chains": monitor.config.chains,
            "events_24h": stats.get("events_processed", 0),
            "alerts_24h": stats.get("alerts_generated", 0),
            "liquidations_24h": stats.get("liquidations_detected", 0),
        })
        
        total_alerts += stats.get("alerts_generated", 0)
        total_liquidations += stats.get("liquidations_detected", 0)
    
    return {
        "protocols": protocols_status,
        "summary": {
            "total_protocols": len(PROTOCOL_MONITORS),
            "healthy_count": len([p for p in protocols_status if p["status"] == "healthy"]),
            "warning_count": len([p for p in protocols_status if p["status"] == "warning"]),
            "critical_count": len([p for p in protocols_status if p["status"] == "critical"]),
            "total_alerts_24h": total_alerts,
            "total_liquidations_24h": total_liquidations,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/supported-chains")
async def get_supported_chains():
    """Get list of chains supported by protocol monitoring."""
    chains = set()
    for monitor in PROTOCOL_MONITORS.values():
        chains.update(monitor.config.chains)
    
    return {
        "chains": sorted(list(chains)),
        "total": len(chains),
    }
