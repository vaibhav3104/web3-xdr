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
from ..protocols.compound import compound_monitor
from ..protocols.uniswap import uniswap_monitor
from ..protocols.makerdao import makerdao_monitor
from ..protocols.spark import spark_monitor
from ..protocols.morpho import morpho_monitor
from ..protocols.curve import curve_monitor
from ..protocols.balancer import balancer_monitor
from ..protocols.sushiswap import sushiswap_monitor
from ..protocols.pancakeswap import pancakeswap_monitor
from ..protocols.lido import lido_monitor
from ..protocols.rocketpool import rocketpool_monitor
from ..protocols.eigenlayer import eigenlayer_monitor
from ..protocols.wormhole import wormhole_monitor
from ..protocols.layerzero import layerzero_monitor
from ..protocols.stargate import stargate_monitor
from ..protocols.across import across_monitor
from ..protocols.gmx import gmx_monitor
from ..protocols.dydx import dydx_monitor
from ..protocols.synthetix import synthetix_monitor
from ..protocols.yearn import yearn_monitor
from ..protocols.convex import convex_monitor

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
    # Lending
    "aave_v3": aave_monitor,
    "compound": compound_monitor,
    "makerdao": makerdao_monitor,
    "spark": spark_monitor,
    "morpho": morpho_monitor,
    
    # DEX
    "uniswap": uniswap_monitor,
    "curve": curve_monitor,
    "balancer": balancer_monitor,
    "sushiswap": sushiswap_monitor,
    "pancakeswap": pancakeswap_monitor,
    
    # Liquid Staking
    "lido": lido_monitor,
    "rocketpool": rocketpool_monitor,
    "eigenlayer": eigenlayer_monitor,
    
    # Bridges
    "wormhole": wormhole_monitor,
    "layerzero": layerzero_monitor,
    "stargate": stargate_monitor,
    "across": across_monitor,
    
    # Derivatives
    "gmx": gmx_monitor,
    "dydx": dydx_monitor,
    "synthetix": synthetix_monitor,
    
    # Yield
    "yearn": yearn_monitor,
    "convex": convex_monitor,
}

PROTOCOL_INFO = {
    # === LENDING PROTOCOLS ===
    "aave_v3": {
        "id": "aave_v3",
        "name": "Aave V3",
        "type": "lending",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "base"],
        "description": "Decentralized lending protocol",
        "website": "https://aave.com",
        "has_monitor": True,
    },
    "compound": {
        "id": "compound",
        "name": "Compound",
        "type": "lending",
        "chains": ["ethereum", "polygon", "arbitrum", "base"],
        "description": "Algorithmic money market protocol",
        "website": "https://compound.finance",
        "has_monitor": True,
    },
    "makerdao": {
        "id": "makerdao",
        "name": "MakerDAO",
        "type": "lending",
        "chains": ["ethereum"],
        "description": "Decentralized stablecoin (DAI) issuer",
        "website": "https://makerdao.com",
        "has_monitor": True,
    },
    "spark": {
        "id": "spark",
        "name": "Spark Protocol",
        "type": "lending",
        "chains": ["ethereum"],
        "description": "DAI-focused lending market (MakerDAO)",
        "website": "https://spark.fi",
        "has_monitor": True,
    },
    "morpho": {
        "id": "morpho",
        "name": "Morpho",
        "type": "lending",
        "chains": ["ethereum", "base"],
        "description": "Peer-to-peer lending optimizer",
        "website": "https://morpho.org",
        "has_monitor": True,
    },
    
    # === DEX PROTOCOLS ===
    "uniswap": {
        "id": "uniswap",
        "name": "Uniswap",
        "type": "dex",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "base"],
        "description": "Decentralized exchange (AMM)",
        "website": "https://uniswap.org",
        "has_monitor": True,
    },
    "curve": {
        "id": "curve",
        "name": "Curve Finance",
        "type": "dex",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "base"],
        "description": "Stablecoin-focused AMM",
        "website": "https://curve.fi",
        "has_monitor": True,
    },
    "balancer": {
        "id": "balancer",
        "name": "Balancer",
        "type": "dex",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "base"],
        "description": "Multi-asset AMM and liquidity protocol",
        "website": "https://balancer.fi",
        "has_monitor": True,
    },
    "sushiswap": {
        "id": "sushiswap",
        "name": "SushiSwap",
        "type": "dex",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche"],
        "description": "Community-driven DEX",
        "website": "https://sushi.com",
        "has_monitor": True,
    },
    "pancakeswap": {
        "id": "pancakeswap",
        "name": "PancakeSwap",
        "type": "dex",
        "chains": ["bsc", "ethereum", "arbitrum", "base"],
        "description": "Leading BSC DEX",
        "website": "https://pancakeswap.finance",
        "has_monitor": True,
    },
    
    # === LIQUID STAKING ===
    "lido": {
        "id": "lido",
        "name": "Lido",
        "type": "liquid_staking",
        "chains": ["ethereum", "polygon"],
        "description": "Liquid staking for ETH (stETH)",
        "website": "https://lido.fi",
        "has_monitor": True,
    },
    "rocketpool": {
        "id": "rocketpool",
        "name": "Rocket Pool",
        "type": "liquid_staking",
        "chains": ["ethereum"],
        "description": "Decentralized ETH staking (rETH)",
        "website": "https://rocketpool.net",
        "has_monitor": True,
    },
    "eigenlayer": {
        "id": "eigenlayer",
        "name": "EigenLayer",
        "type": "restaking",
        "chains": ["ethereum"],
        "description": "ETH restaking protocol",
        "website": "https://eigenlayer.xyz",
        "has_monitor": True,
    },
    
    # === BRIDGES ===
    "wormhole": {
        "id": "wormhole",
        "name": "Wormhole",
        "type": "bridge",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "bsc", "solana"],
        "description": "Cross-chain messaging and bridge",
        "website": "https://wormhole.com",
        "has_monitor": True,
    },
    "layerzero": {
        "id": "layerzero",
        "name": "LayerZero",
        "type": "bridge",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "bsc", "base"],
        "description": "Omnichain interoperability protocol",
        "website": "https://layerzero.network",
        "has_monitor": True,
    },
    "stargate": {
        "id": "stargate",
        "name": "Stargate",
        "type": "bridge",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "bsc", "base"],
        "description": "Native asset bridge (LayerZero)",
        "website": "https://stargate.finance",
        "has_monitor": True,
    },
    "across": {
        "id": "across",
        "name": "Across Protocol",
        "type": "bridge",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism", "base"],
        "description": "Fast cross-chain bridge",
        "website": "https://across.to",
        "has_monitor": True,
    },
    
    # === DERIVATIVES ===
    "gmx": {
        "id": "gmx",
        "name": "GMX",
        "type": "derivatives",
        "chains": ["arbitrum", "avalanche"],
        "description": "Decentralized perpetual exchange",
        "website": "https://gmx.io",
        "has_monitor": True,
    },
    "dydx": {
        "id": "dydx",
        "name": "dYdX",
        "type": "derivatives",
        "chains": ["ethereum"],
        "description": "Decentralized derivatives exchange",
        "website": "https://dydx.exchange",
        "has_monitor": True,
    },
    "synthetix": {
        "id": "synthetix",
        "name": "Synthetix",
        "type": "derivatives",
        "chains": ["ethereum", "optimism"],
        "description": "Synthetic assets protocol",
        "website": "https://synthetix.io",
        "has_monitor": True,
    },
    
    # === YIELD AGGREGATORS ===
    "yearn": {
        "id": "yearn",
        "name": "Yearn Finance",
        "type": "yield",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism"],
        "description": "Yield optimization vaults",
        "website": "https://yearn.fi",
        "has_monitor": True,
    },
    "convex": {
        "id": "convex",
        "name": "Convex Finance",
        "type": "yield",
        "chains": ["ethereum"],
        "description": "Curve yield booster",
        "website": "https://convexfinance.com",
        "has_monitor": True,
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
    
    Shows ALL protocols in PROTOCOL_INFO, with real data for those with monitors.
    """
    protocols_status = []
    total_alerts = 0
    total_liquidations = 0
    
    for protocol_id, info in PROTOCOL_INFO.items():
        # Check if this protocol has an active monitor
        if protocol_id in PROTOCOL_MONITORS:
            monitor = PROTOCOL_MONITORS[protocol_id]
            stats = monitor.get_stats()
            
            # Calculate health based on monitor data
            health_score = 100
            if stats.get("liquidations_detected", 0) > 10:
                health_score -= 20
            if stats.get("events_processed", 0) == 0:
                health_score -= 30
            
            events_24h = stats.get("events_processed", 0)
            alerts_24h = stats.get("alerts_generated", 0)
            liquidations_24h = stats.get("liquidations_detected", 0)
            
            total_alerts += alerts_24h
            total_liquidations += liquidations_24h
        else:
            # Protocol without active monitor - show as monitored but no events yet
            health_score = 85  # Default healthy score
            events_24h = 0
            alerts_24h = 0
            liquidations_24h = 0
        
        # Determine status
        if health_score >= 80:
            status = "healthy"
        elif health_score >= 50:
            status = "warning"
        else:
            status = "critical"
        
        protocols_status.append({
            "protocol_id": protocol_id,
            "name": info["name"],
            "type": info["type"],
            "status": status,
            "health_score": max(0, health_score),
            "chains": info["chains"],
            "events_24h": events_24h,
            "alerts_24h": alerts_24h,
            "liquidations_24h": liquidations_24h,
            "has_active_monitor": protocol_id in PROTOCOL_MONITORS,
            "description": info.get("description", ""),
            "website": info.get("website", ""),
        })
    
    # Sort by: has_active_monitor (True first), then by name
    protocols_status.sort(key=lambda p: (not p["has_active_monitor"], p["name"]))
    
    return {
        "protocols": protocols_status,
        "summary": {
            "total_protocols": len(PROTOCOL_INFO),
            "monitored_with_data": len(PROTOCOL_MONITORS),
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
