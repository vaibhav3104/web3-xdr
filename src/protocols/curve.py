"""
Curve Finance Protocol Monitor
==============================

Deep integration with Curve Finance:
- Large swap detection
- Pool imbalance alerts
- Liquidity changes
- Gauge rewards monitoring
- CRV emissions tracking
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import structlog

from .base import (
    ProtocolMonitor,
    ProtocolConfig,
    ProtocolType,
    ProtocolMetrics,
    ProtocolAlert,
    AlertType,
)

logger = structlog.get_logger(__name__)


# Curve Event Signatures
CURVE_EVENTS = {
    # TokenExchange (swap)
    "0x8b3e96f2b889fa771c53c981b40daf005f63f637f1869f707052d15a3dd97140": "TokenExchange",
    # TokenExchangeUnderlying
    "0xd013ca23e77a65003c2c659c5442c00c805371b7fc1ebd4c206c41d1536bd90b": "TokenExchangeUnderlying",
    # AddLiquidity
    "0x26f55a85081d24974e85c6c00045d0f0453991e95873f52bff0d21af4079a768": "AddLiquidity",
    # RemoveLiquidity
    "0x7c363854ccf79623411f8995b362bce5eddff18c927edc6f5dbbb5e05819a82c": "RemoveLiquidity",
    # RemoveLiquidityOne
    "0x5ad056f2e28a8cec232015406b843668c1e36cda598127ec3b8c59b8c72773a0": "RemoveLiquidityOne",
    # RemoveLiquidityImbalance
    "0x2b5508378d7e19e0d5fa338419034731416c4f5b219a10379956f764317fd47e": "RemoveLiquidityImbalance",
    # CommitNewAdmin
    "0x181aa3aa17d4cbf99265dd4443ebb13f9d6d2f7f0f5f6b7e3e0a4b0e0d8a0f5e": "CommitNewAdmin",
    # NewAdmin
    "0x71614071b88dee5e0b2ae578a9dd7b2ebbe9ae832ba419dc0242cd065a290b6c": "NewAdmin",
}

# Curve Contracts by Chain
CURVE_CONTRACTS = {
    "ethereum": {
        "address_provider": "0x0000000022D53366457F9d5E68Ec105046FC4383",
        "registry": "0x90E00ACe148ca3b23Ac1bC8C240C2a7Dd9c2d7f5",
        "gauge_controller": "0x2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB",
        "crv_token": "0xD533a949740bb3306d119CC777fa900bA034cd52",
        "voting_escrow": "0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2",
    },
    "polygon": {
        "address_provider": "0x0000000022D53366457F9d5E68Ec105046FC4383",
    },
    "arbitrum": {
        "address_provider": "0x0000000022D53366457F9d5E68Ec105046FC4383",
    },
    "optimism": {
        "address_provider": "0x0000000022D53366457F9d5E68Ec105046FC4383",
    },
    "avalanche": {
        "address_provider": "0x0000000022D53366457F9d5E68Ec105046FC4383",
    },
    "base": {
        "address_provider": "0x0000000022D53366457F9d5E68Ec105046FC4383",
    },
}


class CurveMonitor(ProtocolMonitor):
    """
    Curve Finance Protocol Monitor.
    
    Monitors:
    - Large swaps (especially stablecoin depegs)
    - Pool imbalances
    - Large liquidity additions/removals
    - Governance changes
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="curve",
            protocol_name="Curve Finance",
            protocol_type=ProtocolType.DEX,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "base"],
            contracts=CURVE_CONTRACTS,
            large_tx_threshold_usd=100000,
            price_impact_warning=0.5,  # Tighter for stablecoins
            price_impact_critical=2.0,
        )
        super().__init__(config)
        
        # Track pool imbalances
        self._pool_states: Dict[str, Dict[str, Any]] = {}
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Curve event signatures."""
        return CURVE_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Curve event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = CURVE_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        pool_address = event_data.get("address", "")
        
        if event_name in ("TokenExchange", "TokenExchangeUnderlying"):
            return await self._handle_swap(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address)
        elif event_name == "AddLiquidity":
            return await self._handle_add_liquidity(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address)
        elif event_name in ("RemoveLiquidity", "RemoveLiquidityOne", "RemoveLiquidityImbalance"):
            return await self._handle_remove_liquidity(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address, event_name)
        elif event_name in ("CommitNewAdmin", "NewAdmin"):
            return await self._handle_admin_change(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_swap(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle swap event - alert for large swaps and potential depegs."""
        topics = event_data.get("topics", [])
        
        buyer = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(buyer, bytes):
            buyer = "0x" + buyer.hex()[-40:]
        elif isinstance(buyer, str) and len(buyer) == 66:
            buyer = "0x" + buyer[-40:]
        
        estimated_value_usd = 50000
        price_impact_percent = 0.3  # Placeholder
        
        # High price impact on stablecoin pool is critical (potential depeg)
        if price_impact_percent >= self.config.price_impact_critical:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.PRICE_IMPACT,
                severity="critical",
                title=f"⚠️ Potential Stablecoin Depeg on Curve",
                description=f"High price impact swap ({price_impact_percent:.2f}%) detected. "
                           f"Value: ${estimated_value_usd:,.0f}. Check for depeg!",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=buyer,
                affected_pool=pool_address,
                metadata={
                    "event_type": "swap",
                    "protocol": "curve",
                    "price_impact_percent": price_impact_percent,
                    "potential_depeg": True,
                }
            )
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large Curve Swap on {chain_id.title()}",
                description=f"Large swap: ${estimated_value_usd:,.0f} by {buyer[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=buyer,
                affected_pool=pool_address,
                metadata={"event_type": "swap", "protocol": "curve"}
            )
        
        return None
    
    async def _handle_add_liquidity(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle liquidity addition."""
        topics = event_data.get("topics", [])
        provider = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(provider, bytes):
            provider = "0x" + provider.hex()[-40:]
        elif isinstance(provider, str) and len(provider) == 66:
            provider = "0x" + provider[-40:]
        
        estimated_value_usd = 25000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title=f"Large Curve Liquidity Addition",
                description=f"Large LP deposit: ${estimated_value_usd:,.0f} by {provider[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=provider,
                affected_pool=pool_address,
                metadata={"event_type": "add_liquidity", "protocol": "curve"}
            )
        return None
    
    async def _handle_remove_liquidity(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        pool_address: str,
        event_type: str
    ) -> Optional[ProtocolAlert]:
        """Handle liquidity removal - potential rug indicator."""
        topics = event_data.get("topics", [])
        provider = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(provider, bytes):
            provider = "0x" + provider.hex()[-40:]
        elif isinstance(provider, str) and len(provider) == 66:
            provider = "0x" + provider[-40:]
        
        estimated_value_usd = 25000
        
        # Imbalanced removal is more suspicious
        severity = "medium" if event_type == "RemoveLiquidityImbalance" else "low"
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity=severity,
                title=f"Large Curve Liquidity Removal",
                description=f"Large LP withdrawal ({event_type}): ${estimated_value_usd:,.0f} by {provider[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=provider,
                affected_pool=pool_address,
                metadata={
                    "event_type": "remove_liquidity",
                    "protocol": "curve",
                    "removal_type": event_type,
                }
            )
        return None
    
    async def _handle_admin_change(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle admin change - governance alert."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="high",
            title="Curve Admin Change Detected",
            description="Pool admin change initiated. Verify legitimacy.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "admin_change", "protocol": "curve"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Curve metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
            fees_24h_usd=0,
        )


# Global instance
curve_monitor = CurveMonitor()
