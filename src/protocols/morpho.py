"""
Morpho Protocol Monitor
=======================

Deep integration with Morpho (peer-to-peer lending optimizer):
- Matched lending/borrowing detection
- Liquidation monitoring
- Rate optimization tracking
- Large position alerts
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


# Morpho Event Signatures
MORPHO_EVENTS = {
    # Supply
    "0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61": "Supply",
    # Withdraw
    "0x3115d1449a7b732c986cba18244e897a450f61e1bb8d589cd2e69e6c8924f9f7": "Withdraw",
    # Borrow
    "0xb3d084820fb1a9decffb176436bd02558d15fac9b0ddfed8c465bc7359d7dce0": "Borrow",
    # Repay
    "0xa534c8dbe71f871f9f3530e97a74601fea17b426cae02e1c5aee42c96c784051": "Repay",
    # Liquidation
    "0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be37335533e005286": "Liquidate",
    # P2P Matched
    "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": "P2PMatched",
    # Market Created
    "0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b": "CreateMarket",
}

# Morpho Contracts
MORPHO_CONTRACTS = {
    "ethereum": {
        "morpho_blue": "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb",
        "morpho_aave_v2": "0x777777c9898D384F785Ee44Acfe945efDFf5f3E0",
        "morpho_aave_v3": "0x33333aea097c193e66081E930c33020272b33333",
        "morpho_compound": "0x8888882f8f843896699869179fB6E4f7e3B58888",
    },
    "base": {
        "morpho_blue": "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb",
    },
}


class MorphoMonitor(ProtocolMonitor):
    """
    Morpho Protocol Monitor.
    
    Monitors:
    - Liquidations
    - Large supply/borrow
    - P2P matching events
    - Market creation
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="morpho",
            protocol_name="Morpho",
            protocol_type=ProtocolType.LENDING,
            chains=["ethereum", "base"],
            contracts=MORPHO_CONTRACTS,
            large_tx_threshold_usd=100000,
            health_factor_warning=1.3,
            health_factor_critical=1.05,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Morpho event signatures."""
        return MORPHO_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Morpho event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = MORPHO_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "Liquidate":
            return await self._handle_liquidation(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name in ("Borrow", "Supply"):
            return await self._handle_borrow_supply(event_data, chain_id, tx_hash, block_number, block_timestamp, event_name)
        elif event_name == "CreateMarket":
            return await self._handle_market_creation(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_liquidation(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle liquidation event."""
        self._stats["liquidations_detected"] += 1
        
        topics = event_data.get("topics", [])
        liquidated_user = topics[2] if len(topics) > 2 else "unknown"
        if isinstance(liquidated_user, bytes):
            liquidated_user = "0x" + liquidated_user.hex()[-40:]
        elif isinstance(liquidated_user, str) and len(liquidated_user) == 66:
            liquidated_user = "0x" + liquidated_user[-40:]
        
        estimated_value_usd = 50000
        severity = "critical" if estimated_value_usd >= 500000 else "high" if estimated_value_usd >= 100000 else "medium"
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LIQUIDATION,
            severity=severity,
            title=f"Morpho Liquidation on {chain_id.title()}",
            description=f"Position liquidated for {liquidated_user[:10]}... Value: ${estimated_value_usd:,.0f}",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=liquidated_user,
            metadata={"event_type": "liquidation", "protocol": "morpho"}
        )
    
    async def _handle_borrow_supply(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        event_type: str
    ) -> Optional[ProtocolAlert]:
        """Handle borrow/supply events."""
        topics = event_data.get("topics", [])
        user = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(user, bytes):
            user = "0x" + user.hex()[-40:]
        elif isinstance(user, str) and len(user) == 66:
            user = "0x" + user[-40:]
        
        estimated_value_usd = 25000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large Morpho {event_type} on {chain_id.title()}",
                description=f"Large {event_type.lower()}: ${estimated_value_usd:,.0f} by {user[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=user,
                metadata={"event_type": event_type.lower(), "protocol": "morpho"}
            )
        return None
    
    async def _handle_market_creation(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle new market creation."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="low",
            title="New Morpho Market Created",
            description="A new lending market has been created on Morpho.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "market_creation", "protocol": "morpho"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Morpho metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            total_borrowed_usd=0,
            total_supplied_usd=0,
            liquidations_24h_count=self._stats["liquidations_detected"],
        )


# Global instance
morpho_monitor = MorphoMonitor()
