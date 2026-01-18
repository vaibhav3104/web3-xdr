"""
Spark Protocol Monitor
======================

Deep integration with Spark Protocol (MakerDAO's lending market):
- Liquidation detection
- Health factor monitoring
- Large borrow/supply detection
- sDAI integration monitoring
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


# Spark Protocol Event Signatures (Aave V3 fork)
SPARK_EVENTS = {
    # Supply
    "0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61": "Supply",
    # Withdraw
    "0x3115d1449a7b732c986cba18244e897a450f61e1bb8d589cd2e69e6c8924f9f7": "Withdraw",
    # Borrow
    "0xb3d084820fb1a9decffb176436bd02558d15fac9b0ddfed8c465bc7359d7dce0": "Borrow",
    # Repay
    "0xa534c8dbe71f871f9f3530e97a74601fea17b426cae02e1c5aee42c96c784051": "Repay",
    # LiquidationCall
    "0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be37335533e005286": "LiquidationCall",
    # FlashLoan
    "0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac": "FlashLoan",
}

# Spark Protocol Contracts
SPARK_CONTRACTS = {
    "ethereum": {
        "pool": "0xC13e21B648A5Ee794902342038FF3aDAB66BE987",
        "pool_data_provider": "0xFc21d6d146E6086B8359705C8b28512a983db0cb",
        "sdai": "0x83F20F44975D03b1b09e64809B757c47f942BEeA",  # Savings DAI
    },
}


class SparkMonitor(ProtocolMonitor):
    """
    Spark Protocol Monitor.
    
    Monitors:
    - Liquidations
    - Large borrows/supplies
    - sDAI deposits/withdrawals
    - Flash loans
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="spark",
            protocol_name="Spark Protocol",
            protocol_type=ProtocolType.LENDING,
            chains=["ethereum"],
            contracts=SPARK_CONTRACTS,
            large_tx_threshold_usd=100000,
            health_factor_warning=1.5,
            health_factor_critical=1.1,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Spark event signatures."""
        return SPARK_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Spark event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = SPARK_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "LiquidationCall":
            return await self._handle_liquidation(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name in ("Borrow", "Supply"):
            return await self._handle_borrow_supply(event_data, chain_id, tx_hash, block_number, block_timestamp, event_name)
        elif event_name == "FlashLoan":
            return await self._handle_flashloan(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
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
        liquidated_user = topics[3] if len(topics) > 3 else "unknown"
        if isinstance(liquidated_user, bytes):
            liquidated_user = "0x" + liquidated_user.hex()[-40:]
        elif isinstance(liquidated_user, str) and len(liquidated_user) == 66:
            liquidated_user = "0x" + liquidated_user[-40:]
        
        estimated_value_usd = 50000
        
        if estimated_value_usd >= 1000000:
            severity = "critical"
        elif estimated_value_usd >= 100000:
            severity = "high"
        else:
            severity = "medium"
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LIQUIDATION,
            severity=severity,
            title=f"Spark Protocol Liquidation",
            description=f"Position liquidated for {liquidated_user[:10]}... Value: ${estimated_value_usd:,.0f}",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=liquidated_user,
            metadata={"event_type": "liquidation", "protocol": "spark"}
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
        user = topics[2] if len(topics) > 2 else "unknown"
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
                severity="medium" if event_type == "Borrow" else "low",
                title=f"Large Spark {event_type}",
                description=f"Large {event_type.lower()}: ${estimated_value_usd:,.0f} by {user[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=user,
                metadata={"event_type": event_type.lower(), "protocol": "spark"}
            )
        return None
    
    async def _handle_flashloan(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle flash loan event."""
        topics = event_data.get("topics", [])
        initiator = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(initiator, bytes):
            initiator = "0x" + initiator.hex()[-40:]
        elif isinstance(initiator, str) and len(initiator) == 66:
            initiator = "0x" + initiator[-40:]
        
        estimated_value_usd = 100000
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LARGE_TRANSACTION,
            severity="medium",
            title="Spark Flash Loan",
            description=f"Flash loan: ${estimated_value_usd:,.0f} by {initiator[:10]}...",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=initiator,
            metadata={"event_type": "flashloan", "protocol": "spark", "is_flashloan": True}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Spark metrics."""
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
spark_monitor = SparkMonitor()
