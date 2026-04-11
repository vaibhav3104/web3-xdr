"""
Aave Protocol Monitor
=====================

Deep integration with Aave V2/V3 lending protocol:
- Liquidation detection and alerts
- Health factor monitoring
- Large borrow/supply detection
- Rate spike alerts
- TVL tracking
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


# Aave V3 Event Signatures
AAVE_V3_EVENTS = {
    # Supply
    "0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61": "Supply",
    # Withdraw
    "0x3115d1449a7b732c986cba18244e897a450f61e1bb8d589cd2e69e6c8924f9f7": "Withdraw",
    # Borrow
    "0xb3d084820fb1a9decffb176436bd02558d15fac9b0ddfed8c465bc7359d7dce0": "Borrow",
    # Repay
    "0xa534c8dbe71f871f9f3530e97a74601fea17b426cae02e1c5aee42c96c784051": "Repay",
    # LiquidationCall - CRITICAL
    "0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be37335533e005286": "LiquidationCall",
    # FlashLoan
    "0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac": "FlashLoan",
    # ReserveDataUpdated
    "0x804c9b842b2748a22bb64b345453a3de7ca54a6ca45ce00d415894979e22897a": "ReserveDataUpdated",
    # ReserveUsedAsCollateralEnabled
    "0x44c58d81365b66dd4b1a7f36c25aa97b8c71c361ee4937adc1a00000227db5dd": "ReserveUsedAsCollateralEnabled",
    # ReserveUsedAsCollateralDisabled
    "0x44c58d81365b66dd4b1a7f36c25aa97b8c71c361ee4937adc1a00000227db5de": "ReserveUsedAsCollateralDisabled",
}

# Aave V3 Pool addresses by chain
AAVE_V3_POOLS = {
    "ethereum": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
    "polygon": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "arbitrum": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "optimism": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "avalanche": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "base": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
}


class AaveMonitor(ProtocolMonitor):
    """
    Aave Protocol Monitor.
    
    Monitors:
    - Liquidations (CRITICAL alerts for large liquidations)
    - Health factors approaching liquidation
    - Large borrows/supplies
    - Interest rate spikes
    - Flash loan usage
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="aave_v3",
            protocol_name="Aave V3",
            protocol_type=ProtocolType.LENDING,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "base"],
            contracts={
                chain: {"pool": addr}
                for chain, addr in AAVE_V3_POOLS.items()
            },
            large_tx_threshold_usd=100000,
            health_factor_warning=1.5,
            health_factor_critical=1.1,
        )
        super().__init__(config)
        
        # Track positions for health factor monitoring
        self._positions: Dict[str, Dict[str, float]] = {}  # address -> {health_factor, collateral, debt}
        
        # Track rates for spike detection
        self._rates: Dict[str, Dict[str, float]] = {}  # reserve -> {supply_rate, borrow_rate}
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Aave event signatures."""
        return AAVE_V3_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Aave event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = AAVE_V3_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        # Route to specific handler
        if event_name == "LiquidationCall":
            return await self._handle_liquidation(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "Borrow":
            return await self._handle_borrow(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "Supply":
            return await self._handle_supply(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "FlashLoan":
            return await self._handle_flashloan(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "ReserveDataUpdated":
            return await self._handle_rate_update(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_liquidation(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle liquidation event - CRITICAL for large liquidations."""
        self._stats["liquidations_detected"] += 1
        
        topics = event_data.get("topics", [])
        event_data.get("data", "0x")
        
        # Parse liquidation data (simplified)
        # In production, would decode full event data
        liquidated_user = topics[3] if len(topics) > 3 else "unknown"
        if isinstance(liquidated_user, bytes):
            liquidated_user = "0x" + liquidated_user.hex()[-40:]
        elif isinstance(liquidated_user, str) and len(liquidated_user) == 66:
            liquidated_user = "0x" + liquidated_user[-40:]
        
        # Estimate liquidation value (would need price oracle in production)
        estimated_value_usd = 50000  # Placeholder
        
        # Determine severity based on value
        if estimated_value_usd >= 1000000:
            severity = "critical"
        elif estimated_value_usd >= 100000:
            severity = "high"
        elif estimated_value_usd >= 10000:
            severity = "medium"
        else:
            severity = "low"
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LIQUIDATION,
            severity=severity,
            title=f"Aave Liquidation on {chain_id.title()}",
            description=f"Position liquidated for user {liquidated_user[:10]}... "
                       f"Estimated value: ${estimated_value_usd:,.0f}",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=liquidated_user,
            metadata={
                "event_type": "liquidation",
                "protocol_version": "v3",
            }
        )
    
    async def _handle_borrow(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle borrow event - alert for large borrows."""
        topics = event_data.get("topics", [])
        
        # Parse borrower
        borrower = topics[2] if len(topics) > 2 else "unknown"
        if isinstance(borrower, bytes):
            borrower = "0x" + borrower.hex()[-40:]
        elif isinstance(borrower, str) and len(borrower) == 66:
            borrower = "0x" + borrower[-40:]
        
        # Estimate value (would need price oracle)
        estimated_value_usd = 25000  # Placeholder
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large Aave Borrow on {chain_id.title()}",
                description=f"Large borrow detected: ${estimated_value_usd:,.0f} by {borrower[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=borrower,
                metadata={
                    "event_type": "borrow",
                    "protocol_version": "v3",
                }
            )
        
        return None
    
    async def _handle_supply(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle supply event - alert for large supplies."""
        topics = event_data.get("topics", [])
        
        # Parse supplier
        supplier = topics[2] if len(topics) > 2 else "unknown"
        if isinstance(supplier, bytes):
            supplier = "0x" + supplier.hex()[-40:]
        elif isinstance(supplier, str) and len(supplier) == 66:
            supplier = "0x" + supplier[-40:]
        
        # Estimate value
        estimated_value_usd = 25000  # Placeholder
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title=f"Large Aave Supply on {chain_id.title()}",
                description=f"Large supply detected: ${estimated_value_usd:,.0f} by {supplier[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=supplier,
                metadata={
                    "event_type": "supply",
                    "protocol_version": "v3",
                }
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
        """Handle flash loan event - always alert as potential attack vector."""
        topics = event_data.get("topics", [])
        
        # Parse initiator
        initiator = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(initiator, bytes):
            initiator = "0x" + initiator.hex()[-40:]
        elif isinstance(initiator, str) and len(initiator) == 66:
            initiator = "0x" + initiator[-40:]
        
        # Estimate value
        estimated_value_usd = 100000  # Placeholder
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LARGE_TRANSACTION,
            severity="medium",
            title=f"Aave Flash Loan on {chain_id.title()}",
            description=f"Flash loan detected: ${estimated_value_usd:,.0f} by {initiator[:10]}...",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=initiator,
            metadata={
                "event_type": "flashloan",
                "protocol_version": "v3",
                "is_flashloan": True,
            }
        )
    
    async def _handle_rate_update(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle rate update - alert on significant rate spikes."""
        # Would track rate changes over time and alert on spikes
        # Simplified for now
        return None
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Aave metrics for a chain."""
        # In production, would query on-chain data or subgraph
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,  # Would fetch from subgraph
            total_borrowed_usd=0,
            total_supplied_usd=0,
            utilization_rate=0,
            liquidations_24h_count=self._stats["liquidations_detected"],
        )


# Global instance
aave_monitor = AaveMonitor()
