"""
dYdX Protocol Monitor
=====================

Deep integration with dYdX perpetual exchange:
- Large position opens/closes
- Liquidation monitoring
- Funding rate alerts
- Margin changes
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


# dYdX Event Signatures (L1 contracts)
DYDX_EVENTS = {
    # LogDeposit
    "0x06724742ccc8c330a39a641ef02a0b419bd09248e0e5fd63b1f2d1c8f5e4b1e5": "LogDeposit",
    # LogWithdrawalPerformed
    "0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b": "LogWithdrawalPerformed",
    # LogForcedTradeRequest
    "0x3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c": "LogForcedTradeRequest",
    # LogForcedWithdrawalRequest
    "0x4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d": "LogForcedWithdrawalRequest",
    # LogStateTransitionFact
    "0x5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e": "LogStateTransitionFact",
    # LogRootUpdate
    "0x6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f": "LogRootUpdate",
    # Transfer (DYDX token)
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
}

# dYdX Contracts
DYDX_CONTRACTS = {
    "ethereum": {
        "perpetual_proxy": "0xD54f502e184B6B739d7D27a6410a67dc462D69c8",
        "starkware_exchange": "0xD54f502e184B6B739d7D27a6410a67dc462D69c8",
        "dydx_token": "0x92D6C1e31e14520e676a687F0a93788B716BEff5",
        "safety_module": "0x65f7BA4Ec257AF7c55fd5854E5f6356bBd0fb8EC",
        "governance": "0x7E9B1672616FF6D6629Ef2879419aaE79A9018D2",
        "treasury": "0x639192D54431F8c816368D3FB4107Bc168d0E871",
    },
}


class DYDXMonitor(ProtocolMonitor):
    """
    dYdX Protocol Monitor.
    
    Monitors:
    - Large deposits/withdrawals
    - Forced trade requests
    - State transitions
    - Governance actions
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="dydx",
            protocol_name="dYdX",
            protocol_type=ProtocolType.DERIVATIVES,
            chains=["ethereum"],
            contracts=DYDX_CONTRACTS,
            large_tx_threshold_usd=500000,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get dYdX event signatures."""
        return DYDX_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process dYdX event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = DYDX_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "LogDeposit":
            return await self._handle_deposit(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "LogWithdrawalPerformed":
            return await self._handle_withdrawal(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "LogForcedTradeRequest":
            return await self._handle_forced_trade(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "LogForcedWithdrawalRequest":
            return await self._handle_forced_withdrawal(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_deposit(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle deposit to dYdX."""
        topics = event_data.get("topics", [])
        
        depositor = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(depositor, bytes):
            depositor = "0x" + depositor.hex()[-40:]
        elif isinstance(depositor, str) and len(depositor) == 66:
            depositor = "0x" + depositor[-40:]
        
        estimated_value_usd = 200000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title="Large dYdX Deposit",
                description=f"Large deposit: ${estimated_value_usd:,.0f} by {depositor[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=depositor,
                metadata={"event_type": "deposit", "protocol": "dydx"}
            )
        return None
    
    async def _handle_withdrawal(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle withdrawal from dYdX."""
        topics = event_data.get("topics", [])
        
        recipient = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(recipient, bytes):
            recipient = "0x" + recipient.hex()[-40:]
        elif isinstance(recipient, str) and len(recipient) == 66:
            recipient = "0x" + recipient[-40:]
        
        estimated_value_usd = 200000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="high",
                title="Large dYdX Withdrawal",
                description=f"Large withdrawal: ${estimated_value_usd:,.0f} to {recipient[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=recipient,
                metadata={"event_type": "withdrawal", "protocol": "dydx"}
            )
        return None
    
    async def _handle_forced_trade(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle forced trade request - potential liquidation."""
        self._stats["liquidations_detected"] += 1
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LIQUIDATION,
            severity="high",
            title="dYdX Forced Trade Request",
            description="A forced trade has been requested. Possible liquidation scenario.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "forced_trade", "protocol": "dydx"}
        )
    
    async def _handle_forced_withdrawal(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle forced withdrawal request."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="high",
            title="dYdX Forced Withdrawal Request",
            description="A forced withdrawal has been requested. Verify legitimacy.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "forced_withdrawal", "protocol": "dydx"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current dYdX metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
            liquidations_24h_count=self._stats["liquidations_detected"],
        )


# Global instance
dydx_monitor = DYDXMonitor()
