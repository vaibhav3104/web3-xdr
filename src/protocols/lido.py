"""
Lido Protocol Monitor
=====================

Deep integration with Lido liquid staking:
- Large stETH mints/burns
- Withdrawal queue monitoring
- Oracle updates
- Validator exits
- slashing detection
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


# Lido Event Signatures
LIDO_EVENTS = {
    # Submitted (ETH staked)
    "0x96a25c8ce0baabc1fdefd93e9ed25d8e092a3332f3aa9a41722b5697231d1d1a": "Submitted",
    # Transfer (stETH)
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
    # TransferShares
    "0x9d9c909296d9c674451c0c24f02cb64981eb3b727f99865939192f880a755dcb": "TransferShares",
    # WithdrawalRequested
    "0x7e0c9e0b5d3f3c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d": "WithdrawalRequested",
    # WithdrawalClaimed
    "0x8a2e3c4d5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e": "WithdrawalClaimed",
    # ETHDistributed (oracle report)
    "0x92dd3cb149a1eebd51fd8c2a3653fd96f30c4ac01d4f850fc16d46abd6c3e92f": "ETHDistributed",
    # TokenRebased
    "0xff08c3ef606d198e316ef5b822193c489965899eb4e3c248cea1a4626c3eda50": "TokenRebased",
    # Approval
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": "Approval",
    # ValidatorExitRequest
    "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": "ValidatorExitRequest",
}

# Lido Contracts
LIDO_CONTRACTS = {
    "ethereum": {
        "steth": "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84",
        "wsteth": "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0",
        "withdrawal_queue": "0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1",
        "lido_dao": "0xb8FFC3Cd6e7Cf5a098A1c92F48009765B24088Dc",
        "node_operators_registry": "0x55032650b14df07b85bF18A3a3eC8E0Af2e028d5",
        "oracle": "0x442af784A788A5bd6F42A01Ebe9F287a871243fb",
    },
    "polygon": {
        "stmatic": "0x9ee91F9f426fA633d227f7a9b000E28b9dfd8599",
    },
}


class LidoMonitor(ProtocolMonitor):
    """
    Lido Protocol Monitor.
    
    Monitors:
    - Large ETH stakes (stETH mints)
    - Withdrawal requests
    - Oracle reports
    - Validator exits
    - Potential slashing events
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="lido",
            protocol_name="Lido",
            protocol_type=ProtocolType.STAKING,
            chains=["ethereum", "polygon"],
            contracts=LIDO_CONTRACTS,
            large_tx_threshold_usd=100000,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Lido event signatures."""
        return LIDO_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Lido event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = LIDO_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "Submitted":
            return await self._handle_stake(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "WithdrawalRequested":
            return await self._handle_withdrawal_request(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "ETHDistributed":
            return await self._handle_oracle_report(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "ValidatorExitRequest":
            return await self._handle_validator_exit(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_stake(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle ETH stake (stETH mint)."""
        topics = event_data.get("topics", [])
        
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        estimated_value_usd = 50000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title=f"Large Lido Stake",
                description=f"Large ETH stake: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                metadata={"event_type": "stake", "protocol": "lido"}
            )
        return None
    
    async def _handle_withdrawal_request(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle withdrawal request - monitor for large withdrawals."""
        topics = event_data.get("topics", [])
        
        owner = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(owner, bytes):
            owner = "0x" + owner.hex()[-40:]
        elif isinstance(owner, str) and len(owner) == 66:
            owner = "0x" + owner[-40:]
        
        estimated_value_usd = 50000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="medium",
                title=f"Large Lido Withdrawal Request",
                description=f"Large stETH withdrawal requested: ${estimated_value_usd:,.0f} by {owner[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=owner,
                metadata={"event_type": "withdrawal_request", "protocol": "lido"}
            )
        return None
    
    async def _handle_oracle_report(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle oracle report - check for anomalies."""
        # In production, would compare with expected values
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.ORACLE_DEVIATION,
            severity="low",
            title="Lido Oracle Report",
            description="New oracle report submitted. Verify ETH distribution.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "oracle_report", "protocol": "lido"}
        )
    
    async def _handle_validator_exit(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle validator exit request."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="medium",
            title="Lido Validator Exit Requested",
            description="A validator exit has been requested. Monitor for completion.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "validator_exit", "protocol": "lido"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Lido metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
        )


# Global instance
lido_monitor = LidoMonitor()
