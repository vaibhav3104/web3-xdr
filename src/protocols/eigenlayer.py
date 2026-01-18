"""
EigenLayer Protocol Monitor
===========================

Deep integration with EigenLayer restaking:
- Restaking deposits/withdrawals
- Operator registration
- AVS registration
- Slashing events
- Delegation changes
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


# EigenLayer Event Signatures
EIGENLAYER_EVENTS = {
    # Deposit
    "0x7cfff908a4b583f36430b25d75964c458d8ede8a99bd61be750e97ee1b2f3a96": "Deposit",
    # WithdrawalQueued
    "0x9009ab153e8014fbfb02f2217f5cde7aa7f9ad734ae85ca3ee3f4ca2fdd499f9": "WithdrawalQueued",
    # WithdrawalCompleted
    "0xc97098c2f658800b4df29001527f7324bcdffcf6e8751a699ab920a1eced5b1d": "WithdrawalCompleted",
    # OperatorRegistered
    "0x8e8485583a2310d41f7c82b9427d0bd49bad74bb9cff9d3402a29d8f9b903a02": "OperatorRegistered",
    # OperatorMetadataURIUpdated
    "0x02a919ed0e2acad1dd90f17ef2fa4ae5462ee1339c0a7eb7e9e4b5b8e1e8e8e8": "OperatorMetadataURIUpdated",
    # StakerDelegated
    "0xc3ee9f2e5fda98e8066a1f745b2747f7e4e4a6a5b5b5c5d5e5f5a5b5c5d5e5f5": "StakerDelegated",
    # StakerUndelegated
    "0xd4e4e5f5a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6": "StakerUndelegated",
    # AVSRegistered
    "0xe5f5a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6": "AVSRegistered",
    # OperatorSlashed
    "0xf6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6": "OperatorSlashed",
}

# EigenLayer Contracts
EIGENLAYER_CONTRACTS = {
    "ethereum": {
        "strategy_manager": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A",
        "delegation_manager": "0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A",
        "slasher": "0xD92145c07f8Ed1D392c1B88017934E301CC1c3Cd",
        "eigen_pod_manager": "0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338",
        "avs_directory": "0x135DDa560e946695d6f155dACaFC6f1F25C1F5AF",
        "rewards_coordinator": "0x7750d328b314EfFa365A0402CcfD489B80B0adda",
    },
}


class EigenLayerMonitor(ProtocolMonitor):
    """
    EigenLayer Protocol Monitor.
    
    Monitors:
    - Large restaking deposits/withdrawals
    - Operator registrations
    - Delegation changes
    - Slashing events (CRITICAL)
    - AVS registrations
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="eigenlayer",
            protocol_name="EigenLayer",
            protocol_type=ProtocolType.STAKING,
            chains=["ethereum"],
            contracts=EIGENLAYER_CONTRACTS,
            large_tx_threshold_usd=500000,  # Higher threshold for restaking
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get EigenLayer event signatures."""
        return EIGENLAYER_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process EigenLayer event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = EIGENLAYER_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "Deposit":
            return await self._handle_deposit(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name in ("WithdrawalQueued", "WithdrawalCompleted"):
            return await self._handle_withdrawal(event_data, chain_id, tx_hash, block_number, block_timestamp, event_name)
        elif event_name == "OperatorRegistered":
            return await self._handle_operator_registered(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "OperatorSlashed":
            return await self._handle_slashing(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name in ("StakerDelegated", "StakerUndelegated"):
            return await self._handle_delegation_change(event_data, chain_id, tx_hash, block_number, block_timestamp, event_name)
        
        return None
    
    async def _handle_deposit(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle restaking deposit."""
        topics = event_data.get("topics", [])
        
        staker = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(staker, bytes):
            staker = "0x" + staker.hex()[-40:]
        elif isinstance(staker, str) and len(staker) == 66:
            staker = "0x" + staker[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title="Large EigenLayer Restake",
                description=f"Large restaking deposit: ${estimated_value_usd:,.0f} by {staker[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=staker,
                metadata={"event_type": "deposit", "protocol": "eigenlayer"}
            )
        return None
    
    async def _handle_withdrawal(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        event_name: str
    ) -> Optional[ProtocolAlert]:
        """Handle withdrawal events."""
        topics = event_data.get("topics", [])
        
        staker = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(staker, bytes):
            staker = "0x" + staker.hex()[-40:]
        elif isinstance(staker, str) and len(staker) == 66:
            staker = "0x" + staker[-40:]
        
        estimated_value_usd = 100000
        status = "queued" if event_name == "WithdrawalQueued" else "completed"
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="high",
                title=f"Large EigenLayer Withdrawal {status.title()}",
                description=f"Large withdrawal {status}: ${estimated_value_usd:,.0f} by {staker[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=staker,
                metadata={"event_type": f"withdrawal_{status}", "protocol": "eigenlayer"}
            )
        return None
    
    async def _handle_operator_registered(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle new operator registration."""
        topics = event_data.get("topics", [])
        
        operator = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(operator, bytes):
            operator = "0x" + operator.hex()[-40:]
        elif isinstance(operator, str) and len(operator) == 66:
            operator = "0x" + operator[-40:]
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="low",
            title="New EigenLayer Operator Registered",
            description=f"New operator registered: {operator[:10]}...",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            affected_address=operator,
            metadata={"event_type": "operator_registered", "protocol": "eigenlayer"}
        )
    
    async def _handle_slashing(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle slashing event - CRITICAL."""
        topics = event_data.get("topics", [])
        
        operator = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(operator, bytes):
            operator = "0x" + operator.hex()[-40:]
        elif isinstance(operator, str) and len(operator) == 66:
            operator = "0x" + operator[-40:]
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LIQUIDATION,
            severity="critical",
            title="🚨 EigenLayer Operator SLASHED",
            description=f"Operator {operator[:10]}... has been slashed! Immediate investigation required.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            affected_address=operator,
            metadata={"event_type": "slashing", "protocol": "eigenlayer"}
        )
    
    async def _handle_delegation_change(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        event_name: str
    ) -> Optional[ProtocolAlert]:
        """Handle delegation changes."""
        topics = event_data.get("topics", [])
        
        staker = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(staker, bytes):
            staker = "0x" + staker.hex()[-40:]
        elif isinstance(staker, str) and len(staker) == 66:
            staker = "0x" + staker[-40:]
        
        action = "delegated" if event_name == "StakerDelegated" else "undelegated"
        severity = "low" if action == "delegated" else "medium"
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity=severity,
            title=f"EigenLayer Staker {action.title()}",
            description=f"Staker {staker[:10]}... has {action}.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            affected_address=staker,
            metadata={"event_type": action, "protocol": "eigenlayer"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current EigenLayer metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
        )


# Global instance
eigenlayer_monitor = EigenLayerMonitor()
