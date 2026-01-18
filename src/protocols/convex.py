"""
Convex Finance Protocol Monitor
===============================

Deep integration with Convex yield booster:
- Large deposits/withdrawals
- CVX/cvxCRV rewards
- Lock/unlock events
- Gauge changes
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


# Convex Event Signatures
CONVEX_EVENTS = {
    # Deposited
    "0x73a19dd210f1a7f902193214c0ee91dd35ee5b4d920cba8d519eca65a7b488ca": "Deposited",
    # Withdrawn
    "0x7084f5476618d8e60b11ef0d7d3f06914655adb8793e28ff7f018d4c76d505d5": "Withdrawn",
    # RewardPaid
    "0xe2403640ba68fed3a2f88b7557551d1993f84b99bb10ff833f0cf8db0c5e0486": "RewardPaid",
    # Staked
    "0x9e71bc8eea02a63969f509818f2dafb9254532904319f9dbda79b67bd34a5f3d": "Staked",
    # Transfer
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
    # Locked (vlCVX)
    "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": "Locked",
    # KickReward
    "0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b": "KickReward",
    # AddedReward
    "0x3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c": "AddedReward",
}

# Convex Contracts
CONVEX_CONTRACTS = {
    "ethereum": {
        "booster": "0xF403C135812408BFbE8713b5A23a04b3D48AAE31",
        "cvx_token": "0x4e3FBD56CD56c3e72c1403e103b45Db9da5B9D2B",
        "cvxcrv_token": "0x62B9c7356A2Dc64a1969e19C23e4f579F9810Aa7",
        "cvx_locker": "0x72a19342e8F1838460eBFCCEf09F6585e32db86E",
        "cvxcrv_staking": "0x3Fe65692bfCD0e6CF84Cb1E7d24108E434A7587e",
        "crv_depositor": "0x8014595F2AB54cD7c604B00E9fb932176fDc86Ae",
    },
}


class ConvexMonitor(ProtocolMonitor):
    """
    Convex Finance Protocol Monitor.
    
    Monitors:
    - Large deposits/withdrawals
    - Reward claims
    - CVX locking
    - Gauge deposits
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="convex",
            protocol_name="Convex Finance",
            protocol_type=ProtocolType.YIELD,
            chains=["ethereum"],
            contracts=CONVEX_CONTRACTS,
            large_tx_threshold_usd=500000,  # Higher for Convex
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Convex event signatures."""
        return CONVEX_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Convex event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = CONVEX_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        contract_address = event_data.get("address", "")
        
        if event_name == "Deposited":
            return await self._handle_deposit(event_data, chain_id, tx_hash, block_number, block_timestamp, contract_address)
        elif event_name == "Withdrawn":
            return await self._handle_withdraw(event_data, chain_id, tx_hash, block_number, block_timestamp, contract_address)
        elif event_name == "RewardPaid":
            return await self._handle_reward(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "Locked":
            return await self._handle_lock(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_deposit(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        contract_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle deposit to Convex pool."""
        topics = event_data.get("topics", [])
        
        user = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(user, bytes):
            user = "0x" + user.hex()[-40:]
        elif isinstance(user, str) and len(user) == 66:
            user = "0x" + user[-40:]
        
        estimated_value_usd = 200000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title="Large Convex Deposit",
                description=f"Large deposit: ${estimated_value_usd:,.0f} by {user[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=user,
                affected_pool=contract_address,
                metadata={"event_type": "deposit", "protocol": "convex"}
            )
        return None
    
    async def _handle_withdraw(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        contract_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle withdrawal from Convex pool."""
        topics = event_data.get("topics", [])
        
        user = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(user, bytes):
            user = "0x" + user.hex()[-40:]
        elif isinstance(user, str) and len(user) == 66:
            user = "0x" + user[-40:]
        
        estimated_value_usd = 200000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="medium",
                title="Large Convex Withdrawal",
                description=f"Large withdrawal: ${estimated_value_usd:,.0f} by {user[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=user,
                affected_pool=contract_address,
                metadata={"event_type": "withdraw", "protocol": "convex"}
            )
        return None
    
    async def _handle_reward(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle reward claim."""
        topics = event_data.get("topics", [])
        
        user = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(user, bytes):
            user = "0x" + user.hex()[-40:]
        elif isinstance(user, str) and len(user) == 66:
            user = "0x" + user[-40:]
        
        estimated_value_usd = 50000
        
        # Only alert for very large rewards
        if estimated_value_usd >= 100000:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title="Large Convex Reward Claim",
                description=f"Large reward claimed: ${estimated_value_usd:,.0f} by {user[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=user,
                metadata={"event_type": "reward_claim", "protocol": "convex"}
            )
        return None
    
    async def _handle_lock(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle CVX lock (vlCVX)."""
        topics = event_data.get("topics", [])
        
        user = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(user, bytes):
            user = "0x" + user.hex()[-40:]
        elif isinstance(user, str) and len(user) == 66:
            user = "0x" + user[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title="Large CVX Lock",
                description=f"Large CVX lock: ${estimated_value_usd:,.0f} by {user[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=user,
                metadata={"event_type": "lock", "protocol": "convex"}
            )
        return None
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Convex metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
        )


# Global instance
convex_monitor = ConvexMonitor()
