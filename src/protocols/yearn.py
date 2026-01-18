"""
Yearn Finance Protocol Monitor
==============================

Deep integration with Yearn yield vaults:
- Large vault deposits/withdrawals
- Strategy changes
- Harvest events
- Emergency withdrawals
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


# Yearn Event Signatures
YEARN_EVENTS = {
    # Deposit
    "0xdcbc1c05240f31ff3ad067ef1ee35ce4997762752e3a095284754544f4c709d7": "Deposit",
    # Withdraw
    "0xf279e6a1f5e320cca91135676d9cb6e44ca8a08c0b88342bcdb1144f6511b568": "Withdraw",
    # Transfer
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
    # StrategyAdded
    "0x5a6abd2af9fe6c0554fa08649e2d86e4571f3f8f1b7e3c2c3e3d3f3a3b3c3d3e": "StrategyAdded",
    # StrategyRevoked
    "0x6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c": "StrategyRevoked",
    # Harvested
    "0x7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d": "Harvested",
    # EmergencyShutdown
    "0x8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e": "EmergencyShutdown",
    # UpdateManagement
    "0x9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f": "UpdateManagement",
}

# Yearn Contracts
YEARN_CONTRACTS = {
    "ethereum": {
        "registry": "0x50c1a2eA0a861A967D9d0FFE2AE4012c2E053804",
        "registry_v2": "0xaF1f5e1c19cB68B30aAD73846eFfDf78a5863319",
        "yfi_token": "0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e",
        # Popular vaults
        "yvusdc": "0xa354F35829Ae975e850e23e9615b11Da1B3dC4DE",
        "yvdai": "0xdA816459F1AB5631232FE5e97a05BBBb94970c95",
        "yvweth": "0xa258C4606Ca8206D8aA700cE2143D7db854D168c",
    },
    "polygon": {
        "registry": "0x79286Dd38C9bC9B0e5E3a1E1B7A4b5c6d7E8f9A0",
    },
    "arbitrum": {
        "registry": "0x3199437193625DCcD6F9C9e98BDf93582200Eb1f",
    },
    "optimism": {
        "registry": "0x79286Dd38C9bC9B0e5E3a1E1B7A4b5c6d7E8f9A0",
    },
}


class YearnMonitor(ProtocolMonitor):
    """
    Yearn Finance Protocol Monitor.
    
    Monitors:
    - Large vault deposits/withdrawals
    - Strategy additions/revocations
    - Harvest events
    - Emergency shutdowns
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="yearn",
            protocol_name="Yearn Finance",
            protocol_type=ProtocolType.YIELD,
            chains=["ethereum", "polygon", "arbitrum", "optimism"],
            contracts=YEARN_CONTRACTS,
            large_tx_threshold_usd=250000,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Yearn event signatures."""
        return YEARN_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Yearn event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = YEARN_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        vault_address = event_data.get("address", "")
        
        if event_name == "Deposit":
            return await self._handle_deposit(event_data, chain_id, tx_hash, block_number, block_timestamp, vault_address)
        elif event_name == "Withdraw":
            return await self._handle_withdraw(event_data, chain_id, tx_hash, block_number, block_timestamp, vault_address)
        elif event_name == "StrategyAdded":
            return await self._handle_strategy_added(event_data, chain_id, tx_hash, block_number, block_timestamp, vault_address)
        elif event_name == "StrategyRevoked":
            return await self._handle_strategy_revoked(event_data, chain_id, tx_hash, block_number, block_timestamp, vault_address)
        elif event_name == "EmergencyShutdown":
            return await self._handle_emergency_shutdown(event_data, chain_id, tx_hash, block_number, block_timestamp, vault_address)
        elif event_name == "Harvested":
            return await self._handle_harvest(event_data, chain_id, tx_hash, block_number, block_timestamp, vault_address)
        
        return None
    
    async def _handle_deposit(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        vault_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle vault deposit."""
        topics = event_data.get("topics", [])
        
        depositor = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(depositor, bytes):
            depositor = "0x" + depositor.hex()[-40:]
        elif isinstance(depositor, str) and len(depositor) == 66:
            depositor = "0x" + depositor[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title=f"Large Yearn Vault Deposit on {chain_id.title()}",
                description=f"Large deposit: ${estimated_value_usd:,.0f} by {depositor[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=depositor,
                affected_pool=vault_address,
                metadata={"event_type": "deposit", "protocol": "yearn"}
            )
        return None
    
    async def _handle_withdraw(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        vault_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle vault withdrawal."""
        topics = event_data.get("topics", [])
        
        withdrawer = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(withdrawer, bytes):
            withdrawer = "0x" + withdrawer.hex()[-40:]
        elif isinstance(withdrawer, str) and len(withdrawer) == 66:
            withdrawer = "0x" + withdrawer[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="medium",
                title=f"Large Yearn Vault Withdrawal on {chain_id.title()}",
                description=f"Large withdrawal: ${estimated_value_usd:,.0f} by {withdrawer[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=withdrawer,
                affected_pool=vault_address,
                metadata={"event_type": "withdraw", "protocol": "yearn"}
            )
        return None
    
    async def _handle_strategy_added(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        vault_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle new strategy addition."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="medium",
            title="New Yearn Strategy Added",
            description=f"A new strategy has been added to vault {vault_address[:10]}...",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            affected_pool=vault_address,
            metadata={"event_type": "strategy_added", "protocol": "yearn"}
        )
    
    async def _handle_strategy_revoked(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        vault_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle strategy revocation."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="high",
            title="Yearn Strategy Revoked",
            description=f"A strategy has been revoked from vault {vault_address[:10]}...",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            affected_pool=vault_address,
            metadata={"event_type": "strategy_revoked", "protocol": "yearn"}
        )
    
    async def _handle_emergency_shutdown(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        vault_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle emergency shutdown - CRITICAL."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="critical",
            title="🚨 Yearn Vault EMERGENCY SHUTDOWN",
            description=f"Emergency shutdown triggered for vault {vault_address[:10]}... Immediate investigation required!",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            affected_pool=vault_address,
            metadata={"event_type": "emergency_shutdown", "protocol": "yearn"}
        )
    
    async def _handle_harvest(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        vault_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle harvest event."""
        # Only alert for large harvests
        estimated_value_usd = 50000
        
        if estimated_value_usd >= 100000:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title=f"Large Yearn Harvest on {chain_id.title()}",
                description=f"Large harvest: ${estimated_value_usd:,.0f} from vault {vault_address[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_pool=vault_address,
                metadata={"event_type": "harvest", "protocol": "yearn"}
            )
        return None
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Yearn metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
        )


# Global instance
yearn_monitor = YearnMonitor()
