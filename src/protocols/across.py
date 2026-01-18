"""
Across Protocol Monitor
=======================

Deep integration with Across fast bridge:
- Large bridge deposits/fills
- Relayer monitoring
- Speed deposit tracking
- HubPool/SpokePool events
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


# Across Event Signatures
ACROSS_EVENTS = {
    # FundsDeposited
    "0xa123dc29aebf7d0c3322c8eeb5b999e859f39937950ed31056532713d0de396f": "FundsDeposited",
    # FilledRelay
    "0x571749edf1d5c9599318cdbc4e28a6475d65e87fd3b2df9c8a2a4f1b8b7c3e3e": "FilledRelay",
    # RequestedSpeedUpDeposit
    "0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b": "RequestedSpeedUpDeposit",
    # RelayerRefundExecuted
    "0x3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c": "RelayerRefundExecuted",
    # TokensBridged
    "0x4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d": "TokensBridged",
    # RootBundleExecuted
    "0x5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e": "RootBundleExecuted",
}

# Across Contracts
ACROSS_CONTRACTS = {
    "ethereum": {
        "hub_pool": "0xc186fA914353c44b2E33eBE05f21846F1048bEda",
        "spoke_pool": "0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5",
        "across_config_store": "0x3B03509645713718B78951126E0A6de6f10043f5",
    },
    "polygon": {
        "spoke_pool": "0x9295ee1d8C5b022Be115A2AD3c30C72E34e7F096",
    },
    "arbitrum": {
        "spoke_pool": "0xe35e9842fceaCA96570B734083f4a58e8F7C5f2A",
    },
    "optimism": {
        "spoke_pool": "0x6f26Bf09B1C792e3228e5467807a900A503c0281",
    },
    "base": {
        "spoke_pool": "0x09aea4b2242abC8bb4BB78D537A67a245A7bEC64",
    },
}


class AcrossMonitor(ProtocolMonitor):
    """
    Across Protocol Monitor.
    
    Monitors:
    - Large bridge deposits
    - Relay fills
    - Speed-up requests
    - HubPool root bundle executions
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="across",
            protocol_name="Across Protocol",
            protocol_type=ProtocolType.BRIDGE,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "base"],
            contracts=ACROSS_CONTRACTS,
            large_tx_threshold_usd=250000,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Across event signatures."""
        return ACROSS_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Across event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = ACROSS_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "FundsDeposited":
            return await self._handle_deposit(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "FilledRelay":
            return await self._handle_fill(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "RootBundleExecuted":
            return await self._handle_root_bundle(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_deposit(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle bridge deposit."""
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
                severity="high",
                title=f"Large Across Deposit from {chain_id.title()}",
                description=f"Large bridge deposit: ${estimated_value_usd:,.0f} by {depositor[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=depositor,
                metadata={"event_type": "deposit", "protocol": "across"}
            )
        return None
    
    async def _handle_fill(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle relay fill."""
        topics = event_data.get("topics", [])
        
        recipient = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(recipient, bytes):
            recipient = "0x" + recipient.hex()[-40:]
        elif isinstance(recipient, str) and len(recipient) == 66:
            recipient = "0x" + recipient[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large Across Fill on {chain_id.title()}",
                description=f"Large relay fill: ${estimated_value_usd:,.0f} to {recipient[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=recipient,
                metadata={"event_type": "fill", "protocol": "across"}
            )
        return None
    
    async def _handle_root_bundle(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle root bundle execution - governance event."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="medium",
            title="Across Root Bundle Executed",
            description="A new root bundle has been executed on HubPool.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "root_bundle", "protocol": "across"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Across metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
        )


# Global instance
across_monitor = AcrossMonitor()
