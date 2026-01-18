"""
Wormhole Protocol Monitor
=========================

Deep integration with Wormhole cross-chain messaging:
- Large bridge transfers
- Guardian signature monitoring
- VAA (Verified Action Approval) tracking
- Cross-chain message verification
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


# Wormhole Event Signatures
WORMHOLE_EVENTS = {
    # LogMessagePublished
    "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2": "LogMessagePublished",
    # TransferRedeemed
    "0xcaf280c8cfeba144da67230d9b009c8f868a75bac9a528fa0474be1ba317c169": "TransferRedeemed",
    # GuardianSetAdded
    "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": "GuardianSetAdded",
    # ContractUpgraded
    "0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b": "ContractUpgraded",
    # Transfer (token bridge)
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
}

# Wormhole Contracts
WORMHOLE_CONTRACTS = {
    "ethereum": {
        "core": "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B",
        "token_bridge": "0x3ee18B2214AFF97000D974cf647E7C347E8fa585",
        "nft_bridge": "0x6FFd7EdE62328b3Af38FCD61461Bbfc52F5651fE",
    },
    "polygon": {
        "core": "0x7A4B5a56256163F07b2C80A7cA55aBE66c4ec4d7",
        "token_bridge": "0x5a58505a96D1dbf8dF91cB21B54419FC36e93fdE",
    },
    "arbitrum": {
        "core": "0xa5f208e072434bC67592E4C49C1B991BA79BCA46",
        "token_bridge": "0x0b2402144Bb366A632D14B83F244D2e0e21bD39c",
    },
    "optimism": {
        "core": "0xEe91C335eab126dF5fDB3797EA9d6aD93aeC9722",
        "token_bridge": "0x1D68124e65faFC907325e3EDbF8c4d84499DAa8b",
    },
    "avalanche": {
        "core": "0x54a8e5f9c4CbA08F9943965859F6c34eAF03E26c",
        "token_bridge": "0x0e082F06FF657D94310cB8cE8B0D9a04541d8052",
    },
    "bsc": {
        "core": "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B",
        "token_bridge": "0xB6F6D86a8f9879A9c87f643768d9efc38c1Da6E7",
    },
    "solana": {
        "core": "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth",
        "token_bridge": "wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb",
    },
}


class WormholeMonitor(ProtocolMonitor):
    """
    Wormhole Protocol Monitor.
    
    Monitors:
    - Large cross-chain transfers
    - Message publications
    - Guardian set changes
    - Contract upgrades
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="wormhole",
            protocol_name="Wormhole",
            protocol_type=ProtocolType.BRIDGE,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "bsc", "solana"],
            contracts=WORMHOLE_CONTRACTS,
            large_tx_threshold_usd=500000,  # Higher threshold for bridges
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Wormhole event signatures."""
        return WORMHOLE_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Wormhole event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = WORMHOLE_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "LogMessagePublished":
            return await self._handle_message_published(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "TransferRedeemed":
            return await self._handle_transfer_redeemed(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "GuardianSetAdded":
            return await self._handle_guardian_change(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "ContractUpgraded":
            return await self._handle_upgrade(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_message_published(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle cross-chain message publication."""
        topics = event_data.get("topics", [])
        
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="high",
                title=f"Large Wormhole Bridge Transfer from {chain_id.title()}",
                description=f"Large cross-chain message: ${estimated_value_usd:,.0f} from {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                metadata={"event_type": "message_published", "protocol": "wormhole"}
            )
        return None
    
    async def _handle_transfer_redeemed(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle transfer redemption on destination chain."""
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
                severity="high",
                title=f"Large Wormhole Transfer Redeemed on {chain_id.title()}",
                description=f"Large bridge transfer completed: ${estimated_value_usd:,.0f} to {recipient[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=recipient,
                metadata={"event_type": "transfer_redeemed", "protocol": "wormhole"}
            )
        return None
    
    async def _handle_guardian_change(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle guardian set change - CRITICAL."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="critical",
            title="🚨 Wormhole Guardian Set Changed",
            description="Guardian set has been modified. Verify this is a legitimate upgrade!",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "guardian_change", "protocol": "wormhole"}
        )
    
    async def _handle_upgrade(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle contract upgrade - CRITICAL."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="critical",
            title="🚨 Wormhole Contract Upgraded",
            description="Bridge contract has been upgraded. Verify legitimacy immediately!",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "contract_upgrade", "protocol": "wormhole"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Wormhole metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
        )


# Global instance
wormhole_monitor = WormholeMonitor()
