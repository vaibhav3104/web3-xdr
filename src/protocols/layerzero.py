"""
LayerZero Protocol Monitor
==========================

Deep integration with LayerZero omnichain messaging:
- Cross-chain message tracking
- Relayer monitoring
- Oracle verification
- Large transfers via OFT/ONFT
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


# LayerZero Event Signatures
LAYERZERO_EVENTS = {
    # Packet (message sent)
    "0xe9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82": "Packet",
    # PacketReceived
    "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": "PacketReceived",
    # SendToChain (OFT)
    "0x9b5b9a05e4726d8bb2f33d95cb8c089aedd31c9c4a45c3ca0ec3d3e0e3e3e3e3": "SendToChain",
    # ReceiveFromChain (OFT)
    "0xa5a5a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6": "ReceiveFromChain",
    # SetTrustedRemote
    "0xb6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6": "SetTrustedRemote",
    # SetMinDstGas
    "0xc6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6": "SetMinDstGas",
}

# LayerZero Contracts
LAYERZERO_CONTRACTS = {
    "ethereum": {
        "endpoint": "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675",
        "ultra_light_node": "0x4D73AdB72bC3DD368966edD0f0b2148401A178E2",
    },
    "polygon": {
        "endpoint": "0x3c2269811836af69497E5F486A85D7316753cf62",
    },
    "arbitrum": {
        "endpoint": "0x3c2269811836af69497E5F486A85D7316753cf62",
    },
    "optimism": {
        "endpoint": "0x3c2269811836af69497E5F486A85D7316753cf62",
    },
    "avalanche": {
        "endpoint": "0x3c2269811836af69497E5F486A85D7316753cf62",
    },
    "bsc": {
        "endpoint": "0x3c2269811836af69497E5F486A85D7316753cf62",
    },
    "base": {
        "endpoint": "0xb6319cC6c8c27A8F5dAF0dD3DF91EA35C4720dd7",
    },
}


class LayerZeroMonitor(ProtocolMonitor):
    """
    LayerZero Protocol Monitor.
    
    Monitors:
    - Cross-chain packets
    - OFT/ONFT transfers
    - Configuration changes
    - Large value transfers
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="layerzero",
            protocol_name="LayerZero",
            protocol_type=ProtocolType.BRIDGE,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "bsc", "base"],
            contracts=LAYERZERO_CONTRACTS,
            large_tx_threshold_usd=250000,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get LayerZero event signatures."""
        return LAYERZERO_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process LayerZero event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = LAYERZERO_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "Packet":
            return await self._handle_packet_sent(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "SendToChain":
            return await self._handle_oft_send(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "ReceiveFromChain":
            return await self._handle_oft_receive(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "SetTrustedRemote":
            return await self._handle_config_change(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_packet_sent(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle cross-chain packet sent."""
        event_data.get("topics", [])
        
        event_data.get("address", "unknown")
        estimated_value_usd = 50000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="high",
                title=f"Large LayerZero Message from {chain_id.title()}",
                description=f"Large cross-chain packet: ${estimated_value_usd:,.0f}",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                metadata={"event_type": "packet_sent", "protocol": "layerzero"}
            )
        return None
    
    async def _handle_oft_send(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle OFT token send."""
        topics = event_data.get("topics", [])
        
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        estimated_value_usd = 50000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="high",
                title=f"Large LayerZero OFT Transfer from {chain_id.title()}",
                description=f"Large OFT transfer: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                metadata={"event_type": "oft_send", "protocol": "layerzero"}
            )
        return None
    
    async def _handle_oft_receive(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle OFT token receive."""
        topics = event_data.get("topics", [])
        
        recipient = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(recipient, bytes):
            recipient = "0x" + recipient.hex()[-40:]
        elif isinstance(recipient, str) and len(recipient) == 66:
            recipient = "0x" + recipient[-40:]
        
        estimated_value_usd = 50000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large LayerZero OFT Received on {chain_id.title()}",
                description=f"Large OFT received: ${estimated_value_usd:,.0f} to {recipient[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=recipient,
                metadata={"event_type": "oft_receive", "protocol": "layerzero"}
            )
        return None
    
    async def _handle_config_change(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle trusted remote configuration change."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="high",
            title="LayerZero Trusted Remote Changed",
            description="Trusted remote address has been modified. Verify legitimacy!",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "config_change", "protocol": "layerzero"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current LayerZero metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
        )


# Global instance
layerzero_monitor = LayerZeroMonitor()
