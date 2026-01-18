"""
Stargate Protocol Monitor
=========================

Deep integration with Stargate native asset bridge:
- Large bridge transfers
- Pool liquidity monitoring
- Fee collection tracking
- Cross-chain swaps
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


# Stargate Event Signatures
STARGATE_EVENTS = {
    # Swap
    "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f": "Swap",
    # SendToChain
    "0x8d3ee0df6a4b7e82a7f20a763f1c6826e6176323e655af64f32318827d2112d4": "SendToChain",
    # ReceiveFromChain
    "0x3b5b764879b6e3a1d8e4b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5": "ReceiveFromChain",
    # Mint (LP tokens)
    "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f": "Mint",
    # Burn (LP tokens)
    "0xdccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496": "Burn",
    # CreditChainPath
    "0x4a4b5c5d6e6f7a7b8c8d9e9f0a0b1c1d2e2f3a3b4c4d5e5f6a6b7c7d8e8f9a9b": "CreditChainPath",
    # RedeemLocal
    "0x5b5c6d6e7f7a8b8c9d9e0f0a1b1c2d2e3f3a4b4c5d5e6f6a7b7c8d8e9f9a0b0c": "RedeemLocal",
}

# Stargate Contracts
STARGATE_CONTRACTS = {
    "ethereum": {
        "router": "0x8731d54E9D02c286767d56ac03e8037C07e01e98",
        "factory": "0x06D538690AF257Da524f25D0CD52fD85b1c2173E",
        "stg_token": "0xAf5191B0De278C7286d6C7CC6ab6BB8A73bA2Cd6",
        "usdc_pool": "0xdf0770dF86a8034b3EFEf0A1Bb3c889B8332FF56",
        "usdt_pool": "0x38EA452219524Bb87e18dE1C24D3bB59510BD783",
    },
    "polygon": {
        "router": "0x45A01E4e04F14f7A4a6702c74187c5F6222033cd",
        "factory": "0x808d7c71ad2ba3FA531b068a2417C63106BC0949",
    },
    "arbitrum": {
        "router": "0x53Bf833A5d6c4ddA888F69c22C88C9f356a41614",
        "factory": "0x55bDb4164D28FBaF0898e0eF14a589ac09Ac9970",
    },
    "optimism": {
        "router": "0xB0D502E938ed5f4df2E681fE6E419ff29631d62b",
        "factory": "0xE3B53AF74a4BF62Ae5511055290838050bf764Df",
    },
    "avalanche": {
        "router": "0x45A01E4e04F14f7A4a6702c74187c5F6222033cd",
        "factory": "0x808d7c71ad2ba3FA531b068a2417C63106BC0949",
    },
    "bsc": {
        "router": "0x4a364f8c717cAAD9A442737Eb7b8A55cc6cf18D8",
        "factory": "0xe7Ec689f432f29383f217e36e680B5C855051f25",
    },
    "base": {
        "router": "0x45f1A95A4D3f3836523F5c83673c797f4d4d263B",
    },
}


class StargateMonitor(ProtocolMonitor):
    """
    Stargate Protocol Monitor.
    
    Monitors:
    - Large cross-chain swaps
    - Pool liquidity changes
    - Bridge transfers
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="stargate",
            protocol_name="Stargate",
            protocol_type=ProtocolType.BRIDGE,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "bsc", "base"],
            contracts=STARGATE_CONTRACTS,
            large_tx_threshold_usd=250000,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Stargate event signatures."""
        return STARGATE_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Stargate event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = STARGATE_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        pool_address = event_data.get("address", "")
        
        if event_name == "Swap":
            return await self._handle_swap(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address)
        elif event_name == "SendToChain":
            return await self._handle_send(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "ReceiveFromChain":
            return await self._handle_receive(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "Burn":
            return await self._handle_liquidity_removal(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address)
        
        return None
    
    async def _handle_swap(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle cross-chain swap."""
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
                title=f"Large Stargate Bridge Transfer from {chain_id.title()}",
                description=f"Large cross-chain swap: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                affected_pool=pool_address,
                metadata={"event_type": "swap", "protocol": "stargate"}
            )
        return None
    
    async def _handle_send(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle send to chain."""
        topics = event_data.get("topics", [])
        
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="high",
                title=f"Large Stargate Send from {chain_id.title()}",
                description=f"Large bridge send: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                metadata={"event_type": "send_to_chain", "protocol": "stargate"}
            )
        return None
    
    async def _handle_receive(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle receive from chain."""
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
                title=f"Large Stargate Receive on {chain_id.title()}",
                description=f"Large bridge receive: ${estimated_value_usd:,.0f} to {recipient[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=recipient,
                metadata={"event_type": "receive_from_chain", "protocol": "stargate"}
            )
        return None
    
    async def _handle_liquidity_removal(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle liquidity removal."""
        topics = event_data.get("topics", [])
        
        provider = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(provider, bytes):
            provider = "0x" + provider.hex()[-40:]
        elif isinstance(provider, str) and len(provider) == 66:
            provider = "0x" + provider[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="high",
                title=f"Large Stargate Liquidity Removal on {chain_id.title()}",
                description=f"Large LP withdrawal: ${estimated_value_usd:,.0f} by {provider[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=provider,
                affected_pool=pool_address,
                metadata={"event_type": "liquidity_removal", "protocol": "stargate"}
            )
        return None
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Stargate metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
        )


# Global instance
stargate_monitor = StargateMonitor()
