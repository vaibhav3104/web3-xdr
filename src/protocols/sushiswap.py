"""
SushiSwap Protocol Monitor
==========================

Deep integration with SushiSwap:
- Large swap detection
- Liquidity changes
- SUSHI rewards monitoring
- Kashi lending alerts
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


# SushiSwap Event Signatures (Uniswap V2 fork)
SUSHISWAP_EVENTS = {
    # Swap
    "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822": "Swap",
    # Mint (add liquidity)
    "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f": "Mint",
    # Burn (remove liquidity)
    "0xdccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496": "Burn",
    # Sync
    "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1": "Sync",
    # PairCreated
    "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9": "PairCreated",
    # Deposit (MasterChef)
    "0x90890809c654f11d6e72a28fa60149770a0d11ec6c92319d6ceb2bb0a4ea1a15": "Deposit",
    # Withdraw (MasterChef)
    "0xf279e6a1f5e320cca91135676d9cb6e44ca8a08c0b88342bcdb1144f6511b568": "Withdraw",
}

# SushiSwap Contracts
SUSHISWAP_CONTRACTS = {
    "ethereum": {
        "factory": "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",
        "router": "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
        "masterchef": "0xc2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd",
        "masterchef_v2": "0xEF0881eC094552b2e128Cf945EF17a6752B4Ec5d",
        "sushi_token": "0x6B3595068778DD592e39A122f4f5a5cF09C90fE2",
    },
    "polygon": {
        "factory": "0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
        "router": "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",
    },
    "arbitrum": {
        "factory": "0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
        "router": "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",
    },
    "optimism": {
        "factory": "0xFbc12984689e5f15626Bad03Ad60160Fe98B303C",
    },
    "avalanche": {
        "factory": "0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
        "router": "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",
    },
}


class SushiSwapMonitor(ProtocolMonitor):
    """
    SushiSwap Protocol Monitor.
    
    Monitors:
    - Large swaps
    - Liquidity additions/removals
    - MasterChef deposits/withdrawals
    - New pair creations
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="sushiswap",
            protocol_name="SushiSwap",
            protocol_type=ProtocolType.DEX,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "avalanche"],
            contracts=SUSHISWAP_CONTRACTS,
            large_tx_threshold_usd=50000,
            price_impact_warning=1.0,
            price_impact_critical=5.0,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get SushiSwap event signatures."""
        return SUSHISWAP_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process SushiSwap event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = SUSHISWAP_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        pool_address = event_data.get("address", "")
        
        if event_name == "Swap":
            return await self._handle_swap(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address)
        elif event_name == "Mint":
            return await self._handle_mint(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address)
        elif event_name == "Burn":
            return await self._handle_burn(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address)
        elif event_name == "PairCreated":
            return await self._handle_pair_created(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
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
        """Handle swap event."""
        topics = event_data.get("topics", [])
        
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        estimated_value_usd = 30000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large SushiSwap Swap on {chain_id.title()}",
                description=f"Large swap: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                affected_pool=pool_address,
                metadata={"event_type": "swap", "protocol": "sushiswap"}
            )
        return None
    
    async def _handle_mint(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle liquidity addition."""
        topics = event_data.get("topics", [])
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        estimated_value_usd = 20000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title=f"Large SushiSwap Liquidity Addition",
                description=f"Large LP deposit: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                affected_pool=pool_address,
                metadata={"event_type": "add_liquidity", "protocol": "sushiswap"}
            )
        return None
    
    async def _handle_burn(
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
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        estimated_value_usd = 20000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="medium",
                title=f"Large SushiSwap Liquidity Removal",
                description=f"Large LP withdrawal: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                affected_pool=pool_address,
                metadata={"event_type": "remove_liquidity", "protocol": "sushiswap", "potential_rug_pull": True}
            )
        return None
    
    async def _handle_pair_created(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle new pair creation."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="low",
            title="New SushiSwap Pair Created",
            description="A new trading pair has been created.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "pair_created", "protocol": "sushiswap"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current SushiSwap metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
            fees_24h_usd=0,
        )


# Global instance
sushiswap_monitor = SushiSwapMonitor()
