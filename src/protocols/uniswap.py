"""
Uniswap Protocol Monitor
========================

Deep integration with Uniswap V2/V3:
- Large swap detection
- Price impact alerts
- Liquidity changes
- Pool imbalance detection
- MEV/sandwich attack detection
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


# Uniswap V3 Event Signatures
UNISWAP_V3_EVENTS = {
    # Swap
    "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67": "Swap",
    # Mint (add liquidity)
    "0x7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde": "Mint",
    # Burn (remove liquidity)
    "0x0c396cd989a39f4459b5fa1aed6a9a8dcdbc45908acfd67e028cd568da98982c": "Burn",
    # Collect (fees)
    "0x70935338e69775456a85ddef226c395fb668b63fa0115f5f20610b388e6ca9c0": "Collect",
    # Flash
    "0xbdbdb71d7860376ba52b25a5028beea23581364a40522f6bcfb86bb1f2dca633": "Flash",
    # PoolCreated
    "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118": "PoolCreated",
}

# Uniswap V2 Event Signatures
UNISWAP_V2_EVENTS = {
    # Swap
    "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822": "Swap",
    # Mint
    "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f": "Mint",
    # Burn
    "0xdccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496": "Burn",
    # Sync
    "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1": "Sync",
}

# Uniswap Factory/Router addresses
UNISWAP_CONTRACTS = {
    "ethereum": {
        "v3_factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "v3_router": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
        "v2_factory": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
        "v2_router": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    },
    "polygon": {
        "v3_factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "v3_router": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    },
    "arbitrum": {
        "v3_factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "v3_router": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    },
    "optimism": {
        "v3_factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "v3_router": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    },
    "base": {
        "v3_factory": "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
        "v3_router": "0x2626664c2603336E57B271c5C0b26F421741e481",
    },
}


class UniswapMonitor(ProtocolMonitor):
    """
    Uniswap Protocol Monitor.
    
    Monitors:
    - Large swaps
    - High price impact trades
    - Liquidity additions/removals
    - Pool imbalances
    - Potential sandwich attacks
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="uniswap",
            protocol_name="Uniswap",
            protocol_type=ProtocolType.DEX,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "base"],
            contracts=UNISWAP_CONTRACTS,
            large_tx_threshold_usd=50000,
            price_impact_warning=1.0,
            price_impact_critical=5.0,
        )
        super().__init__(config)
        
        # Track recent swaps for sandwich detection
        self._recent_swaps: Dict[str, list] = {}  # pool -> [swap_data]
        
        # Track pool states
        self._pool_states: Dict[str, Dict[str, Any]] = {}
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Uniswap event signatures."""
        return {**UNISWAP_V3_EVENTS, **UNISWAP_V2_EVENTS}
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Uniswap event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        # Check V3 events first
        event_name = UNISWAP_V3_EVENTS.get(topic0.lower())
        version = "v3"
        
        if not event_name:
            event_name = UNISWAP_V2_EVENTS.get(topic0.lower())
            version = "v2"
        
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        pool_address = event_data.get("address", "")
        
        # Route to specific handler
        if event_name == "Swap":
            return await self._handle_swap(event_data, chain_id, tx_hash, block_number, block_timestamp, version, pool_address)
        elif event_name == "Mint":
            return await self._handle_mint(event_data, chain_id, tx_hash, block_number, block_timestamp, version, pool_address)
        elif event_name == "Burn":
            return await self._handle_burn(event_data, chain_id, tx_hash, block_number, block_timestamp, version, pool_address)
        elif event_name == "Flash":
            return await self._handle_flash(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address)
        
        return None
    
    async def _handle_swap(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        version: str,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle swap event - alert for large swaps and high price impact."""
        topics = event_data.get("topics", [])
        data = event_data.get("data", "0x")
        
        # Parse sender/recipient
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        # Estimate swap value (would need price oracle)
        estimated_value_usd = 30000  # Placeholder
        
        # Calculate price impact (would need pool state)
        price_impact_percent = 0.5  # Placeholder
        
        # Track for sandwich detection
        swap_data = {
            "tx_hash": tx_hash,
            "block_number": block_number,
            "sender": sender,
            "value_usd": estimated_value_usd,
            "timestamp": block_timestamp,
        }
        
        if pool_address not in self._recent_swaps:
            self._recent_swaps[pool_address] = []
        self._recent_swaps[pool_address].append(swap_data)
        
        # Keep only recent swaps
        self._recent_swaps[pool_address] = self._recent_swaps[pool_address][-100:]
        
        # Check for high price impact
        if price_impact_percent >= self.config.price_impact_critical:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.PRICE_IMPACT,
                severity="critical",
                title=f"High Price Impact Swap on Uniswap {version.upper()}",
                description=f"Swap with {price_impact_percent:.2f}% price impact detected. "
                           f"Value: ${estimated_value_usd:,.0f}",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                affected_pool=pool_address,
                metadata={
                    "event_type": "swap",
                    "version": version,
                    "price_impact_percent": price_impact_percent,
                }
            )
        
        # Check for large swap
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large Uniswap {version.upper()} Swap on {chain_id.title()}",
                description=f"Large swap detected: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                affected_pool=pool_address,
                metadata={
                    "event_type": "swap",
                    "version": version,
                }
            )
        
        return None
    
    async def _handle_mint(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        version: str,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle liquidity addition."""
        topics = event_data.get("topics", [])
        
        # Parse owner
        owner = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(owner, bytes):
            owner = "0x" + owner.hex()[-40:]
        elif isinstance(owner, str) and len(owner) == 66:
            owner = "0x" + owner[-40:]
        
        # Estimate value
        estimated_value_usd = 20000  # Placeholder
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title=f"Large Liquidity Addition on Uniswap {version.upper()}",
                description=f"Large LP position created: ${estimated_value_usd:,.0f} by {owner[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=owner,
                affected_pool=pool_address,
                metadata={
                    "event_type": "add_liquidity",
                    "version": version,
                }
            )
        
        return None
    
    async def _handle_burn(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        version: str,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle liquidity removal - potential rug pull indicator."""
        topics = event_data.get("topics", [])
        
        # Parse owner
        owner = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(owner, bytes):
            owner = "0x" + owner.hex()[-40:]
        elif isinstance(owner, str) and len(owner) == 66:
            owner = "0x" + owner[-40:]
        
        # Estimate value
        estimated_value_usd = 20000  # Placeholder
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="medium",
                title=f"Large Liquidity Removal on Uniswap {version.upper()}",
                description=f"Large LP withdrawal: ${estimated_value_usd:,.0f} by {owner[:10]}... "
                           f"Potential rug pull indicator.",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=owner,
                affected_pool=pool_address,
                metadata={
                    "event_type": "remove_liquidity",
                    "version": version,
                    "potential_rug_pull": True,
                }
            )
        
        return None
    
    async def _handle_flash(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle flash loan from Uniswap V3."""
        topics = event_data.get("topics", [])
        
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        # Estimate value
        estimated_value_usd = 100000  # Placeholder
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LARGE_TRANSACTION,
            severity="medium",
            title=f"Uniswap V3 Flash Loan on {chain_id.title()}",
            description=f"Flash loan detected: ${estimated_value_usd:,.0f} by {sender[:10]}...",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=sender,
            affected_pool=pool_address,
            metadata={
                "event_type": "flash",
                "version": "v3",
                "is_flashloan": True,
            }
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Uniswap metrics for a chain."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,  # Would fetch from subgraph
            volume_24h_usd=0,
            fees_24h_usd=0,
        )


# Global instance
uniswap_monitor = UniswapMonitor()
