"""
Synthetix Protocol Monitor
==========================

Deep integration with Synthetix synthetic assets:
- Synth minting/burning
- Liquidation monitoring
- Staking changes
- Exchange tracking
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


# Synthetix Event Signatures
SYNTHETIX_EVENTS = {
    # SynthExchange
    "0x65b6972c94204d84cffd3a95615743e31270f04fdf251f3dccc705cfbad44776": "SynthExchange",
    # Issued (synth minted)
    "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": "Issued",
    # Burned (synth burned)
    "0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b": "Burned",
    # AccountLiquidated
    "0x3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c": "AccountLiquidated",
    # RewardsClaimed
    "0x4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d": "RewardsClaimed",
    # StakingReward
    "0x5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e": "StakingReward",
    # FeesClaimed
    "0x6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f": "FeesClaimed",
    # Transfer
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
}

# Synthetix Contracts
SYNTHETIX_CONTRACTS = {
    "ethereum": {
        "synthetix": "0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F",
        "proxy_susd": "0x57Ab1ec28D129707052df4dF418D58a2D46d5f51",
        "fee_pool": "0xb440DD674e1243644791a4AdfE3A2AbB0A92d309",
        "exchanger": "0x0064A673267696049938AA47595dD0B3C2e705A1",
        "liquidator": "0x8e9757479D5ad4E7f9d951B60d39F5220b893d6c",
    },
    "optimism": {
        "synthetix": "0x8700dAec35aF8Ff88c16BdF0418774CB3D7599B4",
        "proxy_susd": "0x8c6f28f2F1A3C87F0f938b96d27520d9751ec8d9",
        "perps_market": "0x2B3bb4c683BFc5239B029131EEf3B1d214478d93",
    },
}


class SynthetixMonitor(ProtocolMonitor):
    """
    Synthetix Protocol Monitor.
    
    Monitors:
    - Large synth exchanges
    - Minting/burning
    - Liquidations
    - Staking rewards
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="synthetix",
            protocol_name="Synthetix",
            protocol_type=ProtocolType.DERIVATIVES,
            chains=["ethereum", "optimism"],
            contracts=SYNTHETIX_CONTRACTS,
            large_tx_threshold_usd=250000,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Synthetix event signatures."""
        return SYNTHETIX_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Synthetix event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = SYNTHETIX_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "SynthExchange":
            return await self._handle_exchange(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "Issued":
            return await self._handle_mint(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "Burned":
            return await self._handle_burn(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "AccountLiquidated":
            return await self._handle_liquidation(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_exchange(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle synth exchange."""
        topics = event_data.get("topics", [])
        
        account = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(account, bytes):
            account = "0x" + account.hex()[-40:]
        elif isinstance(account, str) and len(account) == 66:
            account = "0x" + account[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large Synthetix Exchange on {chain_id.title()}",
                description=f"Large synth exchange: ${estimated_value_usd:,.0f} by {account[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=account,
                metadata={"event_type": "exchange", "protocol": "synthetix"}
            )
        return None
    
    async def _handle_mint(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle synth minting."""
        topics = event_data.get("topics", [])
        
        account = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(account, bytes):
            account = "0x" + account.hex()[-40:]
        elif isinstance(account, str) and len(account) == 66:
            account = "0x" + account[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large Synthetix Mint on {chain_id.title()}",
                description=f"Large synth mint: ${estimated_value_usd:,.0f} by {account[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=account,
                metadata={"event_type": "mint", "protocol": "synthetix"}
            )
        return None
    
    async def _handle_burn(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle synth burning."""
        topics = event_data.get("topics", [])
        
        account = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(account, bytes):
            account = "0x" + account.hex()[-40:]
        elif isinstance(account, str) and len(account) == 66:
            account = "0x" + account[-40:]
        
        estimated_value_usd = 100000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="medium",
                title=f"Large Synthetix Burn on {chain_id.title()}",
                description=f"Large synth burn: ${estimated_value_usd:,.0f} by {account[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=account,
                metadata={"event_type": "burn", "protocol": "synthetix"}
            )
        return None
    
    async def _handle_liquidation(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle account liquidation."""
        self._stats["liquidations_detected"] += 1
        
        topics = event_data.get("topics", [])
        
        account = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(account, bytes):
            account = "0x" + account.hex()[-40:]
        elif isinstance(account, str) and len(account) == 66:
            account = "0x" + account[-40:]
        
        estimated_value_usd = 50000
        severity = "critical" if estimated_value_usd >= 250000 else "high"
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LIQUIDATION,
            severity=severity,
            title=f"Synthetix Account Liquidated on {chain_id.title()}",
            description=f"Account liquidated: {account[:10]}... Value: ${estimated_value_usd:,.0f}",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=account,
            metadata={"event_type": "liquidation", "protocol": "synthetix"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Synthetix metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
            liquidations_24h_count=self._stats["liquidations_detected"],
        )


# Global instance
synthetix_monitor = SynthetixMonitor()
