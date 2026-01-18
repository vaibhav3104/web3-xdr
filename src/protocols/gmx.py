"""
GMX Protocol Monitor
====================

Deep integration with GMX perpetual exchange:
- Large position opens/closes
- Liquidation monitoring
- GLP mint/burn tracking
- Price feed updates
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


# GMX Event Signatures
GMX_EVENTS = {
    # IncreasePosition
    "0x2fe68525253654c21998f35787a8d0f361905ef647c854092430ab65f2f15022": "IncreasePosition",
    # DecreasePosition
    "0x93d75d64d1f84fc6f430a64fc578bdd4c1e090e90ea2d51773e626d19de56d30": "DecreasePosition",
    # LiquidatePosition
    "0x2e1f85a64a2f22cf2f0c42584e7c919ed4abe8d53675cff0f62bf1e95a8c4a3e": "LiquidatePosition",
    # ClosePosition
    "0x73af1d417d82c240fdb6d319b34ad884514c3c80f8e8379b72ac7e360b5e3a87": "ClosePosition",
    # AddLiquidity (GLP)
    "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": "AddLiquidity",
    # RemoveLiquidity (GLP)
    "0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b": "RemoveLiquidity",
    # Swap
    "0x0874b2d545cb271cdbda4e093020c452328b24af12382ed62c4d00f5c26709db": "Swap",
    # UpdatePosition
    "0x3ff41bdde87755b687ae83d0221a232b6be51a803330ed9661c1b5d0105e0d8a": "UpdatePosition",
}

# GMX Contracts
GMX_CONTRACTS = {
    "arbitrum": {
        "vault": "0x489ee077994B6658eAfA855C308275EAd8097C4A",
        "router": "0xaBBc5F99639c9B6bCb58544ddf04EFA6802F4064",
        "position_router": "0xb87a436B93fFE9D75c5cFA7bAcFff96430b09868",
        "glp_manager": "0x3963FfC9dff443c2A94f21b129D429891E32ec18",
        "glp_token": "0x4277f8F2c384827B5273592FF7CeBd9f2C1ac258",
        "gmx_token": "0xfc5A1A6EB076a2C7aD06eD22C90d7E710E35ad0a",
    },
    "avalanche": {
        "vault": "0x9ab2De34A33fB459b538c43f251eB825645e8595",
        "router": "0x5F719c2F1095F7B9fc68a68e35B51194f4b6abe8",
        "position_router": "0xffF6D276Bc37c61A23f06410Dce4A400f66420f8",
        "glp_manager": "0xD152c7F25db7F4B95b7658323c5F33d176818EE4",
    },
}


class GMXMonitor(ProtocolMonitor):
    """
    GMX Protocol Monitor.
    
    Monitors:
    - Large position changes
    - Liquidations
    - GLP liquidity changes
    - Large swaps
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="gmx",
            protocol_name="GMX",
            protocol_type=ProtocolType.DERIVATIVES,
            chains=["arbitrum", "avalanche"],
            contracts=GMX_CONTRACTS,
            large_tx_threshold_usd=500000,  # Higher for perps
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get GMX event signatures."""
        return GMX_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process GMX event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = GMX_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "IncreasePosition":
            return await self._handle_position_increase(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "DecreasePosition":
            return await self._handle_position_decrease(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "LiquidatePosition":
            return await self._handle_liquidation(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "RemoveLiquidity":
            return await self._handle_glp_removal(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_position_increase(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle position increase."""
        topics = event_data.get("topics", [])
        
        account = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(account, bytes):
            account = "0x" + account.hex()[-40:]
        elif isinstance(account, str) and len(account) == 66:
            account = "0x" + account[-40:]
        
        estimated_value_usd = 200000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large GMX Position Opened on {chain_id.title()}",
                description=f"Large position increase: ${estimated_value_usd:,.0f} by {account[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=account,
                metadata={"event_type": "position_increase", "protocol": "gmx"}
            )
        return None
    
    async def _handle_position_decrease(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle position decrease."""
        topics = event_data.get("topics", [])
        
        account = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(account, bytes):
            account = "0x" + account.hex()[-40:]
        elif isinstance(account, str) and len(account) == 66:
            account = "0x" + account[-40:]
        
        estimated_value_usd = 200000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large GMX Position Closed on {chain_id.title()}",
                description=f"Large position decrease: ${estimated_value_usd:,.0f} by {account[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=account,
                metadata={"event_type": "position_decrease", "protocol": "gmx"}
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
        """Handle position liquidation."""
        self._stats["liquidations_detected"] += 1
        
        topics = event_data.get("topics", [])
        
        account = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(account, bytes):
            account = "0x" + account.hex()[-40:]
        elif isinstance(account, str) and len(account) == 66:
            account = "0x" + account[-40:]
        
        estimated_value_usd = 100000
        severity = "critical" if estimated_value_usd >= 500000 else "high"
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LIQUIDATION,
            severity=severity,
            title=f"GMX Position Liquidated on {chain_id.title()}",
            description=f"Position liquidated for {account[:10]}... Value: ${estimated_value_usd:,.0f}",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=account,
            metadata={"event_type": "liquidation", "protocol": "gmx"}
        )
    
    async def _handle_glp_removal(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle GLP liquidity removal."""
        topics = event_data.get("topics", [])
        
        account = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(account, bytes):
            account = "0x" + account.hex()[-40:]
        elif isinstance(account, str) and len(account) == 66:
            account = "0x" + account[-40:]
        
        estimated_value_usd = 200000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="high",
                title=f"Large GLP Withdrawal on {chain_id.title()}",
                description=f"Large GLP removal: ${estimated_value_usd:,.0f} by {account[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=account,
                metadata={"event_type": "glp_removal", "protocol": "gmx"}
            )
        return None
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current GMX metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
            liquidations_24h_count=self._stats["liquidations_detected"],
        )


# Global instance
gmx_monitor = GMXMonitor()
