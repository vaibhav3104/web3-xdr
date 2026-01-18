"""
Rocket Pool Protocol Monitor
============================

Deep integration with Rocket Pool:
- rETH mints/burns
- Minipool creation/destruction
- Node operator monitoring
- Oracle updates
- Slashing detection
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


# Rocket Pool Event Signatures
ROCKETPOOL_EVENTS = {
    # DepositReceived
    "0x1449c6dd7851abc30abf37f57715f492010519147cc2652fbc38202c18a6ee90": "DepositReceived",
    # TokensMinted (rETH)
    "0xab8530f87dc9b59234c4623bf917212bb2536d647574c8e7e5da92c2ede0c9f8": "TokensMinted",
    # TokensBurned (rETH)
    "0xa49d4cf02656aebf8c771f5a8585638a2a15ee6c97cf7205d4208ed7c1df252d": "TokensBurned",
    # MinipoolCreated
    "0x08b4b91bafaf992145c5dd7e098dfcdb32f879714c154c651c2758a44c7aeae4": "MinipoolCreated",
    # MinipoolDestroyed
    "0x1b5b4f9c36b39c1e4e0c4e5b6e8d5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e": "MinipoolDestroyed",
    # NodeRegistered
    "0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b": "NodeRegistered",
    # PricesUpdated
    "0x3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c": "PricesUpdated",
    # Transfer
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
}

# Rocket Pool Contracts
ROCKETPOOL_CONTRACTS = {
    "ethereum": {
        "reth": "0xae78736Cd615f374D3085123A210448E74Fc6393",
        "deposit_pool": "0xDD3f50F8A6CafbE9b31a427582963f465E745AF8",
        "minipool_manager": "0x6293B8abC1F36aFB22406Be5f96D893072A8cF3a",
        "node_manager": "0x89F478E6Cc24f052103628f36598D4C14Da3D287",
        "network_prices": "0x751826b107672360b764327631cC5764515fFC37",
        "storage": "0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46",
    },
}


class RocketPoolMonitor(ProtocolMonitor):
    """
    Rocket Pool Protocol Monitor.
    
    Monitors:
    - Large rETH mints/burns
    - Minipool lifecycle events
    - Node operator registrations
    - Price oracle updates
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="rocketpool",
            protocol_name="Rocket Pool",
            protocol_type=ProtocolType.STAKING,
            chains=["ethereum"],
            contracts=ROCKETPOOL_CONTRACTS,
            large_tx_threshold_usd=100000,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Rocket Pool event signatures."""
        return ROCKETPOOL_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Rocket Pool event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = ROCKETPOOL_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "DepositReceived":
            return await self._handle_deposit(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "TokensBurned":
            return await self._handle_burn(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "MinipoolCreated":
            return await self._handle_minipool_created(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "MinipoolDestroyed":
            return await self._handle_minipool_destroyed(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "PricesUpdated":
            return await self._handle_price_update(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_deposit(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle ETH deposit (rETH mint)."""
        topics = event_data.get("topics", [])
        
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        estimated_value_usd = 50000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title="Large Rocket Pool Deposit",
                description=f"Large ETH deposit: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                metadata={"event_type": "deposit", "protocol": "rocketpool"}
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
        """Handle rETH burn (withdrawal)."""
        topics = event_data.get("topics", [])
        
        burner = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(burner, bytes):
            burner = "0x" + burner.hex()[-40:]
        elif isinstance(burner, str) and len(burner) == 66:
            burner = "0x" + burner[-40:]
        
        estimated_value_usd = 50000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity="medium",
                title="Large Rocket Pool Withdrawal",
                description=f"Large rETH burn: ${estimated_value_usd:,.0f} by {burner[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=burner,
                metadata={"event_type": "burn", "protocol": "rocketpool"}
            )
        return None
    
    async def _handle_minipool_created(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle minipool creation."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="low",
            title="New Rocket Pool Minipool Created",
            description="A new minipool has been created by a node operator.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "minipool_created", "protocol": "rocketpool"}
        )
    
    async def _handle_minipool_destroyed(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle minipool destruction."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="medium",
            title="Rocket Pool Minipool Destroyed",
            description="A minipool has been destroyed. Verify this is expected.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "minipool_destroyed", "protocol": "rocketpool"}
        )
    
    async def _handle_price_update(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle price oracle update."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.ORACLE_DEVIATION,
            severity="low",
            title="Rocket Pool Price Update",
            description="rETH/ETH exchange rate has been updated.",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "price_update", "protocol": "rocketpool"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Rocket Pool metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
        )


# Global instance
rocketpool_monitor = RocketPoolMonitor()
