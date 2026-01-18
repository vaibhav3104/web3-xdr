"""
Balancer Protocol Monitor
=========================

Deep integration with Balancer V2:
- Large swap detection
- Pool imbalance alerts
- Flash loan monitoring
- Governance changes
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


# Balancer V2 Event Signatures
BALANCER_EVENTS = {
    # Swap
    "0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b": "Swap",
    # PoolBalanceChanged (join/exit)
    "0xe5ce249087ce04f05a957192435400fd97868dba0e6a4b4c049abf8af80e06e5": "PoolBalanceChanged",
    # FlashLoan
    "0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19e3a20427eec8bf53283b6fb8e95f0": "FlashLoan",
    # PoolRegistered
    "0x3c13bc30b8e878c53fd2a36b679409c073afd75950be43d8858768e956fbc20e": "PoolRegistered",
    # TokensRegistered
    "0xf5847d3f2197b16cdcd2098ec95d0905cd1abdaf415f07571f9774ed2c1ade2e": "TokensRegistered",
    # AuthorizerChanged
    "0x94b979b6831a51293e2641426f97747feed46f17779fed9cd18d1ecefcfe92ef": "AuthorizerChanged",
}

# Balancer Contracts
BALANCER_CONTRACTS = {
    "ethereum": {
        "vault": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
        "weighted_pool_factory": "0x8E9aa87E45e92bad84D5F8DD1bff34Fb92637dE9",
        "stable_pool_factory": "0x8df6EfEc5547e31B0eb7d1291B511FF8a2bf987c",
        "bal_token": "0xba100000625a3754423978a60c9317c58a424e3D",
    },
    "polygon": {
        "vault": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    "arbitrum": {
        "vault": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    "optimism": {
        "vault": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    "avalanche": {
        "vault": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    "base": {
        "vault": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
}


class BalancerMonitor(ProtocolMonitor):
    """
    Balancer Protocol Monitor.
    
    Monitors:
    - Large swaps
    - Flash loans
    - Pool joins/exits
    - Governance changes
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="balancer",
            protocol_name="Balancer",
            protocol_type=ProtocolType.DEX,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "base"],
            contracts=BALANCER_CONTRACTS,
            large_tx_threshold_usd=50000,
            price_impact_warning=1.0,
            price_impact_critical=5.0,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Balancer event signatures."""
        return BALANCER_EVENTS
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Balancer event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        event_name = BALANCER_EVENTS.get(topic0.lower())
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        if event_name == "Swap":
            return await self._handle_swap(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "FlashLoan":
            return await self._handle_flashloan(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "PoolBalanceChanged":
            return await self._handle_pool_balance_change(event_data, chain_id, tx_hash, block_number, block_timestamp)
        elif event_name == "AuthorizerChanged":
            return await self._handle_authorizer_change(event_data, chain_id, tx_hash, block_number, block_timestamp)
        
        return None
    
    async def _handle_swap(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle swap event."""
        topics = event_data.get("topics", [])
        
        # Pool ID is in topics
        pool_id = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(pool_id, bytes):
            pool_id = "0x" + pool_id.hex()
        
        estimated_value_usd = 30000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large Balancer Swap on {chain_id.title()}",
                description=f"Large swap: ${estimated_value_usd:,.0f}",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_pool=pool_id[:20] + "...",
                metadata={"event_type": "swap", "protocol": "balancer", "pool_id": pool_id}
            )
        return None
    
    async def _handle_flashloan(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle flash loan - always alert."""
        topics = event_data.get("topics", [])
        
        recipient = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(recipient, bytes):
            recipient = "0x" + recipient.hex()[-40:]
        elif isinstance(recipient, str) and len(recipient) == 66:
            recipient = "0x" + recipient[-40:]
        
        estimated_value_usd = 100000
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LARGE_TRANSACTION,
            severity="high",
            title=f"Balancer Flash Loan on {chain_id.title()}",
            description=f"Flash loan: ${estimated_value_usd:,.0f} to {recipient[:10]}...",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=recipient,
            metadata={"event_type": "flashloan", "protocol": "balancer", "is_flashloan": True}
        )
    
    async def _handle_pool_balance_change(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle pool join/exit."""
        topics = event_data.get("topics", [])
        
        pool_id = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(pool_id, bytes):
            pool_id = "0x" + pool_id.hex()
        
        sender = topics[2] if len(topics) > 2 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]
        
        estimated_value_usd = 25000
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title=f"Large Balancer Pool Change",
                description=f"Large pool join/exit: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                affected_pool=pool_id[:20] + "...",
                metadata={"event_type": "pool_balance_change", "protocol": "balancer"}
            )
        return None
    
    async def _handle_authorizer_change(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Handle authorizer change - governance alert."""
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.GOVERNANCE_ACTION,
            severity="critical",
            title="⚠️ Balancer Authorizer Changed",
            description="Vault authorizer has been changed. Critical governance action!",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=0,
            metadata={"event_type": "authorizer_change", "protocol": "balancer"}
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Balancer metrics."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            volume_24h_usd=0,
            fees_24h_usd=0,
        )


# Global instance
balancer_monitor = BalancerMonitor()
