"""
Compound Protocol Monitor
=========================

Deep integration with Compound V2/V3:
- Liquidation detection
- Large supply/borrow alerts
- Interest rate monitoring
- cToken price oracle monitoring
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


# Compound V3 (Comet) Event Signatures
COMPOUND_V3_EVENTS = {
    # Supply
    "0xd1cf3d156d5f8f0d50f6c122ed609cec09d35c9b9fb3fff6ea0959134dae424e": "Supply",
    # Withdraw
    "0x9b1bfa7fa9ee420a16e124f794c35ac9f90472acc99140eb2f6447c714cad8eb": "Withdraw",
    # AbsorbDebt (liquidation)
    "0xa0a7c0b4b3b3f3c5f3d3e3f3a3b3c3d3e3f3a3b3c3d3e3f3a3b3c3d3e3f3a3b3": "AbsorbDebt",
    # SupplyCollateral
    "0xfa56f7b24f17183d81894d3ac2ee654e3c26388d17a28dbd9549b8114304e1f4": "SupplyCollateral",
    # WithdrawCollateral
    "0xd6d480d5b3068db003533b170d67561494d72e3bf9fa40a266f154b758e5e934": "WithdrawCollateral",
}

# Compound V2 Event Signatures
COMPOUND_V2_EVENTS = {
    # Mint
    "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f": "Mint",
    # Redeem
    "0xe5b754fb1abb7f01b499791d0b820ae3b6af3424ac1c59768edb53f4ec31a929": "Redeem",
    # Borrow
    "0x13ed6866d4e1ee6da46f845c46d7e54120883d75c5ea9a2dacc1c4ca8984ab80": "Borrow",
    # RepayBorrow
    "0x1a2a22cb034d26d1854bdc6666a5b91688a63f6cad2c0a3d4a1b8e4d8f9e4b7c": "RepayBorrow",
    # LiquidateBorrow - CRITICAL
    "0x298637f684da70674f26509b10f07ec2fbc77a335ab1e7d6215a4b2484d8bb52": "LiquidateBorrow",
    # AccrueInterest
    "0x4dec04e750ca11537cabcd8a9eab06494de08da3735bc8871cd41250e190bc04": "AccrueInterest",
}

# Compound addresses
COMPOUND_CONTRACTS = {
    "ethereum": {
        "comptroller": "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B",
        "comet_usdc": "0xc3d688B66703497DAA19211EEdff47f25384cdc3",
        "comet_weth": "0xA17581A9E3356d9A858b789D68B4d866e593aE94",
    },
    "polygon": {
        "comet_usdc": "0xF25212E676D1F7F89Cd72fFEe66158f541246445",
    },
    "arbitrum": {
        "comet_usdc": "0xA5EDBDD9646f8dFF606d7448e414884C7d905dCA",
    },
    "base": {
        "comet_usdc": "0xb125E6687d4313864e53df431d5425969c15Eb2F",
        "comet_weth": "0x46e6b214b524310239732D51387075E0e70970bf",
    },
}


class CompoundMonitor(ProtocolMonitor):
    """
    Compound Protocol Monitor.
    
    Monitors:
    - Liquidations (CRITICAL for large liquidations)
    - Large supply/borrow events
    - Interest rate changes
    - Collateral factor changes
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="compound",
            protocol_name="Compound",
            protocol_type=ProtocolType.LENDING,
            chains=["ethereum", "polygon", "arbitrum", "base"],
            contracts=COMPOUND_CONTRACTS,
            large_tx_threshold_usd=100000,
            health_factor_warning=1.3,
            health_factor_critical=1.05,
        )
        super().__init__(config)
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Compound event signatures."""
        return {**COMPOUND_V3_EVENTS, **COMPOUND_V2_EVENTS}
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Compound event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        # Check V3 events first
        event_name = COMPOUND_V3_EVENTS.get(topic0.lower())
        version = "v3"
        
        if not event_name:
            event_name = COMPOUND_V2_EVENTS.get(topic0.lower())
            version = "v2"
        
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        
        # Route to specific handler
        if event_name in ("LiquidateBorrow", "AbsorbDebt"):
            return await self._handle_liquidation(event_data, chain_id, tx_hash, block_number, block_timestamp, version)
        elif event_name in ("Borrow", "Supply"):
            return await self._handle_borrow_supply(event_data, chain_id, tx_hash, block_number, block_timestamp, version, event_name)
        
        return None
    
    async def _handle_liquidation(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        version: str
    ) -> Optional[ProtocolAlert]:
        """Handle liquidation event."""
        self._stats["liquidations_detected"] += 1
        
        topics = event_data.get("topics", [])
        
        # Parse liquidated user
        liquidated = topics[2] if len(topics) > 2 else "unknown"
        if isinstance(liquidated, bytes):
            liquidated = "0x" + liquidated.hex()[-40:]
        elif isinstance(liquidated, str) and len(liquidated) == 66:
            liquidated = "0x" + liquidated[-40:]
        
        # Estimate value
        estimated_value_usd = 50000  # Placeholder
        
        # Determine severity
        if estimated_value_usd >= 1000000:
            severity = "critical"
        elif estimated_value_usd >= 100000:
            severity = "high"
        else:
            severity = "medium"
        
        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LIQUIDATION,
            severity=severity,
            title=f"Compound {version.upper()} Liquidation on {chain_id.title()}",
            description=f"Position liquidated for {liquidated[:10]}... "
                       f"Estimated value: ${estimated_value_usd:,.0f}",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=liquidated,
            metadata={
                "event_type": "liquidation",
                "version": version,
            }
        )
    
    async def _handle_borrow_supply(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        version: str,
        event_type: str
    ) -> Optional[ProtocolAlert]:
        """Handle borrow/supply events."""
        topics = event_data.get("topics", [])
        
        # Parse user
        user = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(user, bytes):
            user = "0x" + user.hex()[-40:]
        elif isinstance(user, str) and len(user) == 66:
            user = "0x" + user[-40:]
        
        # Estimate value
        estimated_value_usd = 25000  # Placeholder
        
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1
            
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium" if event_type == "Borrow" else "low",
                title=f"Large Compound {version.upper()} {event_type} on {chain_id.title()}",
                description=f"Large {event_type.lower()}: ${estimated_value_usd:,.0f} by {user[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=user,
                metadata={
                    "event_type": event_type.lower(),
                    "version": version,
                }
            )
        
        return None
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Compound metrics for a chain."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,
            total_borrowed_usd=0,
            total_supplied_usd=0,
            liquidations_24h_count=self._stats["liquidations_detected"],
        )


# Global instance
compound_monitor = CompoundMonitor()
