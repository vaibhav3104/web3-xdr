"""
Invariant Engine
================

Checks protocol invariants for security violations:
- TVL velocity (drain detection)
- Stablecoin pegs
- Health factors
- Mint/lock parity (cross-chain)
- Total supply invariants
- Timelock enforcement
- Oracle price validity
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class InvariantType(Enum):
    """Types of invariants."""
    TVL_VELOCITY = "TVL_VELOCITY"
    STABLECOIN_PEG = "STABLECOIN_PEG"
    STETH_PEG = "STETH_PEG"
    HEALTH_FACTOR = "HEALTH_FACTOR"
    MINT_LOCK_PARITY = "MINT_LOCK_PARITY"
    TOTAL_SUPPLY_INVARIANT = "TOTAL_SUPPLY_INVARIANT"
    TIMELOCK_RESPECTED = "TIMELOCK_RESPECTED"
    ORACLE_PRICE_VALIDITY = "ORACLE_PRICE_VALIDITY"
    MESSAGE_UNIQUENESS = "MESSAGE_UNIQUENESS"
    VALIDATOR_THRESHOLD = "VALIDATOR_THRESHOLD"
    UTILIZATION_RATE = "UTILIZATION_RATE"


@dataclass
class InvariantViolation:
    """Invariant violation detection."""
    invariant_type: InvariantType
    protocol: str
    chain: str
    expected_value: Any
    actual_value: Any
    deviation: float
    severity: str
    timestamp: datetime
    details: Dict = field(default_factory=dict)


@dataclass
class InvariantConfig:
    """Configuration for an invariant check."""
    invariant_type: InvariantType
    threshold: float
    severity: str
    description: str
    check_interval_seconds: int = 60


class InvariantEngine:
    """
    Engine for checking protocol invariants.
    
    Monitors:
    - Protocol state consistency
    - Cross-chain parity
    - Economic invariants
    - Governance constraints
    """
    
    # Default configurations
    DEFAULT_CONFIGS = {
        InvariantType.TVL_VELOCITY: InvariantConfig(
            invariant_type=InvariantType.TVL_VELOCITY,
            threshold=10.0,  # 10% per hour
            severity="HIGH",
            description="TVL drain rate exceeds threshold",
        ),
        InvariantType.STABLECOIN_PEG: InvariantConfig(
            invariant_type=InvariantType.STABLECOIN_PEG,
            threshold=2.0,  # 2% deviation from $1
            severity="HIGH",
            description="Stablecoin depegged from $1",
        ),
        InvariantType.STETH_PEG: InvariantConfig(
            invariant_type=InvariantType.STETH_PEG,
            threshold=1.0,  # 1% deviation from ETH
            severity="HIGH",
            description="stETH depegged from ETH",
        ),
        InvariantType.HEALTH_FACTOR: InvariantConfig(
            invariant_type=InvariantType.HEALTH_FACTOR,
            threshold=1.0,  # Below 1.0 is liquidatable
            severity="HIGH",
            description="Position health factor below threshold",
        ),
        InvariantType.MINT_LOCK_PARITY: InvariantConfig(
            invariant_type=InvariantType.MINT_LOCK_PARITY,
            threshold=0.1,  # 0.1% mismatch
            severity="CRITICAL",
            description="Cross-chain mint/lock mismatch",
        ),
        InvariantType.TOTAL_SUPPLY_INVARIANT: InvariantConfig(
            invariant_type=InvariantType.TOTAL_SUPPLY_INVARIANT,
            threshold=0.01,  # 0.01% unexpected change
            severity="CRITICAL",
            description="Unexpected total supply change",
        ),
        InvariantType.TIMELOCK_RESPECTED: InvariantConfig(
            invariant_type=InvariantType.TIMELOCK_RESPECTED,
            threshold=0,  # Any bypass is violation
            severity="CRITICAL",
            description="Timelock delay not respected",
        ),
        InvariantType.ORACLE_PRICE_VALIDITY: InvariantConfig(
            invariant_type=InvariantType.ORACLE_PRICE_VALIDITY,
            threshold=10.0,  # 10% deviation from TWAP
            severity="HIGH",
            description="Oracle price deviates from TWAP",
        ),
        InvariantType.MESSAGE_UNIQUENESS: InvariantConfig(
            invariant_type=InvariantType.MESSAGE_UNIQUENESS,
            threshold=0,  # Any replay is violation
            severity="CRITICAL",
            description="Cross-chain message replay detected",
        ),
        InvariantType.VALIDATOR_THRESHOLD: InvariantConfig(
            invariant_type=InvariantType.VALIDATOR_THRESHOLD,
            threshold=0,  # Any bypass is violation
            severity="CRITICAL",
            description="Validator signature threshold not met",
        ),
        InvariantType.UTILIZATION_RATE: InvariantConfig(
            invariant_type=InvariantType.UTILIZATION_RATE,
            threshold=95.0,  # 95% utilization
            severity="HIGH",
            description="Protocol utilization rate too high",
        ),
    }
    
    def __init__(self):
        """Initialize invariant engine."""
        self._configs = self.DEFAULT_CONFIGS.copy()
        self._state: Dict[str, Any] = {}
        self._violations: List[InvariantViolation] = []
        self._message_hashes: set = set()
        self._pending_timelocks: Dict[str, datetime] = {}
        logger.info("invariant_engine_initialized")
    
    def check_event(self, event: Dict[str, Any]) -> List[InvariantViolation]:
        """
        Check all relevant invariants for an event.
        
        Args:
            event: Enriched event dictionary
            
        Returns:
            List of invariant violations
        """
        violations = []
        
        # TVL velocity check
        if event.get("drain_percent_per_hour", 0) > 0:
            v = self._check_tvl_velocity(event)
            if v:
                violations.append(v)
        
        # Stablecoin peg check
        if event.get("token_symbol") in ("USDC", "USDT", "DAI", "FRAX", "LUSD"):
            v = self._check_stablecoin_peg(event)
            if v:
                violations.append(v)
        
        # stETH peg check
        if event.get("token_symbol") in ("stETH", "wstETH", "rETH", "cbETH"):
            v = self._check_steth_peg(event)
            if v:
                violations.append(v)
        
        # Health factor check
        if "health_factor" in event:
            v = self._check_health_factor(event)
            if v:
                violations.append(v)
        
        # Mint/lock parity check
        if event.get("event_type") in ("Mint", "Lock", "TransferRedeemed"):
            v = self._check_mint_lock_parity(event)
            if v:
                violations.append(v)
        
        # Message uniqueness check
        if event.get("message_hash"):
            v = self._check_message_uniqueness(event)
            if v:
                violations.append(v)
        
        # Timelock check
        if event.get("event_type") in ("ProposalExecuted", "ExecuteTransaction"):
            v = self._check_timelock(event)
            if v:
                violations.append(v)
        
        # Oracle price validity
        if event.get("event_type") == "PriceUpdated":
            v = self._check_oracle_price(event)
            if v:
                violations.append(v)
        
        # Utilization rate check
        if "utilization" in event:
            v = self._check_utilization(event)
            if v:
                violations.append(v)
        
        self._violations.extend(violations)
        return violations
    
    def _check_tvl_velocity(self, event: Dict[str, Any]) -> Optional[InvariantViolation]:
        """Check TVL drain rate."""
        config = self._configs[InvariantType.TVL_VELOCITY]
        drain_rate = event.get("drain_percent_per_hour", 0)
        
        if drain_rate >= config.threshold:
            return InvariantViolation(
                invariant_type=InvariantType.TVL_VELOCITY,
                protocol=event.get("protocol", "unknown"),
                chain=event.get("chain_id", "unknown"),
                expected_value=f"<{config.threshold}% per hour",
                actual_value=f"{drain_rate:.2f}% per hour",
                deviation=drain_rate,
                severity=config.severity,
                timestamp=datetime.now(timezone.utc),
                details={
                    "drain_amount_usd": event.get("drain_amount_usd", 0),
                    "current_tvl_usd": event.get("current_tvl_usd", 0),
                }
            )
        return None
    
    def _check_stablecoin_peg(self, event: Dict[str, Any]) -> Optional[InvariantViolation]:
        """Check stablecoin peg to $1."""
        config = self._configs[InvariantType.STABLECOIN_PEG]
        price = event.get("token_price_usd", 1.0)
        
        deviation = abs(price - 1.0) * 100
        
        if deviation >= config.threshold:
            return InvariantViolation(
                invariant_type=InvariantType.STABLECOIN_PEG,
                protocol=event.get("token_symbol", "unknown"),
                chain=event.get("chain_id", "unknown"),
                expected_value="$1.00",
                actual_value=f"${price:.4f}",
                deviation=deviation,
                severity=config.severity,
                timestamp=datetime.now(timezone.utc),
                details={
                    "token_symbol": event.get("token_symbol"),
                    "price_deviation_percent": deviation,
                }
            )
        return None
    
    def _check_steth_peg(self, event: Dict[str, Any]) -> Optional[InvariantViolation]:
        """Check stETH peg to ETH."""
        config = self._configs[InvariantType.STETH_PEG]
        
        # Get stETH/ETH ratio
        steth_price = event.get("token_price_usd", 0)
        eth_price = 3200  # Should fetch from price feed
        
        if steth_price <= 0 or eth_price <= 0:
            return None
        
        ratio = steth_price / eth_price
        deviation = abs(ratio - 1.0) * 100
        
        if deviation >= config.threshold:
            return InvariantViolation(
                invariant_type=InvariantType.STETH_PEG,
                protocol="lido",
                chain=event.get("chain_id", "ethereum"),
                expected_value="1.0 (parity with ETH)",
                actual_value=f"{ratio:.4f}",
                deviation=deviation,
                severity=config.severity,
                timestamp=datetime.now(timezone.utc),
                details={
                    "steth_eth_ratio": ratio,
                    "steth_price_usd": steth_price,
                    "eth_price_usd": eth_price,
                }
            )
        return None
    
    def _check_health_factor(self, event: Dict[str, Any]) -> Optional[InvariantViolation]:
        """Check lending position health factor."""
        config = self._configs[InvariantType.HEALTH_FACTOR]
        health_factor = event.get("health_factor", 999)
        
        if health_factor < config.threshold:
            return InvariantViolation(
                invariant_type=InvariantType.HEALTH_FACTOR,
                protocol=event.get("protocol", "unknown"),
                chain=event.get("chain_id", "unknown"),
                expected_value=f">={config.threshold}",
                actual_value=f"{health_factor:.4f}",
                deviation=config.threshold - health_factor,
                severity=config.severity,
                timestamp=datetime.now(timezone.utc),
                details={
                    "user": event.get("from_address"),
                    "collateral_usd": event.get("collateral_usd", 0),
                    "debt_usd": event.get("debt_usd", 0),
                }
            )
        return None
    
    def _check_mint_lock_parity(self, event: Dict[str, Any]) -> Optional[InvariantViolation]:
        """Check cross-chain mint/lock parity."""
        config = self._configs[InvariantType.MINT_LOCK_PARITY]
        
        # Track locked vs minted amounts
        key = f"{event.get('token_address', '')}:{event.get('dest_chain', '')}"
        
        if event.get("event_type") == "Lock":
            locked = event.get("amount", 0)
            self._state[f"locked:{key}"] = self._state.get(f"locked:{key}", 0) + float(locked)
        elif event.get("event_type") == "Mint":
            minted = event.get("amount", 0)
            self._state[f"minted:{key}"] = self._state.get(f"minted:{key}", 0) + float(minted)
        
        # Check parity
        locked = self._state.get(f"locked:{key}", 0)
        minted = self._state.get(f"minted:{key}", 0)
        
        if locked > 0:
            deviation = abs(minted - locked) / locked * 100
            if deviation > config.threshold:
                return InvariantViolation(
                    invariant_type=InvariantType.MINT_LOCK_PARITY,
                    protocol=event.get("bridge_id", "unknown"),
                    chain=event.get("chain_id", "unknown"),
                    expected_value="minted ≈ locked",
                    actual_value=f"locked={locked}, minted={minted}",
                    deviation=deviation,
                    severity=config.severity,
                    timestamp=datetime.now(timezone.utc),
                    details={
                        "locked_amount": locked,
                        "minted_amount": minted,
                        "token_address": event.get("token_address"),
                    }
                )
        
        return None
    
    def _check_message_uniqueness(self, event: Dict[str, Any]) -> Optional[InvariantViolation]:
        """Check for cross-chain message replay."""
        config = self._configs[InvariantType.MESSAGE_UNIQUENESS]
        message_hash = event.get("message_hash")
        
        if not message_hash:
            return None
        
        if message_hash in self._message_hashes:
            return InvariantViolation(
                invariant_type=InvariantType.MESSAGE_UNIQUENESS,
                protocol=event.get("bridge_id", "unknown"),
                chain=event.get("chain_id", "unknown"),
                expected_value="unique message",
                actual_value="duplicate message",
                deviation=100,
                severity=config.severity,
                timestamp=datetime.now(timezone.utc),
                details={
                    "message_hash": message_hash,
                    "message_hash_seen_before": True,
                }
            )
        
        self._message_hashes.add(message_hash)
        return None
    
    def _check_timelock(self, event: Dict[str, Any]) -> Optional[InvariantViolation]:
        """Check timelock delay enforcement."""
        config = self._configs[InvariantType.TIMELOCK_RESPECTED]
        
        tx_hash = event.get("tx_hash", "")
        queued_at = self._pending_timelocks.get(tx_hash)
        
        if not queued_at:
            # Not queued, might be bypass
            return InvariantViolation(
                invariant_type=InvariantType.TIMELOCK_RESPECTED,
                protocol=event.get("protocol", "unknown"),
                chain=event.get("chain_id", "unknown"),
                expected_value="transaction queued with delay",
                actual_value="executed without queue",
                deviation=100,
                severity=config.severity,
                timestamp=datetime.now(timezone.utc),
                details={
                    "execution_delay": 0,
                    "required_delay": event.get("required_delay", 86400),
                }
            )
        
        # Check if delay was respected
        required_delay = event.get("required_delay", 86400)  # Default 24h
        actual_delay = (datetime.now(timezone.utc) - queued_at).total_seconds()
        
        if actual_delay < required_delay:
            return InvariantViolation(
                invariant_type=InvariantType.TIMELOCK_RESPECTED,
                protocol=event.get("protocol", "unknown"),
                chain=event.get("chain_id", "unknown"),
                expected_value=f">={required_delay}s delay",
                actual_value=f"{actual_delay}s delay",
                deviation=(required_delay - actual_delay) / required_delay * 100,
                severity=config.severity,
                timestamp=datetime.now(timezone.utc),
                details={
                    "execution_delay": actual_delay,
                    "required_delay": required_delay,
                }
            )
        
        return None
    
    def _check_oracle_price(self, event: Dict[str, Any]) -> Optional[InvariantViolation]:
        """Check oracle price validity against TWAP."""
        config = self._configs[InvariantType.ORACLE_PRICE_VALIDITY]
        
        spot_price = event.get("price", 0)
        twap_price = event.get("twap_price", spot_price)
        
        if twap_price <= 0:
            return None
        
        deviation = abs(spot_price - twap_price) / twap_price * 100
        
        if deviation >= config.threshold:
            return InvariantViolation(
                invariant_type=InvariantType.ORACLE_PRICE_VALIDITY,
                protocol=event.get("oracle", "unknown"),
                chain=event.get("chain_id", "unknown"),
                expected_value=f"within {config.threshold}% of TWAP",
                actual_value=f"{deviation:.2f}% deviation",
                deviation=deviation,
                severity=config.severity,
                timestamp=datetime.now(timezone.utc),
                details={
                    "spot_price": spot_price,
                    "twap_price": twap_price,
                    "twap_deviation_percent": deviation,
                    "sustained_blocks": event.get("sustained_blocks", 1),
                }
            )
        
        return None
    
    def _check_utilization(self, event: Dict[str, Any]) -> Optional[InvariantViolation]:
        """Check protocol utilization rate."""
        config = self._configs[InvariantType.UTILIZATION_RATE]
        utilization = event.get("utilization", 0)
        
        if utilization >= config.threshold:
            return InvariantViolation(
                invariant_type=InvariantType.UTILIZATION_RATE,
                protocol=event.get("protocol", "unknown"),
                chain=event.get("chain_id", "unknown"),
                expected_value=f"<{config.threshold}%",
                actual_value=f"{utilization:.2f}%",
                deviation=utilization - config.threshold,
                severity=config.severity,
                timestamp=datetime.now(timezone.utc),
                details={
                    "utilization": utilization,
                    "total_borrows": event.get("total_borrows", 0),
                    "total_supply": event.get("total_supply", 0),
                }
            )
        
        return None
    
    def queue_timelock(self, tx_hash: str, queued_at: Optional[datetime] = None):
        """Record a timelock queue event."""
        self._pending_timelocks[tx_hash] = queued_at or datetime.now(timezone.utc)
    
    def get_violations(self, limit: int = 100) -> List[InvariantViolation]:
        """Get recent violations."""
        return self._violations[-limit:]
    
    def clear_violations(self):
        """Clear violation history."""
        self._violations = []


# Global singleton
_invariant_engine: Optional[InvariantEngine] = None


def get_invariant_engine() -> InvariantEngine:
    """Get global invariant engine instance."""
    global _invariant_engine
    if _invariant_engine is None:
        _invariant_engine = InvariantEngine()
    return _invariant_engine
