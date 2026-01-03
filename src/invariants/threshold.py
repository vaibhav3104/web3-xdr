"""
Threshold Invariants - Signature, access control, and governance thresholds.
"""

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Set
import structlog

from .base import Invariant, InvariantContext, InvariantRegistry
from ..models.events import EventType, Severity
from ..models.invariants import InvariantResult, InvariantType

logger = structlog.get_logger()


@InvariantRegistry.register("SIGNATURE_THRESHOLD")
class SignatureThresholdInvariant(Invariant):
    """
    Bridge messages must meet signature threshold.
    
    INVARIANT: valid_signatures >= required_threshold
    
    Detects:
    - Validator key compromise
    - Threshold reduction attacks
    - Signature forgery
    """
    
    description = "Bridge messages must meet multi-sig threshold"
    invariant_type = InvariantType.THRESHOLD
    severity = Severity.CRITICAL
    
    def __init__(
        self,
        bridge_id: str,
        required_signatures: int,
        total_validators: int
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.required_signatures = required_signatures
        self.total_validators = total_validators
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check signature thresholds on bridge operations.
        """
        # Get recent bridge executions
        events = await context.get_events(
            event_type=EventType.MINT,
            bridge_id=self.bridge_id,
            window=timedelta(minutes=10)
        )
        
        violations = []
        
        for event in events:
            if event.signature_count is not None and event.threshold is not None:
                if event.signature_count < event.threshold:
                    violations.append({
                        "event": event.to_dict(),
                        "signatures_provided": event.signature_count,
                        "threshold_required": event.threshold,
                        "shortfall": event.threshold - event.signature_count
                    })
            elif event.signature_count is not None:
                if event.signature_count < self.required_signatures:
                    violations.append({
                        "event": event.to_dict(),
                        "signatures_provided": event.signature_count,
                        "threshold_required": self.required_signatures,
                        "shortfall": self.required_signatures - event.signature_count
                    })
        
        if violations:
            self.record_violation()
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                confidence=0.95,
                bridge_id=self.bridge_id,
                evidence={
                    "violations": violations,
                    "count": len(violations),
                    "required_signatures": self.required_signatures,
                    "total_validators": self.total_validators
                },
                description=f"Detected {len(violations)} operations below signature threshold"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("ADMIN_ACTION_FREQUENCY")
class AdminActionInvariant(Invariant):
    """
    Admin actions should not occur too frequently.
    
    INVARIANT: admin_action_count in window < threshold
    
    Detects:
    - Compromised admin keys
    - Insider abuse
    - Unauthorized access
    """
    
    description = "Admin actions must not exceed frequency threshold"
    invariant_type = InvariantType.THRESHOLD
    severity = Severity.HIGH
    
    def __init__(
        self,
        contract_addresses: List[str],
        max_actions_per_hour: int = 5,
        critical_actions: Optional[List[str]] = None
    ):
        super().__init__()
        self.contract_addresses = [a.lower() for a in contract_addresses]
        self.max_actions_per_hour = max_actions_per_hour
        self.critical_actions = critical_actions or [
            "setGuardian",
            "setValidator",
            "updateThreshold",
            "pause",
            "unpause",
            "upgradeTo",
            "transferOwnership"
        ]
        
        # Track admin actions
        self._action_history: List[Dict] = []
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check admin action frequency.
        """
        # Get recent admin actions
        events = await context.get_events(
            event_type=EventType.ADMIN_ACTION,
            window=timedelta(hours=1)
        )
        
        # Filter for monitored contracts
        relevant_events = [
            e for e in events
            if e.contract_address.lower() in self.contract_addresses
        ]
        
        now = datetime.utcnow()
        
        # Track actions
        for event in relevant_events:
            self._action_history.append({
                "timestamp": event.block_timestamp,
                "event": event.to_dict()
            })
        
        # Prune old history
        cutoff = now - timedelta(hours=24)
        self._action_history = [a for a in self._action_history if a["timestamp"] > cutoff]
        
        # Count recent actions
        hour_ago = now - timedelta(hours=1)
        recent_actions = [a for a in self._action_history if a["timestamp"] > hour_ago]
        
        if len(recent_actions) > self.max_actions_per_hour:
            self.record_violation()
            
            # Check for critical actions
            critical_found = []
            for action in recent_actions:
                event_data = action.get("event", {})
                raw = event_data.get("raw_event", {})
                if any(crit.lower() in str(raw).lower() for crit in self.critical_actions):
                    critical_found.append(action)
            
            severity = Severity.CRITICAL if critical_found else Severity.HIGH
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=severity,
                evidence={
                    "action_count": len(recent_actions),
                    "threshold": self.max_actions_per_hour,
                    "critical_actions_found": len(critical_found),
                    "recent_actions": recent_actions[-10:]  # Last 10
                },
                description=f"Detected {len(recent_actions)} admin actions in last hour (threshold: {self.max_actions_per_hour})"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type
        )


@InvariantRegistry.register("VALIDATOR_SET_CHANGE")
class ValidatorSetChangeInvariant(Invariant):
    """
    Validator set changes should be monitored.
    
    INVARIANT: Validator changes should not reduce security threshold.
    
    Detects:
    - Validator set manipulation
    - Threshold reduction attacks
    - Guardian removal
    """
    
    description = "Validator set changes must not reduce security"
    invariant_type = InvariantType.THRESHOLD
    severity = Severity.CRITICAL
    
    def __init__(
        self,
        bridge_id: str,
        min_validators: int = 3,
        min_threshold_ratio: float = 0.66  # 2/3 threshold
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.min_validators = min_validators
        self.min_threshold_ratio = min_threshold_ratio
        
        # Track validator state
        self._current_validators: Set[str] = set()
        self._current_threshold: int = 0
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check for dangerous validator set changes.
        """
        # Get validator set update events
        events = await context.get_events(
            event_type=EventType.VALIDATOR_SET_UPDATE,
            bridge_id=self.bridge_id,
            window=timedelta(hours=24)
        )
        
        violations = []
        
        for event in events:
            # Extract validator info from event
            raw = event.raw_event
            new_count = raw.get("validator_count", 0)
            new_threshold = raw.get("threshold", 0)
            removed_validators = raw.get("removed", [])
            
            # Check minimum validators
            if new_count < self.min_validators:
                violations.append({
                    "event": event.to_dict(),
                    "issue": "BELOW_MIN_VALIDATORS",
                    "validator_count": new_count,
                    "minimum": self.min_validators
                })
            
            # Check threshold ratio
            if new_count > 0 and new_threshold > 0:
                ratio = new_threshold / new_count
                if ratio < self.min_threshold_ratio:
                    violations.append({
                        "event": event.to_dict(),
                        "issue": "LOW_THRESHOLD_RATIO",
                        "ratio": ratio,
                        "minimum_ratio": self.min_threshold_ratio
                    })
            
            # Check for mass removal
            if len(removed_validators) > 1:
                violations.append({
                    "event": event.to_dict(),
                    "issue": "MASS_VALIDATOR_REMOVAL",
                    "removed_count": len(removed_validators)
                })
        
        if violations:
            self.record_violation()
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                bridge_id=self.bridge_id,
                evidence={
                    "violations": violations,
                    "count": len(violations)
                },
                description=f"Detected {len(violations)} suspicious validator set changes"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("WITHDRAWAL_LIMIT")
class WithdrawalLimitInvariant(Invariant):
    """
    Withdrawals should not exceed configured limits.
    
    INVARIANT: withdrawal_amount <= limit per address per period
    
    Detects:
    - Limit bypass attacks
    - Unusual withdrawal patterns
    """
    
    description = "Withdrawals must not exceed configured limits"
    invariant_type = InvariantType.THRESHOLD
    severity = Severity.HIGH
    
    def __init__(
        self,
        bridge_id: str,
        per_tx_limit_usd: float = 1_000_000,
        per_address_daily_limit_usd: float = 5_000_000
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.per_tx_limit = per_tx_limit_usd
        self.per_address_daily_limit = per_address_daily_limit_usd
        
        # Track withdrawals per address
        self._address_withdrawals: Dict[str, List[Dict]] = {}
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check withdrawal limits.
        """
        # Get recent unlocks/withdrawals
        events = await context.get_events(
            event_type=EventType.UNLOCK,
            bridge_id=self.bridge_id,
            window=timedelta(hours=24)
        )
        
        now = datetime.utcnow()
        violations = []
        
        for event in events:
            amount_usd = float(event.amount_usd)
            
            # Check per-tx limit
            if amount_usd > self.per_tx_limit:
                violations.append({
                    "event": event.to_dict(),
                    "issue": "EXCEEDS_PER_TX_LIMIT",
                    "amount": amount_usd,
                    "limit": self.per_tx_limit
                })
            
            # Track per-address
            address = event.dest_address
            if address not in self._address_withdrawals:
                self._address_withdrawals[address] = []
            
            self._address_withdrawals[address].append({
                "timestamp": event.block_timestamp,
                "amount": amount_usd
            })
        
        # Check per-address daily limits
        day_ago = now - timedelta(days=1)
        
        for address, withdrawals in self._address_withdrawals.items():
            recent = [w for w in withdrawals if w["timestamp"] > day_ago]
            total = sum(w["amount"] for w in recent)
            
            if total > self.per_address_daily_limit:
                violations.append({
                    "address": address,
                    "issue": "EXCEEDS_DAILY_LIMIT",
                    "total_24h": total,
                    "limit": self.per_address_daily_limit,
                    "withdrawal_count": len(recent)
                })
        
        # Prune old data
        for address in list(self._address_withdrawals.keys()):
            self._address_withdrawals[address] = [
                w for w in self._address_withdrawals[address]
                if w["timestamp"] > day_ago
            ]
            if not self._address_withdrawals[address]:
                del self._address_withdrawals[address]
        
        if violations:
            self.record_violation()
            
            total_violation_amount = sum(
                v.get("amount", v.get("total_24h", 0))
                for v in violations
            )
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                violation_amount_usd=total_violation_amount,
                bridge_id=self.bridge_id,
                evidence={
                    "violations": violations,
                    "count": len(violations)
                },
                description=f"Detected {len(violations)} withdrawal limit violations"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )

