"""
Guardian Safety Policy Engine
=============================

Phase 5: Evaluates whether an incident warrants automated pause action.
Implements "Defense in Depth" to prevent accidental or malicious pauses.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import structlog

from ..correlation.incident_builder import Incident, IncidentStatus
from ..models.invariants import InvariantResult
from ..models.predicted_incidents import PredictedIncident, PredictedIncidentStatus
import os

logger = structlog.get_logger(__name__)


class PauseDecision(Enum):
    """Decision on whether to pause."""
    APPROVED = "approved"  # Safe to pause
    REJECTED = "rejected"  # Do not pause
    REQUIRES_APPROVAL = "requires_approval"  # Requires human approval


@dataclass
class PausePolicyConfig:
    """Configuration for pause policy."""
    # Rule: REQUIRE_CONFIRMED
    require_confirmed: bool = True
    
    # Rule: MIN_CONFIDENCE
    min_confidence: float = 0.85
    
    # Rule: MULTI_SIGNAL
    require_multi_signal: bool = False  # Optional: require >1 distinct violations
    
    # Rule: COOLDOWN
    cooldown_seconds: int = 3600  # 1 hour
    
    # Safety checks
    simulate_before_send: bool = True
    max_gas_limit: int = 500000  # Maximum gas for pause tx
    
    # Value thresholds
    auto_pause_threshold_usd: Decimal = Decimal("1000000")  # $1M+
    require_approval_threshold_usd: Decimal = Decimal("10000000")  # $10M+ requires approval
    
    # Runtime Security Plane: Predicted incident settings
    runtime_enabled: bool = os.getenv("RUNTIME_ENABLED", "false").lower() == "true"
    runtime_auto_action_enabled: bool = os.getenv("RUNTIME_AUTO_ACTION_ENABLED", "false").lower() == "true"
    runtime_auto_action_min_confidence: float = float(os.getenv("RUNTIME_AUTO_ACTION_MIN_CONFIDENCE", "0.95"))
    runtime_action_cooldown_seconds: int = int(os.getenv("RUNTIME_ACTION_COOLDOWN_SECONDS", "3600"))
    runtime_allowlist_protocols: Set[str] = field(default_factory=set)
    runtime_allowlist_contracts: Set[str] = field(default_factory=set)


@dataclass
class PausePolicyResult:
    """Result of policy evaluation."""
    decision: PauseDecision
    reason: str
    checks_passed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)
    requires_approval_reason: Optional[str] = None


class PausePolicy:
    """
    Evaluates whether an incident warrants automated pause.
    
    Implements multiple safety checks:
    1. Incident must be CONFIRMED (finality)
    2. Confidence must exceed threshold
    3. Optional: Multiple distinct violations
    4. Cooldown: Prevent spamming
    5. Value threshold: High-value incidents require approval
    """
    
    def __init__(self, config: Optional[PausePolicyConfig] = None):
        self.config = config or PausePolicyConfig()
        self._last_pause_attempts: Dict[str, datetime] = {}  # protocol_id -> last attempt time
        logger.info(
            "pause_policy_initialized",
            min_confidence=self.config.min_confidence,
            cooldown_seconds=self.config.cooldown_seconds
        )
    
    def evaluate(
        self,
        incident: Incident,
        violations: List[InvariantResult],
        protocol_id: str
    ) -> PausePolicyResult:
        """
        Evaluate whether incident warrants pause.
        
        Args:
            incident: The incident to evaluate
            violations: List of violations that created this incident
            protocol_id: Protocol identifier
        
        Returns:
            PausePolicyResult with decision and reasoning
        """
        checks_passed = []
        checks_failed = []
        
        # Check 1: REQUIRE_CONFIRMED
        if self.config.require_confirmed:
            if incident.status != IncidentStatus.OPEN_CONFIRMED:
                checks_failed.append(
                    f"Incident status is {incident.status.value}, requires OPEN_CONFIRMED"
                )
                return PausePolicyResult(
                    decision=PauseDecision.REJECTED,
                    reason="Incident not yet confirmed (finality check)",
                    checks_failed=checks_failed
                )
            checks_passed.append("Incident is CONFIRMED")
        
        # Check 2: MIN_CONFIDENCE
        if incident.confidence < self.config.min_confidence:
            checks_failed.append(
                f"Confidence {incident.confidence:.2f} < threshold {self.config.min_confidence}"
            )
            return PausePolicyResult(
                decision=PauseDecision.REJECTED,
                reason=f"Confidence too low: {incident.confidence:.2f} < {self.config.min_confidence}",
                checks_failed=checks_failed
            )
        checks_passed.append(f"Confidence {incident.confidence:.2f} >= {self.config.min_confidence}")
        
        # Check 3: MULTI_SIGNAL (optional)
        if self.config.require_multi_signal:
            unique_violations = set(v.violation_type for v in violations if hasattr(v, 'violation_type'))
            if len(unique_violations) < 2:
                checks_failed.append(
                    f"Only {len(unique_violations)} distinct violation type(s), requires >= 2"
                )
                return PausePolicyResult(
                    decision=PauseDecision.REJECTED,
                    reason="Multi-signal requirement not met",
                    checks_failed=checks_failed
                )
            checks_passed.append(f"Multi-signal: {len(unique_violations)} distinct violations")
        
        # Check 4: COOLDOWN
        last_attempt = self._last_pause_attempts.get(protocol_id)
        if last_attempt:
            elapsed = (datetime.now(timezone.utc) - last_attempt).total_seconds()
            if elapsed < self.config.cooldown_seconds:
                checks_failed.append(
                    f"Cooldown: {elapsed:.0f}s elapsed, requires {self.config.cooldown_seconds}s"
                )
                return PausePolicyResult(
                    decision=PauseDecision.REJECTED,
                    reason=f"Cooldown period not elapsed: {elapsed:.0f}s < {self.config.cooldown_seconds}s",
                    checks_failed=checks_failed
                )
        checks_passed.append("Cooldown period elapsed")
        
        # Check 5: Value threshold
        value_at_risk = incident.total_value_at_risk_usd or Decimal("0")
        
        if value_at_risk >= self.config.require_approval_threshold_usd:
            checks_passed.append(f"Value at risk ${value_at_risk:,.0f} requires human approval")
            return PausePolicyResult(
                decision=PauseDecision.REQUIRES_APPROVAL,
                reason=f"High value at risk: ${value_at_risk:,.0f} >= ${self.config.require_approval_threshold_usd:,.0f}",
                checks_passed=checks_passed,
                requires_approval_reason="Value exceeds approval threshold"
            )
        
        if value_at_risk < self.config.auto_pause_threshold_usd:
            checks_failed.append(
                f"Value at risk ${value_at_risk:,.0f} < auto-pause threshold ${self.config.auto_pause_threshold_usd:,.0f}"
            )
            return PausePolicyResult(
                decision=PauseDecision.REJECTED,
                reason=f"Value at risk too low: ${value_at_risk:,.0f} < ${self.config.auto_pause_threshold_usd:,.0f}",
                checks_failed=checks_failed
            )
        
        checks_passed.append(f"Value at risk ${value_at_risk:,.0f} >= threshold ${self.config.auto_pause_threshold_usd:,.0f}")
        
        # All checks passed
        logger.info(
            "pause_policy_approved",
            incident_id=incident.incident_id,
            protocol_id=protocol_id,
            confidence=incident.confidence,
            value_at_risk=str(value_at_risk)
        )
        
        # Record pause attempt
        self._last_pause_attempts[protocol_id] = datetime.now(timezone.utc)
        
        return PausePolicyResult(
            decision=PauseDecision.APPROVED,
            reason="All safety checks passed",
            checks_passed=checks_passed
        )
    
    def should_simulate(self) -> bool:
        """Check if transaction should be simulated before sending."""
        return self.config.simulate_before_send
    
    def get_max_gas_limit(self) -> int:
        """Get maximum gas limit for pause transaction."""
        return self.config.max_gas_limit
    
    def reset_cooldown(self, protocol_id: str):
        """Manually reset cooldown for a protocol (admin override)."""
        if protocol_id in self._last_pause_attempts:
            del self._last_pause_attempts[protocol_id]
            logger.info("pause_cooldown_reset", protocol_id=protocol_id)
    
    def evaluate_predicted(
        self,
        predicted_incident: PredictedIncident,
        violations: List[InvariantResult],
        protocol_id: Optional[str] = None,
        state_diff_severe: bool = False,
        oracle_deviation_active: bool = False,
        anomaly_high: bool = False
    ) -> PausePolicyResult:
        """
        Evaluate whether a PREDICTED incident warrants automated pause.
        
        This has STRICTER requirements than confirmed incidents:
        - Runtime auto-action must be explicitly enabled
        - Higher confidence threshold (default 0.95)
        - Must be allowlisted (protocol or contract)
        - Requires multiple independent signals
        - Cooldown applies
        
        Default behavior: NO auto-pause (safe by default)
        """
        checks_passed = []
        checks_failed = []
        
        # Check 0: Runtime enabled
        if not self.config.runtime_enabled:
            checks_failed.append("Runtime Security Plane is disabled")
            return PausePolicyResult(
                decision=PauseDecision.REJECTED,
                reason="Runtime Security Plane is disabled (RUNTIME_ENABLED=false)",
                checks_failed=checks_failed
            )
        
        # Check 1: Auto-action enabled
        if not self.config.runtime_auto_action_enabled:
            checks_failed.append("Runtime auto-action is disabled (default safe)")
            return PausePolicyResult(
                decision=PauseDecision.REJECTED,
                reason="Runtime auto-action is disabled. Predicted incidents do not trigger auto-pause by default.",
                checks_failed=checks_failed
            )
        checks_passed.append("Runtime auto-action is enabled")
        
        # Check 2: Allowlist (protocol or contract)
        is_allowlisted = False
        if protocol_id and protocol_id in self.config.runtime_allowlist_protocols:
            is_allowlisted = True
            checks_passed.append(f"Protocol {protocol_id} is allowlisted")
        
        # Check contract allowlist (would need contract address from predicted incident)
        # For now, assume not allowlisted unless protocol is
        
        if not is_allowlisted:
            checks_failed.append("Protocol/contract is not allowlisted")
            return PausePolicyResult(
                decision=PauseDecision.REJECTED,
                reason="Protocol/contract is not in allowlist. Auto-action requires explicit allowlisting.",
                checks_failed=checks_failed
            )
        
        # Check 3: Confidence threshold (higher for predicted)
        if predicted_incident.confidence < self.config.runtime_auto_action_min_confidence:
            checks_failed.append(
                f"Confidence {predicted_incident.confidence:.2f} < threshold {self.config.runtime_auto_action_min_confidence}"
            )
            return PausePolicyResult(
                decision=PauseDecision.REJECTED,
                reason=f"Confidence too low for predicted incident: {predicted_incident.confidence:.2f} < {self.config.runtime_auto_action_min_confidence}",
                checks_failed=checks_failed
            )
        checks_passed.append(f"Confidence {predicted_incident.confidence:.2f} >= {self.config.runtime_auto_action_min_confidence}")
        
        # Check 4: Multiple independent signals (REQUIRED for predicted)
        signal_count = 0
        if violations:
            signal_count += 1
        if state_diff_severe:
            signal_count += 1
        if oracle_deviation_active:
            signal_count += 1
        if anomaly_high:
            signal_count += 1
        
        if signal_count < 2:
            checks_failed.append(f"Only {signal_count} independent signal(s), requires >= 2")
            return PausePolicyResult(
                decision=PauseDecision.REJECTED,
                reason=f"Insufficient independent signals: {signal_count} < 2. Required: invariant violation + (state diff OR oracle deviation OR anomaly)",
                checks_failed=checks_failed
            )
        checks_passed.append(f"Multiple independent signals: {signal_count} >= 2")
        
        # Check 5: Cooldown
        last_attempt = self._last_pause_attempts.get(protocol_id or "unknown")
        if last_attempt:
            elapsed = (datetime.now(timezone.utc) - last_attempt).total_seconds()
            if elapsed < self.config.runtime_action_cooldown_seconds:
                checks_failed.append(
                    f"Cooldown: {elapsed:.0f}s elapsed, requires {self.config.runtime_action_cooldown_seconds}s"
                )
                return PausePolicyResult(
                    decision=PauseDecision.REJECTED,
                    reason=f"Cooldown period not elapsed: {elapsed:.0f}s < {self.config.runtime_action_cooldown_seconds}s",
                    checks_failed=checks_failed
                )
        checks_passed.append("Cooldown period elapsed")
        
        # All checks passed - but still require approval for predicted incidents
        logger.warning(
            "predicted_incident_auto_pause_approved",
            predicted_incident_id=predicted_incident.id,
            protocol_id=protocol_id,
            confidence=predicted_incident.confidence,
            signals=signal_count
        )
        
        # Record pause attempt
        self._last_pause_attempts[protocol_id or "unknown"] = datetime.now(timezone.utc)
        
        # Even if all checks pass, predicted incidents require approval by default
        return PausePolicyResult(
            decision=PauseDecision.REQUIRES_APPROVAL,
            reason="Predicted incident passed all checks but requires manual approval for safety",
            checks_passed=checks_passed,
            requires_approval_reason="Predicted incidents require explicit approval even when all checks pass"
        )

