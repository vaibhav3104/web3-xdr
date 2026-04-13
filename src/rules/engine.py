"""
YAML-based Alert Rule Engine

Loads alert rules from YAML files and evaluates them against events.
Similar to Sigma rules for traditional SIEM systems.
"""

import os
import yaml
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
import re

# Import event normalizer for type matching
try:
    from src.telemetry.event_normalizer import event_type_matches, normalize_event_type
except ImportError:
    # Fallback if normalizer not available
    def event_type_matches(ingested_type: str, rule_types: list) -> bool:
        if not rule_types or "any" in rule_types:
            return True
        return ingested_type in rule_types or ingested_type.lower() in [t.lower() for t in rule_types]
    
    def normalize_event_type(event_type: str) -> str:
        return event_type

# Import invariant and pattern engines
try:
    from src.rules.invariants import InvariantEngine, get_invariant_engine
    from src.rules.patterns import PatternMatcher, get_pattern_matcher
    ADVANCED_ENGINES_AVAILABLE = True
except ImportError:
    ADVANCED_ENGINES_AVAILABLE = False
    InvariantEngine = None
    PatternMatcher = None
    get_invariant_engine = None
    get_pattern_matcher = None

# Import enrichment layer
try:
    from src.enrichment import get_enricher
    ENRICHMENT_AVAILABLE = True
except ImportError:
    ENRICHMENT_AVAILABLE = False
    get_enricher = None

# Import feedback loop for auto-suppression
try:
    from src.rules.feedback_loop import get_feedback_loop
    FEEDBACK_LOOP_AVAILABLE = True
except ImportError:
    FEEDBACK_LOOP_AVAILABLE = False
    get_feedback_loop = None

# Import entity registry for reputation-based suppression
try:
    from src.enrichment.entity_registry import get_entity_registry
    ENTITY_REGISTRY_AVAILABLE = True
except ImportError:
    ENTITY_REGISTRY_AVAILABLE = False
    get_entity_registry = None

# Import confidence calculator for evidence-weighted scoring
try:
    from src.rules.confidence import get_confidence_calculator
    CONFIDENCE_AVAILABLE = True
except ImportError:
    CONFIDENCE_AVAILABLE = False
    get_confidence_calculator = None


@dataclass
class AlertRule:
    """Represents a parsed alert rule."""
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low
    confidence: float
    enabled: bool
    detection: Dict[str, Any]
    thresholds: Dict[str, Any] = field(default_factory=dict)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    rate_limit: Optional[Dict[str, Any]] = None
    schedule: Optional[Dict[str, Any]] = None
    exclusions: Dict[str, Any] = field(default_factory=dict)  # Contracts/addresses to exclude
    
    @property
    def is_critical(self) -> bool:
        return self.severity == "critical"
    
    @property
    def is_high(self) -> bool:
        return self.severity == "high"
    
    def is_excluded(self, contract_address: str, addresses: List[str] = None) -> bool:
        """Check if the contract or addresses should be excluded from this rule."""
        if not self.exclusions:
            return False
        
        # Check contract exclusions
        excluded_contracts = self.exclusions.get('contracts', [])
        if contract_address and excluded_contracts:
            contract_lower = contract_address.lower()
            if any(c.lower() == contract_lower for c in excluded_contracts):
                return True
        
        # Check address exclusions
        excluded_addresses = self.exclusions.get('addresses', [])
        if addresses and excluded_addresses:
            excluded_lower = [a.lower() for a in excluded_addresses]
            for addr in addresses:
                if addr and addr.lower() in excluded_lower:
                    return True
        
        return False


@dataclass
class AlertMatch:
    """Result of a rule matching an event."""
    rule: AlertRule
    event: Dict[str, Any]
    matched_at: datetime
    match_details: Dict[str, Any]
    dynamic_confidence: Optional[float] = None  # Evidence-weighted confidence
    evidence: Optional[Dict[str, Any]] = None    # Evidence bundle for transparency

    def to_dict(self) -> Dict[str, Any]:
        confidence = self.dynamic_confidence if self.dynamic_confidence is not None else self.rule.confidence
        result = {
            "rule_id": self.rule.id,
            "rule_name": self.rule.name,
            "severity": self.rule.severity,
            "confidence": confidence,
            "base_confidence": self.rule.confidence,
            "event": self.event,
            "matched_at": self.matched_at.isoformat(),
            "details": self.match_details,
        }
        if self.evidence:
            result["evidence"] = self.evidence
        return result


import structlog as _structlog

_spike_logger = _structlog.get_logger("alert_spike_guard")


class AlertSpikeGuard:
    """
    Detects abnormal alert-rate spikes and triggers guardian auto-pause.

    Keeps a sliding window of critical/high alert timestamps per protocol.
    When the rate exceeds the configured threshold, fires a guardian pause
    for the affected protocol and enters a cooldown to prevent re-triggering.

    Config (env vars):
      SPIKE_WINDOW_SECONDS   – sliding window size (default 300 = 5 min)
      SPIKE_THRESHOLD        – critical+high alerts in window to trigger (default 20)
      SPIKE_COOLDOWN_SECONDS – seconds to suppress after triggering (default 900)
    """

    def __init__(self):
        self._window = int(os.getenv("SPIKE_WINDOW_SECONDS", "300"))
        self._threshold = int(os.getenv("SPIKE_THRESHOLD", "20"))
        self._cooldown = int(os.getenv("SPIKE_COOLDOWN_SECONDS", "900"))
        # protocol -> list of timestamps
        self._timestamps: Dict[str, List[datetime]] = {}
        # protocol -> last trigger time
        self._last_triggered: Dict[str, datetime] = {}

    def record_matches(self, matches: List["AlertMatch"]):
        """Record alert matches and check for spikes."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self._window)

        for match in matches:
            if match.rule.severity not in ("critical", "high"):
                continue

            # Determine protocol key from event
            protocol = (
                match.event.get("protocol")
                or match.event.get("affected_protocol")
                or match.event.get("contract_address", "unknown")
            )

            if protocol not in self._timestamps:
                self._timestamps[protocol] = []

            self._timestamps[protocol].append(now)

            # Prune old entries
            self._timestamps[protocol] = [
                t for t in self._timestamps[protocol] if t > cutoff
            ]

            # Check if spike threshold exceeded
            count = len(self._timestamps[protocol])
            if count >= self._threshold:
                self._maybe_trigger_pause(protocol, count, now)

    def _maybe_trigger_pause(self, protocol: str, count: int, now: datetime):
        """Trigger guardian pause if not in cooldown."""
        last = self._last_triggered.get(protocol)
        if last and (now - last).total_seconds() < self._cooldown:
            return  # Still in cooldown

        self._last_triggered[protocol] = now

        _spike_logger.critical(
            "alert_spike_detected",
            protocol=protocol,
            alert_count=count,
            window_seconds=self._window,
            threshold=self._threshold,
            action="triggering_guardian_auto_pause",
        )

        # Fire guardian pause asynchronously (best-effort)
        try:
            import asyncio
            from src.response.guardian import auto_respond_to_incident

            asyncio.ensure_future(
                auto_respond_to_incident(
                    incident_id=f"spike-{protocol}-{now.strftime('%Y%m%d%H%M%S')}",
                    severity="critical",
                    attack_type="alert_rate_spike",
                    protocol=protocol,
                    estimated_loss_usd=0,
                    chain="unknown",
                    contract=protocol,
                )
            )
        except Exception as e:
            _spike_logger.error("spike_auto_pause_failed", error=str(e))


class RuleEngine:
    """
    Loads and evaluates YAML-based alert rules.

    Supports:
    - Event-based rules (simple field matching)
    - Invariant-based rules (protocol state checks)
    - Pattern-based rules (multi-event sequences)
    - Aggregation rules (time-windowed counts)

    Usage:
        engine = RuleEngine()
        engine.load_rules_from_directory("config/rules/")

        matches = engine.evaluate(event)
        for match in matches:
            print(f"Rule {match.rule.name} triggered!")
    """
    
    def __init__(self):
        self.rules: List[AlertRule] = []
        self._rule_index: Dict[str, AlertRule] = {}
        self._alert_history: Dict[str, List[datetime]] = {}  # For rate limiting

        # Anomaly spike auto-guard
        self._spike_guard = AlertSpikeGuard()

        # Feedback loop for TP/FP auto-suppression
        self._feedback_loop = get_feedback_loop() if FEEDBACK_LOOP_AVAILABLE and get_feedback_loop else None

        # Entity registry for reputation-based suppression
        self._entity_registry = get_entity_registry() if ENTITY_REGISTRY_AVAILABLE and get_entity_registry else None

        # Evidence-weighted confidence calculator
        self._confidence_calc = get_confidence_calculator() if CONFIDENCE_AVAILABLE and get_confidence_calculator else None

        # Initialize advanced engines if available
        self._invariant_engine = get_invariant_engine() if ADVANCED_ENGINES_AVAILABLE and get_invariant_engine else None
        self._pattern_matcher = get_pattern_matcher() if ADVANCED_ENGINES_AVAILABLE and get_pattern_matcher else None
        self._enricher = get_enricher() if ENRICHMENT_AVAILABLE and get_enricher else None
    
    def load_rules_from_directory(self, directory: str) -> int:
        """Load all YAML rules from a directory."""
        rules_dir = Path(directory)
        loaded = 0
        
        if not rules_dir.exists():
            print(f"⚠️  Rules directory not found: {directory}")
            return 0
        
        for yaml_file in rules_dir.glob("*.yaml"):
            try:
                loaded += self.load_rules_from_file(str(yaml_file))
            except Exception as e:
                print(f"❌ Error loading {yaml_file}: {e}")
        
        return loaded
    
    def load_rules_from_file(self, filepath: str) -> int:
        """Load rules from a single YAML file."""
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        
        if not data or 'rules' not in data:
            return 0
        
        loaded = 0
        for rule_data in data['rules']:
            try:
                rule = self._parse_rule(rule_data)
                if rule.enabled:
                    self.rules.append(rule)
                    self._rule_index[rule.id] = rule
                    loaded += 1
            except Exception as e:
                print(f"❌ Error parsing rule {rule_data.get('id', 'unknown')}: {e}")
        
        return loaded
    
    def _parse_rule(self, data: Dict) -> AlertRule:
        """Parse a rule dictionary into an AlertRule object."""
        detection = data.get('detection', {})
        # Promote top-level time_window into detection dict so velocity rules can access it
        if 'time_window' in data and 'time_window' not in detection:
            detection['time_window'] = data['time_window']
        return AlertRule(
            id=data['id'],
            name=data['name'],
            description=data.get('description', ''),
            severity=data.get('severity', 'medium'),
            confidence=float(data.get('confidence', 0.5)),
            enabled=data.get('enabled', True),
            detection=detection,
            thresholds=data.get('thresholds', {}),
            actions=data.get('actions', []),
            rate_limit=data.get('rate_limit'),
            schedule=data.get('schedule'),
            exclusions=data.get('exclusions', {})
        )
    
    def evaluate(self, event: Dict[str, Any]) -> List[AlertMatch]:
        """
        Evaluate all rules against an event.
        Returns list of matching rules.
        """
        matches = []
        
        # Enrich event if enricher available
        if self._enricher:
            try:
                event = self._enricher.enrich_sync(event)
            except Exception:
                pass  # Continue with unenriched event
        
        # Check invariants if engine available
        if self._invariant_engine:
            try:
                violations = self._invariant_engine.check_event(event)
                for violation in violations:
                    # Create synthetic match for invariant violation
                    matches.append(AlertMatch(
                        rule=AlertRule(
                            id=f"invariant-{violation.invariant_type.value}",
                            name=f"Invariant Violation: {violation.invariant_type.value}",
                            description=str(violation.details),
                            severity=violation.severity.lower(),
                            confidence=0.9,
                            enabled=True,
                            detection={"type": "invariant", "invariant": violation.invariant_type.value},
                        ),
                        event=event,
                        matched_at=violation.timestamp,
                        match_details={
                            "invariant_type": violation.invariant_type.value,
                            "expected": violation.expected_value,
                            "actual": violation.actual_value,
                            "deviation": violation.deviation,
                        }
                    ))
            except Exception:
                pass
        
        # --- Reputation pre-check: extract involved addresses once ---
        event_addresses = [
            event.get("from_address", ""),
            event.get("to_address", ""),
            event.get("source_address", ""),
            event.get("dest_address", ""),
        ]
        event_addresses = [a for a in event_addresses if a]

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check feedback loop auto-suppression
            if self._feedback_loop and self._feedback_loop.is_suppressed(rule.id):
                continue

            # --- Reputation-based suppression ---
            # If ALL involved addresses are trusted/known, suppress low-severity rules
            if self._entity_registry and event_addresses:
                should_suppress = all(
                    self._entity_registry.should_suppress_severity(addr, rule.severity)
                    for addr in event_addresses
                )
                if should_suppress:
                    continue

            # Check rate limiting
            if self._is_rate_limited(rule):
                continue

            # Evaluate rule
            match_result = self._evaluate_rule(rule, event)

            if match_result:
                match = AlertMatch(
                    rule=rule,
                    event=event,
                    matched_at=datetime.now(timezone.utc),
                    match_details=match_result,
                )
                matches.append(match)

                # Record for rate limiting
                self._record_alert(rule)

        # --- Post-processing: compute dynamic confidence + corroboration ---
        if self._confidence_calc and matches:
            corroboration_count = len(matches) - 1  # Each match corroborated by N-1 others
            for match in matches:
                threshold_usd = match.rule.thresholds.get("min_amount_usd", 0)
                evidence = self._confidence_calc.build_evidence(
                    event=match.event,
                    rule_id=match.rule.id,
                    rule_threshold_usd=float(threshold_usd),
                    corroborating_count=corroboration_count,
                )
                match.dynamic_confidence = self._confidence_calc.calculate(
                    base_confidence=match.rule.confidence,
                    evidence=evidence,
                )
                match.evidence = evidence.to_dict()

        # Feed matches into spike guard for anomaly detection
        if matches:
            self._spike_guard.record_matches(matches)

        return matches
    
    def _evaluate_rule(self, rule: AlertRule, event: Dict[str, Any]) -> Optional[Dict]:
        """
        Evaluate a single rule against an event.
        Returns match details if matched, None otherwise.
        
        Supports detection types:
        - event: Simple field matching
        - invariant: Protocol state checks
        - pattern: Multi-event sequences
        - aggregation: Time-windowed counts
        """
        detection = rule.detection
        detection_type = detection.get('type', 'event')
        
        # ========================================
        # EXCLUSION CHECK: Skip if contract/address is excluded
        # ========================================
        if rule.exclusions:
            contract_address = event.get('contract_address', '')
            involved_addresses = [
                event.get('from_address', ''),
                event.get('to_address', ''),
                event.get('source_address', ''),
                event.get('dest_address', ''),
            ]
            involved_addresses = [a for a in involved_addresses if a]  # Filter empty
            
            if rule.is_excluded(contract_address, involved_addresses):
                return None  # Skip this rule for excluded contracts/addresses
        
        # ========================================
        # CONTRACT TYPE CHECK: Only match specific contract types (e.g., ERC-721)
        # ========================================
        required_contract_types = detection.get('contract_types', [])
        if required_contract_types:
            event_contract_type = event.get('contract_type', '').upper()
            # If contract type is specified in rule, event must match
            if event_contract_type:
                type_matched = any(
                    ct.upper() in event_contract_type or event_contract_type in ct.upper()
                    for ct in required_contract_types
                )
                if not type_matched:
                    return None  # Contract type doesn't match
            else:
                # If event has no contract type info, skip NFT-specific rules
                # This prevents ERC-20 tokens from triggering NFT rules
                return None
        
        # Handle invariant-based rules
        if detection_type == 'invariant':
            if not self._invariant_engine:
                return None
            # Invariants are checked in evaluate() method
            return None
        
        # Handle pattern-based rules
        if detection_type == 'pattern':
            if not self._pattern_matcher:
                return None
            pattern_name = detection.get('pattern', '')
            if pattern_name and self._pattern_matcher.check_pattern(pattern_name, event):
                return {
                    "pattern": pattern_name,
                    "matched_at": datetime.now(timezone.utc).isoformat(),
                }
            return None
        
        # Handle velocity-based rules — actual time-windowed counting
        if detection_type == 'velocity':
            # Chain filter
            if 'chain' in detection:
                expected_chain = detection['chain']
                if expected_chain != 'any':
                    event_chain = event.get('chain', '') or event.get('chain_id', '')
                    expected_chain_lower = expected_chain.lower()
                    event_chain_lower = str(event_chain).lower() if event_chain else ''
                    if event_chain_lower != expected_chain_lower:
                        return None

            # Event type filter (if specified)
            expected_types = detection.get('event_types') or detection.get('event_type')
            if expected_types:
                if isinstance(expected_types, str):
                    expected_types = [expected_types]
                event_type = event.get('event_type', '')
                if not event_type_matches(event_type, expected_types):
                    return None

            # Track this event in the velocity counter (with per-event dedup)
            velocity_key = f"velocity:{rule.id}"
            if velocity_key not in self._alert_history:
                self._alert_history[velocity_key] = []

            # Dedup: use event_id so the same event counted via multiple paths only increments once
            event_id = event.get('event_id', '')
            dedup_key = f"_velocity_seen:{rule.id}"
            if dedup_key not in self._alert_history:
                self._alert_history[dedup_key] = set()
            if event_id and event_id in self._alert_history[dedup_key]:
                # Already counted this event for this rule — skip
                pass
            else:
                self._alert_history[velocity_key].append(datetime.now(timezone.utc))
                if event_id:
                    self._alert_history[dedup_key].add(event_id)

            # Parse time window from rule (default 5m)
            getattr(rule, 'schedule', None)
            time_window_str = detection.get('time_window') or rule.__dict__.get('time_window', '5m') if hasattr(rule, '__dict__') else '5m'
            # Try to get time_window from the rule YAML (stored in raw data)
            window_seconds = 300  # default 5 min
            if isinstance(time_window_str, str):
                if time_window_str.endswith('m'):
                    window_seconds = int(time_window_str[:-1]) * 60
                elif time_window_str.endswith('s'):
                    window_seconds = int(time_window_str[:-1])
                elif time_window_str.endswith('h'):
                    window_seconds = int(time_window_str[:-1]) * 3600

            cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
            old_len = len(self._alert_history[velocity_key])
            self._alert_history[velocity_key] = [
                t for t in self._alert_history[velocity_key] if t > cutoff
            ]
            # If timestamps were pruned, clear the dedup set to prevent unbounded growth
            if len(self._alert_history[velocity_key]) < old_len:
                old_len - len(self._alert_history[velocity_key])
                seen_set = self._alert_history.get(dedup_key, set())
                if isinstance(seen_set, set) and len(seen_set) > 10000:
                    self._alert_history[dedup_key] = set()

            count = len(self._alert_history[velocity_key])
            threshold = detection.get('threshold', 100)

            # Only fire when threshold is actually exceeded
            if count < threshold:
                return None

            return {
                "velocity_type": detection.get('metric', 'events_per_minute'),
                "threshold": threshold,
                "actual_count": count,
                "window_seconds": window_seconds,
                "chain": detection.get('chain', 'any'),
                "matched_at": datetime.now(timezone.utc).isoformat(),
            }
        
        # Standard event-based rule evaluation
        # Check event type with normalization
        # Support both 'event_type' (singular) and 'event_types' (plural)
        expected_types = detection.get('event_types') or detection.get('event_type')
        if expected_types:
            if isinstance(expected_types, str):
                expected_types = [expected_types]
            
            event_type = event.get('event_type', '')
            # Use event type normalizer for flexible matching
            if not event_type_matches(event_type, expected_types):
                return None
        
        # Check chain
        if 'chain' in detection:
            expected_chain = detection['chain']
            if expected_chain != 'any':
                event_chain = event.get('chain', '') or event.get('chain_id', '')
                if event_chain != expected_chain:
                    return None
        
        # Check conditions
        conditions = detection.get('conditions', [])
        match_details = {"matched_conditions": []}
        
        for condition in conditions:
            if not self._evaluate_condition(condition, event, rule.thresholds):
                return None
            match_details["matched_conditions"].append(condition)
        
        # Check thresholds
        thresholds = rule.thresholds
        if thresholds:
            # Get both amount values
            amount_usd_raw = event.get('amount_usd', 0)
            amount_raw = event.get('amount', 0)
            
            try:
                amount_usd = float(amount_usd_raw) if amount_usd_raw else 0
            except (ValueError, TypeError):
                amount_usd = 0
            
            try:
                amount = float(amount_raw) if amount_raw else 0
            except (ValueError, TypeError):
                amount = 0
            
            # Check USD threshold (if price is available)
            if 'min_amount_usd' in thresholds:
                min_usd = thresholds['min_amount_usd']

                # If USD value is available and meets threshold, pass
                if amount_usd >= min_usd:
                    match_details["amount_usd"] = amount_usd
                else:
                    # USD below threshold OR unavailable — reject.
                    # A rule that requires min_amount_usd should not fire
                    # when we can't confirm the value meets it.
                    return None
            
            # Check raw token amount threshold
            if 'min_amount' in thresholds:
                if amount < thresholds['min_amount']:
                    return None
                match_details["amount"] = amount
        
        return match_details
    
    def _evaluate_condition(
        self, 
        condition: Dict, 
        event: Dict,
        thresholds: Dict
    ) -> bool:
        """Evaluate a single condition."""
        field = condition.get('field')
        operator = condition.get('operator')
        value = condition.get('value')
        compare_to = condition.get('compare_to')
        
        # Get the actual field value from event
        actual_value = event.get(field)
        
        if actual_value is None:
            return False
        
        # If comparing to another field
        if compare_to:
            value = event.get(compare_to, thresholds.get(compare_to, 0))
        
        # Apply operator
        if operator == 'eq':
            return actual_value == value
        elif operator == 'neq':
            return actual_value != value
        elif operator == 'gt':
            return float(actual_value) > float(value)
        elif operator == 'gte':
            return float(actual_value) >= float(value)
        elif operator == 'lt':
            return float(actual_value) < float(value)
        elif operator == 'lte':
            return float(actual_value) <= float(value)
        elif operator == 'contains':
            return value in str(actual_value)
        elif operator == 'regex':
            return bool(re.match(value, str(actual_value)))
        
        return False
    
    def _is_rate_limited(self, rule: AlertRule) -> bool:
        """Check if rule is currently rate limited."""
        if not rule.rate_limit:
            return False
        
        max_alerts = rule.rate_limit.get('max_alerts', 100)
        period = rule.rate_limit.get('period', '1h')
        
        # Parse period
        period_seconds = self._parse_period(period)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=period_seconds)
        
        # Count recent alerts
        history = self._alert_history.get(rule.id, [])
        recent = [t for t in history if t > cutoff]
        
        return len(recent) >= max_alerts
    
    def _record_alert(self, rule: AlertRule):
        """Record that an alert was triggered."""
        if rule.id not in self._alert_history:
            self._alert_history[rule.id] = []
        
        self._alert_history[rule.id].append(datetime.now(timezone.utc))
        
        # Cleanup old history
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        self._alert_history[rule.id] = [
            t for t in self._alert_history[rule.id] if t > cutoff
        ]
    
    def _parse_period(self, period: str) -> int:
        """Parse period string to seconds."""
        if period.endswith('s'):
            return int(period[:-1])
        elif period.endswith('m'):
            return int(period[:-1]) * 60
        elif period.endswith('h'):
            return int(period[:-1]) * 3600
        elif period.endswith('d'):
            return int(period[:-1]) * 86400
        return int(period)
    
    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Get a rule by ID."""
        return self._rule_index.get(rule_id)
    
    def get_rules_by_severity(self, severity: str) -> List[AlertRule]:
        """Get all rules of a given severity."""
        return [r for r in self.rules if r.severity == severity]
    
    def stats(self) -> Dict[str, Any]:
        """Get statistics about loaded rules."""
        return {
            "total_rules": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "by_severity": {
                "critical": len(self.get_rules_by_severity("critical")),
                "high": len(self.get_rules_by_severity("high")),
                "medium": len(self.get_rules_by_severity("medium")),
                "low": len(self.get_rules_by_severity("low")),
            }
        }


# Convenience function
def load_rules(directory: str = None) -> RuleEngine:
    """Load rules from default or specified directory."""
    if directory is None:
        directory = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "config", "rules"
        )
    
    engine = RuleEngine()
    count = engine.load_rules_from_directory(directory)
    print(f"✅ Loaded {count} alert rules")
    print(f"   {engine.stats()}")
    
    return engine

