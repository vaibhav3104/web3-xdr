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
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "rule_name": self.rule.name,
            "severity": self.rule.severity,
            "confidence": self.rule.confidence,
            "event": self.event,
            "matched_at": self.matched_at.isoformat(),
            "details": self.match_details
        }


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
        return AlertRule(
            id=data['id'],
            name=data['name'],
            description=data.get('description', ''),
            severity=data.get('severity', 'medium'),
            confidence=float(data.get('confidence', 0.5)),
            enabled=data.get('enabled', True),
            detection=data.get('detection', {}),
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
            except Exception as e:
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
            except Exception as e:
                pass
        
        for rule in self.rules:
            if not rule.enabled:
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
                    match_details=match_result
                )
                matches.append(match)
                
                # Record for rate limiting
                self._record_alert(rule)
        
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
        
        # Handle velocity-based rules
        if detection_type == 'velocity':
            # ========================================
            # FIX: Check chain BEFORE triggering velocity rules
            # ========================================
            if 'chain' in detection:
                expected_chain = detection['chain']
                if expected_chain != 'any':
                    event_chain = event.get('chain', '') or event.get('chain_id', '')
                    # Normalize chain names
                    expected_chain_lower = expected_chain.lower()
                    event_chain_lower = str(event_chain).lower() if event_chain else ''
                    if event_chain_lower != expected_chain_lower:
                        return None  # Chain doesn't match, skip this rule
            
            # Velocity rules are based on frequency, not individual events
            # They should trigger to track velocity metrics
            return {
                "velocity_type": detection.get('metric', 'events_per_minute'),
                "threshold": detection.get('threshold', 0),
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
                # If USD is 0 but we have token amount, check conditions instead
                elif amount_usd == 0 and amount > 0:
                    # Fall through to condition checks (already passed above)
                    match_details["amount"] = amount
                    match_details["note"] = "USD price unavailable, matched on token amount"
                else:
                    # USD value below threshold
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

