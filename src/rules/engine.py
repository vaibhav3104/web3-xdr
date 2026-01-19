"""
YAML-based Alert Rule Engine

Loads alert rules from YAML files and evaluates them against events.
Similar to Sigma rules for traditional SIEM systems.
"""

import os
import yaml
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
import re


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
    
    @property
    def is_critical(self) -> bool:
        return self.severity == "critical"
    
    @property
    def is_high(self) -> bool:
        return self.severity == "high"


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
            schedule=data.get('schedule')
        )
    
    def evaluate(self, event: Dict[str, Any]) -> List[AlertMatch]:
        """
        Evaluate all rules against an event.
        Returns list of matching rules.
        """
        matches = []
        
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
                    matched_at=datetime.utcnow(),
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
        """
        detection = rule.detection
        
        # Check event type
        if 'event_type' in detection:
            expected_types = detection['event_type']
            if isinstance(expected_types, str):
                expected_types = [expected_types]
            
            event_type = event.get('event_type', '')
            if event_type not in expected_types and 'any' not in expected_types:
                return None
        
        # Check chain
        if 'chain' in detection:
            expected_chain = detection['chain']
            if expected_chain != 'any':
                event_chain = event.get('chain', '')
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
            if 'min_amount_usd' in thresholds:
                # Handle amount_usd as string, Decimal, or number
                amount_usd_raw = event.get('amount_usd', 0)
                try:
                    amount_usd = float(amount_usd_raw) if amount_usd_raw else 0
                except (ValueError, TypeError):
                    amount_usd = 0
                
                if amount_usd < thresholds['min_amount_usd']:
                    return None
                
                # Add matched threshold to details
                match_details["amount_usd"] = amount_usd
            
            if 'min_amount' in thresholds:
                # Also support raw token amount thresholds
                amount_raw = event.get('amount', 0)
                try:
                    amount = float(amount_raw) if amount_raw else 0
                except (ValueError, TypeError):
                    amount = 0
                
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
        cutoff = datetime.utcnow() - timedelta(seconds=period_seconds)
        
        # Count recent alerts
        history = self._alert_history.get(rule.id, [])
        recent = [t for t in history if t > cutoff]
        
        return len(recent) >= max_alerts
    
    def _record_alert(self, rule: AlertRule):
        """Record that an alert was triggered."""
        if rule.id not in self._alert_history:
            self._alert_history[rule.id] = []
        
        self._alert_history[rule.id].append(datetime.utcnow())
        
        # Cleanup old history
        cutoff = datetime.utcnow() - timedelta(hours=24)
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

