"""
YAML Rules to ML Feature Converter
==================================

Extracts knowledge from YAML detection rules and converts them
into ML features and training signals.

This is the bridge between rule-based detection and ML-based detection.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class RuleKnowledge:
    """Knowledge extracted from a single YAML rule."""
    rule_id: str
    name: str
    severity: str
    
    # What the rule looks for
    event_types: List[str]
    required_fields: List[str]
    
    # Conditions
    threshold_conditions: List[Dict[str, Any]]  # field, operator, value
    pattern_conditions: List[Dict[str, Any]]    # regex, contains, etc.
    
    # Context
    category: str
    description: str
    
    # For ML training
    feature_importance: Dict[str, float]  # Which features matter most


@dataclass
class ExtractedKnowledge:
    """Aggregated knowledge from all YAML rules."""
    
    # Event types that matter
    important_event_types: Set[str] = field(default_factory=set)
    
    # Fields that matter
    important_fields: Set[str] = field(default_factory=set)
    
    # Threshold patterns
    thresholds: List[Dict[str, Any]] = field(default_factory=list)
    
    # Severity mappings
    severity_indicators: Dict[str, List[Dict]] = field(default_factory=lambda: defaultdict(list))
    
    # Category mappings
    category_patterns: Dict[str, List[Dict]] = field(default_factory=lambda: defaultdict(list))
    
    # Individual rules
    rules: List[RuleKnowledge] = field(default_factory=list)
    
    # Statistics
    total_rules: int = 0
    rules_by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    rules_by_category: Dict[str, int] = field(default_factory=lambda: defaultdict(int))


class YAMLToMLConverter:
    """
    Converts YAML detection rules into ML features and training signals.
    
    Process:
    1. Parse all YAML rules
    2. Extract important event types, fields, thresholds
    3. Create feature engineering blueprint
    4. Generate training signal weights
    """
    
    # Operator mappings for ML features
    OPERATOR_TO_FEATURE = {
        "gt": "greater_than",
        "gte": "greater_than_or_equal",
        "lt": "less_than",
        "lte": "less_than_or_equal",
        "eq": "equals",
        "neq": "not_equals",
        "in": "in_set",
        "not_in": "not_in_set",
        "contains": "contains",
        "regex": "matches_pattern"
    }
    
    # Severity to numeric mapping
    SEVERITY_WEIGHTS = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.3,
        "info": 0.1
    }
    
    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize converter.
        
        Args:
            rules_dir: Directory containing YAML rules
        """
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(__file__), 
            "../../config/rules"
        )
        self.knowledge = ExtractedKnowledge()
    
    def load_and_convert(self) -> ExtractedKnowledge:
        """
        Load all YAML rules and extract knowledge.
        
        Returns:
            ExtractedKnowledge object with all extracted information
        """
        rules_path = Path(self.rules_dir)
        
        if not rules_path.exists():
            logger.warning("rules_dir_not_found", path=self.rules_dir)
            return self.knowledge
        
        # Find all YAML files
        yaml_files = list(rules_path.glob("**/*.yaml")) + list(rules_path.glob("**/*.yml"))
        
        logger.info("loading_yaml_rules", file_count=len(yaml_files))
        
        for yaml_file in yaml_files:
            try:
                self._process_yaml_file(yaml_file)
            except Exception as e:
                logger.error("yaml_parse_error", file=str(yaml_file), error=str(e))
        
        # Calculate statistics
        self._calculate_statistics()
        
        logger.info(
            "yaml_conversion_complete",
            total_rules=self.knowledge.total_rules,
            event_types=len(self.knowledge.important_event_types),
            fields=len(self.knowledge.important_fields),
            thresholds=len(self.knowledge.thresholds)
        )
        
        return self.knowledge
    
    def _process_yaml_file(self, file_path: Path):
        """Process a single YAML file."""
        with open(file_path, "r") as f:
            content = yaml.safe_load(f)
        
        if not content:
            return
        
        # Handle both list of rules and dict with rules key
        rules = content if isinstance(content, list) else content.get("rules", [])
        
        for rule in rules:
            if isinstance(rule, dict):
                self._extract_rule_knowledge(rule)
    
    def _extract_rule_knowledge(self, rule: Dict[str, Any]):
        """Extract knowledge from a single rule."""
        rule_id = rule.get("id", "unknown")
        name = rule.get("name", "")
        severity = rule.get("severity", "medium").lower()
        description = rule.get("description", "")
        category = rule.get("category", "unknown")
        
        # Track event types
        event_types = []
        detection = rule.get("detection", {})
        
        # Direct event_type
        if "event_type" in detection:
            et = detection["event_type"]
            if isinstance(et, list):
                event_types.extend(et)
            else:
                event_types.append(et)
            self.knowledge.important_event_types.update(event_types)
        
        # Event types from conditions
        if "event_types" in detection:
            event_types.extend(detection["event_types"])
            self.knowledge.important_event_types.update(detection["event_types"])
        
        # Extract required fields and conditions
        required_fields = []
        threshold_conditions = []
        pattern_conditions = []
        
        conditions = detection.get("conditions", [])
        for condition in conditions:
            if isinstance(condition, dict):
                field = condition.get("field", "")
                operator = condition.get("operator", "")
                value = condition.get("value")
                
                if field:
                    required_fields.append(field)
                    self.knowledge.important_fields.add(field)
                
                # Categorize condition type
                if operator in ["gt", "gte", "lt", "lte"]:
                    threshold_conditions.append({
                        "field": field,
                        "operator": operator,
                        "value": value,
                        "severity": severity
                    })
                    self.knowledge.thresholds.append({
                        "field": field,
                        "operator": operator,
                        "value": value,
                        "severity": severity,
                        "rule_id": rule_id
                    })
                elif operator in ["contains", "regex", "matches"]:
                    pattern_conditions.append({
                        "field": field,
                        "operator": operator,
                        "value": value
                    })
        
        # Extract thresholds from rule-level
        thresholds = rule.get("thresholds", {})
        for field, value in thresholds.items():
            self.knowledge.important_fields.add(field)
            threshold_conditions.append({
                "field": field,
                "operator": "gte",
                "value": value,
                "severity": severity
            })
            self.knowledge.thresholds.append({
                "field": field,
                "operator": "gte",
                "value": value,
                "severity": severity,
                "rule_id": rule_id
            })
        
        # Calculate feature importance based on conditions
        feature_importance = self._calculate_feature_importance(
            threshold_conditions, 
            pattern_conditions,
            severity
        )
        
        # Create rule knowledge object
        rule_knowledge = RuleKnowledge(
            rule_id=rule_id,
            name=name,
            severity=severity,
            event_types=event_types,
            required_fields=required_fields,
            threshold_conditions=threshold_conditions,
            pattern_conditions=pattern_conditions,
            category=category,
            description=description,
            feature_importance=feature_importance
        )
        
        self.knowledge.rules.append(rule_knowledge)
        
        # Track severity indicators
        self.knowledge.severity_indicators[severity].append({
            "rule_id": rule_id,
            "conditions": threshold_conditions + pattern_conditions
        })
        
        # Track category patterns
        self.knowledge.category_patterns[category].append({
            "rule_id": rule_id,
            "event_types": event_types,
            "conditions": threshold_conditions
        })
    
    def _calculate_feature_importance(
        self,
        threshold_conditions: List[Dict],
        pattern_conditions: List[Dict],
        severity: str
    ) -> Dict[str, float]:
        """Calculate importance weights for features based on rule conditions."""
        importance = {}
        severity_weight = self.SEVERITY_WEIGHTS.get(severity, 0.5)
        
        # Threshold conditions are important
        for condition in threshold_conditions:
            field = condition.get("field", "")
            if field:
                # Higher severity rules = more important features
                importance[field] = importance.get(field, 0) + severity_weight
        
        # Pattern conditions
        for condition in pattern_conditions:
            field = condition.get("field", "")
            if field:
                importance[field] = importance.get(field, 0) + severity_weight * 0.8
        
        return importance
    
    def _calculate_statistics(self):
        """Calculate aggregate statistics."""
        self.knowledge.total_rules = len(self.knowledge.rules)
        
        for rule in self.knowledge.rules:
            self.knowledge.rules_by_severity[rule.severity] += 1
            self.knowledge.rules_by_category[rule.category] += 1
    
    def get_feature_blueprint(self) -> Dict[str, Any]:
        """
        Generate a feature engineering blueprint for ML.
        
        Returns:
            Blueprint describing features to extract
        """
        # Aggregate feature importance across all rules
        aggregated_importance = defaultdict(float)
        for rule in self.knowledge.rules:
            for field, importance in rule.feature_importance.items():
                aggregated_importance[field] += importance
        
        # Sort by importance
        sorted_features = sorted(
            aggregated_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Generate threshold-based features
        threshold_features = []
        for threshold in self.knowledge.thresholds:
            field = threshold["field"]
            value = threshold["value"]
            severity = threshold["severity"]
            
            # Create binary feature for threshold
            threshold_features.append({
                "name": f"{field}_above_{value}",
                "type": "binary",
                "condition": f"{field} > {value}",
                "weight": self.SEVERITY_WEIGHTS.get(severity, 0.5)
            })
        
        return {
            "event_types": list(self.knowledge.important_event_types),
            "numeric_features": [
                f for f in sorted_features 
                if f[0] in ["amount", "amount_usd", "gas_price", "gas_used", "value"]
            ],
            "categorical_features": [
                f for f in sorted_features
                if f[0] in ["event_type", "chain_id", "protocol", "asset_type"]
            ],
            "address_features": [
                f for f in sorted_features
                if "address" in f[0].lower()
            ],
            "threshold_features": threshold_features,
            "feature_importance": dict(sorted_features[:20])  # Top 20
        }
    
    def get_training_signals(self) -> Dict[str, Any]:
        """
        Generate training signals for ML model.
        
        Returns:
            Training signal configuration
        """
        signals = {
            "severity_weights": self.SEVERITY_WEIGHTS,
            "category_mappings": {},
            "threshold_signals": []
        }
        
        # Create category to numeric mapping
        categories = list(self.knowledge.rules_by_category.keys())
        signals["category_mappings"] = {
            cat: idx for idx, cat in enumerate(categories)
        }
        
        # Create threshold-based training signals
        for threshold in self.knowledge.thresholds:
            signals["threshold_signals"].append({
                "field": threshold["field"],
                "threshold": threshold["value"],
                "label_if_exceeded": threshold["severity"],
                "confidence": 0.7  # Rule-based signals have moderate confidence
            })
        
        return signals
    
    def export_for_vertex_ai(self, output_path: str):
        """
        Export knowledge in format suitable for Vertex AI training.
        
        Args:
            output_path: Path to write export files
        """
        import json
        
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Export feature blueprint
        blueprint = self.get_feature_blueprint()
        with open(output_dir / "feature_blueprint.json", "w") as f:
            json.dump(blueprint, f, indent=2, default=str)
        
        # Export training signals
        signals = self.get_training_signals()
        with open(output_dir / "training_signals.json", "w") as f:
            json.dump(signals, f, indent=2, default=str)
        
        # Export rule summaries
        rule_summaries = []
        for rule in self.knowledge.rules:
            rule_summaries.append({
                "id": rule.rule_id,
                "name": rule.name,
                "severity": rule.severity,
                "category": rule.category,
                "event_types": rule.event_types,
                "feature_importance": rule.feature_importance
            })
        
        with open(output_dir / "rule_summaries.json", "w") as f:
            json.dump(rule_summaries, f, indent=2, default=str)
        
        # Export statistics
        stats = {
            "total_rules": self.knowledge.total_rules,
            "rules_by_severity": dict(self.knowledge.rules_by_severity),
            "rules_by_category": dict(self.knowledge.rules_by_category),
            "event_types": list(self.knowledge.important_event_types),
            "important_fields": list(self.knowledge.important_fields)
        }
        
        with open(output_dir / "statistics.json", "w") as f:
            json.dump(stats, f, indent=2)
        
        logger.info(
            "vertex_ai_export_complete",
            output_path=str(output_dir),
            files=["feature_blueprint.json", "training_signals.json", "rule_summaries.json", "statistics.json"]
        )
