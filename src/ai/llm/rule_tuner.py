"""
LLM Rule Tuner
===============

Analyzes feedback loop statistics and production alert patterns to
suggest rule threshold changes, new exclusions, and severity adjustments.

Usage:
    tuner = RuleTuner()
    recommendations = tuner.analyze_and_recommend()
    for rec in recommendations:
        print(f"{rec.rule_id}: {rec.change_type} — {rec.reasoning}")
        # tuner.apply(rec)  # auto-apply if desired
"""

import json
import yaml
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from pathlib import Path
import structlog

from .client import get_client, MODEL, MAX_TOKENS

logger = structlog.get_logger(__name__)

# Import feedback loop for FP/TP data
try:
    from src.rules.feedback_loop import get_feedback_loop

    FEEDBACK_AVAILABLE = True
except ImportError:
    FEEDBACK_AVAILABLE = False


@dataclass
class TuningRecommendation:
    """A single recommended change to a rule."""

    rule_id: str
    change_type: str  # "raise_threshold", "add_exclusion", "lower_severity", "disable", "tighten_rate_limit"
    field: str  # Which field to change (e.g., "thresholds.min_amount_usd")
    current_value: Any
    recommended_value: Any
    reasoning: str
    confidence: float  # 0.0 - 1.0
    expected_fp_reduction: float  # Estimated % FP reduction

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "change_type": self.change_type,
            "field": self.field,
            "current_value": self.current_value,
            "recommended_value": self.recommended_value,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "expected_fp_reduction": self.expected_fp_reduction,
        }


TUNER_SYSTEM_PROMPT = """You are a Web3 SIEM rule tuning expert. You analyze alert rule performance data (TP/FP rates, sample counts) and the rule definitions to recommend specific changes that reduce false positives while preserving true positive detection.

Key principles:
- Rules with FP rate > 50% need threshold increases or new exclusions
- Rules with FP rate > 80% should be disabled or fundamentally redesigned
- Low-severity rules with high FP rates are noise generators — raise thresholds aggressively
- If the same addresses keep causing FPs, add them to exclusions
- Rate limits should be tightened for noisy rules (not just thresholds)
- Never weaken detection of CRITICAL severity rules for hackers/sanctioned addresses

Respond with ONLY valid JSON — an array of recommendation objects:
[
  {
    "rule_id": "the-rule-id",
    "change_type": "raise_threshold" | "add_exclusion" | "lower_severity" | "disable" | "tighten_rate_limit",
    "field": "thresholds.min_amount_usd",
    "current_value": 5000000,
    "recommended_value": 15000000,
    "reasoning": "1-2 sentence explanation",
    "confidence": 0.85,
    "expected_fp_reduction": 0.40
  }
]

Return an empty array [] if no changes are recommended."""


class RuleTuner:
    """
    LLM-powered rule tuner that analyzes feedback data and suggests changes.
    """

    def __init__(self, rules_dir: str = None):
        self._feedback = get_feedback_loop() if FEEDBACK_AVAILABLE else None
        if rules_dir is None:
            rules_dir = str(
                Path(__file__).resolve().parent.parent.parent.parent
                / "config"
                / "rules"
            )
        self._rules_dir = Path(rules_dir)

    def _load_rule_definitions(self) -> Dict[str, Dict]:
        """Load all rule YAML definitions indexed by rule ID."""
        rules = {}
        if not self._rules_dir.exists():
            return rules

        for yaml_file in self._rules_dir.glob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                for rule in data.get("rules", []):
                    rules[rule["id"]] = {
                        "file": yaml_file.name,
                        **rule,
                    }
            except Exception as e:
                logger.warning("rule_load_failed", file=yaml_file.name, error=str(e))

        return rules

    def _build_context(self) -> str:
        """Build context with feedback stats and rule definitions."""
        parts = []

        # Feedback stats
        if self._feedback:
            stats = self._feedback.get_all_stats()
            if stats:
                parts.append("=== RULE PERFORMANCE (last 7 days) ===")
                for s in stats:
                    status = ""
                    if s["suppressed"]:
                        status = " [SUPPRESSED]"
                    elif s["auto_disabled"]:
                        status = " [AUTO-DISABLED]"
                    parts.append(
                        f"  {s['rule_id']}: "
                        f"TP={s['tp_count']} FP={s['fp_count']} "
                        f"FP_rate={s['fp_rate']:.1%} "
                        f"total={s['total']}{status}"
                    )
            else:
                parts.append("=== No feedback data available yet ===")

        # Rule definitions
        rules = self._load_rule_definitions()
        if rules:
            parts.append("\n=== RULE DEFINITIONS ===")
            for rule_id, rule in rules.items():
                parts.append(f"\n--- {rule_id} ({rule.get('file', 'unknown')}) ---")
                parts.append(f"  Name: {rule.get('name', 'N/A')}")
                parts.append(f"  Severity: {rule.get('severity', 'N/A')}")
                parts.append(f"  Enabled: {rule.get('enabled', True)}")

                thresholds = rule.get("thresholds", {})
                if thresholds:
                    parts.append(f"  Thresholds: {json.dumps(thresholds)}")

                rate_limit = rule.get("rate_limit", {})
                if rate_limit:
                    parts.append(f"  Rate Limit: {json.dumps(rate_limit)}")

                exclusions = rule.get("exclusions", {})
                n_excluded_addrs = len(exclusions.get("addresses", []))
                n_excluded_contracts = len(exclusions.get("contracts", []))
                if n_excluded_addrs or n_excluded_contracts:
                    parts.append(
                        f"  Exclusions: {n_excluded_addrs} addresses, "
                        f"{n_excluded_contracts} contracts"
                    )

        return "\n".join(parts)

    def analyze_and_recommend(self) -> List[TuningRecommendation]:
        """
        Analyze current rule performance and return tuning recommendations.
        """
        client = get_client()
        if not client:
            return []

        context = self._build_context()
        if "No feedback data" in context and "RULE DEFINITIONS" not in context:
            logger.info("no_data_for_tuning")
            return []

        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=2048,  # Need more tokens for multiple recommendations
                system=TUNER_SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": (
                            "Analyze these rules and their performance data. "
                            "Recommend specific changes to reduce false positives:\n\n"
                            f"{context}"
                        ),
                    }
                ],
            )

            raw = response.content[0].text.strip()
            if "```" in raw:
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            results = json.loads(raw)
            if not isinstance(results, list):
                results = [results]

            recommendations = []
            for r in results:
                rec = TuningRecommendation(
                    rule_id=r["rule_id"],
                    change_type=r["change_type"],
                    field=r.get("field", ""),
                    current_value=r.get("current_value"),
                    recommended_value=r.get("recommended_value"),
                    reasoning=r.get("reasoning", ""),
                    confidence=float(r.get("confidence", 0.5)),
                    expected_fp_reduction=float(
                        r.get("expected_fp_reduction", 0.0)
                    ),
                )
                recommendations.append(rec)

            logger.info(
                "tuning_recommendations_generated",
                count=len(recommendations),
                rules_affected=list({r.rule_id for r in recommendations}),
            )

            return recommendations

        except Exception as e:
            logger.error("rule_tuning_failed", error=str(e))
            return []

    def apply(self, recommendation: TuningRecommendation) -> bool:
        """
        Apply a single recommendation to the YAML rule file.

        Returns True if applied successfully.
        """
        rules = self._load_rule_definitions()
        rule = rules.get(recommendation.rule_id)
        if not rule:
            logger.error("rule_not_found", rule_id=recommendation.rule_id)
            return False

        yaml_file = self._rules_dir / rule["file"]
        if not yaml_file.exists():
            return False

        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)

            for r in data.get("rules", []):
                if r["id"] != recommendation.rule_id:
                    continue

                if recommendation.change_type == "raise_threshold":
                    parts = recommendation.field.split(".")
                    target = r
                    for part in parts[:-1]:
                        target = target.setdefault(part, {})
                    target[parts[-1]] = recommendation.recommended_value

                elif recommendation.change_type == "add_exclusion":
                    exclusions = r.setdefault("exclusions", {})
                    addr_list = exclusions.setdefault("addresses", [])
                    if recommendation.recommended_value not in addr_list:
                        addr_list.append(recommendation.recommended_value)

                elif recommendation.change_type == "lower_severity":
                    r["severity"] = recommendation.recommended_value

                elif recommendation.change_type == "disable":
                    r["enabled"] = False

                elif recommendation.change_type == "tighten_rate_limit":
                    rate_limit = r.setdefault("rate_limit", {})
                    if isinstance(recommendation.recommended_value, dict):
                        rate_limit.update(recommendation.recommended_value)
                    else:
                        rate_limit["max_alerts"] = recommendation.recommended_value

                break

            with open(yaml_file, "w") as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)

            logger.info(
                "tuning_applied",
                rule_id=recommendation.rule_id,
                change=recommendation.change_type,
                field=recommendation.field,
                new_value=recommendation.recommended_value,
            )
            return True

        except Exception as e:
            logger.error(
                "tuning_apply_failed",
                rule_id=recommendation.rule_id,
                error=str(e),
            )
            return False
