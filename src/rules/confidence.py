"""
Evidence-Weighted Confidence Calculator

Replaces static YAML confidence values with dynamic scores computed
from multiple evidence signals:
  - Entity reputation (source/dest address classification)
  - Amount magnitude (how far above threshold)
  - Temporal signals (time-of-day, burst patterns)
  - Historical rule accuracy (from feedback loop TP/FP ratios)
  - Corroboration (multiple rules firing on same event)
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import math
import structlog

logger = structlog.get_logger(__name__)

# Import entity registry for reputation scoring
try:
    from src.enrichment.entity_registry import (
        get_entity_registry,
        ReputationTier,
        EntityType,
    )
    ENTITY_AVAILABLE = True
except ImportError:
    ENTITY_AVAILABLE = False

# Import feedback loop for historical accuracy
try:
    from src.rules.feedback_loop import get_feedback_loop
    FEEDBACK_AVAILABLE = True
except ImportError:
    FEEDBACK_AVAILABLE = False


@dataclass
class EvidenceBundle:
    """Collected evidence signals for confidence calculation."""
    # Entity reputation
    source_tier: str = "neutral"       # ReputationTier value
    dest_tier: str = "neutral"
    source_entity_name: Optional[str] = None
    dest_entity_name: Optional[str] = None

    # Amount signals
    amount_usd: float = 0.0
    threshold_usd: float = 0.0        # The rule's min_amount_usd
    amount_multiple: float = 0.0       # amount_usd / threshold_usd

    # Temporal signals
    is_off_hours: bool = False         # UTC weekend or 00:00-06:00
    events_last_hour: int = 0          # Same-address activity count

    # Historical rule accuracy
    rule_fp_rate: float = 0.0          # From feedback loop
    rule_sample_count: int = 0

    # Corroboration
    corroborating_rules: int = 0       # Other rules that also matched this event

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_tier": self.source_tier,
            "dest_tier": self.dest_tier,
            "source_entity": self.source_entity_name,
            "dest_entity": self.dest_entity_name,
            "amount_usd": self.amount_usd,
            "threshold_usd": self.threshold_usd,
            "amount_multiple": round(self.amount_multiple, 2),
            "is_off_hours": self.is_off_hours,
            "rule_fp_rate": round(self.rule_fp_rate, 3),
            "corroborating_rules": self.corroborating_rules,
        }


class ConfidenceCalculator:
    """
    Computes evidence-weighted confidence for alert matches.

    Weights (sum to 1.0):
      - reputation:    0.30  (both source + dest)
      - magnitude:     0.25  (how far above threshold)
      - history:       0.25  (rule's historical TP rate)
      - corroboration: 0.10  (multiple rules match)
      - temporal:      0.10  (off-hours activity)
    """

    WEIGHT_REPUTATION = 0.30
    WEIGHT_MAGNITUDE = 0.25
    WEIGHT_HISTORY = 0.25
    WEIGHT_CORROBORATION = 0.10
    WEIGHT_TEMPORAL = 0.10

    def __init__(self):
        self._registry = get_entity_registry() if ENTITY_AVAILABLE else None
        self._feedback = get_feedback_loop() if FEEDBACK_AVAILABLE else None

    def build_evidence(
        self,
        event: Dict[str, Any],
        rule_id: str,
        rule_threshold_usd: float = 0.0,
        corroborating_count: int = 0,
    ) -> EvidenceBundle:
        """Gather evidence signals from event and rule context."""
        evidence = EvidenceBundle()

        # --- Entity reputation ---
        if self._registry:
            source_addr = (
                event.get("from_address")
                or event.get("source_address")
                or ""
            )
            dest_addr = (
                event.get("to_address")
                or event.get("dest_address")
                or ""
            )

            if source_addr:
                src_entity = self._registry.classify(source_addr)
                evidence.source_tier = self._registry.get_reputation_tier(source_addr).value
                evidence.source_entity_name = src_entity.name

            if dest_addr:
                dst_entity = self._registry.classify(dest_addr)
                evidence.dest_tier = self._registry.get_reputation_tier(dest_addr).value
                evidence.dest_entity_name = dst_entity.name

        # --- Amount magnitude ---
        try:
            evidence.amount_usd = float(event.get("amount_usd", 0) or 0)
        except (ValueError, TypeError):
            evidence.amount_usd = 0.0

        evidence.threshold_usd = rule_threshold_usd
        if rule_threshold_usd > 0 and evidence.amount_usd > 0:
            evidence.amount_multiple = evidence.amount_usd / rule_threshold_usd
        else:
            evidence.amount_multiple = 1.0

        # --- Temporal ---
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        evidence.is_off_hours = now.weekday() >= 5 or now.hour < 6

        # --- Historical accuracy ---
        if self._feedback:
            stats = self._feedback.get_rule_stats(rule_id)
            if stats:
                evidence.rule_fp_rate = stats.get("fp_rate", 0.0)
                evidence.rule_sample_count = stats.get("total", 0)

        # --- Corroboration ---
        evidence.corroborating_rules = corroborating_count

        return evidence

    def calculate(
        self,
        base_confidence: float,
        evidence: EvidenceBundle,
    ) -> float:
        """
        Calculate dynamic confidence score from evidence.

        Returns a float in [0.0, 1.0].

        The base_confidence from the YAML rule is used as the starting anchor
        and then adjusted by evidence weights.
        """
        scores = {}

        # 1. Reputation score (0.0 - 1.0)
        #    MALICIOUS source/dest → boost confidence
        #    TRUSTED both sides → reduce confidence (likely routine)
        scores["reputation"] = self._score_reputation(evidence)

        # 2. Magnitude score (0.0 - 1.0)
        #    Higher multiples above threshold → higher confidence
        scores["magnitude"] = self._score_magnitude(evidence)

        # 3. Historical accuracy (0.0 - 1.0)
        #    Low FP rate → high confidence; high FP rate → penalize
        scores["history"] = self._score_history(evidence)

        # 4. Corroboration (0.0 - 1.0)
        #    Multiple rules matching same event → higher confidence
        scores["corroboration"] = self._score_corroboration(evidence)

        # 5. Temporal (0.0 - 1.0)
        #    Off-hours activity → slight confidence boost (more suspicious)
        scores["temporal"] = self._score_temporal(evidence)

        # Weighted combination
        weighted = (
            scores["reputation"] * self.WEIGHT_REPUTATION
            + scores["magnitude"] * self.WEIGHT_MAGNITUDE
            + scores["history"] * self.WEIGHT_HISTORY
            + scores["corroboration"] * self.WEIGHT_CORROBORATION
            + scores["temporal"] * self.WEIGHT_TEMPORAL
        )

        # Blend with base confidence: 40% base, 60% evidence
        final = 0.4 * base_confidence + 0.6 * weighted

        # Clamp to [0.05, 0.99]
        final = max(0.05, min(0.99, final))

        logger.debug(
            "confidence_calculated",
            base=round(base_confidence, 3),
            final=round(final, 3),
            scores={k: round(v, 3) for k, v in scores.items()},
            weighted=round(weighted, 3),
        )

        return round(final, 4)

    def _score_reputation(self, evidence: EvidenceBundle) -> float:
        """Score based on entity reputation of source and destination."""
        tier_scores = {
            "malicious": 1.0,
            "suspicious": 0.8,
            "neutral": 0.5,
            "known": 0.2,
            "trusted": 0.1,
        }

        src_score = tier_scores.get(evidence.source_tier, 0.5)
        dst_score = tier_scores.get(evidence.dest_tier, 0.5)

        # Source reputation matters more (60/40 split)
        return 0.6 * src_score + 0.4 * dst_score

    def _score_magnitude(self, evidence: EvidenceBundle) -> float:
        """Score based on how far amount exceeds threshold."""
        if evidence.amount_multiple <= 0:
            return 0.3  # No amount data

        # Log scale: 1x = 0.3, 2x = 0.5, 5x = 0.7, 10x = 0.85, 100x = 1.0
        if evidence.amount_multiple < 1:
            return 0.1
        score = 0.3 + 0.7 * (1 - 1 / (1 + math.log10(evidence.amount_multiple)))
        return min(1.0, score)

    def _score_history(self, evidence: EvidenceBundle) -> float:
        """Score based on rule's historical accuracy."""
        if evidence.rule_sample_count < 5:
            return 0.5  # Not enough data, neutral

        # TP rate = 1 - FP rate. Direct mapping.
        tp_rate = 1.0 - evidence.rule_fp_rate
        return tp_rate

    def _score_corroboration(self, evidence: EvidenceBundle) -> float:
        """Score based on how many other rules also matched."""
        if evidence.corroborating_rules == 0:
            return 0.3  # Single rule match
        if evidence.corroborating_rules == 1:
            return 0.6
        if evidence.corroborating_rules == 2:
            return 0.8
        return 1.0  # 3+ corroborating rules

    def _score_temporal(self, evidence: EvidenceBundle) -> float:
        """Score based on temporal signals."""
        if evidence.is_off_hours:
            return 0.7  # Off-hours activity more suspicious
        return 0.4  # Normal hours


# Singleton
_calculator: Optional[ConfidenceCalculator] = None


def get_confidence_calculator() -> ConfidenceCalculator:
    """Get or create global confidence calculator."""
    global _calculator
    if _calculator is None:
        _calculator = ConfidenceCalculator()
    return _calculator
