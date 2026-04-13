"""Tests for evidence-weighted confidence calculator."""
import pytest
from unittest.mock import patch, MagicMock

from src.rules.confidence import ConfidenceCalculator, EvidenceBundle


class TestEvidenceBundle:
    def test_default_values(self):
        eb = EvidenceBundle()
        assert eb.source_tier == "neutral"
        assert eb.dest_tier == "neutral"
        assert eb.amount_usd == 0.0

    def test_to_dict(self):
        eb = EvidenceBundle(source_tier="malicious", amount_usd=1000000)
        d = eb.to_dict()
        assert d["source_tier"] == "malicious"
        assert d["amount_usd"] == 1000000


class TestConfidenceCalculator:
    def setup_method(self):
        # Patch singletons so tests don't depend on global state
        with patch("src.rules.confidence.get_entity_registry", return_value=None):
            with patch("src.rules.confidence.get_feedback_loop", return_value=None):
                self.calc = ConfidenceCalculator()
                self.calc._registry = None
                self.calc._feedback = None

    def test_malicious_source_boosts_confidence(self):
        evidence = EvidenceBundle(source_tier="malicious", dest_tier="neutral")
        score = self.calc.calculate(0.5, evidence)
        # Malicious source should push confidence up
        assert score > 0.5

    def test_trusted_both_sides_lowers_confidence(self):
        evidence = EvidenceBundle(source_tier="trusted", dest_tier="trusted")
        score = self.calc.calculate(0.5, evidence)
        assert score < 0.5

    def test_high_amount_multiple_boosts(self):
        evidence = EvidenceBundle(amount_multiple=10.0)
        score_high = self.calc.calculate(0.5, evidence)
        evidence_low = EvidenceBundle(amount_multiple=1.0)
        score_low = self.calc.calculate(0.5, evidence_low)
        assert score_high > score_low

    def test_high_fp_rate_lowers_confidence(self):
        evidence = EvidenceBundle(rule_fp_rate=0.9, rule_sample_count=100)
        score = self.calc.calculate(0.5, evidence)
        evidence_low_fp = EvidenceBundle(rule_fp_rate=0.1, rule_sample_count=100)
        score_low_fp = self.calc.calculate(0.5, evidence_low_fp)
        assert score < score_low_fp

    def test_corroboration_boosts(self):
        ev1 = EvidenceBundle(corroborating_rules=0)
        ev3 = EvidenceBundle(corroborating_rules=3)
        s1 = self.calc.calculate(0.5, ev1)
        s3 = self.calc.calculate(0.5, ev3)
        assert s3 > s1

    def test_off_hours_boosts(self):
        ev_on = EvidenceBundle(is_off_hours=False)
        ev_off = EvidenceBundle(is_off_hours=True)
        s_on = self.calc.calculate(0.5, ev_on)
        s_off = self.calc.calculate(0.5, ev_off)
        assert s_off > s_on

    def test_clamps_to_range(self):
        # Very high evidence
        evidence = EvidenceBundle(
            source_tier="malicious", dest_tier="malicious",
            amount_multiple=100.0, corroborating_rules=5,
            is_off_hours=True, rule_fp_rate=0.0, rule_sample_count=100
        )
        score = self.calc.calculate(1.0, evidence)
        assert score <= 0.99

        # Very low evidence
        evidence_low = EvidenceBundle(
            source_tier="trusted", dest_tier="trusted",
            amount_multiple=0.1, rule_fp_rate=1.0, rule_sample_count=100
        )
        score_low = self.calc.calculate(0.0, evidence_low)
        assert score_low >= 0.05

    def test_score_magnitude_no_data(self):
        score = self.calc._score_magnitude(EvidenceBundle(amount_multiple=0))
        assert score == 0.3

    def test_score_history_insufficient_samples(self):
        score = self.calc._score_history(EvidenceBundle(rule_sample_count=3))
        assert score == 0.5
