"""
End-to-End Integration Tests: Event → Rule Engine → Incident → LLM Triage → Feedback Loop
==========================================================================================

Tests the full Sentinel3 detection pipeline with mocked external dependencies
(database, LLM API) but real rule engine, confidence calculator, entity registry,
and feedback loop logic.
"""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, AsyncMock

from src.rules.engine import RuleEngine
from src.rules.feedback_loop import FeedbackLoop
from src.rules.confidence import ConfidenceCalculator, EvidenceBundle
from src.enrichment.entity_registry import (
    EntityRegistry,
    Entity,
    EntityType,
)
from src.ai.llm.incident_triage import IncidentTriage
from src.ai.llm.rate_limiter import LLMRateLimiter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_claude_response(text: str):
    """Create a mock Anthropic message response."""
    mock_resp = MagicMock()
    mock_content = MagicMock()
    mock_content.text = text
    mock_resp.content = [mock_content]
    mock_resp.usage = MagicMock()
    mock_resp.usage.input_tokens = 500
    mock_resp.usage.output_tokens = 200
    return mock_resp


def _whale_transfer_event(
    amount_usd: float = 25_000_000,
    from_address: str = "0xaaa0000000000000000000000000000000000001",
    to_address: str = "0xbbb0000000000000000000000000000000000002",
    chain: str = "ethereum",
) -> dict:
    """Build a whale-sized transfer event that should trigger high-severity rules."""
    return {
        "event_type": "Transfer",
        "chain": chain,
        "chain_id": chain,
        "tx_hash": "0xdeadbeef" + "0" * 56,
        "block_number": 19_000_000,
        "contract_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "from_address": from_address,
        "to_address": to_address,
        "amount": str(int(amount_usd * 1e6)),
        "amount_usd": amount_usd,
        "severity": "high",
        "raw_data": {},
    }


def _hacker_drain_event() -> dict:
    """Build a suspicious drain event from a known-malicious address."""
    return {
        "event_type": "Transfer",
        "chain": "ethereum",
        "chain_id": "ethereum",
        "tx_hash": "0xbadcafe" + "0" * 57,
        "block_number": 19_000_001,
        "contract_address": "0x6b175474e89094c44da98b954eedeac495271d0f",
        "from_address": "0xhacker0000000000000000000000000000000000",
        "to_address": "0xtornado0000000000000000000000000000000000",
        "amount": "50000000000000000000000",
        "amount_usd": 50_000_000,
        "severity": "critical",
        "raw_data": {},
    }


# ---------------------------------------------------------------------------
# 1. Rule Engine — loads rules, evaluates events, produces AlertMatch
# ---------------------------------------------------------------------------


class TestRuleEngineLoadsAndEvaluates:
    """Verify the rule engine loads YAML rules and matches events."""

    def setup_method(self):
        self.engine = RuleEngine()
        self.engine._feedback_loop = None
        self.engine._entity_registry = None
        self.engine._confidence_calc = None
        self.engine._invariant_engine = None
        self.engine._pattern_matcher = None
        self.engine._enricher = None

    def test_load_rules_from_directory(self):
        count = self.engine.load_rules_from_directory("config/rules")
        assert count > 0, "Should load at least one rule from config/rules"

    def test_whale_transfer_triggers_rule(self):
        self.engine.load_rules_from_directory("config/rules")
        event = _whale_transfer_event(amount_usd=25_000_000)
        matches = self.engine.evaluate(event)
        assert len(matches) >= 1, "A $25M transfer should trigger at least one rule"

    def test_small_transfer_no_match(self):
        self.engine.load_rules_from_directory("config/rules")
        event = _whale_transfer_event(amount_usd=50)
        matches = self.engine.evaluate(event)
        # Small transfers should not trigger high-value rules
        high_value_matches = [
            m for m in matches
            if m.rule.thresholds.get("min_amount_usd", 0) > 50
        ]
        assert len(high_value_matches) == 0

    def test_alert_match_to_dict(self):
        self.engine.load_rules_from_directory("config/rules")
        event = _whale_transfer_event()
        matches = self.engine.evaluate(event)
        if matches:
            d = matches[0].to_dict()
            assert "rule_id" in d
            assert "rule_name" in d
            assert "severity" in d
            assert "event" in d
            assert "confidence" in d


# ---------------------------------------------------------------------------
# 2. Confidence Calculator — evidence-weighted scoring
# ---------------------------------------------------------------------------


class TestConfidenceIntegration:
    """Verify dynamic confidence adjustment integrates with rule matches."""

    def setup_method(self):
        with patch("src.rules.confidence.get_entity_registry", return_value=None):
            with patch("src.rules.confidence.get_feedback_loop", return_value=None):
                self.calc = ConfidenceCalculator()
                self.calc._registry = None
                self.calc._feedback = None

    def test_high_amount_multiple_increases_confidence(self):
        evidence = EvidenceBundle(
            source_tier="neutral",
            dest_tier="neutral",
            amount_multiple=20.0,
        )
        base = 0.5
        adjusted = self.calc.calculate(base, evidence)
        assert adjusted > base, "High amount multiple should raise confidence"

    def test_trusted_both_sides_lowers_confidence(self):
        evidence = EvidenceBundle(
            source_tier="trusted",
            dest_tier="trusted",
        )
        base = 0.5
        adjusted = self.calc.calculate(base, evidence)
        assert adjusted < base, "Trusted source+dest should lower confidence"


# ---------------------------------------------------------------------------
# 3. Entity Registry — address classification & suppression
# ---------------------------------------------------------------------------


class TestEntityRegistrySuppression:
    """Verify entity registry suppresses rules for known addresses."""

    def test_trusted_address_suppresses_low_severity(self):
        registry = EntityRegistry()
        # Add a trusted exchange address
        registry.add_entity(Entity(
            address="0xbinance0000000000000000000000000000000000",
            entity_type=EntityType.CEX,
            name="Binance Hot Wallet",
            labels=["exchange"],
            risk_score=5.0,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            metadata={},
        ))

        # Trusted addresses should suppress low-severity alerts
        result = registry.should_suppress_severity(
            "0xbinance0000000000000000000000000000000000", "low"
        )
        assert result is True

    def test_unknown_address_does_not_suppress(self):
        registry = EntityRegistry()
        result = registry.should_suppress_severity(
            "0xunknown0000000000000000000000000000000000", "high"
        )
        assert result is False


# ---------------------------------------------------------------------------
# 4. Feedback Loop — TP/FP tracking and auto-suppression
# ---------------------------------------------------------------------------


class TestFeedbackLoopIntegration:
    """Verify feedback loop records verdicts and suppresses noisy rules."""

    def setup_method(self):
        self.loop = FeedbackLoop()

    def test_record_tp_and_fp(self):
        self.loop.record_feedback("rule-001", is_tp=True)
        self.loop.record_feedback("rule-001", is_tp=False)

        stats = self.loop.get_rule_stats("rule-001")
        assert stats is not None
        assert stats["tp_count"] == 1
        assert stats["fp_count"] == 1
        assert stats["total"] == 2

    def test_high_fp_rate_suppresses_rule(self):
        rule_id = "noisy-rule-999"
        # Record enough FPs to exceed threshold
        for _ in range(10):
            self.loop.record_feedback(rule_id, is_tp=False)
        self.loop.record_feedback(rule_id, is_tp=True)  # 1 TP, 10 FP = ~91%

        actions = self.loop.evaluate_rules()
        suppressed_rules = [a for a in actions if a[1] in ("suppressed", "auto_disabled")]
        rule_ids = [a[0] for a in suppressed_rules]
        assert rule_id in rule_ids, "Rule with >80% FP rate should be suppressed"

    def test_healthy_rule_not_suppressed(self):
        rule_id = "good-rule-100"
        for _ in range(10):
            self.loop.record_feedback(rule_id, is_tp=True)
        self.loop.record_feedback(rule_id, is_tp=False)  # 10 TP, 1 FP = ~9%

        assert not self.loop.is_suppressed(rule_id)

    def test_suppressed_rule_skipped_by_engine(self):
        """Integration: engine skips rules that feedback loop has suppressed."""
        engine = RuleEngine()
        engine._entity_registry = None
        engine._confidence_calc = None
        engine._invariant_engine = None
        engine._pattern_matcher = None
        engine._enricher = None
        engine.load_rules_from_directory("config/rules")

        # Set up a feedback loop with a suppressed rule
        fl = FeedbackLoop()
        # Pick a real rule from the loaded engine
        if not engine.rules:
            pytest.skip("No rules loaded")
        target_rule = engine.rules[0]

        for _ in range(20):
            fl.record_feedback(target_rule.id, is_tp=False)
        fl.evaluate_rules()

        assert fl.is_suppressed(target_rule.id), "Rule should be suppressed after 20 FPs"

        # Wire the loop into the engine
        engine._feedback_loop = fl

        # Evaluate — the suppressed rule should not match
        event = _whale_transfer_event()
        matches = engine.evaluate(event)
        matched_rule_ids = [m.rule.id for m in matches]
        assert target_rule.id not in matched_rule_ids, (
            f"Suppressed rule {target_rule.id} should not appear in matches"
        )


# ---------------------------------------------------------------------------
# 5. LLM Triage — Claude classifies alerts as TP/FP
# ---------------------------------------------------------------------------


class TestLLMTriageIntegration:
    """Verify LLM triage returns structured verdicts from mocked Claude API."""

    @patch("src.ai.llm.incident_triage.get_client")
    @patch("src.ai.llm.incident_triage.get_entity_registry", return_value=None)
    @patch("src.ai.llm.incident_triage.get_feedback_loop", return_value=None)
    def test_triage_true_positive_from_rule_match(self, mock_fl, mock_er, mock_client):
        """Full flow: rule match → to_dict() → LLM triage → verdict."""
        response_json = json.dumps({
            "verdict": "true_positive",
            "confidence": 0.92,
            "reasoning": "Large transfer to an unknown mixer address. High risk.",
            "suggested_action": "escalate",
            "risk_factors": ["mixer destination", "off-hours activity"],
            "mitigating_factors": [],
        })
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response(
            response_json
        )

        # Step 1: evaluate event through rule engine
        engine = RuleEngine()
        engine._feedback_loop = None
        engine._entity_registry = None
        engine._confidence_calc = None
        engine._invariant_engine = None
        engine._pattern_matcher = None
        engine._enricher = None
        engine.load_rules_from_directory("config/rules")

        event = _whale_transfer_event()
        matches = engine.evaluate(event)
        if not matches:
            pytest.skip("No rules matched the test event")

        # Step 2: triage through LLM
        triage = IncidentTriage(auto_feed_feedback=False)
        triage._registry = None
        triage._feedback = None

        alert_dict = matches[0].to_dict()
        verdict = triage.analyze(alert_dict)

        assert verdict is not None
        assert verdict.is_tp is True
        assert verdict.confidence >= 0.9
        assert verdict.suggested_action == "escalate"

    @patch("src.ai.llm.incident_triage.get_client")
    @patch("src.ai.llm.incident_triage.get_entity_registry", return_value=None)
    @patch("src.ai.llm.incident_triage.get_feedback_loop", return_value=None)
    def test_triage_false_positive_feeds_feedback_loop(self, mock_fl, mock_er, mock_client):
        """Verify FP verdict auto-feeds into feedback loop for suppression."""
        response_json = json.dumps({
            "verdict": "false_positive",
            "confidence": 0.88,
            "reasoning": "Routine exchange-to-exchange transfer.",
            "suggested_action": "dismiss",
            "risk_factors": [],
            "mitigating_factors": ["both addresses are exchanges"],
        })
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response(
            response_json
        )

        # Create a real feedback loop to capture verdicts
        feedback = FeedbackLoop()
        triage = IncidentTriage(auto_feed_feedback=True)
        triage._registry = None
        triage._feedback = feedback

        alert = {
            "rule_id": "large-bridge-transfer-101",
            "rule_name": "Large Cross-Chain Transfer",
            "severity": "high",
            "base_confidence": 0.7,
            "confidence": 0.75,
            "event": _whale_transfer_event(),
            "details": {},
            "evidence": {"source_tier": "trusted", "dest_tier": "trusted"},
        }

        verdict = triage.analyze(alert)
        assert verdict is not None
        assert verdict.is_tp is False

        # Verify feedback was recorded (confidence >= 0.8 triggers auto-feed)
        stats = feedback.get_rule_stats("large-bridge-transfer-101")
        assert stats is not None
        assert stats["fp_count"] == 1


# ---------------------------------------------------------------------------
# 6. LLM Async Triage — non-blocking variant
# ---------------------------------------------------------------------------


class TestLLMAsyncTriageIntegration:
    """Verify async LLM triage works end-to-end."""

    @pytest.mark.asyncio
    @patch("src.ai.llm.incident_triage.get_async_client")
    @patch("src.ai.llm.incident_triage.get_entity_registry", return_value=None)
    @patch("src.ai.llm.incident_triage.get_feedback_loop", return_value=None)
    async def test_async_triage_returns_verdict(self, mock_fl, mock_er, mock_async_client):
        response_json = json.dumps({
            "verdict": "true_positive",
            "confidence": 0.85,
            "reasoning": "Suspicious transfer pattern.",
            "suggested_action": "investigate",
            "risk_factors": ["unknown destination"],
            "mitigating_factors": ["known source"],
        })

        mock_client_instance = AsyncMock()
        mock_client_instance.messages.create = AsyncMock(
            return_value=_mock_claude_response(response_json)
        )
        mock_async_client.return_value = mock_client_instance

        triage = IncidentTriage(auto_feed_feedback=False)
        triage._registry = None
        triage._feedback = None

        alert = {
            "rule_id": "whale-alert-test",
            "rule_name": "Whale Transfer",
            "severity": "high",
            "confidence": 0.7,
            "event": _whale_transfer_event(),
            "details": {},
            "evidence": {},
        }

        verdict = await triage.analyze_async(alert)
        assert verdict is not None
        assert verdict.verdict == "true_positive"
        assert verdict.confidence == 0.85


# ---------------------------------------------------------------------------
# 7. Circuit Breaker — LLM rate limiter protects against cascading failures
# ---------------------------------------------------------------------------


class TestCircuitBreakerIntegration:
    """Verify the circuit breaker opens after repeated failures and recovers."""

    def test_circuit_breaker_opens_after_failures(self):
        limiter = LLMRateLimiter()
        # Simulate consecutive failures
        for _ in range(limiter.cb_failure_threshold):
            limiter.record_failure()

        assert not limiter.can_make_request(), (
            "Circuit should be open after threshold failures"
        )

        stats = limiter.get_usage_stats()
        assert stats["circuit_breaker"] == "open"

    def test_circuit_breaker_closes_on_success(self):
        limiter = LLMRateLimiter()
        # Open the circuit
        for _ in range(limiter.cb_failure_threshold):
            limiter.record_failure()
        assert not limiter.can_make_request()

        # Force half-open by resetting the open timestamp
        limiter._circuit_open_since = datetime(2000, 1, 1, tzinfo=timezone.utc)

        # Should allow one probe request (half-open)
        assert limiter.can_make_request()

        # Record success → circuit closes
        limiter.record_success()
        stats = limiter.get_usage_stats()
        assert stats["circuit_breaker"] == "closed"
        assert stats["consecutive_failures"] == 0

    def test_usage_stats_include_all_fields(self):
        limiter = LLMRateLimiter()
        limiter.record_request(input_tokens=1000, output_tokens=200)

        stats = limiter.get_usage_stats()
        assert "current_rpm" in stats
        assert "rpm_limit" in stats
        assert "daily_request_count" in stats
        assert "daily_spend_usd" in stats
        assert "circuit_breaker" in stats
        assert "total_failures" in stats
        assert "total_successes" in stats
        assert stats["daily_request_count"] == 1


# ---------------------------------------------------------------------------
# 8. Full Pipeline — event → rules → triage → feedback → suppression
# ---------------------------------------------------------------------------


class TestFullPipelineEndToEnd:
    """
    Integration test covering the complete detection lifecycle:
    1. Event ingested
    2. Rule engine evaluates → AlertMatch
    3. LLM triages alert → TriageVerdict
    4. Verdict fed into feedback loop
    5. Noisy rule eventually suppressed
    """

    @patch("src.ai.llm.incident_triage.get_client")
    @patch("src.ai.llm.incident_triage.get_entity_registry", return_value=None)
    @patch("src.ai.llm.incident_triage.get_feedback_loop", return_value=None)
    def test_repeated_fp_verdicts_suppress_rule(self, mock_fl, mock_er, mock_client):
        """
        Simulate: 10 events all triaged as FP → rule gets auto-suppressed → next
        event does not match that rule.
        """
        # --- Setup ---
        fp_response = json.dumps({
            "verdict": "false_positive",
            "confidence": 0.90,
            "reasoning": "Routine exchange withdrawal.",
            "suggested_action": "dismiss",
            "risk_factors": [],
            "mitigating_factors": ["known exchange"],
        })
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response(
            fp_response
        )

        feedback = FeedbackLoop()

        engine = RuleEngine()
        engine._entity_registry = None
        engine._confidence_calc = None
        engine._invariant_engine = None
        engine._pattern_matcher = None
        engine._enricher = None
        engine.load_rules_from_directory("config/rules")

        if not engine.rules:
            pytest.skip("No rules loaded")

        triage = IncidentTriage(auto_feed_feedback=True)
        triage._registry = None
        triage._feedback = feedback

        # --- Phase 1: Generate matches and triage them ---
        event = _whale_transfer_event()
        initial_matches = engine.evaluate(event)
        if not initial_matches:
            pytest.skip("No rules matched the whale transfer event")

        target_rule_id = initial_matches[0].rule.id

        # Simulate 12 FP verdicts for the same rule
        for _ in range(12):
            alert_dict = initial_matches[0].to_dict()
            verdict = triage.analyze(alert_dict)
            assert verdict is not None
            assert verdict.is_tp is False

        # --- Phase 2: Evaluate feedback and check suppression ---
        actions = feedback.evaluate_rules()
        suppressed = [a for a in actions if a[1] in ("suppressed", "auto_disabled")]
        suppressed_ids = [a[0] for a in suppressed]
        assert target_rule_id in suppressed_ids, (
            f"Rule {target_rule_id} should be suppressed after 12 FP verdicts"
        )

        # --- Phase 3: Wire feedback into engine, verify suppression ---
        engine._feedback_loop = feedback
        new_matches = engine.evaluate(event)
        new_match_ids = [m.rule.id for m in new_matches]
        assert target_rule_id not in new_match_ids, (
            f"Suppressed rule {target_rule_id} should not match after feedback suppression"
        )

    @patch("src.ai.llm.incident_triage.get_client")
    @patch("src.ai.llm.incident_triage.get_entity_registry", return_value=None)
    @patch("src.ai.llm.incident_triage.get_feedback_loop", return_value=None)
    def test_tp_verdict_does_not_suppress(self, mock_fl, mock_er, mock_client):
        """Rules with consistently TP verdicts should remain active."""
        tp_response = json.dumps({
            "verdict": "true_positive",
            "confidence": 0.95,
            "reasoning": "Confirmed attack pattern.",
            "suggested_action": "escalate",
            "risk_factors": ["hacker address"],
            "mitigating_factors": [],
        })
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response(
            tp_response
        )

        feedback = FeedbackLoop()
        triage = IncidentTriage(auto_feed_feedback=True)
        triage._registry = None
        triage._feedback = feedback

        engine = RuleEngine()
        engine._entity_registry = None
        engine._confidence_calc = None
        engine._invariant_engine = None
        engine._pattern_matcher = None
        engine._enricher = None
        engine.load_rules_from_directory("config/rules")

        if not engine.rules:
            pytest.skip("No rules loaded")

        event = _whale_transfer_event()
        matches = engine.evaluate(event)
        if not matches:
            pytest.skip("No rules matched")

        target_rule_id = matches[0].rule.id

        # 10 TP verdicts
        for _ in range(10):
            verdict = triage.analyze(matches[0].to_dict())
            assert verdict is not None
            assert verdict.is_tp is True

        actions = feedback.evaluate_rules()
        suppressed_ids = [a[0] for a in actions if a[1] in ("suppressed", "auto_disabled")]
        assert target_rule_id not in suppressed_ids

        # Rule should still match
        engine._feedback_loop = feedback
        new_matches = engine.evaluate(event)
        new_match_ids = [m.rule.id for m in new_matches]
        assert target_rule_id in new_match_ids
