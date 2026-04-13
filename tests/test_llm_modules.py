"""Tests for LLM-powered analysis modules."""
import json
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from src.ai.llm.incident_triage import IncidentTriage, TriageVerdict
from src.ai.llm.bytecode_analyzer import BytecodeAnalyzer, ContractAnalysis
from src.ai.llm.rule_tuner import RuleTuner, TuningRecommendation


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


class TestIncidentTriage:
    def _sample_alert(self):
        return {
            "rule_id": "whale-transfer-001",
            "rule_name": "Whale Transfer",
            "severity": "high",
            "base_confidence": 0.7,
            "confidence": 0.8,
            "event": {
                "event_type": "transfer",
                "chain": "ethereum",
                "amount_usd": 15000000,
                "from_address": "0x28c6c06298d514db089934071355e5743bf21d60",
                "to_address": "0x0000000000000000000000000000000000000001",
            },
            "details": {"threshold_exceeded": True},
            "evidence": {"source_tier": "trusted", "dest_tier": "neutral"},
        }

    @patch("src.ai.llm.incident_triage.get_client")
    @patch("src.ai.llm.incident_triage.get_entity_registry", return_value=None)
    @patch("src.ai.llm.incident_triage.get_feedback_loop", return_value=None)
    def test_true_positive_verdict(self, mock_fl, mock_er, mock_client):
        response_json = json.dumps({
            "verdict": "true_positive",
            "confidence": 0.9,
            "reasoning": "Large transfer to unknown address",
            "suggested_action": "escalate",
            "risk_factors": ["unknown destination"],
            "mitigating_factors": ["known source"]
        })
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response(response_json)

        triage = IncidentTriage(auto_feed_feedback=False)
        triage._registry = None
        triage._feedback = None
        verdict = triage.analyze(self._sample_alert())

        assert verdict is not None
        assert verdict.is_tp is True
        assert verdict.verdict == "true_positive"
        assert verdict.confidence == 0.9

    @patch("src.ai.llm.incident_triage.get_client")
    @patch("src.ai.llm.incident_triage.get_entity_registry", return_value=None)
    @patch("src.ai.llm.incident_triage.get_feedback_loop", return_value=None)
    def test_false_positive_verdict(self, mock_fl, mock_er, mock_client):
        response_json = json.dumps({
            "verdict": "false_positive",
            "confidence": 0.85,
            "reasoning": "Routine CEX to CEX transfer",
            "suggested_action": "dismiss",
            "risk_factors": [],
            "mitigating_factors": ["both addresses are exchanges"]
        })
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response(response_json)

        triage = IncidentTriage(auto_feed_feedback=False)
        triage._registry = None
        triage._feedback = None
        verdict = triage.analyze(self._sample_alert())

        assert verdict is not None
        assert verdict.is_tp is False
        assert verdict.suggested_action == "dismiss"

    @patch("src.ai.llm.incident_triage.get_client")
    @patch("src.ai.llm.incident_triage.get_entity_registry", return_value=None)
    @patch("src.ai.llm.incident_triage.get_feedback_loop", return_value=None)
    def test_no_client_returns_none(self, mock_fl, mock_er, mock_client):
        mock_client.return_value = None
        triage = IncidentTriage(auto_feed_feedback=False)
        triage._registry = None
        triage._feedback = None
        verdict = triage.analyze(self._sample_alert())
        assert verdict is None

    @patch("src.ai.llm.incident_triage.get_client")
    @patch("src.ai.llm.incident_triage.get_entity_registry", return_value=None)
    @patch("src.ai.llm.incident_triage.get_feedback_loop", return_value=None)
    def test_markdown_code_block_parsed(self, mock_fl, mock_er, mock_client):
        response_text = '```json\n{"verdict":"false_positive","confidence":0.7,"reasoning":"test","suggested_action":"dismiss","risk_factors":[],"mitigating_factors":[]}\n```'
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response(response_text)

        triage = IncidentTriage(auto_feed_feedback=False)
        triage._registry = None
        triage._feedback = None
        verdict = triage.analyze(self._sample_alert())
        assert verdict is not None
        assert verdict.verdict == "false_positive"

    def test_verdict_to_dict(self):
        v = TriageVerdict(
            rule_id="test", is_tp=True, confidence=0.9,
            verdict="true_positive", reasoning="test",
            suggested_action="escalate", risk_factors=["a"],
            mitigating_factors=["b"]
        )
        d = v.to_dict()
        assert d["rule_id"] == "test"
        assert d["is_tp"] is True


class TestBytecodeAnalyzer:
    def test_disassemble_basic(self):
        analyzer = BytecodeAnalyzer()
        # PUSH1 0x80 PUSH1 0x40 MSTORE
        bytecode = "6080604052"
        result = analyzer._disassemble(bytecode)
        assert "PUSH1" in result
        assert "MSTORE" in result

    def test_extract_patterns_flash_loan(self):
        analyzer = BytecodeAnalyzer()
        # Bytecode containing Aave flash loan selector
        bytecode = "0x00000023e30c8b0000"
        patterns = analyzer._extract_patterns(bytecode)
        assert patterns["has_flash_loan_callback"] is True

    def test_extract_patterns_no_threats(self):
        analyzer = BytecodeAnalyzer()
        bytecode = "0x6080604052"
        patterns = analyzer._extract_patterns(bytecode)
        assert patterns["has_flash_loan_callback"] is False

    @patch("src.ai.llm.bytecode_analyzer.get_client")
    def test_analyze_returns_analysis(self, mock_client):
        response_json = json.dumps({
            "summary": "Simple storage contract",
            "threat_assessment": "safe",
            "threat_level": 0.1,
            "identified_functions": ["store(uint256)"],
            "attack_vectors": [],
            "similar_to": [],
            "recommendations": ["No action needed"]
        })
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response(response_json)

        analyzer = BytecodeAnalyzer()
        analysis = analyzer.analyze("0x6080604052")

        assert analysis is not None
        assert analysis.threat_assessment == "safe"
        assert analysis.threat_level == 0.1

    @patch("src.ai.llm.bytecode_analyzer.get_client")
    def test_analyze_no_client(self, mock_client):
        mock_client.return_value = None
        analyzer = BytecodeAnalyzer()
        assert analyzer.analyze("0x6080604052") is None

    def test_analysis_to_dict(self):
        a = ContractAnalysis(
            contract_address="0x123",
            summary="test", threat_assessment="safe",
            threat_level=0.1, identified_functions=[],
            attack_vectors=[], similar_to=[],
            recommendations=[], decompiled_highlights=""
        )
        d = a.to_dict()
        assert d["threat_assessment"] == "safe"


class TestRuleTuner:
    @patch("src.ai.llm.rule_tuner.get_client")
    @patch("src.ai.llm.rule_tuner.get_feedback_loop", return_value=None)
    def test_analyze_returns_recommendations(self, mock_fl, mock_client):
        response_json = json.dumps([{
            "rule_id": "whale-transfer-001",
            "change_type": "raise_threshold",
            "field": "thresholds.min_amount_usd",
            "current_value": 5000000,
            "recommended_value": 15000000,
            "reasoning": "High FP rate from routine CEX transfers",
            "confidence": 0.85,
            "expected_fp_reduction": 0.40
        }])
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response(response_json)

        tuner = RuleTuner()
        tuner._feedback = None
        recs = tuner.analyze_and_recommend()

        assert len(recs) == 1
        assert recs[0].rule_id == "whale-transfer-001"
        assert recs[0].change_type == "raise_threshold"
        assert recs[0].confidence == 0.85

    @patch("src.ai.llm.rule_tuner.get_client")
    @patch("src.ai.llm.rule_tuner.get_feedback_loop", return_value=None)
    def test_empty_recommendations(self, mock_fl, mock_client):
        mock_client.return_value = MagicMock()
        mock_client.return_value.messages.create.return_value = _mock_claude_response("[]")

        tuner = RuleTuner()
        tuner._feedback = None
        recs = tuner.analyze_and_recommend()
        assert len(recs) == 0

    @patch("src.ai.llm.rule_tuner.get_client")
    @patch("src.ai.llm.rule_tuner.get_feedback_loop", return_value=None)
    def test_no_client_returns_empty(self, mock_fl, mock_client):
        mock_client.return_value = None
        tuner = RuleTuner()
        tuner._feedback = None
        recs = tuner.analyze_and_recommend()
        assert recs == []

    def test_recommendation_to_dict(self):
        rec = TuningRecommendation(
            rule_id="test", change_type="raise_threshold",
            field="thresholds.x", current_value=1, recommended_value=2,
            reasoning="test", confidence=0.9, expected_fp_reduction=0.5
        )
        d = rec.to_dict()
        assert d["rule_id"] == "test"
        assert d["confidence"] == 0.9
