"""
ML Threat Detector Tests
========================

Tests for the ThreatDetector heuristic pipeline, risk-to-severity mapping,
batch prediction, and fallback behaviour when PyTorch is unavailable.

torch is blocked at import time so every test exercises the heuristic path.
"""

import builtins

_real_import = builtins.__import__


def _patched_import(name, *args, **kwargs):
    if name == "torch" or name.startswith("torch."):
        raise ImportError(f"No module named '{name}' (mocked for test)")
    return _real_import(name, *args, **kwargs)


builtins.__import__ = _patched_import

import pytest
import pytest_asyncio

from src.ml.threat_detector import ThreatDetector, ThreatPrediction, ThreatTypes


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def detector() -> ThreatDetector:
    """ThreatDetector with no model (heuristic fallback)."""
    return ThreatDetector(model_path=None, vertex_endpoint=None, use_gpu=False)


@pytest.fixture
def safe_features() -> dict:
    """Feature set representing a normal, low-risk transaction."""
    return {
        "amount_usd": 500,
        "to_is_mixer": 0,
        "from_is_mixer": 0,
        "to_is_hacker": 0,
        "from_is_hacker": 0,
        "from_graph_risk_score": 0.1,
        "to_graph_risk_score": 0.05,
        "event_type_flashloan": 0,
        "is_night": 0,
        "from_graph_tx_count_log": 10,
    }


@pytest.fixture
def mixer_features() -> dict:
    """Feature set with mixer interaction."""
    return {
        "amount_usd": 200_000,
        "to_is_mixer": 1,
        "from_is_mixer": 0,
        "to_is_hacker": 0,
        "from_is_hacker": 0,
        "from_graph_risk_score": 0.3,
        "to_graph_risk_score": 0.2,
        "event_type_flashloan": 0,
        "is_night": 0,
        "from_graph_tx_count_log": 5,
    }


@pytest.fixture
def hacker_features() -> dict:
    """Feature set connected to a known hacker address."""
    return {
        "amount_usd": 50_000,
        "to_is_mixer": 0,
        "from_is_mixer": 0,
        "to_is_hacker": 1,
        "from_is_hacker": 0,
        "from_graph_risk_score": 0.2,
        "to_graph_risk_score": 0.9,
        "event_type_flashloan": 0,
        "is_night": 0,
        "from_graph_tx_count_log": 8,
    }


@pytest.fixture
def flashloan_features() -> dict:
    """Feature set for a large flash loan event."""
    return {
        "amount_usd": 15_000_000,
        "to_is_mixer": 0,
        "from_is_mixer": 0,
        "to_is_hacker": 0,
        "from_is_hacker": 0,
        "from_graph_risk_score": 0.3,
        "to_graph_risk_score": 0.2,
        "event_type_flashloan": 1,
        "is_night": 0,
        "from_graph_tx_count_log": 6,
    }


# ---------------------------------------------------------------------------
# 1. TestThreatPredictionDataclass
# ---------------------------------------------------------------------------


class TestThreatPredictionDataclass:
    def test_fields_present(self):
        pred = ThreatPrediction(
            is_threat=True,
            threat_probability=0.85,
            threat_type="flash_loan_attack",
            confidence=0.9,
            risk_score=75,
            top_factors=[{"factor": "large_amount", "impact": 40}],
            severity="HIGH",
            model_version="heuristic-1.0",
            inference_time_ms=1.5,
        )
        assert pred.is_threat is True
        assert pred.threat_probability == 0.85
        assert pred.threat_type == "flash_loan_attack"
        assert pred.confidence == 0.9
        assert pred.risk_score == 75
        assert len(pred.top_factors) == 1
        assert pred.severity == "HIGH"
        assert pred.model_version == "heuristic-1.0"
        assert pred.inference_time_ms == 1.5


# ---------------------------------------------------------------------------
# 2. TestHeuristicSafe
# ---------------------------------------------------------------------------


class TestHeuristicSafe:
    def test_low_risk_not_threat(self, detector: ThreatDetector, safe_features: dict):
        pred = detector._predict_heuristic(safe_features)
        assert pred.is_threat is False
        assert pred.threat_type == ThreatTypes.SAFE
        assert pred.risk_score < 40
        assert pred.severity == "LOW"

    def test_empty_features_is_safe(self, detector: ThreatDetector):
        pred = detector._predict_heuristic({})
        assert pred.is_threat is False
        assert pred.risk_score < 40


# ---------------------------------------------------------------------------
# 3. TestHeuristicHighRisk -- mixer interaction
# ---------------------------------------------------------------------------


class TestHeuristicHighRisk:
    def test_mixer_is_threat(self, detector: ThreatDetector, mixer_features: dict):
        pred = detector._predict_heuristic(mixer_features)
        assert pred.is_threat is True
        assert pred.risk_score >= 50
        assert pred.threat_type == ThreatTypes.SUSPICIOUS_TRANSFER

    def test_mixer_factors_include_mixer(self, detector: ThreatDetector, mixer_features: dict):
        pred = detector._predict_heuristic(mixer_features)
        factor_names = [f["factor"] for f in pred.top_factors]
        assert any("Mixer" in f for f in factor_names)


# ---------------------------------------------------------------------------
# 4. TestHeuristicCritical -- hacker connection
# ---------------------------------------------------------------------------


class TestHeuristicCritical:
    def test_hacker_connection_high_risk(self, detector: ThreatDetector, hacker_features: dict):
        pred = detector._predict_heuristic(hacker_features)
        assert pred.is_threat is True
        assert pred.risk_score >= 80
        assert pred.severity in ("CRITICAL", "HIGH")

    def test_hacker_plus_high_graph_risk(self, detector: ThreatDetector, hacker_features: dict):
        """to_graph_risk_score > 0.6 adds another +30."""
        pred = detector._predict_heuristic(hacker_features)
        # 80 (hacker) + 30 (to_graph_risk) = 110 capped to 100
        assert pred.risk_score == 100
        assert pred.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# 5. TestHeuristicFlashLoan
# ---------------------------------------------------------------------------


class TestHeuristicFlashLoan:
    def test_large_flashloan_detected(self, detector: ThreatDetector, flashloan_features: dict):
        pred = detector._predict_heuristic(flashloan_features)
        assert pred.is_threat is True
        # 40 (>10M amount) + 30 (flashloan >1M) = 70
        assert pred.risk_score >= 70
        assert pred.threat_type == ThreatTypes.FLASH_LOAN_ATTACK


# ---------------------------------------------------------------------------
# 6. TestRiskToSeverity
# ---------------------------------------------------------------------------


class TestRiskToSeverity:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, "LOW"),
            (20, "LOW"),
            (39, "LOW"),
            (40, "MEDIUM"),
            (59, "MEDIUM"),
            (60, "HIGH"),
            (79, "HIGH"),
            (80, "CRITICAL"),
            (100, "CRITICAL"),
        ],
    )
    def test_risk_to_severity_mapping(self, detector: ThreatDetector, score: int, expected: str):
        assert detector._risk_to_severity(score) == expected


# ---------------------------------------------------------------------------
# 7. TestBatchPredict
# ---------------------------------------------------------------------------


class TestBatchPredict:
    @pytest.mark.asyncio
    async def test_batch_returns_list(
        self,
        detector: ThreatDetector,
        safe_features: dict,
        mixer_features: dict,
    ):
        results = await detector.batch_predict([safe_features, mixer_features])
        assert len(results) == 2
        assert isinstance(results[0], ThreatPrediction)
        assert isinstance(results[1], ThreatPrediction)

    @pytest.mark.asyncio
    async def test_batch_order_preserved(
        self,
        detector: ThreatDetector,
        safe_features: dict,
        hacker_features: dict,
    ):
        results = await detector.batch_predict([safe_features, hacker_features])
        assert results[0].is_threat is False
        assert results[1].is_threat is True


# ---------------------------------------------------------------------------
# 8. TestFallbackToHeuristic
# ---------------------------------------------------------------------------


class TestFallbackToHeuristic:
    def test_no_model_loaded(self, detector: ThreatDetector):
        """With torch blocked, model should be None."""
        assert detector.model is None
        assert detector.device is None

    @pytest.mark.asyncio
    async def test_predict_uses_heuristic(self, detector: ThreatDetector, safe_features: dict):
        """predict() should fall through to _predict_heuristic when no model."""
        pred = await detector.predict(safe_features, use_vertex=False)
        assert pred.model_version == "heuristic-1.0"
        assert pred.is_threat is False

    @pytest.mark.asyncio
    async def test_predict_inference_time_set(self, detector: ThreatDetector, safe_features: dict):
        pred = await detector.predict(safe_features)
        assert pred.inference_time_ms >= 0
