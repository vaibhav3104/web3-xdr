"""
Unsupervised Anomaly Detection for Zero-Day Threat Discovery
=============================================================

Uses Isolation Forest and statistical methods to detect events that deviate
from learned normal patterns, catching attacks that don't match known signatures.

Detectors:
- StatisticalAnomalyDetector: Z-score on rolling windows (fast, online)
- IsolationForestDetector: sklearn Isolation Forest (batch, high-accuracy)
- TemporalAnomalyDetector: Unusual event timing patterns
- AnomalyDetectionEngine: Orchestrator combining all methods
"""
from __future__ import annotations

import os
import pickle
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog

logger = structlog.get_logger(__name__)

# Try to import sklearn (optional for IsolationForest)
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("sklearn_not_available", hint="IsolationForest detector disabled")


@dataclass
class AnomalyResult:
    """Result from anomaly detection analysis."""

    event_id: str
    anomaly_score: float  # higher = more anomalous
    is_anomalous: bool
    features: Dict[str, float]
    explanation: str
    detector: str  # which detector flagged it
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Statistical Detector
# ============================================================================

class StatisticalAnomalyDetector:
    """Fast statistical anomaly detection using rolling z-scores."""

    def __init__(self, window_size: int = 1000, z_threshold: float = 3.0):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self._stats: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))

    def detect(self, features: Dict[str, float], chain_id: str = "global") -> Tuple[bool, float, str]:
        """Detect anomalies using z-score on rolling window."""
        max_z = 0.0
        anomalous_features: list[str] = []

        for feat_name, value in features.items():
            window = self._stats[chain_id][feat_name]
            window.append(value)

            if len(window) > self.window_size:
                window.pop(0)

            if len(window) < 10:
                continue

            mean = np.mean(window[:-1])
            std = np.std(window[:-1])

            if std == 0:
                continue

            z = abs((value - mean) / std)
            if z > max_z:
                max_z = z

            if z > self.z_threshold:
                anomalous_features.append(f"{feat_name} (z={z:.1f})")

        is_anomalous = max_z > self.z_threshold
        explanation = (
            f"Statistical anomaly: {', '.join(anomalous_features)}"
            if anomalous_features
            else "Normal"
        )

        return is_anomalous, max_z, explanation


# ============================================================================
# Isolation Forest Detector
# ============================================================================

class IsolationForestDetector:
    """Isolation Forest-based anomaly detection."""

    def __init__(self, contamination: float = 0.01, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model: Any = None
        self.feature_names: List[str] = []
        self._training_buffer: List[Dict[str, float]] = []
        self.min_training_samples = 500
        self.is_trained = False

    def add_sample(self, features: Dict[str, float]):
        """Add a sample to the training buffer."""
        self._training_buffer.append(features)

        if len(self._training_buffer) >= self.min_training_samples and not self.is_trained:
            self.train()

    def train(self, samples: Optional[List[Dict[str, float]]] = None):
        """Train the Isolation Forest model."""
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn_not_available", hint="Skipping IF training")
            return

        data = samples or self._training_buffer
        if len(data) < self.min_training_samples:
            logger.info(
                "insufficient_training_data",
                current=len(data),
                required=self.min_training_samples,
            )
            return

        self.feature_names = sorted(data[0].keys())
        X = np.array([[s.get(f, 0) for f in self.feature_names] for s in data])

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        self.is_trained = True
        logger.info("isolation_forest_trained", samples=len(data), features=len(self.feature_names))

    def detect(self, features: Dict[str, float]) -> Tuple[bool, float, str]:
        """Detect anomaly using trained model."""
        if not self.is_trained or self.model is None:
            self.add_sample(features)
            return False, 0.0, "Model not yet trained"

        X = np.array([[features.get(f, 0) for f in self.feature_names]])
        score = self.model.decision_function(X)[0]
        prediction = self.model.predict(X)[0]

        is_anomalous = prediction == -1

        if is_anomalous:
            # Identify which features are most unusual
            feature_scores = [
                (fname, features.get(fname, 0))
                for fname in self.feature_names
            ]
            top_features = sorted(feature_scores, key=lambda x: abs(x[1]), reverse=True)[:3]
            explanation = (
                f"Isolation Forest anomaly (score={score:.3f}): "
                f"top features: {', '.join(f'{n}={v:.2f}' for n, v in top_features)}"
            )
        else:
            explanation = "Normal"

        # Negate score so higher = more anomalous (IF returns negative for anomalies)
        return is_anomalous, float(-score), explanation

    def save(self, path: str):
        """Save trained model to disk."""
        if self.model:
            with open(path, "wb") as f:
                pickle.dump({"model": self.model, "feature_names": self.feature_names}, f)
            logger.info("isolation_forest_saved", path=path)

    def load(self, path: str):
        """Load trained model from disk."""
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = pickle.load(f)  # noqa: S301
                self.model = data["model"]
                self.feature_names = data["feature_names"]
                self.is_trained = True
            logger.info("isolation_forest_loaded", path=path)


# ============================================================================
# Temporal Detector
# ============================================================================

class TemporalAnomalyDetector:
    """Detects temporal anomalies -- unusual event timing patterns."""

    def __init__(self, window_days: int = 7):
        self._event_times: Dict[str, List[datetime]] = defaultdict(list)
        self._hourly_counts: Dict[str, Dict[int, List[int]]] = defaultdict(lambda: defaultdict(list))
        self.window_days = window_days

    def detect(self, chain_id: str, event_type: str, timestamp: datetime) -> Tuple[bool, float, str]:
        """Detect temporal anomalies (spikes/drops in event frequency)."""
        key = f"{chain_id}:{event_type}"
        self._event_times[key].append(timestamp)

        # Count events in the last hour
        hour = timestamp.hour
        cutoff = timestamp - timedelta(hours=1)
        recent = [t for t in self._event_times[key] if t >= cutoff]
        current_count = len(recent)

        # Track hourly counts for baseline
        history = self._hourly_counts[key][hour]
        history.append(current_count)
        if len(history) > self.window_days * 24:
            history.pop(0)

        if len(history) < 24:
            return False, 0.0, "Insufficient history"

        mean = np.mean(history[:-1])
        std = np.std(history[:-1]) or 1.0
        z = (current_count - mean) / std

        is_anomalous = abs(z) > 3.0
        score = abs(z)

        if is_anomalous:
            direction = "spike" if z > 0 else "drop"
            explanation = (
                f"Temporal anomaly: {event_type} {direction} on {chain_id} "
                f"-- {current_count} events/hour vs avg {mean:.0f} (z={z:.1f})"
            )
        else:
            explanation = "Normal timing"

        # Prune old data
        cutoff_old = timestamp - timedelta(days=self.window_days)
        self._event_times[key] = [t for t in self._event_times[key] if t >= cutoff_old]

        return is_anomalous, score, explanation


# ============================================================================
# Orchestrator
# ============================================================================

class AnomalyDetectionEngine:
    """Orchestrates multiple anomaly detection methods for zero-day discovery."""

    def __init__(self, config: Optional[dict] = None):
        config = config or {}
        self.statistical = StatisticalAnomalyDetector(
            z_threshold=config.get("z_threshold", 3.0),
        )
        self.isolation_forest = IsolationForestDetector(
            contamination=config.get("contamination", 0.01),
        )
        self.temporal = TemporalAnomalyDetector()
        self.enabled = config.get("enabled", True)
        self._anomaly_history: List[AnomalyResult] = []

    # -- Feature extraction ---------------------------------------------------

    def extract_features(self, event_data: dict) -> Dict[str, float]:
        """Extract numerical features from a raw event dictionary."""
        features: Dict[str, float] = {}

        features["amount_usd"] = float(event_data.get("amount_usd", 0) or 0)
        features["block_number"] = float(event_data.get("block_number", 0) or 0)
        features["log_amount"] = np.log1p(features["amount_usd"])

        # Event type as numeric
        event_types = {
            "TRANSFER": 1, "LOCK": 2, "UNLOCK": 3, "MINT": 4, "BURN": 5,
            "BRIDGE_DEPOSIT": 6, "SWAP": 7, "FLASH_BORROW": 8, "CONTRACT_DEPLOY": 9,
        }
        et = str(event_data.get("event_type", "")).upper()
        features["event_type_code"] = float(event_types.get(et, 0))

        # Severity as numeric
        sev_map = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        features["severity_code"] = float(
            sev_map.get(str(event_data.get("severity", "")).upper(), 0)
        )

        # Address features
        from_addr = event_data.get("from_address", "") or event_data.get("source_address", "") or ""
        to_addr = event_data.get("to_address", "") or event_data.get("dest_address", "") or ""
        features["has_from"] = 1.0 if from_addr else 0.0
        features["has_to"] = 1.0 if to_addr else 0.0
        features["same_sender_receiver"] = 1.0 if from_addr and from_addr == to_addr else 0.0

        return features

    # -- Core analysis --------------------------------------------------------

    async def analyze_event(self, event_data: dict) -> Optional[AnomalyResult]:
        """Run all anomaly detectors on an event."""
        if not self.enabled:
            return None

        features = self.extract_features(event_data)
        chain_id = event_data.get("chain_id", "unknown")
        event_type = str(event_data.get("event_type", ""))
        event_id = event_data.get("event_id", "")
        timestamp = event_data.get("block_timestamp", datetime.now(timezone.utc))

        results: List[Tuple[str, float, str]] = []

        # 1. Statistical detection
        stat_anomaly, stat_score, stat_exp = self.statistical.detect(features, chain_id)
        if stat_anomaly:
            results.append(("statistical", stat_score, stat_exp))

        # 2. Isolation Forest detection
        if_anomaly, if_score, if_exp = self.isolation_forest.detect(features)
        if if_anomaly:
            results.append(("isolation_forest", if_score, if_exp))

        # 3. Temporal detection
        if isinstance(timestamp, datetime):
            temp_anomaly, temp_score, temp_exp = self.temporal.detect(
                chain_id, event_type, timestamp,
            )
            if temp_anomaly:
                results.append(("temporal", temp_score, temp_exp))

        if not results:
            return None

        # Pick the strongest signal
        best = max(results, key=lambda x: x[1])

        result = AnomalyResult(
            event_id=event_id,
            anomaly_score=best[1],
            is_anomalous=True,
            features=features,
            explanation=best[2],
            detector=best[0],
        )

        self._anomaly_history.append(result)
        # Trim history to avoid unbounded memory growth
        if len(self._anomaly_history) > 1000:
            self._anomaly_history = self._anomaly_history[-500:]

        return result

    # -- Query helpers --------------------------------------------------------

    def get_recent_anomalies(self, limit: int = 50) -> List[dict]:
        """Get recent anomalies for API / dashboard."""
        return [
            {
                "event_id": a.event_id,
                "score": a.anomaly_score,
                "detector": a.detector,
                "explanation": a.explanation,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in self._anomaly_history[-limit:]
        ]

    def get_stats(self) -> dict:
        """Get anomaly detection engine statistics."""
        return {
            "total_anomalies": len(self._anomaly_history),
            "isolation_forest_trained": self.isolation_forest.is_trained,
            "training_buffer_size": len(self.isolation_forest._training_buffer),
            "sklearn_available": SKLEARN_AVAILABLE,
            "enabled": self.enabled,
        }


# ============================================================================
# Module-level singleton
# ============================================================================

_engine: Optional[AnomalyDetectionEngine] = None


def get_anomaly_engine(config: Optional[dict] = None) -> AnomalyDetectionEngine:
    """Get or create the global anomaly detection engine."""
    global _engine
    if _engine is None:
        _engine = AnomalyDetectionEngine(config)
    return _engine
