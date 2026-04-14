"""
Anomaly Detection API Routes
=============================

REST API endpoints for unsupervised anomaly detection.
Exposes zero-day threat discovery via statistical, Isolation Forest,
and temporal anomaly detectors.
"""

from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.ml.anomaly_detector import AnomalyDetectionEngine, get_anomaly_engine

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/anomaly", tags=["Anomaly Detection"])

# Global engine instance
_engine: Optional[AnomalyDetectionEngine] = None


def _get_engine() -> AnomalyDetectionEngine:
    """Lazy-init the anomaly detection engine."""
    global _engine
    if _engine is None:
        _engine = get_anomaly_engine()
    return _engine


# ============================================================================
# Request / Response models
# ============================================================================

class AnalyzeEventRequest(BaseModel):
    """Request body for single-event anomaly analysis."""
    event: Dict[str, Any] = Field(..., description="Raw event data to analyze")


class AnomalyResultResponse(BaseModel):
    """Response for a detected anomaly."""
    event_id: str
    score: float
    detector: str
    explanation: str
    timestamp: str


class TrainResponse(BaseModel):
    """Response after triggering training."""
    success: bool
    message: str
    stats: Dict[str, Any]


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/recent", response_model=List[AnomalyResultResponse])
async def get_recent_anomalies(limit: int = 50):
    """
    Get recent anomaly detections.

    Returns the most recent anomalies found by the detection engine,
    ordered chronologically (oldest first within the window).
    """
    engine = _get_engine()
    anomalies = engine.get_recent_anomalies(limit=limit)
    return anomalies


@router.get("/stats")
async def get_anomaly_stats():
    """
    Get anomaly detection engine statistics.

    Returns training status, buffer sizes, and total anomaly count.
    """
    engine = _get_engine()
    return engine.get_stats()


@router.post("/train")
async def trigger_training():
    """
    Manually trigger Isolation Forest model training on buffered events.

    The engine collects incoming events in a buffer.  This endpoint forces
    a training pass even if the minimum sample threshold has not been reached
    (will return an error if the buffer is truly empty).
    """
    engine = _get_engine()

    buffer_size = len(engine.isolation_forest._training_buffer)
    if buffer_size == 0:
        raise HTTPException(
            status_code=400,
            detail="Training buffer is empty. Analyze some events first.",
        )

    try:
        # Temporarily lower the minimum so manual trigger always works
        original_min = engine.isolation_forest.min_training_samples
        engine.isolation_forest.min_training_samples = min(buffer_size, original_min)
        engine.isolation_forest.train()
        engine.isolation_forest.min_training_samples = original_min

        return TrainResponse(
            success=True,
            message=f"Isolation Forest trained on {buffer_size} samples",
            stats=engine.get_stats(),
        )
    except Exception as e:
        logger.error("anomaly_training_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
async def analyze_event(body: AnalyzeEventRequest):
    """
    Analyze a single event for anomalies.

    Runs all enabled detectors (statistical, Isolation Forest, temporal)
    and returns the strongest signal if an anomaly is found.
    """
    engine = _get_engine()

    try:
        result = await engine.analyze_event(body.event)

        if result is None:
            return {
                "is_anomalous": False,
                "message": "No anomaly detected",
            }

        return {
            "is_anomalous": True,
            "event_id": result.event_id,
            "score": result.anomaly_score,
            "detector": result.detector,
            "explanation": result.explanation,
            "features": result.features,
            "timestamp": result.timestamp.isoformat(),
        }
    except Exception as e:
        logger.error("anomaly_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
