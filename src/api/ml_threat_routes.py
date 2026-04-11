"""
ML Threat Detection API Routes
==============================

REST API endpoints for ML-based threat detection.
Replaces YAML rule evaluation with intelligent ML classification.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import structlog

# Import ML components
from src.ml.yaml_converter import YAMLToMLConverter
from src.ml.feature_extractor import FeatureExtractor
from src.ml.threat_detector import ThreatDetector, ThreatTypes
from src.ml.training_pipeline import TrainingPipeline

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/ml-threat", tags=["ML Threat Detection"])

# Global instances
_yaml_converter: Optional[YAMLToMLConverter] = None
_feature_extractor: Optional[FeatureExtractor] = None
_threat_detector: Optional[ThreatDetector] = None
_training_pipeline: Optional[TrainingPipeline] = None
_training_status: Dict[str, Any] = {"status": "idle"}


# ============================================================================
# Request/Response Models
# ============================================================================

class ThreatPredictionRequest(BaseModel):
    """Request for threat prediction."""
    event: Dict[str, Any] = Field(..., description="Security event to analyze")
    context: Optional[Dict[str, Any]] = Field(None, description="Optional context")
    use_vertex: bool = Field(default=False, description="Use Vertex AI endpoint")


class BatchPredictionRequest(BaseModel):
    """Request for batch threat prediction."""
    events: List[Dict[str, Any]] = Field(..., description="Events to analyze")
    use_vertex: bool = Field(default=False)


class ThreatPredictionResponse(BaseModel):
    """Threat prediction response."""
    is_threat: bool
    threat_probability: float
    threat_type: str
    confidence: float
    risk_score: int
    severity: str
    top_factors: List[Dict[str, Any]]
    model_version: str
    inference_time_ms: float


class TrainingRequest(BaseModel):
    """Request to start model training."""
    epochs: int = Field(default=100, ge=10, le=500)
    batch_size: int = Field(default=32, ge=8, le=256)
    learning_rate: float = Field(default=0.001)
    include_historical: bool = Field(default=True)
    include_yaml_matches: bool = Field(default=True)


class YAMLKnowledgeResponse(BaseModel):
    """YAML knowledge extraction response."""
    total_rules: int
    event_types: List[str]
    important_fields: List[str]
    rules_by_severity: Dict[str, int]
    rules_by_category: Dict[str, int]
    feature_blueprint: Dict[str, Any]


# ============================================================================
# Initialization
# ============================================================================

async def initialize_ml_components():
    """Initialize ML components."""
    global _yaml_converter, _feature_extractor, _threat_detector, _training_pipeline
    
    try:
        # Initialize YAML converter
        _yaml_converter = YAMLToMLConverter()
        knowledge = _yaml_converter.load_and_convert()
        blueprint = _yaml_converter.get_feature_blueprint()
        
        # Initialize feature extractor with blueprint
        _feature_extractor = FeatureExtractor(feature_blueprint=blueprint)
        
        # Initialize threat detector (will use heuristics if no model)
        _threat_detector = ThreatDetector()
        
        # Initialize training pipeline
        _training_pipeline = TrainingPipeline()
        
        logger.info(
            "ml_components_initialized",
            rules_loaded=knowledge.total_rules,
            event_types=len(knowledge.important_event_types)
        )
        
    except Exception as e:
        logger.error("ml_initialization_failed", error=str(e))


# ============================================================================
# Threat Prediction
# ============================================================================

@router.post("/predict", response_model=ThreatPredictionResponse)
async def predict_threat(request: ThreatPredictionRequest):
    """
    Predict if an event is a threat.
    
    Uses ML model to classify the event and return:
    - Threat probability
    - Threat type classification
    - Risk score
    - Top contributing factors
    """
    if not _threat_detector:
        await initialize_ml_components()
    
    try:
        # Extract features
        features = _feature_extractor.extract_features(
            request.event,
            request.context
        )
        
        # Make prediction
        prediction = await _threat_detector.predict(
            features.to_dict(),
            use_vertex=request.use_vertex
        )
        
        return ThreatPredictionResponse(
            is_threat=prediction.is_threat,
            threat_probability=prediction.threat_probability,
            threat_type=prediction.threat_type,
            confidence=prediction.confidence,
            risk_score=prediction.risk_score,
            severity=prediction.severity,
            top_factors=prediction.top_factors,
            model_version=prediction.model_version,
            inference_time_ms=prediction.inference_time_ms
        )
        
    except Exception as e:
        logger.error("prediction_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict/batch")
async def batch_predict_threats(request: BatchPredictionRequest):
    """
    Predict threats for multiple events.
    """
    if not _threat_detector:
        await initialize_ml_components()
    
    try:
        # Extract features for all events
        feature_list = [
            _feature_extractor.extract_features(event).to_dict()
            for event in request.events
        ]
        
        # Batch prediction
        predictions = await _threat_detector.batch_predict(
            feature_list,
            use_vertex=request.use_vertex
        )
        
        return {
            "success": True,
            "count": len(predictions),
            "threats_found": sum(1 for p in predictions if p.is_threat),
            "predictions": [
                {
                    "is_threat": p.is_threat,
                    "threat_probability": p.threat_probability,
                    "threat_type": p.threat_type,
                    "risk_score": p.risk_score,
                    "severity": p.severity
                }
                for p in predictions
            ]
        }
        
    except Exception as e:
        logger.error("batch_prediction_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threat-types")
async def get_threat_types():
    """
    Get all supported threat types.
    """
    return {
        "threat_types": ThreatTypes.ALL_TYPES,
        "descriptions": {
            ThreatTypes.SAFE: "Normal, non-threatening activity",
            ThreatTypes.FLASH_LOAN_ATTACK: "Attack using flash loans for price manipulation",
            ThreatTypes.REENTRANCY: "Reentrancy vulnerability exploitation",
            ThreatTypes.ORACLE_MANIPULATION: "Price oracle manipulation attack",
            ThreatTypes.RUG_PULL: "Liquidity removal scam",
            ThreatTypes.SANDWICH_ATTACK: "MEV sandwich attack on swaps",
            ThreatTypes.FRONT_RUNNING: "Transaction front-running",
            ThreatTypes.GOVERNANCE_ATTACK: "Governance manipulation",
            ThreatTypes.BRIDGE_EXPLOIT: "Cross-chain bridge exploit",
            ThreatTypes.ADMIN_KEY_COMPROMISE: "Admin/owner key compromise",
            ThreatTypes.LIQUIDITY_DRAIN: "Unauthorized liquidity removal",
            ThreatTypes.PRICE_MANIPULATION: "Market price manipulation",
            ThreatTypes.SUSPICIOUS_TRANSFER: "Suspicious fund transfer pattern",
            ThreatTypes.UNKNOWN_THREAT: "Unknown but suspicious activity"
        }
    }


# ============================================================================
# YAML Knowledge
# ============================================================================

@router.get("/yaml-knowledge", response_model=YAMLKnowledgeResponse)
async def get_yaml_knowledge():
    """
    Get extracted knowledge from YAML rules.
    
    Shows what the ML model learned from the YAML detection rules:
    - Important event types
    - Critical fields
    - Threshold patterns
    - Category mappings
    """
    if not _yaml_converter:
        await initialize_ml_components()
    
    knowledge = _yaml_converter.knowledge
    blueprint = _yaml_converter.get_feature_blueprint()
    
    return YAMLKnowledgeResponse(
        total_rules=knowledge.total_rules,
        event_types=list(knowledge.important_event_types),
        important_fields=list(knowledge.important_fields),
        rules_by_severity=dict(knowledge.rules_by_severity),
        rules_by_category=dict(knowledge.rules_by_category),
        feature_blueprint=blueprint
    )


@router.get("/yaml-knowledge/thresholds")
async def get_yaml_thresholds():
    """
    Get threshold patterns from YAML rules.
    
    Shows the threshold values that YAML rules use,
    which are converted to ML features.
    """
    if not _yaml_converter:
        await initialize_ml_components()
    
    knowledge = _yaml_converter.knowledge
    
    # Group thresholds by field
    by_field = {}
    for threshold in knowledge.thresholds:
        field = threshold["field"]
        if field not in by_field:
            by_field[field] = []
        by_field[field].append({
            "value": threshold["value"],
            "operator": threshold["operator"],
            "severity": threshold["severity"],
            "rule_id": threshold["rule_id"]
        })
    
    return {
        "total_thresholds": len(knowledge.thresholds),
        "by_field": by_field
    }


@router.post("/yaml-knowledge/export")
async def export_yaml_knowledge(output_dir: str = "data/ml_export"):
    """
    Export YAML knowledge for Vertex AI training.
    """
    if not _yaml_converter:
        await initialize_ml_components()
    
    try:
        _yaml_converter.export_for_vertex_ai(output_dir)
        
        return {
            "success": True,
            "output_dir": output_dir,
            "files": [
                "feature_blueprint.json",
                "training_signals.json",
                "rule_summaries.json",
                "statistics.json"
            ]
        }
        
    except Exception as e:
        logger.error("yaml_export_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Feature Extraction
# ============================================================================

@router.post("/features/extract")
async def extract_features(event: Dict[str, Any]):
    """
    Extract ML features from an event.
    
    Shows the feature vector that would be fed to the ML model.
    Useful for debugging and understanding model inputs.
    """
    if not _feature_extractor:
        await initialize_ml_components()
    
    try:
        features = _feature_extractor.extract_features(event)
        feature_dict = features.to_dict()
        
        # Sort by category
        categorized = {
            "basic": features.basic,
            "event_type": features.event_type,
            "amount": features.amount,
            "address": features.address,
            "temporal": features.temporal,
            "context": features.context
        }
        
        return {
            "success": True,
            "total_features": len(feature_dict),
            "categorized": categorized,
            "flat": feature_dict
        }
        
    except Exception as e:
        logger.error("feature_extraction_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/features/names")
async def get_feature_names():
    """
    Get list of all feature names.
    """
    if not _feature_extractor:
        await initialize_ml_components()
    
    names = _feature_extractor.get_feature_names()
    
    return {
        "total_features": len(names),
        "feature_names": names
    }


# ============================================================================
# Model Training
# ============================================================================

@router.post("/train/start")
async def start_training(
    request: TrainingRequest,
    background_tasks: BackgroundTasks
):
    """
    Start model training.
    
    Training runs in background and can be monitored via /train/status.
    """
    global _training_status
    
    if _training_status.get("status") == "running":
        raise HTTPException(
            status_code=409,
            detail="Training already in progress"
        )
    
    if not _training_pipeline:
        await initialize_ml_components()
    
    # Start training in background
    _training_status = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "config": request.dict()
    }
    
    background_tasks.add_task(
        _run_training,
        request.epochs,
        request.batch_size,
        request.learning_rate,
        request.include_historical,
        request.include_yaml_matches
    )
    
    return {
        "success": True,
        "message": "Training started",
        "status": _training_status
    }


async def _run_training(
    epochs: int,
    batch_size: int,
    learning_rate: float,
    include_historical: bool,
    include_yaml_matches: bool
):
    """Background training task."""
    global _training_status, _threat_detector
    
    try:
        # Prepare data
        _training_status["step"] = "preparing_data"
        dataset = await _training_pipeline.prepare_training_data(
            include_historical_exploits=include_historical,
            include_yaml_matches=include_yaml_matches
        )
        
        _training_status["samples"] = len(dataset)
        _training_status["step"] = "training"
        
        # Train
        results = _training_pipeline.train(
            dataset=dataset,
            epochs=epochs,
            batch_size=batch_size,
            learning_rate=learning_rate
        )
        
        # Save model
        _training_status["step"] = "saving"
        model_path = _training_pipeline.save_model()
        
        # Reload detector with new model
        _threat_detector = ThreatDetector(model_path=model_path)
        
        _training_status = {
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "model_path": model_path,
            "metrics": results["final_metrics"]
        }
        
    except Exception as e:
        logger.error("training_failed", error=str(e))
        _training_status = {
            "status": "failed",
            "error": str(e),
            "failed_at": datetime.now(timezone.utc).isoformat()
        }


@router.get("/train/status")
async def get_training_status():
    """
    Get current training status.
    """
    return _training_status


@router.post("/train/cancel")
async def cancel_training():
    """
    Cancel running training (if possible).
    """
    global _training_status
    
    if _training_status.get("status") != "running":
        return {"success": False, "message": "No training in progress"}
    
    _training_status["status"] = "cancelling"
    # Note: Actual cancellation would require more sophisticated handling
    
    return {"success": True, "message": "Cancellation requested"}


# ============================================================================
# Model Management
# ============================================================================

@router.get("/model/info")
async def get_model_info():
    """
    Get information about the current model.
    """
    if not _threat_detector:
        await initialize_ml_components()
    
    return {
        "model_version": _threat_detector.model_version,
        "device": str(_threat_detector.device) if _threat_detector.device else "cpu",
        "has_local_model": _threat_detector.model is not None,
        "has_vertex_endpoint": _threat_detector.vertex_client is not None,
        "threat_types": ThreatTypes.ALL_TYPES
    }


@router.post("/model/export")
async def export_model(output_dir: str = "data/model_export"):
    """
    Export model for Vertex AI deployment.
    """
    if not _training_pipeline:
        await initialize_ml_components()
    
    try:
        _training_pipeline.export_for_vertex_ai(output_dir)
        
        return {
            "success": True,
            "output_dir": output_dir,
            "message": "Model exported for Vertex AI"
        }
        
    except Exception as e:
        logger.error("model_export_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Comparison: ML vs YAML
# ============================================================================

@router.post("/compare")
async def compare_ml_vs_yaml(event: Dict[str, Any]):
    """
    Compare ML prediction with YAML rule evaluation.
    
    Useful for validating ML model against existing rules.
    """
    if not _threat_detector:
        await initialize_ml_components()
    
    try:
        # ML prediction
        features = _feature_extractor.extract_features(event)
        ml_prediction = await _threat_detector.predict(features.to_dict())
        
        # YAML rule evaluation (would need rule engine)
        # For now, return placeholder
        yaml_result = {
            "triggered_rules": [],
            "highest_severity": "none"
        }
        
        return {
            "ml_prediction": {
                "is_threat": ml_prediction.is_threat,
                "threat_type": ml_prediction.threat_type,
                "risk_score": ml_prediction.risk_score,
                "confidence": ml_prediction.confidence
            },
            "yaml_evaluation": yaml_result,
            "agreement": ml_prediction.is_threat == (len(yaml_result["triggered_rules"]) > 0)
        }
        
    except Exception as e:
        logger.error("comparison_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
