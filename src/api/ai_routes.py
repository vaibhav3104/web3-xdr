"""
AI/ML API Routes
Endpoints for contract analysis, auto-collection, and deep learning models
"""

from typing import Dict, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/ai", tags=["AI/ML"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class AnalyzeRequest(BaseModel):
    bytecode: str
    use_deep_learning: bool = False
    model_type: str = "mlp"  # mlp, cnn, transformer, ensemble


class AnalyzeResponse(BaseModel):
    category: str
    risk_score: float
    confidence: float
    is_threat: bool
    alerts: List[str] = []
    model_used: str
    inference_time_ms: float
    features: Dict = {}


class CollectorStatusResponse(BaseModel):
    running: bool
    contracts_collected: int
    contracts_analyzed: int
    threats_detected: int
    chains_monitoring: List[str]
    by_chain: Dict[str, int]
    by_threat_type: Dict[str, int]


class TrainRequest(BaseModel):
    model_type: str = "mlp"  # mlp, random_forest
    epochs: int = 50
    use_real_bytecode: bool = True


class TrainResponse(BaseModel):
    status: str
    model_type: str
    accuracy: float
    training_samples: int
    message: str


# =============================================================================
# AUTO-COLLECTOR ENDPOINTS
# =============================================================================

@router.post("/collector/start", summary="Start automatic contract collection")
async def start_collector(
    chains: List[str] = ["ethereum", "arbitrum", "polygon"],
    background_tasks: BackgroundTasks = None
) -> Dict:
    """
    Start the automatic contract deployment collector.
    Monitors specified chains for new contract deployments and analyzes them.
    """
    try:
        from ..ai.collectors import start_auto_collection, get_collector
        
        # Check if already running
        collector = get_collector()
        if collector and collector.running:
            return {
                "status": "already_running",
                "chains": collector.chains,
                "stats": collector.get_stats()
            }
        
        # Define callbacks
        async def on_threat(analysis):
            logger.warning(
                "threat_detected_via_api",
                address=analysis.contract.address,
                category=analysis.threat_category,
                risk_score=analysis.risk_score
            )
            # TODO: Send notifications (Telegram, Slack, etc.)
        
        # Start collector
        collector = await start_auto_collection(
            chains=chains,
            threat_callback=on_threat
        )
        
        return {
            "status": "started",
            "chains": chains,
            "message": f"Now monitoring {len(chains)} chains for new contract deployments"
        }
        
    except Exception as e:
        logger.error("collector_start_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collector/stop", summary="Stop automatic contract collection")
async def stop_collector() -> Dict:
    """Stop the automatic contract collector"""
    try:
        from ..ai.collectors import stop_auto_collection, get_collector
        
        collector = get_collector()
        if not collector or not collector.running:
            return {"status": "not_running"}
        
        stats = collector.get_stats()
        await stop_auto_collection()
        
        return {
            "status": "stopped",
            "final_stats": stats
        }
        
    except Exception as e:
        logger.error("collector_stop_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/collector/status", response_model=CollectorStatusResponse, summary="Get collector status")
async def get_collector_status() -> CollectorStatusResponse:
    """Get the current status of the auto-collector"""
    try:
        from ..ai.collectors import get_collector
        
        collector = get_collector()
        if not collector:
            return CollectorStatusResponse(
                running=False,
                contracts_collected=0,
                contracts_analyzed=0,
                threats_detected=0,
                chains_monitoring=[],
                by_chain={},
                by_threat_type={}
            )
        
        stats = collector.get_stats()
        return CollectorStatusResponse(
            running=stats.get("running", False),
            contracts_collected=stats.get("contracts_collected", 0),
            contracts_analyzed=stats.get("contracts_analyzed", 0),
            threats_detected=stats.get("threats_detected", 0),
            chains_monitoring=stats.get("chains_monitoring", []),
            by_chain=stats.get("by_chain", {}),
            by_threat_type=stats.get("by_threat_type", {})
        )
        
    except Exception as e:
        logger.error("collector_status_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# CONTRACT ANALYSIS ENDPOINTS
# =============================================================================

@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyze contract bytecode")
async def analyze_contract(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze a contract's bytecode for potential threats.
    
    Supports:
    - Traditional ML (RandomForest)
    - Deep Learning (MLP, CNN, Transformer, Ensemble)
    - Hybrid mode (combines both)
    """
    import time
    start_time = time.time()
    
    try:
        if request.use_deep_learning:
            # Use deep learning model
            try:
                from ..ai.models.deep_classifier import DeepContractClassifier
                
                classifier = DeepContractClassifier(model_type=request.model_type)
                result = classifier.classify(request.bytecode)
                
                return AnalyzeResponse(
                    category=result.category,
                    risk_score=result.risk_score,
                    confidence=result.confidence,
                    is_threat=result.category != "safe" and result.risk_score > 0.5,
                    alerts=[],
                    model_used=result.model_used,
                    inference_time_ms=result.inference_time_ms,
                    features={}
                )
                
            except ImportError:
                raise HTTPException(
                    status_code=400,
                    detail="PyTorch not available. Install with: pip install torch"
                )
        else:
            # Use traditional ML (RandomForest)
            from ..ai.models.contract_classifier import ContractThreatClassifier
            from ..ai.data.bytecode_collector import RealBytecodeFeatureExtractor
            
            classifier = ContractThreatClassifier()
            extractor = RealBytecodeFeatureExtractor()
            
            # Extract features
            features = extractor.extract_features(request.bytecode)
            
            # Classify
            result = classifier.classify(request.bytecode)
            
            # Generate alerts based on features
            alerts = []
            if features.get("has_flash_loan_callback"):
                alerts.append("Contains flash loan callback function")
            if features.get("has_reentrancy_pattern"):
                alerts.append("Potential reentrancy pattern detected")
            if features.get("has_selfdestruct"):
                alerts.append("Contains SELFDESTRUCT opcode")
            if features.get("delegatecall_count", 0) > 2:
                alerts.append(f"Multiple DELEGATECALL operations ({features['delegatecall_count']})")
            
            inference_time = (time.time() - start_time) * 1000
            
            return AnalyzeResponse(
                category=result.category.value if hasattr(result.category, 'value') else str(result.category),
                risk_score=result.risk_score,
                confidence=result.confidence,
                is_threat=result.risk_score > 0.5,
                alerts=alerts,
                model_used="random_forest",
                inference_time_ms=inference_time,
                features=features
            )
            
    except Exception as e:
        logger.error("analyze_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/hybrid", summary="Analyze using both ML and Deep Learning")
async def analyze_hybrid(request: AnalyzeRequest) -> Dict:
    """
    Analyze contract using both RandomForest and Deep Learning models.
    Returns combined results with confidence-weighted voting.
    """
    try:
        from ..ai.models.deep_classifier import HybridClassifier
        
        classifier = HybridClassifier(deep_model_type=request.model_type)
        results = classifier.classify(request.bytecode)
        
        return results
        
    except Exception as e:
        logger.error("hybrid_analyze_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# TRAINING ENDPOINTS
# =============================================================================

@router.post("/train", response_model=TrainResponse, summary="Train ML model")
async def train_model(request: TrainRequest, background_tasks: BackgroundTasks) -> TrainResponse:
    """
    Train or retrain the ML model.
    
    For production, this should be run as a background task.
    """
    try:
        if request.model_type == "random_forest":
            # Train RandomForest
            from ..ai.training.pipeline import TrainingPipeline, TrainingConfig
            
            config = TrainingConfig(
                model_type="random_forest",
                n_estimators=100,
                output_dir="./data/models"
            )
            
            pipeline = TrainingPipeline(config)
            pipeline.collect_training_data(use_real_bytecode=request.use_real_bytecode)
            result = pipeline.train()
            pipeline.save_model(result)
            
            return TrainResponse(
                status="completed",
                model_type="random_forest",
                accuracy=result.accuracy,
                training_samples=result.training_samples,
                message="Model trained successfully"
            )
            
        elif request.model_type in ["mlp", "cnn", "transformer", "ensemble"]:
            # Train Deep Learning model
            try:
                from ..ai.models.deep_classifier import DeepContractClassifier
                import json
                
                # Load training data
                data_path = "./data/bytecode/training_data_real.json"
                with open(data_path, "r") as f:
                    training_data = json.load(f)
                
                # Split data
                split_idx = int(len(training_data) * 0.8)
                train_data = training_data[:split_idx]
                val_data = training_data[split_idx:]
                
                # Train
                classifier = DeepContractClassifier(model_type=request.model_type)
                history = classifier.train(
                    train_data=train_data,
                    val_data=val_data,
                    epochs=request.epochs
                )
                
                return TrainResponse(
                    status="completed",
                    model_type=request.model_type,
                    accuracy=history["val_acc"][-1] / 100 if history["val_acc"] else 0,
                    training_samples=len(train_data),
                    message=f"Deep learning model ({request.model_type}) trained successfully"
                )
                
            except ImportError:
                raise HTTPException(
                    status_code=400,
                    detail="PyTorch not available for deep learning training"
                )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown model type: {request.model_type}")
            
    except Exception as e:
        logger.error("training_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collect-bytecode", summary="Collect bytecode from blockchain")
async def collect_bytecode(
    chains: List[str] = ["ethereum", "arbitrum", "polygon", "bsc"],
    background_tasks: BackgroundTasks = None
) -> Dict:
    """
    Collect real bytecode from blockchain for training.
    This fetches bytecode from known exploit and safe contracts.
    """
    try:
        from ..ai.data.bytecode_collector import collect_training_bytecode
        
        # Run collection
        training_data = await collect_training_bytecode()
        
        return {
            "status": "completed",
            "samples_collected": len(training_data),
            "labels": list(set(d["label"] for d in training_data)),
            "output_file": "./data/bytecode/training_data_real.json"
        }
        
    except Exception as e:
        logger.error("bytecode_collection_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# MODEL INFO ENDPOINTS
# =============================================================================

@router.get("/models", summary="List available ML models")
async def list_models() -> Dict:
    """List all available ML models and their status"""
    import os
    
    models = {
        "random_forest": {
            "type": "traditional_ml",
            "path": "./data/models/contract_classifier.pkl",
            "available": os.path.exists("./data/models/contract_classifier.pkl"),
            "description": "RandomForest classifier trained on bytecode features"
        },
        "deep_mlp": {
            "type": "deep_learning",
            "path": "./data/models/deep_mlp.pt",
            "available": os.path.exists("./data/models/deep_mlp.pt"),
            "description": "Multi-layer perceptron for feature-based classification"
        },
        "deep_cnn": {
            "type": "deep_learning",
            "path": "./data/models/deep_cnn.pt",
            "available": os.path.exists("./data/models/deep_cnn.pt"),
            "description": "1D CNN for opcode sequence analysis"
        },
        "deep_transformer": {
            "type": "deep_learning",
            "path": "./data/models/deep_transformer.pt",
            "available": os.path.exists("./data/models/deep_transformer.pt"),
            "description": "Transformer for attention-based analysis"
        },
    }
    
    # Check PyTorch availability
    try:
        import torch
        pytorch_available = True
        pytorch_version = torch.__version__
        cuda_available = torch.cuda.is_available()
    except ImportError:
        pytorch_available = False
        pytorch_version = None
        cuda_available = False
    
    return {
        "models": models,
        "pytorch_available": pytorch_available,
        "pytorch_version": pytorch_version,
        "cuda_available": cuda_available,
        "training_data_available": os.path.exists("./data/bytecode/training_data_real.json")
    }


@router.get("/exploit-database/stats", summary="Get exploit database statistics")
async def get_exploit_stats() -> Dict:
    """Get statistics about the exploit database"""
    try:
        from ..ai.data.exploit_database import get_statistics
        return get_statistics()
    except Exception as e:
        logger.error("exploit_stats_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# CONTINUOUS LEARNING ENDPOINTS
# =============================================================================

class ContinuousLearningRequest(BaseModel):
    chains: List[str] = ["ethereum", "polygon", "arbitrum", "bsc"]
    model_types: List[str] = ["mlp", "random_forest"]
    retrain_interval_hours: int = 6
    min_new_samples: int = 50


@router.post("/learning/start", summary="Start 24/7 continuous learning system")
async def start_continuous_learning_endpoint(
    request: ContinuousLearningRequest = None
) -> Dict:
    """
    Start the 24/7/365 continuous learning system.
    
    This will:
    - Monitor all specified chains for new contract deployments
    - Analyze each contract with ML models
    - Periodically retrain models with new data
    - Alert on detected threats
    """
    try:
        from ..ai.continuous_learning import (
            start_continuous_learning, 
            get_learning_system,
            LearningConfig
        )
        
        # Check if already running
        system = get_learning_system()
        if system and system.running:
            return {
                "status": "already_running",
                "stats": system.get_stats()
            }
        
        # Create config
        config = LearningConfig(
            chains=request.chains if request else ["ethereum", "polygon", "arbitrum", "bsc"],
            model_types=request.model_types if request else ["mlp", "random_forest"],
            retrain_interval_hours=request.retrain_interval_hours if request else 6,
            min_new_samples=request.min_new_samples if request else 50
        )
        
        # Start system
        await start_continuous_learning(config)
        
        return {
            "status": "started",
            "config": {
                "chains": config.chains,
                "model_types": config.model_types,
                "retrain_interval_hours": config.retrain_interval_hours,
                "min_new_samples": config.min_new_samples
            },
            "message": "24/7 continuous learning system started successfully"
        }
        
    except Exception as e:
        logger.error("continuous_learning_start_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/learning/stop", summary="Stop continuous learning system")
async def stop_continuous_learning_endpoint() -> Dict:
    """Stop the continuous learning system"""
    try:
        from ..ai.continuous_learning import stop_continuous_learning, get_learning_system
        
        system = get_learning_system()
        if not system or not system.running:
            return {"status": "not_running"}
        
        final_stats = system.get_stats()
        await stop_continuous_learning()
        
        return {
            "status": "stopped",
            "final_stats": final_stats
        }
        
    except Exception as e:
        logger.error("continuous_learning_stop_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/learning/status", summary="Get continuous learning status")
async def get_continuous_learning_status() -> Dict:
    """Get the status of the continuous learning system"""
    try:
        from ..ai.continuous_learning import get_learning_system
        
        system = get_learning_system()
        if not system:
            return {
                "running": False,
                "message": "Continuous learning system not started"
            }
        
        stats = system.get_stats()
        return {
            "running": system.running,
            "stats": stats,
            "config": {
                "chains": system.config.chains,
                "model_types": system.config.model_types,
                "retrain_interval_hours": system.config.retrain_interval_hours
            }
        }
        
    except Exception as e:
        logger.error("continuous_learning_status_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/learning/retrain", summary="Force immediate model retraining")
async def force_retrain_endpoint() -> Dict:
    """Force immediate retraining of all models"""
    try:
        from ..ai.continuous_learning import get_learning_system
        
        system = get_learning_system()
        if not system or not system.running:
            raise HTTPException(status_code=400, detail="Continuous learning system not running")
        
        await system.force_retrain()
        
        return {
            "status": "retrained",
            "model_accuracies": system.stats.model_accuracies,
            "models_trained": system.stats.models_trained
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("force_retrain_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
