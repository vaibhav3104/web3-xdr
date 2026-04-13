"""
AI/ML API Routes
Endpoints for contract analysis, auto-collection, and deep learning models
"""

from typing import Dict, List, Optional
from datetime import datetime, timezone
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


class LLMBytecodeRequest(BaseModel):
    bytecode: str
    contract_address: Optional[str] = None


class LLMTriageRequest(BaseModel):
    alert_match: Dict


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
            try:
                from ..notifications.alert_notifier import AlertNotifier
                notifier = AlertNotifier()
                await notifier.send_contract_threat_alert({
                    "alert_id": f"auto-{analysis.contract.address[:16]}",
                    "contract_address": analysis.contract.address,
                    "threat_category": analysis.threat_category,
                    "risk_score": analysis.risk_score,
                    "chain": getattr(analysis.contract, "chain", "unknown"),
                })
            except (ImportError, ConnectionError, OSError) as e:
                logger.warning("threat_notification_failed", error=str(e))
        
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
# INCIDENT ANALYSIS ENDPOINTS
# =============================================================================

@router.get("/analyze/{incident_id}", summary="AI analysis of an incident")
async def analyze_incident(incident_id: str) -> Dict:
    """
    Perform AI-powered analysis of an incident.
    
    Returns:
    - Root cause analysis
    - Attack vector identification
    - Similar historical incidents
    - Recommended actions
    - Risk assessment
    """
    from ..database.service import DatabaseService
    
    try:
        # Get incident from database
        incident_model = await DatabaseService.get_incident(incident_id)
        
        if not incident_model:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Convert to dict
        incident = {
            "id": incident_model.incident_id,
            "incident_id": incident_model.incident_id,
            "title": incident_model.title,
            "severity": incident_model.severity,
            "status": incident_model.status,
            "attack_type": incident_model.attack_type,
            "affected_chains": incident_model.affected_chains or [],
            "affected_protocols": incident_model.affected_protocols or [],
            "contract_address": incident_model.contract_address,
            "tx_hash": incident_model.tx_hash,
            "block_number": incident_model.block_number,
            "chain_id": incident_model.chain_id,
            "estimated_loss_usd": float(incident_model.estimated_loss_usd or 0),
            "raw_data": incident_model.raw_data or {},
        }
        
        # Perform AI analysis
        analysis = {
            "incident_id": incident_id,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "root_cause": _analyze_root_cause(incident),
            "attack_vector": _identify_attack_vector(incident),
            "risk_assessment": _assess_risk(incident),
            "similar_incidents": _find_similar_incidents(incident),
            "recommended_actions": _get_recommended_actions(incident),
            "technical_details": _get_technical_details(incident),
            "confidence": 0.85,
            "model_version": "v1.2.0"
        }
        
        return analysis
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("incident_analysis_error", incident_id=incident_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


def _analyze_root_cause(incident: Dict) -> Dict:
    """Analyze the root cause of an incident"""
    attack_type = incident.get('attack_type', 'unknown')
    incident.get('severity', 'medium')
    
    root_causes = {
        "rug_pull": {
            "primary": "Malicious contract owner executed token drain",
            "contributing_factors": [
                "Lack of ownership renouncement",
                "No timelock on admin functions",
                "Hidden mint/burn capabilities"
            ]
        },
        "flash_loan_attack": {
            "primary": "Price oracle manipulation via flash loan",
            "contributing_factors": [
                "Single-source price oracle",
                "No TWAP protection",
                "Insufficient liquidity depth checks"
            ]
        },
        "reentrancy": {
            "primary": "External call before state update",
            "contributing_factors": [
                "Missing reentrancy guard",
                "Incorrect checks-effects-interactions pattern",
                "Complex callback logic"
            ]
        },
        "governance_attack": {
            "primary": "Malicious governance proposal execution",
            "contributing_factors": [
                "Low quorum requirements",
                "Short voting period",
                "Flash loan voting power"
            ]
        },
        "unknown_threat": {
            "primary": "Suspicious contract behavior detected by ML",
            "contributing_factors": [
                "Unusual bytecode patterns",
                "High-risk opcode combinations",
                "Similar to known exploit contracts"
            ]
        }
    }
    
    cause = root_causes.get(attack_type, {
        "primary": f"Security incident of type: {attack_type}",
        "contributing_factors": ["Under investigation"]
    })
    
    return {
        "analysis": cause["primary"],
        "contributing_factors": cause["contributing_factors"],
        "confidence": 0.8 if attack_type in root_causes else 0.5
    }


def _identify_attack_vector(incident: Dict) -> Dict:
    """Identify the attack vector used"""
    attack_type = incident.get('attack_type', 'unknown')
    
    vectors = {
        "rug_pull": {
            "vector": "Admin Key Compromise / Malicious Owner",
            "entry_point": "Owner-only functions",
            "technique": "Direct fund extraction via privileged access"
        },
        "flash_loan_attack": {
            "vector": "Economic Exploit",
            "entry_point": "Price oracle / AMM pools",
            "technique": "Flash loan → Price manipulation → Arbitrage"
        },
        "reentrancy": {
            "vector": "Smart Contract Vulnerability",
            "entry_point": "External call in vulnerable function",
            "technique": "Recursive callback before state update"
        },
        "bridge_exploit": {
            "vector": "Cross-chain Message Manipulation",
            "entry_point": "Bridge validator / Message verification",
            "technique": "Fake deposit proof or message replay"
        }
    }
    
    return vectors.get(attack_type, {
        "vector": "Unknown",
        "entry_point": "Under investigation",
        "technique": f"ML-detected {attack_type} pattern"
    })


def _assess_risk(incident: Dict) -> Dict:
    """Assess the risk level of the incident"""
    severity = incident.get('severity', 'medium').upper()
    status = incident.get('status', 'open')
    loss = incident.get('estimated_loss_usd', 0)
    
    severity_scores = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2}
    base_score = severity_scores.get(severity, 5)
    
    # Adjust for loss amount
    if loss > 10_000_000:
        base_score = min(10, base_score + 2)
    elif loss > 1_000_000:
        base_score = min(10, base_score + 1)
    
    return {
        "overall_score": base_score,
        "severity": severity,
        "estimated_loss_usd": loss,
        "ongoing_risk": status.upper() not in ["RESOLVED", "CLOSED"],
        "risk_factors": [
            f"Severity: {severity}",
            f"Estimated loss: ${loss:,.2f}",
            f"Status: {status}"
        ]
    }


def _find_similar_incidents(incident: Dict) -> List[Dict]:
    """Find similar historical incidents"""
    attack_type = incident.get('attack_type', 'unknown')
    
    # Historical incidents database (simplified)
    historical = {
        "rug_pull": [
            {"name": "Squid Game Token", "date": "2021-11", "loss": "$3.4M"},
            {"name": "AnubisDAO", "date": "2021-10", "loss": "$60M"},
        ],
        "flash_loan_attack": [
            {"name": "Euler Finance", "date": "2023-03", "loss": "$197M"},
            {"name": "Mango Markets", "date": "2022-10", "loss": "$117M"},
        ],
        "reentrancy": [
            {"name": "The DAO", "date": "2016-06", "loss": "$60M"},
            {"name": "Curve Finance", "date": "2023-07", "loss": "$70M"},
        ],
        "bridge_exploit": [
            {"name": "Ronin Bridge", "date": "2022-03", "loss": "$625M"},
            {"name": "Wormhole", "date": "2022-02", "loss": "$326M"},
        ]
    }
    
    return historical.get(attack_type, [
        {"name": "Similar ML-detected incident", "date": "Recent", "loss": "Varies"}
    ])


def _get_recommended_actions(incident: Dict) -> List[Dict]:
    """Get recommended actions for the incident"""
    severity = incident.get('severity', 'medium').upper()
    attack_type = incident.get('attack_type', 'unknown')
    
    actions = [
        {
            "priority": 1,
            "action": "Acknowledge incident and assign investigator",
            "status": "required"
        }
    ]
    
    if severity in ["CRITICAL", "HIGH"]:
        actions.append({
            "priority": 2,
            "action": "Consider emergency pause of affected protocols",
            "status": "recommended"
        })
        actions.append({
            "priority": 3,
            "action": "Alert affected users and stakeholders",
            "status": "recommended"
        })
    
    if attack_type in ["rug_pull", "flash_loan_attack"]:
        actions.append({
            "priority": 4,
            "action": "Track fund movement and flag mixer interactions",
            "status": "recommended"
        })
    
    actions.append({
        "priority": 5,
        "action": "Document incident for post-mortem analysis",
        "status": "required"
    })
    
    return actions


def _get_technical_details(incident: Dict) -> Dict:
    """Get technical details about the incident"""
    raw_data = incident.get('raw_data', {})
    
    return {
        "contract_address": incident.get('contract_address'),
        "transaction_hash": incident.get('tx_hash'),
        "block_number": incident.get('block_number'),
        "chain": incident.get('chain_id'),
        "affected_protocols": incident.get('affected_protocols', []),
        "ml_confidence": raw_data.get('confidence', 0),
        "ml_risk_score": raw_data.get('risk_score', 0),
        "detection_method": raw_data.get('detection_method', 'rule_based')
    }


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
                category=result.threat_category.value if hasattr(result.threat_category, 'value') else str(result.threat_category),
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


# =============================================================================
# LLM-POWERED ANALYSIS ENDPOINTS
# =============================================================================

@router.post("/llm/analyze/bytecode", summary="LLM-powered bytecode analysis")
async def llm_analyze_bytecode(request: LLMBytecodeRequest) -> Dict:
    """
    Analyze contract bytecode using LLM (Claude) for deep semantic analysis.

    Returns detailed analysis including vulnerability identification,
    code quality assessment, and risk scoring.
    """
    try:
        from ..ai.llm import BytecodeAnalyzer
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="LLM module unavailable. Ensure LLM API key (GEMINI_API_KEY or ANTHROPIC_API_KEY) is set and dependencies are installed."
        )

    try:
        analyzer = BytecodeAnalyzer()
        result = await analyzer.analyze_async(request.bytecode, request.contract_address)
        if result is None:
            raise HTTPException(
                status_code=503,
                detail="LLM analysis unavailable. Check LLM API key configuration and quota."
            )
        return result.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.error("llm_bytecode_analysis_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/llm/triage", summary="LLM-powered incident triage")
async def llm_triage_incident(request: LLMTriageRequest) -> Dict:
    """
    Triage an alert match using LLM for intelligent severity assessment,
    root cause hypothesis, and recommended response actions.
    """
    try:
        from ..ai.llm import IncidentTriage
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="LLM module unavailable. Ensure LLM API key (GEMINI_API_KEY or ANTHROPIC_API_KEY) is set and dependencies are installed."
        )

    try:
        triage = IncidentTriage()
        result = await triage.analyze_async(request.alert_match)
        if result is None:
            raise HTTPException(
                status_code=503,
                detail="LLM triage unavailable. Check LLM API key configuration and quota."
            )
        return result.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.error("llm_triage_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/llm/rules/recommendations", summary="LLM-powered detection rule recommendations")
async def llm_rule_recommendations() -> List[Dict]:
    """
    Analyze current detection rules and return LLM-generated recommendations
    for tuning, optimization, and new rule creation.
    """
    try:
        from ..ai.llm import RuleTuner
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="LLM module unavailable. Ensure LLM API key (GEMINI_API_KEY or ANTHROPIC_API_KEY) is set and dependencies are installed."
        )

    try:
        tuner = RuleTuner()
        recommendations = tuner.analyze_and_recommend()
        if recommendations is None:
            raise HTTPException(
                status_code=503,
                detail="LLM rule analysis unavailable. Check LLM API key configuration and quota."
            )
        return [rec.to_dict() for rec in recommendations]
    except HTTPException:
        raise
    except Exception as e:
        logger.error("llm_rule_recommendations_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/llm/usage", summary="Get LLM rate limiter usage stats")
async def llm_usage_stats() -> Dict:
    """
    Return current LLM API usage statistics including token counts,
    request rates, and remaining quota.
    """
    try:
        from ..ai.llm.rate_limiter import get_rate_limiter
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="LLM rate limiter module unavailable."
        )

    try:
        limiter = get_rate_limiter()
        return limiter.get_usage_stats()
    except Exception as e:
        logger.error("llm_usage_stats_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
