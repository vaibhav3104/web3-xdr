"""
ML API Routes
Endpoints for AI/ML contract analysis and threat detection
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime
import json
import asyncio
import structlog

logger = structlog.get_logger(__name__)

# Import AI modules
try:
    from ..ai.models.contract_classifier import ContractThreatClassifier, ThreatCategory
    from ..ai.inference.contract_monitor import SimulatedDeploymentMonitor, ThreatAlert
    from ..ai.data.bytecode_extractor import BytecodeExtractor
    from ..ai.data.attack_database import (
        get_all_attacks, 
        get_statistics,
        get_bridge_attacks,
        get_defi_attacks
    )
    AI_AVAILABLE = True
except ImportError as e:
    print(f"AI modules not fully loaded: {e}")
    AI_AVAILABLE = False

# Import Deep Learning classifier (PyTorch/GPU)
try:
    from ..ai.models.deep_classifier import DeepContractClassifier, PYTORCH_AVAILABLE
    DEEP_ML_AVAILABLE = PYTORCH_AVAILABLE
except ImportError as e:
    print(f"Deep ML modules not available: {e}")
    DEEP_ML_AVAILABLE = False
    PYTORCH_AVAILABLE = False

import os

router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])

# Initialize components
if AI_AVAILABLE:
    classifier = ContractThreatClassifier()
    extractor = BytecodeExtractor()
    simulated_monitor = SimulatedDeploymentMonitor(classifier)
else:
    classifier = None
    extractor = None
    simulated_monitor = None

# Initialize Deep Learning classifier (Transformer with GPU)
deep_classifier = None
if DEEP_ML_AVAILABLE:
    try:
        model_type = os.environ.get("ML_MODEL_TYPE", "transformer")
        device = os.environ.get("ML_DEVICE", "auto")
        deep_classifier = DeepContractClassifier(model_type=model_type, device=device)
        print(f"✅ Deep ML Classifier initialized: model={model_type}, device={deep_classifier.device}")
    except Exception as e:
        print(f"❌ Failed to initialize deep classifier: {e}")
        deep_classifier = None

# Request/Response Models
class ContractAnalysisRequest(BaseModel):
    bytecode: str
    contract_address: Optional[str] = None
    chain: Optional[str] = "ethereum"

class ContractAnalysisResponse(BaseModel):
    contract_address: str
    threat_category: str
    confidence: float
    risk_score: float
    risk_factors: List[str]
    similar_exploits: List[str]
    recommendation: str
    analysis_time_ms: float

class BytecodeFeatureResponse(BaseModel):
    bytecode_length: int
    unique_opcodes: int
    call_count: int
    delegatecall_count: int
    has_flash_loan_callback: bool
    has_reentrancy_pattern: bool
    has_selfdestruct: bool
    risk_score: float
    risk_factors: List[str]

class SimulateDeploymentRequest(BaseModel):
    bytecode: str
    deployer_address: Optional[str] = "0x0000000000000000000000000000000000000000"
    chain: Optional[str] = "ethereum"

class AttackDatabaseStats(BaseModel):
    total_attacks: int
    total_loss_usd: float
    bridge_attacks: int
    bridge_loss_usd: float
    defi_attacks: int
    defi_loss_usd: float
    attack_types: List[str]

# Endpoints

@router.get("/health")
async def get_ml_health():
    """Get ML system health status - used by frontend"""
    return {
        "status": "healthy" if AI_AVAILABLE else "degraded",
        "model_loaded": classifier is not None,
        "deep_ml_available": DEEP_ML_AVAILABLE,
        "deep_classifier_loaded": deep_classifier is not None,
        "components": {
            "rule_based_classifier": classifier is not None,
            "deep_learning_classifier": deep_classifier is not None,
            "bytecode_extractor": extractor is not None,
            "simulated_monitor": simulated_monitor is not None,
        }
    }

@router.get("/status")
async def get_ml_status():
    """Get detailed ML system status"""
    # Check GPU availability
    gpu_info = {}
    if DEEP_ML_AVAILABLE:
        import torch
        gpu_info = {
            "pytorch_version": torch.__version__,
            "cuda_available": torch.cuda.is_available(),
            "cuda_version": torch.version.cuda if torch.cuda.is_available() else None,
            "gpu_count": torch.cuda.device_count() if torch.cuda.is_available() else 0,
            "gpu_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() and torch.cuda.device_count() > 0 else None,
            "mps_available": hasattr(torch.backends, 'mps') and torch.backends.mps.is_available(),
        }
    
    return {
        "ml_available": AI_AVAILABLE,
        "classifier_loaded": classifier is not None,
        "model_type": "rule_based" if classifier and not classifier.model else "ml_model",
        "known_exploits": len(classifier.known_exploits) if classifier else 0,
        "alerts_count": len(simulated_monitor.alerts) if simulated_monitor else 0,
        "deep_ml_available": DEEP_ML_AVAILABLE,
        "deep_classifier_loaded": deep_classifier is not None,
        "deep_model_type": deep_classifier.model_type if deep_classifier else None,
        "deep_model_device": str(deep_classifier.device) if deep_classifier else None,
        "gpu_info": gpu_info,
    }

@router.post("/analyze/deep", response_model=ContractAnalysisResponse)
async def analyze_contract_deep(request: ContractAnalysisRequest):
    """
    Analyze contract using Deep Learning (Transformer) model with GPU acceleration
    
    This endpoint uses the PyTorch Transformer model for:
    1. Sequence-based bytecode analysis
    2. Attention-based pattern detection
    3. GPU-accelerated inference
    """
    if not DEEP_ML_AVAILABLE or not deep_classifier:
        raise HTTPException(
            status_code=503, 
            detail="Deep ML system not available. Check GPU/PyTorch installation."
        )
    
    import time
    start = time.time()
    
    try:
        result = deep_classifier.classify(request.bytecode)
        analysis_time = (time.time() - start) * 1000
        
        # Map to response format
        recommendation = {
            "safe": "Contract appears safe. Standard monitoring recommended.",
            "rug_pull": "HIGH RISK: Rug pull indicators detected. Do not interact.",
            "honeypot": "HIGH RISK: Honeypot pattern detected. Trading may be blocked.",
            "reentrancy_exploit": "CRITICAL: Reentrancy vulnerability detected.",
            "flash_loan_attack": "HIGH RISK: Flash loan attack pattern detected.",
            "price_manipulation": "HIGH RISK: Price manipulation vectors present.",
            "access_control_exploit": "MEDIUM: Access control issues detected.",
            "unknown_threat": "MEDIUM: Unknown threat pattern. Manual review recommended.",
        }.get(result.category, "Review recommended.")
        
        return ContractAnalysisResponse(
            contract_address=request.contract_address or "unknown",
            threat_category=result.category,
            confidence=result.confidence,
            risk_score=result.risk_score * 100,  # Convert to 0-100 scale
            risk_factors=[f"Model: {result.model_used}", f"Features: {result.features_used}"],
            similar_exploits=[],
            recommendation=recommendation,
            analysis_time_ms=analysis_time
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deep analysis failed: {str(e)}")


@router.post("/analyze/contract", response_model=ContractAnalysisResponse)
async def analyze_contract(request: ContractAnalysisRequest):
    """
    Analyze a smart contract bytecode for threats
    
    This endpoint performs:
    1. Feature extraction from bytecode
    2. Pattern matching against known exploits
    3. ML classification (if model loaded)
    4. Risk scoring and recommendation
    """
    if not AI_AVAILABLE or not classifier:
        raise HTTPException(status_code=503, detail="ML system not available")
    
    import time
    start = time.time()
    
    try:
        result = classifier.classify(
            request.bytecode,
            request.contract_address or "unknown"
        )
        
        analysis_time = (time.time() - start) * 1000
        
        return ContractAnalysisResponse(
            contract_address=result.contract_address,
            threat_category=result.threat_category.value,
            confidence=result.confidence,
            risk_score=result.risk_score,
            risk_factors=result.risk_factors,
            similar_exploits=result.similar_exploits,
            recommendation=result.recommendation,
            analysis_time_ms=analysis_time
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/analyze/features", response_model=BytecodeFeatureResponse)
async def extract_features(request: ContractAnalysisRequest):
    """
    Extract features from bytecode without full classification
    Useful for understanding what the analyzer sees
    """
    if not AI_AVAILABLE or not extractor:
        raise HTTPException(status_code=503, detail="ML system not available")
    
    try:
        features = extractor.extract_features(request.bytecode)
        
        return BytecodeFeatureResponse(
            bytecode_length=features.bytecode_length,
            unique_opcodes=features.unique_opcodes,
            call_count=features.call_count,
            delegatecall_count=features.delegatecall_count,
            has_flash_loan_callback=features.has_flash_loan_callback,
            has_reentrancy_pattern=features.has_reentrancy_pattern,
            has_selfdestruct=features.has_selfdestruct,
            risk_score=features.risk_score,
            risk_factors=features.risk_factors
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feature extraction failed: {str(e)}")

@router.post("/simulate/deployment")
async def simulate_deployment(request: SimulateDeploymentRequest):
    """
    Simulate a contract deployment for testing
    Returns alert if threat detected
    """
    if not AI_AVAILABLE or not simulated_monitor:
        raise HTTPException(status_code=503, detail="ML system not available")
    
    try:
        alert = simulated_monitor.simulate_deployment(
            bytecode=request.bytecode,
            deployer=request.deployer_address,
            chain=request.chain
        )
        
        if alert:
            return {
                "threat_detected": True,
                "alert": alert.to_dict()
            }
        else:
            return {
                "threat_detected": False,
                "message": "Contract classified as safe"
            }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")

@router.get("/alerts")
async def get_ml_alerts(status: Optional[str] = None, limit: int = 50):
    """
    Get ML-generated threat alerts.
    
    Combines:
    1. In-memory alerts from simulated_monitor (real-time)
    2. Database alerts from ML contract scanner (persistent)
    """
    alerts_list = []
    
    # 1. Get in-memory alerts from simulated monitor
    if AI_AVAILABLE and simulated_monitor:
        in_memory_alerts = simulated_monitor.alerts
        if status:
            in_memory_alerts = [a for a in in_memory_alerts if a.status == status]
        for alert in in_memory_alerts:
            alerts_list.append(alert.to_dict())
    
    # 2. Get database alerts from ML contract scanner
    try:
        from ..database.service import DatabaseService
        
        # Fetch ML-detected contract deployments (threats)
        db_alerts = await DatabaseService.get_contract_deploy_alerts(limit=limit)
        
        for db_alert in db_alerts:
            # Only include threats (CRITICAL, HIGH, or has threat_category)
            severity = (db_alert.get('severity') or '').upper()
            raw_data = db_alert.get('raw_data') or {}
            
            is_threat = severity in ('CRITICAL', 'HIGH') or raw_data.get('is_threat', False)
            
            if is_threat:
                # Convert to alert format expected by frontend
                threat_category = raw_data.get('threat_category', 'unknown_threat')
                
                alert_dict = {
                    "id": db_alert.get('event_id', ''),
                    "alert_time": db_alert.get('created_at') or db_alert.get('block_timestamp'),
                    "status": "active",
                    "deployment": {
                        "contract_address": db_alert.get('contract_address', ''),
                        "chain": db_alert.get('chain_id', 'unknown'),
                        "deployer": db_alert.get('from_address', ''),
                        "tx_hash": db_alert.get('tx_hash', ''),
                        "block_number": db_alert.get('block_number', 0),
                    },
                    "classification": {
                        "threat_category": threat_category,
                        "confidence": raw_data.get('confidence', 0.5),
                        "risk_score": raw_data.get('risk_score', 50),
                        "risk_factors": raw_data.get('alerts', []),
                    },
                    "source": "ml_contract_scanner"
                }
                alerts_list.append(alert_dict)
    except Exception as e:
        # Log but don't fail - in-memory alerts still work
        print(f"Failed to fetch DB alerts: {e}")
    
    # Sort by time, newest first
    def get_alert_time(alert):
        time_val = alert.get('alert_time')
        if isinstance(time_val, str):
            try:
                return datetime.fromisoformat(time_val.replace('Z', '+00:00'))
            except:
                return datetime.min
        elif isinstance(time_val, datetime):
            return time_val
        return datetime.min
    
    alerts_list = sorted(alerts_list, key=get_alert_time, reverse=True)[:limit]
    
    return {
        "total": len(alerts_list),
        "alerts": alerts_list
    }

@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    """Acknowledge a threat alert"""
    if not AI_AVAILABLE or not simulated_monitor:
        raise HTTPException(status_code=503, detail="ML system not available")
    
    for alert in simulated_monitor.alerts:
        if alert.id == alert_id:
            alert.status = "acknowledged"
            return {"success": True, "alert_id": alert_id, "new_status": "acknowledged"}
    
    raise HTTPException(status_code=404, detail="Alert not found")

@router.post("/alerts/{alert_id}/false-positive")
async def mark_false_positive(alert_id: str):
    """Mark alert as false positive (contributes to retraining)"""
    if not AI_AVAILABLE or not simulated_monitor:
        raise HTTPException(status_code=503, detail="ML system not available")
    
    for alert in simulated_monitor.alerts:
        if alert.id == alert_id:
            alert.status = "false_positive"
            # TODO: Store for retraining
            return {"success": True, "alert_id": alert_id, "new_status": "false_positive"}
    
    raise HTTPException(status_code=404, detail="Alert not found")

@router.get("/attack-database/stats", response_model=AttackDatabaseStats)
async def get_attack_stats():
    """Get statistics about the historical attack database"""
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML system not available")
    
    stats = get_statistics()
    
    return AttackDatabaseStats(**stats)

@router.get("/attack-database/attacks")
async def list_attacks(
    protocol_type: Optional[str] = None,
    attack_type: Optional[str] = None,
    limit: int = 50
):
    """
    List historical attacks from the database
    
    Query params:
    - protocol_type: bridge, dex, lending, etc.
    - attack_type: flash_loan, reentrancy, etc.
    """
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML system not available")
    
    attacks = get_all_attacks()
    
    if protocol_type:
        attacks = [a for a in attacks if a["protocol_type"] == protocol_type]
    
    if attack_type:
        attacks = [a for a in attacks if a["attack_type"] == attack_type]
    
    # Sort by loss
    attacks = sorted(attacks, key=lambda a: a["loss_usd"], reverse=True)[:limit]
    
    return {
        "total": len(attacks),
        "attacks": attacks
    }

@router.get("/threat-categories")
async def list_threat_categories():
    """List all threat categories the classifier can detect"""
    return {
        "categories": [
            {
                "id": cat.value,
                "name": cat.name.replace("_", " ").title(),
                "severity": "critical" if cat in [
                    ThreatCategory.FLASH_LOAN_EXPLOIT,
                    ThreatCategory.REENTRANCY_EXPLOIT,
                    ThreatCategory.BRIDGE_EXPLOIT,
                    ThreatCategory.RUG_PULL
                ] else "high" if cat in [
                    ThreatCategory.ORACLE_MANIPULATION,
                    ThreatCategory.GOVERNANCE_ATTACK,
                    ThreatCategory.HONEYPOT
                ] else "medium"
            }
            for cat in ThreatCategory if cat != ThreatCategory.SAFE
        ]
    }

# Batch analysis endpoint
class BatchAnalysisRequest(BaseModel):
    contracts: List[ContractAnalysisRequest]

@router.post("/analyze/batch")
async def batch_analyze(request: BatchAnalysisRequest):
    """Analyze multiple contracts in batch"""
    if not AI_AVAILABLE or not classifier:
        raise HTTPException(status_code=503, detail="ML system not available")
    
    results = []
    for contract in request.contracts[:100]:  # Limit to 100
        try:
            result = classifier.classify(
                contract.bytecode,
                contract.contract_address or "unknown"
            )
            results.append({
                "contract_address": result.contract_address,
                "threat_category": result.threat_category.value,
                "risk_score": result.risk_score,
                "is_threat": result.threat_category != ThreatCategory.SAFE
            })
        except Exception as e:
            results.append({
                "contract_address": contract.contract_address or "unknown",
                "error": str(e)
            })
    
    threats = sum(1 for r in results if r.get("is_threat", False))
    
    return {
        "total": len(results),
        "threats_found": threats,
        "results": results
    }


@router.post("/train")
async def train_model(background_tasks: BackgroundTasks):
    """
    Trigger model training on GPU
    Training runs in background and saves weights to disk
    """
    if not DEEP_ML_AVAILABLE or not deep_classifier:
        raise HTTPException(
            status_code=503,
            detail="Deep ML not available. Cannot train."
        )
    
    def run_training():
        import torch
        from datetime import datetime
        
        print("🚀 Starting model training...")
        
        # Generate training data
        threat_patterns = {
            "safe": ["608060405234801561001057600080fd5b5060405161001d906100a4565b"],
            "flash_loan_exploit": ["608060405234801561001057600080fd5b5063c3924ed6f1f1f1"],
            "reentrancy_exploit": ["608060405234801561001057600080fd5b5063ccfd60bf1555555"],
            "rug_pull": ["608060405234801561001057600080fd5b506040516100f2fde38bff"],
            "honeypot": ["608060405234801561001057600080fd5b506040516100a9f2fde38b"],
            "bridge_exploit": ["608060405234801561001057600080fd5b5063409c10f19f4f4f4"],
            "price_manipulation": ["608060405234801561001057600080fd5b506040516370a082"],
            "access_control_exploit": ["608060405234801561001057600080fd5b50604051638da5cb5b"],
        }
        
        train_data = []
        extractor = deep_classifier.extractor
        
        for category, patterns in threat_patterns.items():
            for pattern in patterns:
                for i in range(15):
                    variation = pattern + f"{i:02x}" * 15
                    features = extractor.extract_features(variation)
                    feature_vector = extractor.features_to_vector(features)
                    train_data.append({
                        "bytecode": variation,
                        "features": feature_vector,
                        "label": category
                    })
        
        # Shuffle and split
        import random
        random.shuffle(train_data)
        split = int(len(train_data) * 0.8)
        
        # Train
        history = deep_classifier.train(
            train_data=train_data[:split],
            val_data=train_data[split:],
            epochs=50,
            batch_size=16,
            learning_rate=0.001,
            early_stopping_patience=10
        )
        
        print("✅ Training complete!")
        return history
    
    background_tasks.add_task(run_training)
    
    return {
        "status": "training_started",
        "message": "Model training started in background. Check logs for progress.",
        "device": str(deep_classifier.device),
        "model_type": deep_classifier.model_type
    }


@router.get("/model-info")
async def get_model_info():
    """Get detailed model information"""
    info = {
        "rule_based": {
            "available": AI_AVAILABLE,
            "loaded": classifier is not None,
        },
        "deep_learning": {
            "available": DEEP_ML_AVAILABLE,
            "loaded": deep_classifier is not None,
        }
    }
    
    if DEEP_ML_AVAILABLE and deep_classifier:
        import torch
        info["deep_learning"].update({
            "model_type": deep_classifier.model_type,
            "device": str(deep_classifier.device),
            "model_path": deep_classifier.model_path,
            "parameters": sum(p.numel() for p in deep_classifier.model.parameters()),
            "categories": deep_classifier.THREAT_CATEGORIES,
        })
        
        if torch.cuda.is_available():
            info["gpu"] = {
                "name": torch.cuda.get_device_name(0),
                "memory_total_gb": torch.cuda.get_device_properties(0).total_memory / 1e9,
                "memory_allocated_gb": torch.cuda.memory_allocated(0) / 1e9,
                "memory_cached_gb": torch.cuda.memory_reserved(0) / 1e9,
            }
    
    return info


# =============================================================================
# ALERT ANALYZER ENDPOINTS (ML for YAML Rule Filtering)
# =============================================================================

@router.get("/alert-analyzer/status")
async def get_alert_analyzer_status():
    """
    Get status of the ML Alert Analyzer.
    
    The Alert Analyzer is a second-pass ML filter that analyzes YAML rule alerts
    to determine if they are True Positives or False Positives.
    """
    try:
        from ..ml.alert_analyzer import get_alert_analyzer
        
        analyzer = get_alert_analyzer()
        stats = analyzer.get_stats()
        
        return {
            "status": "active",
            "model_loaded": stats.get("model_loaded", False),
            "statistics": {
                "total_analyzed": stats.get("total_analyzed", 0),
                "true_positives": stats.get("true_positives", 0),
                "false_positives": stats.get("false_positives", 0),
                "needs_review": stats.get("needs_review", 0),
                "incidents_prevented": stats.get("incidents_prevented", 0),
                "tp_rate": round(stats.get("tp_rate", 0) * 100, 1),
                "fp_rate": round(stats.get("fp_rate", 0) * 100, 1),
            },
            "description": "ML filter for YAML rule alerts - reduces false positives by ~30%"
        }
    except ImportError:
        return {
            "status": "not_available",
            "error": "Alert analyzer module not installed"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@router.get("/alert-analyzer/analyze")
@router.post("/alert-analyzer/analyze")
async def analyze_alert_manually(
    rule_id: str,
    rule_name: str,
    severity: str,
    chain_id: str,
    amount_usd: float = 0,
    contract_address: Optional[str] = None,
    from_address: Optional[str] = None,
    to_address: Optional[str] = None
):
    """
    Manually analyze an alert to see if it would be classified as TP or FP.
    
    Useful for testing and understanding the ML Alert Analyzer behavior.
    Accepts both GET (query params) and POST (form data).
    """
    try:
        from ..ml.alert_analyzer_transformer import get_alert_analyzer, AlertContext
        
        analyzer = get_alert_analyzer()
        
        context = AlertContext(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            chain_id=chain_id,
            event_type="manual_test",
            amount_usd=amount_usd,
            contract_address=contract_address,
            from_address=from_address,
            to_address=to_address
        )
        
        result = analyzer.predict(context)
        
        # Convert numpy floats to Python floats for JSON serialization
        return {
            "verdict": result.verdict.value,
            "confidence": float(round(result.confidence, 2)),
            "tp_probability": float(round(result.tp_probability, 2)),
            "risk_score": float(round(result.risk_score, 2)),
            "should_create_incident": bool(result.should_create_incident),
            "adjusted_severity": str(result.adjusted_severity),
            "recommended_action": str(result.recommended_action),
            "reasoning": [str(r) for r in result.reasoning],
            "model_used": str(getattr(result, 'model_used', 'rule_based'))
        }
    except ImportError:
        raise HTTPException(status_code=503, detail="Alert analyzer not available")
    except Exception as e:
        logger.error("alert_analyze_failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alert-analyzer/feature-importance")
async def get_alert_analyzer_features():
    """
    Get the features used by the ML Alert Analyzer.
    
    Useful for understanding what factors influence TP/FP classification.
    """
    try:
        from ..ml.alert_analyzer import AlertFeatureExtractor
        
        extractor = AlertFeatureExtractor()
        
        # Group features by category
        feature_groups = {
            "amount": ["amount_usd_log"],
            "address_history": ["address_age_days", "address_tx_count_log", "is_known_entity", "entity_is_risky"],
            "alert_patterns": ["similar_alerts_24h", "similar_alerts_7d", "rule_historical_tp_rate"],
            "graph_proximity": ["hops_to_hacker", "hops_to_mixer", "connected_to_sanctioned"],
            "contract_info": ["contract_verified", "contract_age_days", "contract_tx_count_log", "is_proxy"],
            "severity": ["severity_critical", "severity_high", "severity_medium"],
            "chain": ["chain_ethereum", "chain_polygon", "chain_arbitrum", "chain_optimism", "chain_base"],
            "rule_type": ["rule_flash_loan", "rule_price_impact", "rule_liquidity", "rule_bridge", "rule_whale", "rule_admin"]
        }
        
        return {
            "total_features": len(extractor.FEATURE_NAMES),
            "feature_names": extractor.FEATURE_NAMES,
            "feature_groups": feature_groups,
            "high_importance_features": [
                "entity_is_risky - Connection to known hackers/mixers",
                "hops_to_hacker - Graph proximity to threat actors",
                "rule_historical_tp_rate - Historical accuracy of this rule",
                "amount_usd_log - Transaction value (log scale)",
                "connected_to_sanctioned - OFAC sanctions list"
            ]
        }
    except ImportError:
        raise HTTPException(status_code=503, detail="Alert analyzer not available")


@router.post("/alert-analyzer/train")
async def train_alert_analyzer():
    """
    Train the ML Alert Analyzer ensemble model.
    
    Uses:
    1. Historical incidents from database
    2. Synthetic data based on domain knowledge
    
    Trains:
    1. Transformer model for pattern recognition
    2. XGBoost model for tabular classification
    
    Note: Training runs synchronously for reliability.
    """
    try:
        from ..ml.alert_analyzer_transformer import get_alert_analyzer
        
        analyzer = get_alert_analyzer()
        
        # Run training synchronously
        logger.info("alert_analyzer_training_starting")
        results = await analyzer.train()
        logger.info("alert_analyzer_training_complete", results=results)
        
        return {
            "status": "training_complete",
            "message": "Alert analyzer training completed successfully",
            "models": ["transformer", "xgboost"],
            "results": results
        }
        
    except ImportError as e:
        logger.error("ensemble_analyzer_import_error", error=str(e))
        raise HTTPException(status_code=503, detail=f"Ensemble analyzer not available: {e}")
    except Exception as e:
        logger.error("alert_analyzer_training_failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alert-analyzer/model-info")
async def get_alert_analyzer_model_info():
    """
    Get detailed information about the Alert Analyzer models.
    """
    try:
        from ..ml.alert_analyzer_transformer import get_alert_analyzer
        
        analyzer = get_alert_analyzer()
        
        # Get feature importance and convert numpy floats to Python floats
        feature_importance = {}
        if analyzer.xgboost.model is not None:
            raw_importance = analyzer.xgboost.get_feature_importance()
            feature_importance = {k: float(v) for k, v in raw_importance.items()}
        
        # Convert training stats to JSON-serializable format
        training_stats = {}
        if analyzer.training_stats:
            training_stats = json.loads(json.dumps(analyzer.training_stats, default=str))
        
        info = {
            "ensemble_type": "Transformer + XGBoost + Rule-Based",
            "is_trained": analyzer.is_trained,
            "training_stats": training_stats,
            "model_weights": {k: float(v) for k, v in analyzer.weights.items()},
            "models": {
                "transformer": {
                    "type": "AlertTransformerEncoder",
                    "loaded": analyzer.transformer is not None,
                    "architecture": {
                        "feature_dim": 64,
                        "num_heads": 4,
                        "num_layers": 3,
                        "dropout": 0.1
                    }
                },
                "xgboost": {
                    "type": "XGBClassifier",
                    "loaded": analyzer.xgboost.model is not None,
                    "feature_importance": feature_importance
                },
                "rule_based": {
                    "type": "DomainKnowledgeRules",
                    "loaded": True,
                    "tp_rates": {k: float(v) for k, v in analyzer.rule_tp_rates.items()}
                }
            }
        }
        
        return info
        
    except ImportError:
        return {
            "ensemble_type": "Simple MLP (fallback)",
            "is_trained": False,
            "note": "Ensemble analyzer not available, using basic MLP"
        }
    except Exception as e:
        logger.error("alert_analyzer_model_info_failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
# Rebuild trigger Sun Jan 25 19:42:43 IST 2026
