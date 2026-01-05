"""
ML API Routes
Endpoints for AI/ML contract analysis and threat detection
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime
import json

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

@router.get("/status")
async def get_ml_status():
    """Get ML system status"""
    return {
        "ml_available": AI_AVAILABLE,
        "classifier_loaded": classifier is not None,
        "model_type": "rule_based" if classifier and not classifier.model else "ml_model",
        "known_exploits": len(classifier.known_exploits) if classifier else 0,
        "alerts_count": len(simulated_monitor.alerts) if simulated_monitor else 0,
    }

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
    """Get ML-generated threat alerts"""
    if not AI_AVAILABLE or not simulated_monitor:
        raise HTTPException(status_code=503, detail="ML system not available")
    
    alerts = simulated_monitor.alerts
    
    if status:
        alerts = [a for a in alerts if a.status == status]
    
    # Sort by time, newest first
    alerts = sorted(alerts, key=lambda a: a.alert_time, reverse=True)[:limit]
    
    return {
        "total": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
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
