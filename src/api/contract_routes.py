"""
Contract Threat API Routes
Endpoints for accessing contract deployment alerts and ML analysis
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import structlog

from ..telemetry.contract_alerts import (
    contract_alert_store, 
    ContractThreatAlert, 
    AlertStatus, 
    ThreatLevel
)
from ..database.service import DatabaseService

# Try to import ML classifier
try:
    from ..ai.models.contract_classifier import ContractThreatClassifier, ThreatCategory
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    ContractThreatClassifier = None

logger = structlog.get_logger()
router = APIRouter(prefix="/contracts", tags=["Contract Threats"])

# Pydantic models for API
class ContractAnalysisRequest(BaseModel):
    bytecode: str
    contract_address: Optional[str] = None
    chain_id: str = "ethereum"

class ContractAnalysisResponse(BaseModel):
    contract_address: str
    threat_category: str
    confidence: float
    risk_score: float
    risk_factors: List[str]
    similar_exploits: List[str]
    recommendation: str
    is_safe: bool

class AlertResponse(BaseModel):
    alert_id: str
    timestamp: str
    chain_id: str
    contract_address: str
    deployer_address: str
    tx_hash: str
    block_number: int
    threat_category: str
    threat_level: str
    confidence: float
    risk_score: float
    risk_factors: List[str]
    similar_exploits: List[str]
    recommendation: str
    bytecode_size: int
    bytecode_hash: str
    status: str
    notes: str

class AlertUpdateRequest(BaseModel):
    status: str
    notes: Optional[str] = None

class StatsResponse(BaseModel):
    total_contracts_analyzed: int
    total_threats_detected: int
    active_alerts: int
    alerts_last_24h: int
    contracts_by_chain: dict
    alerts_by_threat_level: dict
    alerts_by_status: dict
    alerts_by_category: dict


# Singleton classifier
_classifier = None

def get_classifier():
    global _classifier
    if _classifier is None and ML_AVAILABLE:
        try:
            _classifier = ContractThreatClassifier()
            logger.info("contract_classifier_initialized_for_api")
        except Exception as e:
            logger.error("contract_classifier_init_failed", error=str(e))
    return _classifier


@router.get("/alerts", response_model=List[AlertResponse])
async def list_contract_alerts(
    chain_id: Optional[str] = Query(None, description="Filter by chain"),
    status: Optional[str] = Query(None, description="Filter by status: active, investigating, resolved, false_positive"),
    threat_level: Optional[str] = Query(None, description="Filter by threat level: safe, low, medium, high, critical"),
    limit: int = Query(100, ge=1, le=500)
):
    """
    List all contract threat alerts with optional filtering.
    """
    # Parse filters
    status_filter = None
    if status:
        try:
            status_filter = AlertStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    
    threat_filter = None
    if threat_level:
        try:
            threat_filter = ThreatLevel(threat_level)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid threat_level: {threat_level}")
    
    alerts = contract_alert_store.get_all_alerts(
        chain_id=chain_id,
        status=status_filter,
        threat_level=threat_filter,
        limit=limit
    )
    
    return [
        AlertResponse(
            alert_id=a.alert_id,
            timestamp=a.timestamp.isoformat(),
            chain_id=a.chain_id,
            contract_address=a.contract_address,
            deployer_address=a.deployer_address,
            tx_hash=a.tx_hash,
            block_number=a.block_number,
            threat_category=a.threat_category,
            threat_level=a.threat_level.value,
            confidence=a.confidence,
            risk_score=a.risk_score,
            risk_factors=a.risk_factors,
            similar_exploits=a.similar_exploits,
            recommendation=a.recommendation,
            bytecode_size=a.bytecode_size,
            bytecode_hash=a.bytecode_hash,
            status=a.status.value,
            notes=a.notes
        )
        for a in alerts
    ]


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_contract_alert(alert_id: str):
    """
    Get a specific contract threat alert by ID.
    """
    alert = contract_alert_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return AlertResponse(
        alert_id=alert.alert_id,
        timestamp=alert.timestamp.isoformat(),
        chain_id=alert.chain_id,
        contract_address=alert.contract_address,
        deployer_address=alert.deployer_address,
        tx_hash=alert.tx_hash,
        block_number=alert.block_number,
        threat_category=alert.threat_category,
        threat_level=alert.threat_level.value,
        confidence=alert.confidence,
        risk_score=alert.risk_score,
        risk_factors=alert.risk_factors,
        similar_exploits=alert.similar_exploits,
        recommendation=alert.recommendation,
        bytecode_size=alert.bytecode_size,
        bytecode_hash=alert.bytecode_hash,
        status=alert.status.value,
        notes=alert.notes
    )


@router.patch("/alerts/{alert_id}")
async def update_contract_alert(alert_id: str, update: AlertUpdateRequest):
    """
    Update the status of a contract threat alert.
    """
    try:
        new_status = AlertStatus(update.status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {update.status}")
    
    success = contract_alert_store.update_status(alert_id, new_status, update.notes or "")
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return {"message": f"Alert {alert_id} updated to {update.status}"}


@router.get("/stats", response_model=StatsResponse)
async def get_contract_stats():
    """
    Get statistics about contract threat detection.
    
    Combines in-memory alert stats with database event counts.
    """
    # Get in-memory stats (alerts detected in this API instance)
    stats = contract_alert_store.get_stats()
    
    # Query database for actual contract deployment events
    try:
        # Count all contract_deploy events
        db_stats = await DatabaseService.get_contract_deployment_stats()
        
        # Merge database stats with in-memory stats
        stats["total_contracts_analyzed"] = db_stats.get("total_contracts", 0)
        stats["contracts_by_chain"] = db_stats.get("by_chain", {})
        
        logger.debug(
            "contract_stats_fetched",
            in_memory_alerts=stats.get("total_threats_detected", 0),
            db_contracts=db_stats.get("total_contracts", 0)
        )
    except Exception as e:
        logger.warning("contract_stats_db_query_failed", error=str(e))
        # Fall back to in-memory stats only
    
    return StatsResponse(**stats)


@router.post("/analyze", response_model=ContractAnalysisResponse)
async def analyze_contract_bytecode(request: ContractAnalysisRequest):
    """
    Analyze contract bytecode for potential threats.
    
    This endpoint allows manual analysis of contract bytecode without
    waiting for deployment detection.
    """
    classifier = get_classifier()
    
    if not classifier:
        raise HTTPException(
            status_code=503, 
            detail="ML classifier not available. Install numpy and scikit-learn."
        )
    
    # Clean bytecode
    bytecode = request.bytecode.strip()
    if bytecode.startswith("0x"):
        bytecode = bytecode[2:]
    
    if len(bytecode) < 10:
        raise HTTPException(status_code=400, detail="Bytecode too short")
    
    try:
        result = classifier.classify(bytecode, request.contract_address or "unknown")
        
        # Record analysis
        contract_alert_store.record_analysis(request.chain_id, result.threat_category.value != "safe")
        
        return ContractAnalysisResponse(
            contract_address=result.contract_address,
            threat_category=result.threat_category.value,
            confidence=result.confidence,
            risk_score=result.risk_score,
            risk_factors=result.risk_factors,
            similar_exploits=result.similar_exploits,
            recommendation=result.recommendation,
            is_safe=result.threat_category.value == "safe"
        )
    except Exception as e:
        logger.error("contract_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/health")
async def contract_detection_health():
    """
    Health check for contract detection system.
    """
    classifier = get_classifier()
    
    return {
        "status": "healthy",
        "ml_available": ML_AVAILABLE,
        "classifier_loaded": classifier is not None,
        "total_alerts": len(contract_alert_store._alerts),
        "total_analyzed": contract_alert_store.total_contracts_analyzed
    }

