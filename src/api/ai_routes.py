"""
AI Analysis API Routes for Sentinel3.

Provides AI-powered incident analysis, explanations, and recommendations.
"""

from typing import Optional, Dict, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

import structlog

from ..ai.analyzer import get_analyzer, ATTACK_PATTERNS

logger = structlog.get_logger()
router = APIRouter(prefix="/ai", tags=["AI Analysis"])


class AnalysisRequest(BaseModel):
    """Request body for incident analysis."""
    incident_id: Optional[str] = None
    incident_data: Optional[Dict[str, Any]] = None


class AnalysisResponse(BaseModel):
    """AI analysis response."""
    incident_id: str
    analysis: str
    summary: str
    recommendations: list
    attack_pattern: Dict[str, Any]
    backend: str
    model: str
    latency_seconds: float
    timestamp: str


@router.get("/analyze/{incident_id}")
async def analyze_incident_by_id(incident_id: str):
    """
    Get AI analysis for a specific incident by ID.
    
    The AI will provide:
    - Executive summary
    - Technical breakdown
    - Impact assessment
    - Recommended actions
    - Root cause hypothesis
    """
    from ..shared_state import monitor_state
    
    # Get incident from state
    incidents = monitor_state.get_incidents()
    incident = None
    for inc in incidents:
        if inc.id == incident_id:
            incident = {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "attack_type": inc.attack_type,
                "confidence": inc.confidence,
                "total_loss_usd": inc.total_loss_usd,
                "affected_chains": inc.affected_chains,
                "created_at": inc.created_at.isoformat() if hasattr(inc.created_at, 'isoformat') else str(inc.created_at)
            }
            break
    
    # Check simulated incidents
    if not incident:
        simulated = _get_simulated_incidents()
        for sim in simulated:
            if sim["id"] == incident_id:
                incident = sim
                break
    
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    
    # Get AI analysis
    analyzer = get_analyzer()
    
    analysis_result = await analyzer.analyze_incident(incident)
    summary = await analyzer.get_quick_summary(incident)
    recommendations = await analyzer.get_recommendations(incident)
    
    return {
        "incident_id": incident_id,
        "incident": incident,
        "analysis": analysis_result["analysis"],
        "summary": summary,
        "recommendations": recommendations,
        "attack_pattern": analysis_result["attack_pattern"],
        "backend": analysis_result["backend"],
        "model": analysis_result["model"],
        "latency_seconds": analysis_result["latency_seconds"],
        "timestamp": analysis_result["timestamp"]
    }


@router.post("/analyze")
async def analyze_incident_data(request: AnalysisRequest):
    """
    Analyze custom incident data with AI.
    
    Send incident details in the request body for analysis.
    """
    if not request.incident_data:
        raise HTTPException(status_code=400, detail="incident_data is required")
    
    analyzer = get_analyzer()
    
    analysis_result = await analyzer.analyze_incident(request.incident_data)
    summary = await analyzer.get_quick_summary(request.incident_data)
    recommendations = await analyzer.get_recommendations(request.incident_data)
    
    return {
        "incident_id": request.incident_data.get("id", "custom"),
        "analysis": analysis_result["analysis"],
        "summary": summary,
        "recommendations": recommendations,
        "attack_pattern": analysis_result["attack_pattern"],
        "backend": analysis_result["backend"],
        "model": analysis_result["model"],
        "latency_seconds": analysis_result["latency_seconds"],
        "timestamp": analysis_result["timestamp"]
    }


@router.get("/patterns")
async def list_attack_patterns():
    """
    List all known attack patterns with their indicators and recommended actions.
    
    Useful for understanding what the XDR can detect.
    """
    return {
        "patterns": ATTACK_PATTERNS,
        "total_patterns": len(ATTACK_PATTERNS),
        "categories": list(ATTACK_PATTERNS.keys())
    }


@router.get("/patterns/{attack_type}")
async def get_attack_pattern(attack_type: str):
    """
    Get detailed information about a specific attack pattern.
    """
    pattern = ATTACK_PATTERNS.get(attack_type)
    if not pattern:
        raise HTTPException(
            status_code=404, 
            detail=f"Attack pattern '{attack_type}' not found. Available: {list(ATTACK_PATTERNS.keys())}"
        )
    
    return {
        "attack_type": attack_type,
        "pattern": pattern
    }


@router.get("/summary/{incident_id}")
async def get_quick_summary(incident_id: str):
    """
    Get a quick 2-sentence summary of an incident for dashboard display.
    """
    from ..shared_state import monitor_state
    
    # Get incident
    incidents = monitor_state.get_incidents()
    incident = None
    for inc in incidents:
        if inc.id == incident_id:
            incident = {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "attack_type": inc.attack_type,
                "total_loss_usd": inc.total_loss_usd,
                "affected_chains": inc.affected_chains
            }
            break
    
    # Check simulated
    if not incident:
        simulated = _get_simulated_incidents()
        for sim in simulated:
            if sim["id"] == incident_id:
                incident = sim
                break
    
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    
    analyzer = get_analyzer()
    summary = await analyzer.get_quick_summary(incident)
    
    return {
        "incident_id": incident_id,
        "summary": summary
    }


@router.get("/status")
async def ai_status():
    """
    Check AI analysis service status and configuration.
    """
    analyzer = get_analyzer()
    
    return {
        "status": "operational",
        "backend": analyzer.backend,
        "model": analyzer.model if analyzer.backend != "local" else "rule-based",
        "api_configured": analyzer.backend != "local",
        "supported_backends": ["openai", "anthropic", "local"],
        "attack_patterns_loaded": len(ATTACK_PATTERNS)
    }


def _get_simulated_incidents():
    """Get simulated incidents for demo."""
    return [
        {
            "id": "SIM-WORMHOLE-001",
            "title": "🔴 CRITICAL: Wormhole Unbacked Mint ($145M)",
            "severity": "critical",
            "status": "open",
            "attack_type": "unbacked_mint",
            "confidence": 0.95,
            "total_loss_usd": 145156044.0,
            "affected_chains": ["solana", "ethereum"],
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "id": "SIM-FLASHLOAN-005",
            "title": "🔴 CRITICAL: Flash Loan Bridge Exploit ($39M)",
            "severity": "critical",
            "status": "open",
            "attack_type": "flash_loan_exploit",
            "confidence": 0.97,
            "total_loss_usd": 39099817.0,
            "affected_chains": ["ethereum"],
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "id": "SIM-LAUNDERING-004",
            "title": "🔴 CRITICAL: Cross-chain Money Laundering ($42M)",
            "severity": "critical",
            "status": "investigating",
            "attack_type": "money_laundering",
            "confidence": 0.92,
            "total_loss_usd": 42700793.0,
            "affected_chains": ["ethereum", "polygon", "arbitrum", "bsc"],
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "id": "SIM-STARGATE-003",
            "title": "🟠 HIGH: Stargate Liquidity Drain ($21M)",
            "severity": "high",
            "status": "open",
            "attack_type": "liquidity_drain",
            "confidence": 0.85,
            "total_loss_usd": 21771041.0,
            "affected_chains": ["ethereum", "arbitrum", "polygon"],
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "id": "SIM-LAYERZERO-002",
            "title": "🟠 HIGH: LayerZero Message Forgery (Blocked)",
            "severity": "high",
            "status": "resolved",
            "attack_type": "message_forgery",
            "confidence": 0.88,
            "total_loss_usd": 0.0,
            "affected_chains": ["arbitrum"],
            "created_at": datetime.utcnow().isoformat()
        }
    ]

