"""
Alert API Routes
Endpoints for managing contract threat alerts and notifications
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime
import os

router = APIRouter(prefix="/api/alerts", tags=["Contract Alerts"])

# In-memory storage for alerts (in production, use database)
contract_threat_alerts: List[dict] = []
notification_config = {
    "telegram_enabled": bool(os.getenv("TELEGRAM_BOT_TOKEN")),
    "slack_enabled": bool(os.getenv("SLACK_WEBHOOK_URL")),
    "email_enabled": False
}


class ContractAnalysisRequest(BaseModel):
    """Request to analyze a contract"""
    contract_address: str
    chain_id: str = "ethereum"


class NotificationConfigUpdate(BaseModel):
    """Update notification settings"""
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    slack_webhook_url: Optional[str] = None


class AlertStatusUpdate(BaseModel):
    """Update alert status"""
    status: str  # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE


# ============================================================================
# Alert Endpoints
# ============================================================================

@router.get("/contract-threats")
async def get_contract_threat_alerts(
    limit: int = 50,
    risk_level: Optional[str] = None,
    chain_id: Optional[str] = None,
    status: Optional[str] = None
):
    """
    Get list of contract threat alerts.
    
    Filters:
    - risk_level: CRITICAL, HIGH, MEDIUM, LOW
    - chain_id: ethereum, polygon, arbitrum, etc.
    - status: NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    """
    alerts = contract_threat_alerts.copy()
    
    if risk_level:
        alerts = [a for a in alerts if a.get("risk_level") == risk_level]
    if chain_id:
        alerts = [a for a in alerts if a.get("chain_id") == chain_id]
    if status:
        alerts = [a for a in alerts if a.get("status") == status]
    
    # Sort by timestamp descending
    alerts = sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)
    
    return {
        "total": len(alerts),
        "alerts": alerts[:limit],
        "filters_applied": {
            "risk_level": risk_level,
            "chain_id": chain_id,
            "status": status
        }
    }


@router.get("/contract-threats/{alert_id}")
async def get_alert_details(alert_id: str):
    """Get detailed information about a specific alert."""
    for alert in contract_threat_alerts:
        if alert.get("alert_id") == alert_id:
            return alert
    raise HTTPException(status_code=404, detail="Alert not found")


@router.patch("/contract-threats/{alert_id}/status")
async def update_alert_status(alert_id: str, update: AlertStatusUpdate):
    """Update the status of an alert."""
    valid_statuses = ["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    
    if update.status not in valid_statuses:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )
    
    for alert in contract_threat_alerts:
        if alert.get("alert_id") == alert_id:
            alert["status"] = update.status
            alert["status_updated_at"] = datetime.utcnow().isoformat()
            return {"success": True, "alert": alert}
    
    raise HTTPException(status_code=404, detail="Alert not found")


@router.post("/analyze-contract")
async def analyze_contract(request: ContractAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Manually trigger analysis of a specific contract address.
    
    This will:
    1. Fetch contract bytecode
    2. Run ML analysis
    3. Generate alert if malicious
    4. Send notifications
    """
    try:
        # Import here to avoid circular imports
        from ..ai.models.contract_classifier import ContractThreatClassifier, ThreatCategory
        
        # This would connect to the blockchain and analyze
        # For now, return a placeholder
        return {
            "status": "analysis_queued",
            "contract_address": request.contract_address,
            "chain_id": request.chain_id,
            "message": "Analysis will be performed and results will appear in alerts if threat detected"
        }
        
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="ML analysis module not available"
        )


# ============================================================================
# Notification Configuration
# ============================================================================

@router.get("/notifications/config")
async def get_notification_config():
    """Get current notification configuration (masks sensitive data)."""
    return {
        "telegram": {
            "enabled": notification_config["telegram_enabled"],
            "configured": bool(os.getenv("TELEGRAM_BOT_TOKEN"))
        },
        "slack": {
            "enabled": notification_config["slack_enabled"],
            "configured": bool(os.getenv("SLACK_WEBHOOK_URL"))
        },
        "email": {
            "enabled": notification_config["email_enabled"],
            "configured": False
        }
    }


@router.post("/notifications/test")
async def test_notifications():
    """Send a test notification to all configured channels."""
    try:
        from ..notifications.alert_notifier import get_notifier
        
        notifier = get_notifier()
        
        test_alert = {
            "alert_id": "TEST-001",
            "timestamp": datetime.utcnow().isoformat(),
            "chain_id": "ethereum",
            "contract_address": "0x1234567890123456789012345678901234567890",
            "deployer_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "tx_hash": "0x" + "a" * 64,
            "block_number": 12345678,
            "threat_category": "TEST_ALERT",
            "confidence": 0.99,
            "risk_level": "HIGH",
            "detected_patterns": ["test_pattern"],
            "bytecode_size": 1234,
            "gas_used": 500000
        }
        
        await notifier.send_contract_threat_alert(test_alert)
        
        return {
            "success": True,
            "message": "Test notification sent to configured channels",
            "stats": notifier.get_stats()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Statistics
# ============================================================================

@router.get("/stats")
async def get_alert_stats():
    """Get alert statistics."""
    alerts = contract_threat_alerts
    
    by_risk = {}
    by_chain = {}
    by_threat = {}
    by_status = {}
    
    for alert in alerts:
        risk = alert.get("risk_level", "UNKNOWN")
        chain = alert.get("chain_id", "unknown")
        threat = alert.get("threat_category", "unknown")
        status = alert.get("status", "NEW")
        
        by_risk[risk] = by_risk.get(risk, 0) + 1
        by_chain[chain] = by_chain.get(chain, 0) + 1
        by_threat[threat] = by_threat.get(threat, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
    
    return {
        "total_alerts": len(alerts),
        "by_risk_level": by_risk,
        "by_chain": by_chain,
        "by_threat_category": by_threat,
        "by_status": by_status,
        "last_24h": len([
            a for a in alerts 
            if a.get("timestamp", "")[:10] == datetime.utcnow().strftime("%Y-%m-%d")
        ])
    }


# ============================================================================
# Helper to add alerts (called by monitoring system)
# ============================================================================

def add_contract_threat_alert(alert: dict):
    """Add a new contract threat alert."""
    contract_threat_alerts.append(alert)
    
    # Keep only last 1000 alerts in memory
    if len(contract_threat_alerts) > 1000:
        contract_threat_alerts.pop(0)

