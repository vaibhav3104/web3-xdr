"""
Public API for Partners
=======================

REST API endpoints for external integrations:
1. Wallet risk scoring
2. Contract threat analysis
3. Transaction monitoring
4. Real-time alerts webhook
5. Block explorer links
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Header, Depends
from pydantic import BaseModel, Field
import structlog
import hashlib
import hmac
import time

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["public-api"])


# =============================================================================
# API Key Authentication
# =============================================================================

# In production, would be stored in database
API_KEYS = {
    "pk_test_sentinel3_demo": {
        "name": "Demo Partner",
        "tier": "free",
        "rate_limit": 100,  # requests per minute
        "permissions": ["read"],
    },
    "pk_live_partner_abc123": {
        "name": "Partner ABC",
        "tier": "pro",
        "rate_limit": 1000,
        "permissions": ["read", "write", "webhook"],
    },
}


async def verify_api_key(x_api_key: str = Header(None, alias="X-API-Key")):
    """Verify API key from header."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return API_KEYS[x_api_key]


# =============================================================================
# Response Models
# =============================================================================

class WalletRiskResponse(BaseModel):
    """Wallet risk assessment response."""
    address: str
    chain_id: str
    risk_score: float = Field(..., ge=0, le=1, description="Risk score from 0 (safe) to 1 (high risk)")
    risk_level: str = Field(..., description="Risk level: minimal, low, medium, high, critical")
    risk_factors: List[str] = Field(default_factory=list)
    labels: List[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_activity: Optional[str] = None
    transaction_count: int = 0
    total_volume_usd: float = 0.0
    connected_to_mixer: bool = False
    connected_to_exchange: bool = False
    is_contract: bool = False
    explorer_url: str = ""


class ContractThreatResponse(BaseModel):
    """Contract threat analysis response."""
    address: str
    chain_id: str
    is_threat: bool
    threat_score: float = Field(..., ge=0, le=1)
    threat_category: Optional[str] = None
    confidence: float = Field(..., ge=0, le=1)
    
    # Analysis details
    has_reentrancy: bool = False
    has_honeypot_pattern: bool = False
    has_rugpull_pattern: bool = False
    has_flash_loan_vulnerability: bool = False
    
    # Deployer info
    deployer_address: Optional[str] = None
    deployer_risk_score: float = 0.0
    
    # Metadata
    bytecode_size: int = 0
    creation_timestamp: Optional[str] = None
    explorer_url: str = ""


class TransactionAnalysisResponse(BaseModel):
    """Transaction analysis response."""
    tx_hash: str
    chain_id: str
    status: str  # pending, confirmed, failed
    risk_score: float = Field(..., ge=0, le=1)
    
    # Classification
    tx_type: str  # transfer, swap, bridge, contract_call, contract_deploy
    protocol: Optional[str] = None
    
    # Participants
    from_address: str
    to_address: Optional[str] = None
    from_risk_score: float = 0.0
    to_risk_score: float = 0.0
    
    # Value
    value_usd: float = 0.0
    gas_price_gwei: float = 0.0
    
    # Alerts
    alerts: List[str] = Field(default_factory=list)
    explorer_url: str = ""


class AlertWebhookPayload(BaseModel):
    """Webhook payload for real-time alerts."""
    alert_id: str
    alert_type: str
    severity: str
    timestamp: str
    chain_id: str
    
    # Details
    title: str
    description: str
    
    # Related entities
    addresses: List[str] = Field(default_factory=list)
    tx_hashes: List[str] = Field(default_factory=list)
    contracts: List[str] = Field(default_factory=list)
    
    # Risk assessment
    risk_score: float = 0.0
    estimated_loss_usd: float = 0.0
    
    # Links
    dashboard_url: str = ""
    explorer_urls: List[str] = Field(default_factory=list)


class WebhookRegistration(BaseModel):
    """Webhook registration request."""
    url: str = Field(..., description="HTTPS URL to receive webhooks")
    events: List[str] = Field(..., description="Event types to subscribe to")
    secret: Optional[str] = Field(None, description="Secret for HMAC signature verification")


# =============================================================================
# Block Explorer Links
# =============================================================================

EXPLORER_URLS = {
    "ethereum": "https://etherscan.io",
    "polygon": "https://polygonscan.com",
    "arbitrum": "https://arbiscan.io",
    "optimism": "https://optimistic.etherscan.io",
    "base": "https://basescan.org",
    "avalanche": "https://snowtrace.io",
    "bsc": "https://bscscan.com",
}


def get_explorer_url(chain_id: str, entity_type: str, value: str) -> str:
    """Generate block explorer URL."""
    base_url = EXPLORER_URLS.get(chain_id.lower(), "https://etherscan.io")
    
    if entity_type == "address":
        return f"{base_url}/address/{value}"
    elif entity_type == "tx":
        return f"{base_url}/tx/{value}"
    elif entity_type == "token":
        return f"{base_url}/token/{value}"
    elif entity_type == "block":
        return f"{base_url}/block/{value}"
    
    return base_url


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("/wallet/{address}/risk", response_model=WalletRiskResponse)
async def get_wallet_risk(
    address: str,
    chain_id: str = Query("ethereum", description="Chain ID"),
    api_key: dict = Depends(verify_api_key)
):
    """
    Get risk assessment for a wallet address.
    
    Returns:
    - Risk score (0-1)
    - Risk factors
    - Transaction history summary
    - Connections to known bad actors
    
    Use this to screen wallets before interaction.
    """
    from ..ai.graph_analysis import graph_analyzer
    
    # Analyze wallet
    analysis = graph_analyzer.analyze_wallet(address)
    
    # Get node data if available
    node = graph_analyzer._nodes.get(address.lower())
    
    return WalletRiskResponse(
        address=address,
        chain_id=chain_id,
        risk_score=analysis.get("risk_score", 0.5),
        risk_level=analysis.get("risk_level", "medium"),
        risk_factors=analysis.get("risk_factors", []),
        labels=[analysis.get("label")] if analysis.get("label") else [],
        first_seen=node.first_seen.isoformat() if node and node.first_seen else None,
        last_activity=node.last_seen.isoformat() if node and node.last_seen else None,
        transaction_count=node.tx_count if node else 0,
        total_volume_usd=(node.total_value_in_usd + node.total_value_out_usd) if node else 0,
        connected_to_mixer=any("mixer" in f.lower() for f in analysis.get("risk_factors", [])),
        connected_to_exchange=analysis.get("role") == "exchange",
        is_contract=node.is_contract if node else False,
        explorer_url=get_explorer_url(chain_id, "address", address),
    )


@router.get("/contract/{address}/threat", response_model=ContractThreatResponse)
async def get_contract_threat(
    address: str,
    chain_id: str = Query("ethereum", description="Chain ID"),
    api_key: dict = Depends(verify_api_key)
):
    """
    Analyze a contract for potential threats.
    
    Returns:
    - Threat classification
    - Vulnerability indicators
    - Deployer risk assessment
    
    Use this to screen contracts before interaction.
    """
    from ..ai.graph_analysis import graph_analyzer
    from ..database.service import DatabaseService
    
    # Check if we have analysis in database
    # For now, return mock analysis
    
    # Get deployer risk
    deployer_analysis = graph_analyzer.get_deployer_risk_score(address)
    
    return ContractThreatResponse(
        address=address,
        chain_id=chain_id,
        is_threat=deployer_analysis.get("risk_score", 0) > 0.6,
        threat_score=deployer_analysis.get("risk_score", 0.3),
        threat_category=None if deployer_analysis.get("risk_score", 0) < 0.6 else "suspicious_deployer",
        confidence=0.7,
        has_reentrancy=False,  # Would need bytecode analysis
        has_honeypot_pattern=False,
        has_rugpull_pattern=False,
        has_flash_loan_vulnerability=False,
        deployer_address=address,  # Would need actual deployer lookup
        deployer_risk_score=deployer_analysis.get("risk_score", 0.3),
        bytecode_size=0,
        creation_timestamp=None,
        explorer_url=get_explorer_url(chain_id, "address", address),
    )


@router.get("/transaction/{tx_hash}/analysis", response_model=TransactionAnalysisResponse)
async def get_transaction_analysis(
    tx_hash: str,
    chain_id: str = Query("ethereum", description="Chain ID"),
    api_key: dict = Depends(verify_api_key)
):
    """
    Analyze a transaction for risks.
    
    Returns:
    - Transaction classification
    - Participant risk scores
    - Alerts for suspicious patterns
    """
    from ..ai.graph_analysis import graph_analyzer
    
    # Would fetch actual transaction data from RPC/database
    # For now, return mock analysis
    
    return TransactionAnalysisResponse(
        tx_hash=tx_hash,
        chain_id=chain_id,
        status="confirmed",
        risk_score=0.2,
        tx_type="transfer",
        protocol=None,
        from_address="0x" + "0" * 40,
        to_address="0x" + "1" * 40,
        from_risk_score=0.1,
        to_risk_score=0.2,
        value_usd=0,
        gas_price_gwei=0,
        alerts=[],
        explorer_url=get_explorer_url(chain_id, "tx", tx_hash),
    )


@router.post("/webhooks/register")
async def register_webhook(
    registration: WebhookRegistration,
    api_key: dict = Depends(verify_api_key)
):
    """
    Register a webhook for real-time alerts.
    
    Event types:
    - threat_detected: New threat detected
    - incident_created: New security incident
    - liquidation_alert: Large liquidation
    - cross_chain_violation: Cross-chain attack detected
    
    Webhooks are signed with HMAC-SHA256 using your secret.
    """
    if "webhook" not in api_key.get("permissions", []):
        raise HTTPException(status_code=403, detail="Webhook permission required")
    
    # Validate URL
    if not registration.url.startswith("https://"):
        raise HTTPException(status_code=400, detail="Webhook URL must use HTTPS")
    
    # In production, would store in database
    webhook_id = hashlib.sha256(
        f"{api_key['name']}:{registration.url}".encode()
    ).hexdigest()[:16]
    
    logger.info(
        "webhook_registered",
        webhook_id=webhook_id,
        partner=api_key["name"],
        events=registration.events
    )
    
    return {
        "webhook_id": webhook_id,
        "url": registration.url,
        "events": registration.events,
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/webhooks")
async def list_webhooks(api_key: dict = Depends(verify_api_key)):
    """List registered webhooks for this API key."""
    # In production, would fetch from database
    return {"webhooks": []}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    api_key: dict = Depends(verify_api_key)
):
    """Delete a registered webhook."""
    # In production, would delete from database
    return {"status": "deleted", "webhook_id": webhook_id}


# =============================================================================
# Batch Endpoints
# =============================================================================

@router.post("/wallets/batch-risk")
async def batch_wallet_risk(
    addresses: List[str],
    chain_id: str = Query("ethereum"),
    api_key: dict = Depends(verify_api_key)
):
    """
    Get risk assessment for multiple wallets.
    
    Maximum 100 addresses per request.
    """
    if len(addresses) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 addresses per request")
    
    from ..ai.graph_analysis import graph_analyzer
    
    results = []
    for address in addresses:
        analysis = graph_analyzer.analyze_wallet(address)
        results.append({
            "address": address,
            "risk_score": analysis.get("risk_score", 0.5),
            "risk_level": analysis.get("risk_level", "medium"),
        })
    
    return {"results": results, "count": len(results)}


# =============================================================================
# Stats & Health
# =============================================================================

@router.get("/stats")
async def get_api_stats(api_key: dict = Depends(verify_api_key)):
    """Get API usage statistics."""
    from ..ai.graph_analysis import graph_analyzer
    
    graph_stats = graph_analyzer.get_stats()
    
    return {
        "api_version": "v1",
        "partner": api_key["name"],
        "tier": api_key["tier"],
        "graph_stats": graph_stats,
        "supported_chains": list(EXPLORER_URLS.keys()),
    }


@router.get("/health")
async def health_check():
    """Public health check endpoint (no auth required)."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
    }


# =============================================================================
# Fireblocks / Safe Integration Helpers
# =============================================================================

@router.post("/integrations/fireblocks/screen")
async def fireblocks_screen(
    addresses: List[str],
    api_key: dict = Depends(verify_api_key)
):
    """
    Screen addresses for Fireblocks integration.
    
    Returns risk assessment in Fireblocks-compatible format.
    """
    from ..ai.graph_analysis import graph_analyzer
    
    results = []
    for address in addresses:
        analysis = graph_analyzer.analyze_wallet(address)
        
        # Map to Fireblocks risk levels
        risk_score = analysis.get("risk_score", 0.5)
        if risk_score >= 0.8:
            fireblocks_risk = "SEVERE"
        elif risk_score >= 0.6:
            fireblocks_risk = "HIGH"
        elif risk_score >= 0.4:
            fireblocks_risk = "MEDIUM"
        else:
            fireblocks_risk = "LOW"
        
        results.append({
            "address": address,
            "risk": fireblocks_risk,
            "score": risk_score,
            "alerts": analysis.get("risk_factors", []),
        })
    
    return {"screeningResults": results}


@router.post("/integrations/safe/check")
async def safe_transaction_check(
    safe_address: str,
    to_address: str,
    value: str,
    data: str,
    api_key: dict = Depends(verify_api_key)
):
    """
    Check a Safe transaction before execution.
    
    Returns risk assessment for the transaction.
    """
    from ..ai.graph_analysis import graph_analyzer
    
    # Analyze recipient
    to_analysis = graph_analyzer.analyze_wallet(to_address)
    
    # Determine if transaction should be flagged
    risk_score = to_analysis.get("risk_score", 0.5)
    
    return {
        "safe_address": safe_address,
        "to_address": to_address,
        "risk_score": risk_score,
        "risk_level": to_analysis.get("risk_level", "medium"),
        "recommendation": "ALLOW" if risk_score < 0.6 else "REVIEW",
        "alerts": to_analysis.get("risk_factors", []),
    }
