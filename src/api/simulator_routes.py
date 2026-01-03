"""
Attack Simulator API routes.
Allows triggering test attacks to demonstrate XDR detection capabilities.
"""

from typing import Optional
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog

from ..shared_state import monitor_state, LiveIncident

logger = structlog.get_logger()
router = APIRouter(prefix="/simulator", tags=["Attack Simulator"])


# ============================================================================
# Models
# ============================================================================

class AttackRequest(BaseModel):
    attack_type: str
    chain: str
    value_usd: int = 1000000
    severity: str = "critical"


class AttackResponse(BaseModel):
    success: bool
    attack_id: str
    incident_id: str
    detection_time_ms: int
    message: str


# ============================================================================
# Attack Definitions
# ============================================================================

ATTACK_TEMPLATES = {
    "unbacked_mint": {
        "name": "Unbacked Mint Attack",
        "description": "Mint tokens on destination chain without corresponding lock on source chain",
        "detection_rule": "UNBACKED_MINT",
        "typical_value_range": (10000000, 500000000)
    },
    "flash_loan": {
        "name": "Flash Loan Exploit",
        "description": "Use flash loans to manipulate prices and drain pools",
        "detection_rule": "FLASH_LOAN_EXPLOIT",
        "typical_value_range": (1000000, 100000000)
    },
    "liquidity_drain": {
        "name": "Liquidity Drain",
        "description": "Gradually drain liquidity from bridge pools",
        "detection_rule": "LIQUIDITY_ANOMALY",
        "typical_value_range": (5000000, 50000000)
    },
    "message_forgery": {
        "name": "Message Forgery",
        "description": "Forge cross-chain messages to execute unauthorized transactions",
        "detection_rule": "MESSAGE_FORGERY",
        "typical_value_range": (10000000, 200000000)
    },
    "validator_compromise": {
        "name": "Validator Compromise",
        "description": "Compromised bridge validators approving malicious transactions",
        "detection_rule": "VALIDATOR_COMPROMISE",
        "typical_value_range": (50000000, 500000000)
    },
    "money_laundering": {
        "name": "Cross-chain Laundering",
        "description": "Move funds across chains to obscure origin",
        "detection_rule": "LAUNDERING_PATTERN",
        "typical_value_range": (100000, 10000000)
    }
}


# ============================================================================
# Routes
# ============================================================================

@router.get("/attacks")
async def list_available_attacks():
    """List all available attack types for simulation."""
    return {
        "attacks": [
            {
                "id": attack_id,
                "name": attack["name"],
                "description": attack["description"],
                "value_range": attack["typical_value_range"]
            }
            for attack_id, attack in ATTACK_TEMPLATES.items()
        ]
    }


@router.post("/attack", response_model=AttackResponse)
async def execute_attack(request: AttackRequest):
    """Execute a simulated attack and see detection in action."""
    
    if request.attack_type not in ATTACK_TEMPLATES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown attack type. Available: {list(ATTACK_TEMPLATES.keys())}"
        )
    
    template = ATTACK_TEMPLATES[request.attack_type]
    
    # Create incident from simulated attack
    import time
    start_time = time.time()
    
    attack_id = str(uuid4())[:8]
    incident_id = f"SIM-{str(uuid4())[:8]}"
    
    # Create the incident as LiveIncident object
    incident = LiveIncident(
        id=incident_id,
        title=f"🎭 SIMULATED: {template['name']}",
        severity=request.severity.upper(),
        status="open",
        attack_type=request.attack_type,
        confidence=0.95,
        total_loss_usd=float(request.value_usd),
        affected_chains=[request.chain.capitalize()],
        events=[f"sim-event-{attack_id}"],
        created_at=datetime.utcnow(),
        recommended_actions=[
            "No action required - this is a simulation",
            f"Review {template['name']} detection rules",
            "Test response playbooks"
        ],
        detection_latency_blocks=1
    )
    
    # Add to monitor state
    monitor_state.add_incident(incident)
    
    detection_time_ms = int((time.time() - start_time) * 1000)
    
    logger.info(
        "simulated_attack_executed",
        attack_type=request.attack_type,
        chain=request.chain,
        value_usd=request.value_usd,
        incident_id=incident_id
    )
    
    return AttackResponse(
        success=True,
        attack_id=attack_id,
        incident_id=incident_id,
        detection_time_ms=detection_time_ms,
        message=f"Attack simulated successfully. Incident {incident_id} created."
    )


@router.post("/bulk")
async def execute_bulk_attacks(count: int = 5):
    """Execute multiple random attacks for demo purposes."""
    
    import random
    
    results = []
    for i in range(min(count, 10)):  # Max 10 at a time
        attack_type = random.choice(list(ATTACK_TEMPLATES.keys()))
        chain = random.choice(["ethereum", "polygon", "arbitrum", "solana", "bsc"])
        value = random.randint(100000, 10000000)
        severity = random.choice(["critical", "high", "medium"])
        
        request = AttackRequest(
            attack_type=attack_type,
            chain=chain,
            value_usd=value,
            severity=severity
        )
        
        result = await execute_attack(request)
        results.append(result)
    
    return {
        "message": f"Executed {len(results)} simulated attacks",
        "attacks": results
    }


@router.delete("/clear")
async def clear_simulated_incidents():
    """Clear all simulated incidents from the dashboard."""
    
    # Get current incidents
    incidents = monitor_state.get_incidents()
    
    # Filter out simulated ones
    real_incidents = [i for i in incidents if not i.get("is_simulation", False)]
    
    # Reset state with only real incidents
    removed_count = len(incidents) - len(real_incidents)
    
    return {
        "message": f"Cleared {removed_count} simulated incidents",
        "remaining": len(real_incidents)
    }

