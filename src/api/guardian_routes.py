"""
Guardian API Routes - Automated Response Actions
================================================

Endpoints for:
- Registering protocols for protection
- Viewing/approving pending actions
- Manual pause triggers
- Response history
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from ..response.guardian import (
    guardian,
    ProtocolConfig,
    ResponseRecord,
    ResponseAction,
    ResponseStatus
)

router = APIRouter(prefix="/api/guardian", tags=["Guardian"])


# ============================================================================
# Request/Response Models
# ============================================================================

class RegisterProtocolRequest(BaseModel):
    protocol_id: str
    protocol_name: str
    chain_id: str
    main_contract: str
    pause_contract: Optional[str] = None
    pause_function: str = "pause()"
    unpause_function: str = "unpause()"
    multisig_address: Optional[str] = None
    auto_pause_on_critical: bool = True
    auto_pause_on_high: bool = False
    require_approval_threshold_usd: float = 1_000_000
    emergency_contacts: List[str] = []


class ManualPauseRequest(BaseModel):
    protocol_id: str
    reason: str
    initiated_by: str


class ApproveResponseRequest(BaseModel):
    response_id: str
    approved_by: str


class RejectResponseRequest(BaseModel):
    response_id: str
    rejected_by: str
    reason: str


class ResponseRecordResponse(BaseModel):
    id: str
    incident_id: str
    action: str
    status: str
    protocol: str
    chain_id: str
    contract_address: str
    initiated_at: str
    completed_at: Optional[str]
    tx_hash: Optional[str]
    error: Optional[str]
    initiated_by: str
    approved_by: Optional[str]


class GuardianStatsResponse(BaseModel):
    registered_protocols: int
    total_responses: int
    pending_approvals: int
    successful_pauses: int
    failed_responses: int
    is_initialized: bool


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/status")
async def get_guardian_status():
    """Get guardian system status."""
    stats = guardian.get_stats()
    protocols = [
        {
            "id": pid,
            "name": config.protocol_name,
            "chain": config.chain_id,
            "contract": config.main_contract,
            "auto_pause_critical": config.auto_pause_on_critical,
            "auto_pause_high": config.auto_pause_on_high
        }
        for pid, config in guardian.protocols.items()
    ]
    
    return {
        "status": "active" if stats["is_initialized"] else "not_initialized",
        "stats": stats,
        "registered_protocols": protocols
    }


@router.post("/protocols/register")
async def register_protocol(request: RegisterProtocolRequest):
    """Register a protocol for guardian protection."""
    config = ProtocolConfig(
        protocol_name=request.protocol_name,
        chain_id=request.chain_id,
        main_contract=request.main_contract,
        pause_contract=request.pause_contract,
        pause_function=request.pause_function,
        unpause_function=request.unpause_function,
        multisig_address=request.multisig_address,
        auto_pause_on_critical=request.auto_pause_on_critical,
        auto_pause_on_high=request.auto_pause_on_high,
        require_approval_threshold_usd=request.require_approval_threshold_usd,
        emergency_contacts=request.emergency_contacts
    )
    
    guardian.register_protocol(request.protocol_id, config)
    
    return {
        "status": "registered",
        "protocol_id": request.protocol_id,
        "message": f"Protocol {request.protocol_name} registered for guardian protection"
    }


@router.delete("/protocols/{protocol_id}")
async def unregister_protocol(protocol_id: str):
    """Unregister a protocol from guardian protection."""
    if protocol_id not in guardian.protocols:
        raise HTTPException(status_code=404, detail="Protocol not found")
    
    del guardian.protocols[protocol_id]
    
    return {"status": "unregistered", "protocol_id": protocol_id}


@router.get("/pending")
async def get_pending_approvals():
    """Get all pending response actions requiring approval."""
    pending = guardian.get_pending_approvals()
    
    return {
        "count": len(pending),
        "pending_actions": [
            {
                "id": r.id,
                "incident_id": r.incident_id,
                "action": r.action.value,
                "protocol": r.protocol,
                "chain": r.chain_id,
                "contract": r.contract_address,
                "initiated_at": r.initiated_at.isoformat(),
                "metadata": r.metadata
            }
            for r in pending
        ]
    }


@router.post("/approve")
async def approve_response(request: ApproveResponseRequest):
    """Approve a pending response action."""
    record = await guardian.approve_response(
        response_id=request.response_id,
        approved_by=request.approved_by
    )
    
    if not record:
        raise HTTPException(status_code=404, detail="Response not found")
    
    return {
        "status": "approved",
        "response_id": record.id,
        "action": record.action.value,
        "execution_status": record.status.value,
        "tx_hash": record.tx_hash
    }


@router.post("/reject")
async def reject_response(request: RejectResponseRequest):
    """Reject a pending response action."""
    success = await guardian.reject_response(
        response_id=request.response_id,
        rejected_by=request.rejected_by,
        reason=request.reason
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Response not found")
    
    return {"status": "rejected", "response_id": request.response_id}


@router.post("/manual-pause")
async def manual_pause(request: ManualPauseRequest):
    """
    Manually trigger a pause action.
    
    Use this for emergency situations where you want to pause
    a protocol without waiting for incident detection.
    """
    if request.protocol_id not in guardian.protocols:
        raise HTTPException(status_code=404, detail="Protocol not registered")
    
    config = guardian.protocols[request.protocol_id]
    
    # Create a manual incident
    record = await guardian.handle_incident(
        incident_id=f"manual-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        severity="critical",
        attack_type="manual_trigger",
        affected_protocol=config.protocol_name,
        estimated_loss_usd=0,  # Manual, bypass approval
        affected_chain=config.chain_id,
        contract_address=config.main_contract
    )
    
    if not record:
        raise HTTPException(
            status_code=500,
            detail="Failed to create pause action"
        )
    
    return {
        "status": "pause_initiated",
        "response_id": record.id,
        "execution_status": record.status.value,
        "tx_hash": record.tx_hash,
        "error": record.error
    }


@router.get("/history")
async def get_response_history(
    limit: int = 50,
    status: Optional[str] = None
):
    """Get response action history."""
    status_filter = None
    if status:
        try:
            status_filter = ResponseStatus[status.upper()]
        except KeyError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Valid values: {[s.name for s in ResponseStatus]}"
            )
    
    history = guardian.get_response_history(limit=limit, status=status_filter)
    
    return {
        "count": len(history),
        "responses": [
            {
                "id": r.id,
                "incident_id": r.incident_id,
                "action": r.action.value,
                "status": r.status.value,
                "protocol": r.protocol,
                "chain": r.chain_id,
                "contract": r.contract_address,
                "initiated_at": r.initiated_at.isoformat(),
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "tx_hash": r.tx_hash,
                "error": r.error,
                "initiated_by": r.initiated_by,
                "approved_by": r.approved_by
            }
            for r in history
        ]
    }


@router.get("/stats")
async def get_guardian_stats():
    """Get guardian system statistics."""
    return guardian.get_stats()


@router.post("/initialize")
async def initialize_guardian():
    """Initialize the guardian system (connects to blockchains)."""
    try:
        await guardian.initialize()
        return {
            "status": "initialized",
            "stats": guardian.get_stats()
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Initialization failed: {str(e)}"
        )

