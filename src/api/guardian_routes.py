"""
Guardian API Routes - Automated Response Actions
================================================

Endpoints for:
- Registering protocols for protection
- Viewing/approving pending actions
- Manual pause triggers
- Response history

SECURITY: All write operations require admin API key authentication.
These endpoints control critical security actions (pause, unpause, approve).
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
import structlog

from ..response.guardian import (
    guardian,
    ProtocolConfig,
    ResponseRecord,
    ResponseAction,
    ResponseStatus
)
from ..response.policy import PausePolicy, PausePolicyConfig, PauseDecision
from ..database.audit import AuditLogger, ActionType

# Import API key authentication
from .middleware.security import require_api_key

# Shared policy instance for manual-pause safety checks
_pause_policy = PausePolicy()

router = APIRouter(prefix="/api/guardian", tags=["Guardian"])
logger = structlog.get_logger(__name__)


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
    override_policy: bool = False  # Skip cooldown check (logged as OVERRIDE)


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
async def register_protocol(
    request: RegisterProtocolRequest,
    client: dict = Depends(require_api_key(["admin"]))
):
    """Register a protocol for guardian protection. Requires admin API key."""
    logger.info("guardian_register_protocol", protocol_id=request.protocol_id, client=client.get("name", "unknown"))
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

    # Auto-initialize Web3 connections if not already done
    if not guardian._is_initialized:
        try:
            await guardian.initialize()
        except Exception as e:
            logger.warning("guardian_auto_init_failed", error=str(e))

    AuditLogger.log(
        action_type=ActionType.CHAIN_ADD,
        actor_id=client.get("name", "unknown"),
        resource_id=request.protocol_id,
        details={
            "protocol_name": request.protocol_name,
            "chain_id": request.chain_id,
            "main_contract": request.main_contract,
            "auto_pause_on_critical": request.auto_pause_on_critical,
        },
    )

    return {
        "status": "registered",
        "protocol_id": request.protocol_id,
        "message": f"Protocol {request.protocol_name} registered for guardian protection"
    }


@router.delete("/protocols/{protocol_id}")
async def unregister_protocol(
    protocol_id: str,
    client: dict = Depends(require_api_key(["admin"]))
):
    """Unregister a protocol from guardian protection. Requires admin API key."""
    logger.info("guardian_unregister_protocol", protocol_id=protocol_id, client=client.get("name", "unknown"))
    if protocol_id not in guardian.protocols:
        raise HTTPException(status_code=404, detail="Protocol not found")
    
    del guardian.protocols[protocol_id]

    AuditLogger.log(
        action_type=ActionType.CHAIN_REMOVE,
        actor_id=client.get("name", "unknown"),
        resource_id=protocol_id,
        details={"action": "unregister_protocol"},
    )

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
async def approve_response(
    request: ApproveResponseRequest,
    client: dict = Depends(require_api_key(["admin"]))
):
    """Approve a pending response action. Requires admin API key."""
    client_name = client.get("name", "unknown")
    logger.info("guardian_approve_response", response_id=request.response_id, approved_by=request.approved_by, client=client_name)
    record = await guardian.approve_response(
        response_id=request.response_id,
        approved_by=request.approved_by
    )

    if not record:
        raise HTTPException(status_code=404, detail="Response not found")

    AuditLogger.log_guardian_pause(
        incident_id=record.incident_id,
        protocol_id=record.protocol,
        contract_address=record.contract_address,
        success=record.status == ResponseStatus.SUCCESS,
        actor_id=request.approved_by,
        tx_hash=record.tx_hash,
        error=record.error,
    )

    return {
        "status": "approved",
        "response_id": record.id,
        "action": record.action.value,
        "execution_status": record.status.value,
        "tx_hash": record.tx_hash
    }


@router.post("/reject")
async def reject_response(
    request: RejectResponseRequest,
    client: dict = Depends(require_api_key(["admin"]))
):
    """Reject a pending response action. Requires admin API key."""
    client_name = client.get("name", "unknown")
    logger.info("guardian_reject_response", response_id=request.response_id, rejected_by=request.rejected_by, client=client_name)
    success = await guardian.reject_response(
        response_id=request.response_id,
        rejected_by=request.rejected_by,
        reason=request.reason
    )

    if not success:
        raise HTTPException(status_code=404, detail="Response not found")

    AuditLogger.log(
        action_type=ActionType.GUARDIAN_PAUSE_FAILED,
        actor_id=request.rejected_by,
        resource_id=request.response_id,
        details={
            "action": "reject",
            "reason": request.reason,
            "client": client_name,
        },
    )

    return {"status": "rejected", "response_id": request.response_id}


@router.post("/manual-pause")
async def manual_pause(
    request: ManualPauseRequest,
    client: dict = Depends(require_api_key(["admin"]))
):
    """
    Manually trigger a pause action. Requires admin API key.

    Safety: Still enforces cooldown policy check unless override_policy=True.
    All manual pauses are audit-logged (override actions logged separately).
    """
    client_name = client.get("name", "unknown")
    logger.warning(
        "guardian_manual_pause_triggered",
        protocol_id=request.protocol_id,
        reason=request.reason,
        initiated_by=request.initiated_by,
        override_policy=request.override_policy,
        client=client_name,
    )

    if request.protocol_id not in guardian.protocols:
        raise HTTPException(status_code=404, detail="Protocol not registered")

    config = guardian.protocols[request.protocol_id]

    # Policy check: enforce cooldown even for manual pauses
    last_attempt = _pause_policy._last_pause_attempts.get(request.protocol_id)
    if last_attempt and not request.override_policy:
        elapsed = (datetime.now(timezone.utc) - last_attempt).total_seconds()
        if elapsed < _pause_policy.config.cooldown_seconds:
            remaining = int(_pause_policy.config.cooldown_seconds - elapsed)
            AuditLogger.log(
                action_type=ActionType.GUARDIAN_PAUSE_FAILED,
                actor_id=request.initiated_by,
                resource_id=request.protocol_id,
                details={
                    "reason": "cooldown_active",
                    "remaining_seconds": remaining,
                    "manual_trigger": True,
                },
            )
            raise HTTPException(
                status_code=429,
                detail=f"Cooldown active: {remaining}s remaining. Use override_policy=true to bypass."
            )

    # Log override if used
    if request.override_policy:
        AuditLogger.log(
            action_type=ActionType.GUARDIAN_PAUSE_OVERRIDE,
            actor_id=request.initiated_by,
            resource_id=request.protocol_id,
            details={
                "reason": request.reason,
                "client": client_name,
                "manual_trigger": True,
                "override_policy": True,
            },
        )

    # Record this attempt in the policy cooldown tracker
    _pause_policy._last_pause_attempts[request.protocol_id] = datetime.now(timezone.utc)

    # Create a manual incident
    record = await guardian.handle_incident(
        incident_id=f"manual-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        severity="critical",
        attack_type="manual_trigger",
        affected_protocol=config.protocol_name,
        estimated_loss_usd=0,  # Manual, bypass approval threshold
        affected_chain=config.chain_id,
        contract_address=config.main_contract,
    )

    if not record:
        AuditLogger.log(
            action_type=ActionType.GUARDIAN_PAUSE_FAILED,
            actor_id=request.initiated_by,
            resource_id=request.protocol_id,
            details={"reason": request.reason, "error": "handle_incident returned None"},
        )
        raise HTTPException(status_code=500, detail="Failed to create pause action")

    # Audit log the attempt result
    AuditLogger.log_guardian_pause(
        incident_id=record.incident_id,
        protocol_id=request.protocol_id,
        contract_address=config.main_contract,
        success=record.status == ResponseStatus.SUCCESS,
        actor_id=request.initiated_by,
        tx_hash=record.tx_hash,
        error=record.error,
    )

    return {
        "status": "pause_initiated",
        "response_id": record.id,
        "execution_status": record.status.value,
        "tx_hash": record.tx_hash,
        "error": record.error,
        "policy_overridden": request.override_policy,
    }


class EmergencyPauseRequest(BaseModel):
    incident_id: str
    chains: List[str] = []
    reason: Optional[str] = None


@router.post("/emergency-pause")
async def emergency_pause(request: EmergencyPauseRequest):
    """
    Emergency pause triggered from an incident.

    This endpoint is called from the dashboard when a user clicks
    "Emergency Pause" on an incident. All actions are audit-logged.
    """
    from ..database.service import DatabaseService

    AuditLogger.log(
        action_type=ActionType.GUARDIAN_PAUSE_ATTEMPT,
        actor_id="dashboard_user",
        resource_id=request.incident_id,
        details={
            "action": "emergency_pause",
            "chains": request.chains,
            "reason": request.reason,
        },
    )

    # Try to get incident details
    incident = None
    try:
        incident_model = await DatabaseService.get_incident(request.incident_id)
        if incident_model:
            incident = {
                "affected_chains": incident_model.affected_chains or []
            }
    except Exception as e:
        pass

    # Find matching protocols for the affected chains
    affected_protocols = []
    chains_to_pause = request.chains or (incident.get('affected_chains', []) if incident else [])

    for protocol_id, config in guardian.protocols.items():
        if not chains_to_pause or config.chain_id in chains_to_pause:
            affected_protocols.append((protocol_id, config))

    if not affected_protocols:
        return {
            "status": "simulated",
            "message": "No protocols registered for guardian protection. In production, this would pause affected contracts.",
            "incident_id": request.incident_id,
            "chains": chains_to_pause,
            "action_required": "Register protocols via /api/guardian/protocols/register to enable real pausing"
        }

    # Execute pause for each affected protocol
    results = []
    for protocol_id, config in affected_protocols:
        try:
            record = await guardian.handle_incident(
                incident_id=request.incident_id,
                severity="critical",
                attack_type="emergency_pause",
                affected_protocol=config.protocol_name,
                estimated_loss_usd=0,
                affected_chain=config.chain_id,
                contract_address=config.main_contract
            )
            success = record and record.status == ResponseStatus.SUCCESS
            results.append({
                "protocol": config.protocol_name,
                "chain": config.chain_id,
                "status": record.status.value if record else "failed",
                "tx_hash": record.tx_hash if record else None
            })
            AuditLogger.log_guardian_pause(
                incident_id=request.incident_id,
                protocol_id=protocol_id,
                contract_address=config.main_contract,
                success=success,
                actor_id="dashboard_user",
                tx_hash=record.tx_hash if record else None,
            )
        except Exception as e:
            results.append({
                "protocol": config.protocol_name,
                "chain": config.chain_id,
                "status": "error",
                "error": str(e)
            })
            AuditLogger.log_guardian_pause(
                incident_id=request.incident_id,
                protocol_id=protocol_id,
                contract_address=config.main_contract,
                success=False,
                actor_id="dashboard_user",
                error=str(e),
            )

    return {
        "status": "pause_initiated",
        "incident_id": request.incident_id,
        "protocols_affected": len(results),
        "results": results
    }


class DryRunPauseRequest(BaseModel):
    protocol_id: str


@router.post("/dry-run-pause")
async def dry_run_pause(
    request: DryRunPauseRequest,
    client: dict = Depends(require_api_key(["admin"]))
):
    """
    Simulate a pause via eth_call without broadcasting a transaction.

    Returns estimated gas and whether the pause() call would succeed or revert
    (e.g. missing PAUSER_ROLE, contract already paused, etc.).
    """
    client_name = client.get("name", "unknown")
    logger.info("guardian_dry_run_pause", protocol_id=request.protocol_id, client=client_name)

    if request.protocol_id not in guardian.protocols:
        raise HTTPException(status_code=404, detail="Protocol not registered")

    result = await guardian.simulate_pause(request.protocol_id)

    AuditLogger.log(
        action_type=ActionType.GUARDIAN_PAUSE_ATTEMPT,
        actor_id=client_name,
        resource_id=request.protocol_id,
        details={"action": "dry_run_pause", "result": result},
    )

    status_code = 200 if result.get("success") else 422
    if not result.get("success"):
        raise HTTPException(status_code=status_code, detail=result)

    return result


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

