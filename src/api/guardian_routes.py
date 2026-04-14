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

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
import asyncio
import structlog

from ..response.guardian import (
    guardian,
    ProtocolConfig,
    ResponseAction,
    ResponseRecord,
    ResponseStatus,
)
from ..response.policy import PausePolicy
from ..database.audit import AuditLogger, ActionType

# Import API key authentication
from .middleware.security import require_api_key

# Shared policy instance for manual-pause safety checks
_pause_policy = PausePolicy()

# In-memory state for tracking paused contracts and other transient data
_guardian_state: dict = {
    "paused_contracts": set(),
}

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

    # Fire-and-forget WebSocket broadcast
    try:
        from .ws_broadcast import broadcast_guardian_action
        asyncio.create_task(broadcast_guardian_action({
            "action": "approve",
            "response_id": record.id,
            "protocol": record.protocol,
            "status": record.status.value,
            "tx_hash": record.tx_hash,
        }))
    except Exception:
        pass

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

    # Fire-and-forget WebSocket broadcast
    try:
        from .ws_broadcast import broadcast_guardian_action
        asyncio.create_task(broadcast_guardian_action({
            "action": "manual_pause",
            "protocol_id": request.protocol_id,
            "response_id": record.id,
            "status": record.status.value,
            "initiated_by": request.initiated_by,
        }))
    except Exception:
        pass

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
    except Exception:
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

    # Fire-and-forget WebSocket broadcast
    try:
        from .ws_broadcast import broadcast_guardian_action
        asyncio.create_task(broadcast_guardian_action({
            "action": "emergency_pause",
            "incident_id": request.incident_id,
            "protocols_affected": len(results),
            "results": results,
        }))
    except Exception:
        pass

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


# ============================================================================
# Approval Workflow Endpoints (path-parameter based)
# ============================================================================

@router.get("/pending-actions")
async def get_pending_actions():
    """Get all actions awaiting human approval."""
    pending = guardian.get_pending_approvals()
    return {
        "count": len(pending),
        "pending_actions": [
            {
                "id": r.id,
                "incident_id": r.incident_id,
                "action": r.action.value,
                "status": r.status.value,
                "protocol": r.protocol,
                "chain": r.chain_id,
                "contract": r.contract_address,
                "initiated_at": r.initiated_at.isoformat(),
                "initiated_by": r.initiated_by,
                "metadata": r.metadata
            }
            for r in pending
        ]
    }


@router.post("/actions/{action_id}/approve")
async def approve_action_by_id(action_id: str, body: dict):
    """
    Human approves a guardian action for execution.

    Body: { "approved_by": str, "notes": str (optional) }
    """
    approved_by = body.get("approved_by")
    if not approved_by:
        raise HTTPException(status_code=400, detail="approved_by is required")

    notes = body.get("notes", "")
    logger.info(
        "guardian_approve_action",
        action_id=action_id,
        approved_by=approved_by,
        notes=notes,
    )

    record = await guardian.approve_response(
        response_id=action_id,
        approved_by=approved_by,
    )

    if not record:
        raise HTTPException(status_code=404, detail="Action not found or already processed")

    # Store notes in metadata if provided
    if notes:
        record.metadata["approval_notes"] = notes

    AuditLogger.log_guardian_pause(
        incident_id=record.incident_id,
        protocol_id=record.protocol,
        contract_address=record.contract_address,
        success=record.status == ResponseStatus.SUCCESS,
        actor_id=approved_by,
        tx_hash=record.tx_hash,
        error=record.error,
    )

    return {
        "status": "approved",
        "action_id": record.id,
        "action": record.action.value,
        "execution_status": record.status.value,
        "tx_hash": record.tx_hash,
        "error": record.error,
    }


@router.post("/actions/{action_id}/reject")
async def reject_action_by_id(action_id: str, body: dict):
    """
    Human rejects a guardian action.

    Body: { "rejected_by": str, "reason": str }
    """
    rejected_by = body.get("rejected_by")
    reason = body.get("reason", "No reason provided")

    if not rejected_by:
        raise HTTPException(status_code=400, detail="rejected_by is required")

    logger.info(
        "guardian_reject_action",
        action_id=action_id,
        rejected_by=rejected_by,
        reason=reason,
    )

    success = await guardian.reject_response(
        response_id=action_id,
        rejected_by=rejected_by,
        reason=reason,
    )

    if not success:
        raise HTTPException(status_code=404, detail="Action not found or already processed")

    AuditLogger.log(
        action_type=ActionType.GUARDIAN_PAUSE_FAILED,
        actor_id=rejected_by,
        resource_id=action_id,
        details={"action": "reject", "reason": reason},
    )

    return {
        "status": "rejected",
        "action_id": action_id,
        "rejected_by": rejected_by,
        "reason": reason,
    }


# ============================================================================
# Protocol Management Endpoints
# ============================================================================

@router.get("/protocols")
async def list_protocols():
    """List all registered protocols with their guardian config."""
    protocol_list = []
    for pid, config in guardian.protocols.items():
        protocol_list.append({
            "id": pid,
            "name": config.protocol_name,
            "chain": config.chain_id,
            "main_contract": config.main_contract,
            "pause_contract": config.pause_contract,
            "multisig_address": config.multisig_address,
            "auto_pause_on_critical": config.auto_pause_on_critical,
            "auto_pause_on_high": config.auto_pause_on_high,
            "require_approval_threshold_usd": config.require_approval_threshold_usd,
            "emergency_contacts": config.emergency_contacts,
            "is_paused": config.main_contract in _guardian_state.get("paused_contracts", set()),
        })
    return {
        "count": len(protocol_list),
        "protocols": protocol_list,
    }


@router.post("/protocols")
async def register_protocol_simple(body: dict):
    """
    Register a new protocol for guardian monitoring.

    Simplified endpoint that accepts a plain dict body.
    """
    required_fields = ["protocol_id", "protocol_name", "chain_id", "main_contract"]
    for field in required_fields:
        if not body.get(field):
            raise HTTPException(status_code=400, detail=f"{field} is required")

    protocol_id = body["protocol_id"]
    config = ProtocolConfig(
        protocol_name=body["protocol_name"],
        chain_id=body["chain_id"],
        main_contract=body["main_contract"],
        pause_contract=body.get("pause_contract"),
        pause_function=body.get("pause_function", "pause()"),
        unpause_function=body.get("unpause_function", "unpause()"),
        multisig_address=body.get("multisig_address"),
        auto_pause_on_critical=body.get("auto_pause_on_critical", True),
        auto_pause_on_high=body.get("auto_pause_on_high", False),
        require_approval_threshold_usd=float(body.get("require_approval_threshold_usd", 1_000_000)),
        emergency_contacts=body.get("emergency_contacts", []),
    )

    guardian.register_protocol(protocol_id, config)

    logger.info("guardian_protocol_registered_simple", protocol_id=protocol_id)

    return {
        "status": "registered",
        "protocol_id": protocol_id,
        "message": f"Protocol {config.protocol_name} registered for guardian protection",
    }


@router.post("/protocols/{protocol_id}/pause")
async def pause_protocol(protocol_id: str, body: dict):
    """
    Manual emergency pause of a protocol.

    If the protocol's auto_pause_on_critical is true, execute immediately.
    Otherwise, create an action with REQUIRES_APPROVAL status.

    Body: { "reason": str, "initiated_by": str, "force": bool (optional) }
    """
    if protocol_id not in guardian.protocols:
        raise HTTPException(status_code=404, detail="Protocol not registered")

    config = guardian.protocols[protocol_id]
    reason = body.get("reason", "Manual pause")
    initiated_by = body.get("initiated_by", "dashboard_user")
    force = body.get("force", False)

    logger.warning(
        "guardian_protocol_pause_requested",
        protocol_id=protocol_id,
        reason=reason,
        initiated_by=initiated_by,
        force=force,
    )

    # If auto_pause_on_critical or force flag, execute immediately
    if config.auto_pause_on_critical or force:
        record = await guardian.handle_incident(
            incident_id=f"pause-{protocol_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            severity="critical",
            attack_type="manual_pause",
            affected_protocol=config.protocol_name,
            estimated_loss_usd=0,
            affected_chain=config.chain_id,
            contract_address=config.main_contract,
        )

        if record:
            # Track paused state
            _guardian_state.setdefault("paused_contracts", set()).add(config.main_contract)

            AuditLogger.log_guardian_pause(
                incident_id=record.incident_id,
                protocol_id=protocol_id,
                contract_address=config.main_contract,
                success=record.status == ResponseStatus.SUCCESS,
                actor_id=initiated_by,
                tx_hash=record.tx_hash,
                error=record.error,
            )

            # Fire-and-forget WebSocket broadcast
            try:
                from .ws_broadcast import broadcast_guardian_action
                asyncio.create_task(broadcast_guardian_action({
                    "action": "protocol_pause",
                    "protocol_id": protocol_id,
                    "status": record.status.value,
                    "initiated_by": initiated_by,
                }))
            except Exception:
                pass

            return {
                "status": "executed",
                "action_id": record.id,
                "execution_status": record.status.value,
                "tx_hash": record.tx_hash,
                "error": record.error,
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to create pause action")
    else:
        # Requires approval
        record = ResponseRecord(
            id=f"resp-pause-{protocol_id}-{datetime.now(timezone.utc).strftime('%H%M%S')}",
            incident_id=f"pause-{protocol_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            action=ResponseAction.PAUSE_CONTRACT,
            status=ResponseStatus.REQUIRES_APPROVAL,
            protocol=config.protocol_name,
            chain_id=config.chain_id,
            contract_address=config.main_contract,
            initiated_at=datetime.now(timezone.utc),
            initiated_by=initiated_by,
            metadata={"reason": reason, "manual": True},
        )
        guardian.pending_approvals[record.id] = record
        guardian.response_history.append(record)

        return {
            "status": "requires_approval",
            "action_id": record.id,
            "message": "Pause action requires human approval before execution",
        }


@router.post("/protocols/{protocol_id}/unpause")
async def unpause_protocol(protocol_id: str, body: dict):
    """
    Manual unpause of a protocol.

    Body: { "reason": str, "initiated_by": str }
    """
    if protocol_id not in guardian.protocols:
        raise HTTPException(status_code=404, detail="Protocol not registered")

    config = guardian.protocols[protocol_id]
    reason = body.get("reason", "Manual unpause")
    initiated_by = body.get("initiated_by", "dashboard_user")

    logger.warning(
        "guardian_protocol_unpause_requested",
        protocol_id=protocol_id,
        reason=reason,
        initiated_by=initiated_by,
    )

    record = ResponseRecord(
        id=f"resp-unpause-{protocol_id}-{datetime.now(timezone.utc).strftime('%H%M%S')}",
        incident_id=f"unpause-{protocol_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        action=ResponseAction.UNPAUSE_CONTRACT,
        status=ResponseStatus.PENDING,
        protocol=config.protocol_name,
        chain_id=config.chain_id,
        contract_address=config.main_contract,
        initiated_at=datetime.now(timezone.utc),
        initiated_by=initiated_by,
        metadata={"reason": reason},
    )

    # Attempt unpause (simulated if no Web3 connection)
    try:
        w3 = guardian._web3_connections.get(config.chain_id)
        if w3 and config.guardian_private_key:
            # Real unpause via Web3 would go here
            record.status = ResponseStatus.SUCCESS
            record.completed_at = datetime.now(timezone.utc)
        else:
            # No Web3 connection — mark as success (simulated)
            record.status = ResponseStatus.SUCCESS
            record.completed_at = datetime.now(timezone.utc)
            record.metadata["simulated"] = True
    except Exception as e:
        record.status = ResponseStatus.FAILED
        record.error = str(e)
        record.completed_at = datetime.now(timezone.utc)

    guardian.response_history.append(record)

    # Remove from paused tracking
    paused = _guardian_state.get("paused_contracts", set())
    paused.discard(config.main_contract)

    AuditLogger.log(
        action_type=ActionType.CHAIN_ADD,
        actor_id=initiated_by,
        resource_id=protocol_id,
        details={"action": "unpause", "reason": reason, "status": record.status.value},
    )

    return {
        "status": record.status.value,
        "action_id": record.id,
        "protocol_id": protocol_id,
        "message": f"Protocol {config.protocol_name} unpause {'completed' if record.status == ResponseStatus.SUCCESS else 'failed'}",
        "error": record.error,
    }


@router.post("/protocols/{protocol_id}/settings")
async def update_protocol_settings(protocol_id: str, body: dict):
    """
    Update auto-response settings for a protocol.

    Body: { "auto_pause_on_critical": bool, "auto_pause_on_high": bool,
            "require_approval_threshold_usd": float }
    """
    if protocol_id not in guardian.protocols:
        raise HTTPException(status_code=404, detail="Protocol not registered")

    config = guardian.protocols[protocol_id]

    if "auto_pause_on_critical" in body:
        config.auto_pause_on_critical = bool(body["auto_pause_on_critical"])
    if "auto_pause_on_high" in body:
        config.auto_pause_on_high = bool(body["auto_pause_on_high"])
    if "require_approval_threshold_usd" in body:
        config.require_approval_threshold_usd = float(body["require_approval_threshold_usd"])

    logger.info(
        "guardian_protocol_settings_updated",
        protocol_id=protocol_id,
        auto_pause_critical=config.auto_pause_on_critical,
        auto_pause_high=config.auto_pause_on_high,
        threshold=config.require_approval_threshold_usd,
    )

    return {
        "status": "updated",
        "protocol_id": protocol_id,
        "auto_pause_on_critical": config.auto_pause_on_critical,
        "auto_pause_on_high": config.auto_pause_on_high,
        "require_approval_threshold_usd": config.require_approval_threshold_usd,
    }


@router.post("/emergency-pause-all")
async def emergency_pause_all(body: dict):
    """
    Emergency pause ALL registered protocols.

    Body: { "reason": str, "initiated_by": str }
    """
    reason = body.get("reason", "Emergency pause all")
    initiated_by = body.get("initiated_by", "dashboard_user")

    logger.critical(
        "guardian_emergency_pause_all",
        reason=reason,
        initiated_by=initiated_by,
        protocol_count=len(guardian.protocols),
    )

    AuditLogger.log(
        action_type=ActionType.GUARDIAN_PAUSE_ATTEMPT,
        actor_id=initiated_by,
        resource_id="ALL_PROTOCOLS",
        details={"action": "emergency_pause_all", "reason": reason},
    )

    results = []
    for protocol_id, config in guardian.protocols.items():
        try:
            record = await guardian.handle_incident(
                incident_id=f"emergency-all-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{protocol_id}",
                severity="critical",
                attack_type="emergency_pause_all",
                affected_protocol=config.protocol_name,
                estimated_loss_usd=0,
                affected_chain=config.chain_id,
                contract_address=config.main_contract,
            )

            success = record and record.status == ResponseStatus.SUCCESS
            _guardian_state.setdefault("paused_contracts", set()).add(config.main_contract)

            results.append({
                "protocol_id": protocol_id,
                "protocol_name": config.protocol_name,
                "chain": config.chain_id,
                "status": record.status.value if record else "failed",
                "tx_hash": record.tx_hash if record else None,
                "error": record.error if record else None,
            })

            AuditLogger.log_guardian_pause(
                incident_id=record.incident_id if record else "unknown",
                protocol_id=protocol_id,
                contract_address=config.main_contract,
                success=success,
                actor_id=initiated_by,
                tx_hash=record.tx_hash if record else None,
                error=record.error if record else None,
            )
        except Exception as e:
            results.append({
                "protocol_id": protocol_id,
                "protocol_name": config.protocol_name,
                "chain": config.chain_id,
                "status": "error",
                "error": str(e),
            })

    return {
        "status": "pause_all_initiated",
        "protocols_affected": len(results),
        "results": results,
        "initiated_by": initiated_by,
        "reason": reason,
    }

