"""
Runtime Security Plane API Routes
=================================

Endpoints for predicted incidents and simulation management.
"""

from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends, Query, Body, status
import structlog
import uuid

from ..auth.jwt_handler import require_auth, require_role
from ..auth.models import User
from ..models.predicted_incidents import (
    PredictedIncidentStatus,
)
from ..database.connection import DatabaseManager
from ..database.models import PredictedIncidentModel, SimulationRunModel
from ..database.audit import AuditLogger, ActionType
from sqlalchemy import select, and_, desc

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/runtime", tags=["Runtime Security"])


@router.get("/predicted-incidents", response_model=List[dict])
async def list_predicted_incidents(
    chain_id: Optional[str] = Query(None, description="Filter by chain ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: User = Depends(require_auth)
):
    """
    List predicted incidents.
    Available to all authenticated users (viewer/operator/admin).
    """
    try:
        async with DatabaseManager.get_session() as session:
            query = select(PredictedIncidentModel)
            
            # Apply filters
            filters = []
            if chain_id:
                filters.append(PredictedIncidentModel.chain_id == chain_id)
            if status:
                filters.append(PredictedIncidentModel.status == status)
            if severity:
                filters.append(PredictedIncidentModel.severity == severity)
            
            if filters:
                query = query.where(and_(*filters))
            
            # Order by created_at descending
            query = query.order_by(desc(PredictedIncidentModel.created_at))
            
            # Pagination
            query = query.limit(limit).offset(offset)
            
            result = await session.execute(query)
            incidents = result.scalars().all()
            
            return [incident_to_dict(inc) for inc in incidents]
    
    except Exception as e:
        logger.error("failed_to_list_predicted_incidents", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list predicted incidents: {str(e)}"
        )


@router.get("/predicted-incidents/{incident_id}", response_model=dict)
async def get_predicted_incident(
    incident_id: str,
    current_user: User = Depends(require_auth)
):
    """
    Get a specific predicted incident by ID.
    Available to all authenticated users.
    """
    try:
        async with DatabaseManager.get_session() as session:
            result = await session.execute(
                select(PredictedIncidentModel).where(PredictedIncidentModel.id == uuid.UUID(incident_id))
            )
            incident = result.scalar_one_or_none()
            
            if not incident:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Predicted incident not found"
                )
            
            return incident_to_dict(incident)
    
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid incident ID format"
        )
    except Exception as e:
        logger.error("failed_to_get_predicted_incident", incident_id=incident_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get predicted incident: {str(e)}"
        )


@router.get("/simulations/{simulation_id}", response_model=dict)
async def get_simulation(
    simulation_id: str,
    current_user: User = Depends(require_auth)
):
    """
    Get a specific simulation run by ID.
    Available to all authenticated users.
    """
    try:
        async with DatabaseManager.get_session() as session:
            result = await session.execute(
                select(SimulationRunModel).where(SimulationRunModel.id == uuid.UUID(simulation_id))
            )
            simulation = result.scalar_one_or_none()
            
            if not simulation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Simulation run not found"
                )
            
            return simulation_to_dict(simulation)
    
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid simulation ID format"
        )
    except Exception as e:
        logger.error("failed_to_get_simulation", simulation_id=simulation_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get simulation: {str(e)}"
        )


@router.post("/simulate", response_model=dict)
async def simulate_transaction(
    chain_id: str = Body(..., description="Chain ID"),
    tx_hash: str = Body(..., description="Transaction hash to simulate"),
    mode: str = Body("FAST", description="Simulation mode: FAST/FULL/BUNDLE"),
    current_user: User = Depends(require_role(["admin", "operator"]))
):
    """
    Manually trigger a simulation for a transaction (dry-run tool).
    Requires operator or admin role.
    """
    try:
        # Log audit
        await AuditLogger.log(
            action_type=ActionType.CONFIG_UPDATE,
            actor_id=current_user.username,
            entity_type="simulation",
            entity_id=tx_hash,
            details={"chain_id": chain_id, "mode": mode, "manual": True}
        )
        
        # TODO: Actually trigger simulation
        # This would require access to RuntimeEngine instance
        # For now, return a placeholder response
        
        logger.info(
            "manual_simulation_requested",
            chain_id=chain_id,
            tx_hash=tx_hash,
            mode=mode,
            user=current_user.username
        )
        
        return {
            "message": "Simulation requested (not yet implemented in API)",
            "chain_id": chain_id,
            "tx_hash": tx_hash,
            "mode": mode,
            "status": "pending"
        }
    
    except Exception as e:
        logger.error("failed_to_simulate", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to simulate transaction: {str(e)}"
        )


@router.post("/predicted-incidents/{incident_id}/dismiss")
async def dismiss_predicted_incident(
    incident_id: str,
    reason: Optional[str] = Body(None, description="Reason for dismissal"),
    current_user: User = Depends(require_role(["admin", "operator"]))
):
    """
    Dismiss a predicted incident as false positive.
    Requires operator or admin role.
    """
    try:
        async with DatabaseManager.get_session() as session:
            result = await session.execute(
                select(PredictedIncidentModel).where(PredictedIncidentModel.id == uuid.UUID(incident_id))
            )
            incident = result.scalar_one_or_none()
            
            if not incident:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Predicted incident not found"
                )
            
            # Update status
            incident.status = PredictedIncidentStatus.DISMISSED.value
            incident.updated_at = datetime.now(timezone.utc)
            
            # Update explanation with dismissal reason
            if incident.explanation_json:
                incident.explanation_json["dismissed_by"] = current_user.username
                incident.explanation_json["dismissed_at"] = datetime.now(timezone.utc).isoformat()
                if reason:
                    incident.explanation_json["dismissal_reason"] = reason
            
            await session.commit()
            
            # Log audit
            await AuditLogger.log(
                action_type=ActionType.INCIDENT_STATUS_CHANGE,
                actor_id=current_user.username,
                entity_type="predicted_incident",
                entity_id=incident_id,
                details={"status": "DISMISSED", "reason": reason}
            )
            
            logger.info(
                "predicted_incident_dismissed",
                incident_id=incident_id,
                user=current_user.username,
                reason=reason
            )
            
            return {"message": "Predicted incident dismissed", "incident_id": incident_id}
    
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid incident ID format"
        )
    except Exception as e:
        logger.error("failed_to_dismiss_predicted_incident", incident_id=incident_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to dismiss predicted incident: {str(e)}"
        )


def incident_to_dict(incident: PredictedIncidentModel) -> dict:
    """Convert PredictedIncidentModel to dictionary."""
    return {
        "id": str(incident.id),
        "chain_id": incident.chain_id,
        "tx_hash": incident.tx_hash,
        "protocol_id": incident.protocol_id,
        "predicted_type": incident.predicted_type,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "status": incident.status,
        "dedupe_key": incident.dedupe_key,
        "explanation_json": incident.explanation_json or {},
        "evidence_json": incident.evidence_json or {},
        "linked_simulation_run_id": str(incident.linked_simulation_run_id) if incident.linked_simulation_run_id else None,
        "confirmed_incident_id": str(incident.confirmed_incident_id) if incident.confirmed_incident_id else None,
        "matched_at": incident.matched_at.isoformat() if incident.matched_at else None,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
        # Financial impact fields (Phase 9)
        "potential_loss_usd": float(incident.potential_loss_usd) if incident.potential_loss_usd else None,
        "potential_loss_token_symbol": incident.potential_loss_token_symbol,
        "financial_impact_json": incident.financial_impact_json or {},
    }


def simulation_to_dict(simulation: SimulationRunModel) -> dict:
    """Convert SimulationRunModel to dictionary."""
    return {
        "id": str(simulation.id),
        "chain_id": simulation.chain_id,
        "block_number": simulation.block_number,
        "block_hash": simulation.block_hash,
        "tx_hash": simulation.tx_hash,
        "tx_from": simulation.tx_from,
        "tx_to": simulation.tx_to,
        "tx_selector": simulation.tx_selector,
        "mode": simulation.mode,
        "status": simulation.status,
        "duration_ms": simulation.duration_ms,
        "rpc_calls": simulation.rpc_calls,
        "state_diff_fingerprint": simulation.state_diff_fingerprint or {},
        "invariant_results": simulation.invariant_results or [],
        "confidence": simulation.confidence,
        "confidence_reasons": simulation.confidence_reasons or {},
        "assumptions": simulation.assumptions or {},
        "created_at": simulation.created_at.isoformat(),
    }

