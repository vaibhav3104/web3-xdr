"""Forensics API routes for historical investigation."""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
import asyncio
import uuid

router = APIRouter(prefix="/api/forensics", tags=["forensics"])

# In-memory store for async investigation results
_investigations: dict = {}


class InvestigationRequest(BaseModel):
    query_type: str = Field(
        ...,
        description="address_history|incident_replay|block_range_scan|fund_flow_trace|pattern_search",
    )
    chain_ids: List[str] = Field(default_factory=list)
    addresses: List[str] = Field(default_factory=list)
    start_block: Optional[int] = None
    end_block: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    incident_id: Optional[str] = None
    max_depth: int = 5


class InvestigationStatus(BaseModel):
    investigation_id: str
    status: str  # pending, running, completed, failed
    progress: float = 0.0
    result: Optional[dict] = None
    error: Optional[str] = None


@router.post("/investigate")
async def start_investigation(req: InvestigationRequest, background_tasks: BackgroundTasks):
    """Start an async forensic investigation."""
    inv_id = str(uuid.uuid4())[:12]
    _investigations[inv_id] = {
        "status": "pending",
        "progress": 0.0,
        "result": None,
        "error": None,
    }

    async def run_investigation():
        try:
            _investigations[inv_id]["status"] = "running"
            from src.forensics.engine import (
                ForensicsEngine,
                ForensicQuery,
                ForensicQueryType,
            )

            engine = ForensicsEngine()
            query = ForensicQuery(
                query_type=ForensicQueryType(req.query_type),
                chain_ids=req.chain_ids,
                addresses=req.addresses,
                start_block=req.start_block,
                end_block=req.end_block,
                start_time=req.start_time,
                end_time=req.end_time,
                incident_id=req.incident_id,
                max_depth=req.max_depth,
            )
            report = await engine.investigate(query)
            _investigations[inv_id]["status"] = "completed"
            _investigations[inv_id]["progress"] = 1.0
            _investigations[inv_id]["result"] = {
                "summary": report.summary,
                "timeline": [
                    {
                        "timestamp": str(e.timestamp),
                        "chain_id": e.chain_id,
                        "event_type": e.event_type,
                        "tx_hash": e.tx_hash,
                        "block_number": e.block_number,
                        "description": e.description,
                        "amount_usd": e.amount_usd,
                        "from_address": e.from_address,
                        "to_address": e.to_address,
                        "severity": e.severity,
                        "is_violation": e.is_violation,
                    }
                    for e in report.timeline
                ],
                "fund_flows": report.fund_flows,
                "violations_found": report.violations_found,
                "affected_addresses": report.affected_addresses,
                "affected_chains": report.affected_chains,
                "total_loss_usd": report.total_loss_usd,
                "attack_pattern": report.attack_pattern,
            }
        except Exception as ex:
            _investigations[inv_id]["status"] = "failed"
            _investigations[inv_id]["error"] = str(ex)

    # Schedule the investigation as a background coroutine
    try:
        asyncio.ensure_future(run_investigation())
    except Exception:
        background_tasks.add_task(run_investigation)

    return {"investigation_id": inv_id, "status": "pending"}


@router.get("/investigate/{investigation_id}")
async def get_investigation(investigation_id: str):
    """Get status and results of a forensic investigation."""
    if investigation_id not in _investigations:
        raise HTTPException(status_code=404, detail="Investigation not found")
    inv = _investigations[investigation_id]
    return InvestigationStatus(
        investigation_id=investigation_id,
        status=inv["status"],
        progress=inv["progress"],
        result=inv["result"],
        error=inv["error"],
    )


@router.get("/investigations")
async def list_investigations():
    """List all investigations."""
    return [
        {"investigation_id": k, "status": v["status"], "progress": v["progress"]}
        for k, v in _investigations.items()
    ]


@router.get("/address/{address}/history")
async def get_address_history(
    address: str, chain_id: Optional[str] = None, limit: int = 100
):
    """Quick address history lookup (synchronous)."""
    from src.forensics.engine import ForensicsEngine, ForensicQuery, ForensicQueryType

    engine = ForensicsEngine()
    query = ForensicQuery(
        query_type=ForensicQueryType.ADDRESS_HISTORY,
        addresses=[address],
        chain_ids=[chain_id] if chain_id else [],
    )
    report = await engine.investigate(query)
    return {
        "address": address,
        "event_count": len(report.timeline),
        "chains": report.affected_chains,
        "timeline": [
            {
                "timestamp": str(e.timestamp),
                "chain_id": e.chain_id,
                "event_type": e.event_type,
                "tx_hash": e.tx_hash,
                "amount_usd": e.amount_usd,
            }
            for e in report.timeline[:limit]
        ],
    }


@router.get("/incident/{incident_id}/replay")
async def replay_incident(incident_id: str):
    """Replay an incident and re-evaluate invariants."""
    from src.forensics.engine import ForensicsEngine, ForensicQuery, ForensicQueryType

    engine = ForensicsEngine()
    query = ForensicQuery(
        query_type=ForensicQueryType.INCIDENT_REPLAY,
        incident_id=incident_id,
    )
    report = await engine.investigate(query)
    return {
        "incident_id": incident_id,
        "summary": report.summary,
        "attack_pattern": report.attack_pattern,
        "total_loss_usd": report.total_loss_usd,
        "timeline_events": len(report.timeline),
        "violations_found": len(report.violations_found),
        "timeline": [
            {
                "timestamp": str(e.timestamp),
                "chain_id": e.chain_id,
                "event_type": e.event_type,
                "tx_hash": e.tx_hash,
                "description": e.description,
                "amount_usd": e.amount_usd,
                "severity": e.severity,
            }
            for e in report.timeline
        ],
        "violations": report.violations_found,
        "affected_chains": report.affected_chains,
    }
