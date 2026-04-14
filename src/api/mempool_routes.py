"""
Mempool Alerter API Routes
===========================

Endpoints for mempool pre-confirmation alerting stats, recent alerts,
and runtime toggle.
"""

from fastapi import APIRouter, HTTPException
import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/mempool", tags=["Mempool"])


def _get_alerter():
    """Retrieve the global MempoolAlerter singleton (lazy import)."""
    from ..runtime.mempool_alerter import get_mempool_alerter
    alerter = get_mempool_alerter()
    if alerter is None:
        raise HTTPException(
            status_code=503,
            detail="Mempool alerter is not running. Start the worker process first.",
        )
    return alerter


@router.get("/stats")
async def mempool_stats():
    """Return live statistics for the mempool alerter."""
    alerter = _get_alerter()
    return alerter.get_stats()


@router.get("/recent-alerts")
async def recent_mempool_alerts(limit: int = 50):
    """Return the most recent mempool pre-confirmation alerts."""
    alerter = _get_alerter()
    return alerter.get_recent_alerts(limit=min(limit, 200))


@router.post("/toggle")
async def toggle_mempool_alerting(body: dict):
    """
    Enable or disable mempool alerting at runtime.

    Body: ``{"enabled": true}`` or ``{"enabled": false}``
    """
    alerter = _get_alerter()
    enabled = body.get("enabled")
    if enabled is None:
        raise HTTPException(status_code=400, detail="Missing 'enabled' field in body")
    alerter.enabled = bool(enabled)
    logger.info("mempool_alerter_toggled", enabled=alerter.enabled)
    return {"enabled": alerter.enabled}
