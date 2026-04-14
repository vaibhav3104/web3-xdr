"""
Production Health Check Endpoints for Sentinel3.

Provides comprehensive health checks including:
- Database connectivity
- Redis connectivity
- Chain listener status
- Memory / CPU usage
- Uptime tracking
- Last event ingested timestamp
- Degraded status when any dependency is unhealthy
"""

import os
import time
from datetime import datetime, timezone
from typing import Any

import psutil
import structlog
from fastapi import APIRouter
from starlette.responses import JSONResponse

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["Health"])

# Module-level state
_start_time: float = time.time()
_last_event_timestamp: float | None = None


def record_event_ingested():
    """Call this whenever a new event is ingested to track recency."""
    global _last_event_timestamp
    _last_event_timestamp = time.time()


# ---------------------------------------------------------------------------
# Internal check helpers
# ---------------------------------------------------------------------------

async def _check_postgres() -> dict[str, Any]:
    """Verify PostgreSQL connectivity with a lightweight query."""
    try:
        from ..database.connection import DatabaseManager
        if DatabaseManager._session_factory is None:
            return {"status": "error", "detail": "session_factory not initialised"}
        async with DatabaseManager.get_session() as session:
            from sqlalchemy import text
            result = await session.execute(text("SELECT 1"))
            result.scalar()
        return {"status": "connected"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)[:120]}


async def _check_redis() -> dict[str, Any]:
    """Verify Redis connectivity."""
    try:
        import redis.asyncio as aioredis
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        r = aioredis.from_url(url, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        return {"status": "connected"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)[:120]}


async def _check_chain_listeners() -> dict[str, Any]:
    """Report chain listener status from shared monitor state."""
    try:
        from ..shared_state import monitor_state
        chains = getattr(monitor_state, "chain_states", {})
        if not chains:
            return {"status": "unknown", "detail": "no chain state available"}

        summary: dict[str, str] = {}
        healthy = 0
        for chain_id, state in chains.items():
            connected = getattr(state, "connected", False)
            summary[chain_id] = "connected" if connected else "disconnected"
            if connected:
                healthy += 1

        total = len(chains)
        overall = "healthy" if healthy == total else ("degraded" if healthy > 0 else "error")
        return {
            "status": overall,
            "healthy": healthy,
            "total": total,
            "chains": summary,
        }
    except (ImportError, AttributeError):
        return {"status": "unknown", "detail": "shared_state not available"}


def _check_system_resources() -> dict[str, Any]:
    """Report memory and CPU usage of the current process."""
    try:
        process = psutil.Process(os.getpid())
        mem = process.memory_info()
        return {
            "memory_rss_mb": round(mem.rss / (1024 * 1024), 1),
            "memory_vms_mb": round(mem.vms / (1024 * 1024), 1),
            "cpu_percent": process.cpu_percent(interval=None),
            "threads": process.num_threads(),
            "open_files": len(process.open_files()),
        }
    except Exception as exc:
        return {"error": str(exc)[:120]}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
async def health_check():
    """
    Basic liveness probe.  Always returns quickly.
    """
    return {
        "status": "healthy",
        "service": "sentinel3",
        "environment": os.getenv("ENVIRONMENT", "development"),
    }


@router.get("/health/detailed")
async def health_detailed():
    """
    Comprehensive health check for production monitoring.

    Returns *degraded* status if any dependency is unhealthy, along with
    per-component details so operators can pinpoint the issue.
    """
    postgres = await _check_postgres()
    redis = await _check_redis()
    chains = await _check_chain_listeners()
    resources = _check_system_resources()

    uptime_seconds = round(time.time() - _start_time, 1)

    last_event_iso = None
    last_event_age_seconds = None
    if _last_event_timestamp is not None:
        last_event_iso = datetime.fromtimestamp(_last_event_timestamp, tz=timezone.utc).isoformat()
        last_event_age_seconds = round(time.time() - _last_event_timestamp, 1)

    checks = {
        "postgres": postgres,
        "redis": redis,
        "chain_listeners": chains,
    }

    # Determine overall status
    component_statuses = [
        postgres.get("status"),
        redis.get("status"),
        chains.get("status"),
    ]
    if all(s == "connected" or s == "healthy" for s in component_statuses):
        overall = "healthy"
    elif any(s == "error" for s in component_statuses):
        overall = "degraded"
    else:
        overall = "degraded"

    # Additional staleness check: if no events in 10 minutes, flag it
    if last_event_age_seconds is not None and last_event_age_seconds > 600:
        overall = "degraded"

    status_code = 200 if overall == "healthy" else 200  # still 200, body carries status

    body = {
        "status": overall,
        "service": "sentinel3",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "uptime_seconds": uptime_seconds,
        "last_event_ingested": last_event_iso,
        "last_event_age_seconds": last_event_age_seconds,
        "checks": checks,
        "resources": resources,
    }
    return JSONResponse(content=body, status_code=status_code)


@router.get("/health/ready")
async def readiness_check():
    """
    Kubernetes readiness probe.

    Returns 503 when the database is unreachable so the load balancer
    stops sending traffic to this instance.
    """
    pg = await _check_postgres()
    if pg.get("status") != "connected":
        return JSONResponse({"ready": False, "reason": "postgres_unavailable"}, status_code=503)
    return {"ready": True}


@router.get("/health/live")
async def liveness_check():
    """
    Kubernetes liveness probe.  Checks that the process is responsive
    and not stuck.  Intentionally minimal.
    """
    return {"alive": True, "uptime_seconds": round(time.time() - _start_time, 1)}
