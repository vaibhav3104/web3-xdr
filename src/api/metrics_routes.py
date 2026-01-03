"""
Prometheus Metrics API routes for Web3 XDR.
"""

from fastapi import APIRouter, Response
from fastapi.responses import PlainTextResponse

from ..metrics import metrics

router = APIRouter(tags=["Metrics"])


@router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """
    Prometheus metrics endpoint.
    
    Returns all metrics in Prometheus exposition format.
    Scrape this endpoint with Prometheus at /metrics
    """
    return Response(
        content=metrics.get_metrics(),
        media_type=metrics.get_content_type()
    )


@router.get("/metrics/health")
async def metrics_health():
    """Check if metrics collection is healthy."""
    return {
        "status": "healthy",
        "metrics_enabled": True,
        "namespace": metrics.namespace
    }

