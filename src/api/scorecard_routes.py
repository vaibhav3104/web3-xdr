"""
Scorecard API Routes - ROI Engine
==================================

API endpoints for accessing ROI and performance metrics.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
import structlog

from ..analytics.scorecard import get_scorecard_service

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/stats", tags=["Scorecard"])


class ScorecardResponse(BaseModel):
    """Scorecard API response model."""
    total_saved_usd: float
    incidents_blocked: int
    avg_reaction_time_ms: float
    min_reaction_time_ms: float
    max_reaction_time_ms: float
    top_save: Optional[dict] = None
    leaderboard: list = []
    timeframe_hours: int
    generated_at: str


@router.get("/scorecard", response_model=ScorecardResponse)
async def get_scorecard(
    timeframe_hours: int = Query(24, ge=1, le=720, description="Time window in hours (1-720)")
):
    """
    Get complete scorecard with ROI metrics.
    
    Returns:
        - total_saved_usd: Total USD value preserved
        - incidents_blocked: Number of incidents blocked
        - avg_reaction_time_ms: Average reaction time
        - top_save: Top save details
        - leaderboard: Top saves list
    """
    try:
        scorecard_service = get_scorecard_service()
        scorecard = await scorecard_service.get_scorecard(timeframe_hours=timeframe_hours)
        
        return ScorecardResponse(**scorecard)
    
    except Exception as e:
        logger.error("scorecard_api_error", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to generate scorecard: {str(e)}")


@router.get("/scorecard/total-saved")
async def get_total_saved(
    timeframe_hours: int = Query(24, ge=1, le=720)
):
    """Get total preserved capital in USD."""
    try:
        scorecard_service = get_scorecard_service()
        total = await scorecard_service.get_total_preserved_capital(timeframe_hours=timeframe_hours)
        return {"total_saved_usd": float(total), "timeframe_hours": timeframe_hours}
    except Exception as e:
        logger.error("total_saved_api_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scorecard/leaderboard")
async def get_leaderboard(
    limit: int = Query(3, ge=1, le=10, description="Number of top saves to return")
):
    """Get leaderboard of top saves."""
    try:
        scorecard_service = get_scorecard_service()
        leaderboard = await scorecard_service.get_leaderboard(limit=limit)
        return {"leaderboard": leaderboard}
    except Exception as e:
        logger.error("leaderboard_api_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

