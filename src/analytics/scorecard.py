"""
Scorecard Service - ROI Engine
===============================

Calculates and aggregates financial metrics from predicted incidents.
Provides ROI metrics to demonstrate value to users.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
import structlog

from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from ..database.models import PredictedIncidentModel
from ..database.connection import DatabaseManager

logger = structlog.get_logger(__name__)


class ScorecardService:
    """Service for calculating ROI and performance metrics."""
    
    def __init__(self):
        self.logger = logger
    
    async def get_total_preserved_capital(
        self,
        timeframe_hours: int = 24,
        status_filter: Optional[List[str]] = None
    ) -> Decimal:
        """
        Calculate total preserved capital (USD) from prevented incidents.
        
        Args:
            timeframe_hours: Time window in hours (default: 24)
            status_filter: List of statuses to include (None = all except DISMISSED)
        
        Returns:
            Total USD value preserved
        """
        if status_filter is None:
            # Default: count OPEN and CONFIRMED_MATCH (prevented attacks)
            status_filter = ["OPEN", "CONFIRMED_MATCH"]
        
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=timeframe_hours)
        
        async with get_db_session() as session:
            query = select(
                func.coalesce(func.sum(PredictedIncidentModel.potential_loss_usd), 0)
            ).where(
                and_(
                    PredictedIncidentModel.created_at >= cutoff_time,
                    PredictedIncidentModel.status.in_(status_filter),
                    PredictedIncidentModel.potential_loss_usd.isnot(None),
                    PredictedIncidentModel.potential_loss_usd > 0
                )
            )
            
            result = await session.execute(query)
            total = result.scalar() or Decimal("0.0")
            
            logger.info(
                "total_preserved_capital_calculated",
                timeframe_hours=timeframe_hours,
                total_usd=str(total),
                status_filter=status_filter
            )
            
            return Decimal(str(total))
    
    async def get_incidents_blocked_count(
        self,
        timeframe_hours: int = 24,
        status_filter: Optional[List[str]] = None
    ) -> int:
        """
        Get count of incidents blocked.
        
        Args:
            timeframe_hours: Time window in hours
            status_filter: List of statuses to include
        
        Returns:
            Number of incidents blocked
        """
        if status_filter is None:
            status_filter = ["OPEN", "CONFIRMED_MATCH"]
        
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=timeframe_hours)
        
        async with DatabaseManager.get_session() as session:
            query = select(func.count(PredictedIncidentModel.id)).where(
                and_(
                    PredictedIncidentModel.created_at >= cutoff_time,
                    PredictedIncidentModel.status.in_(status_filter)
                )
            )
            
            result = await session.execute(query)
            count = result.scalar() or 0
            
            return count
    
    async def get_speed_metrics(self) -> Dict[str, float]:
        """
        Calculate average reaction time metrics.
        
        Returns:
            {
                "avg_reaction_time_ms": float,
                "min_reaction_time_ms": float,
                "max_reaction_time_ms": float,
            }
        """
        # For predicted incidents, reaction time is from detection to resolution
        # This is simplified - in real implementation would track resolution timestamps
        
        async with DatabaseManager.get_session() as session:
            # Get incidents that were resolved
            query = select(
                PredictedIncidentModel.created_at,
                PredictedIncidentModel.updated_at
            ).where(
                and_(
                    PredictedIncidentModel.status.in_(["CONFIRMED_MATCH", "CONFIRMED_MISMATCH", "DISMISSED"]),
                    PredictedIncidentModel.updated_at.isnot(None)
                )
            )
            
            result = await session.execute(query)
            incidents = result.all()
            
            if not incidents:
                return {
                    "avg_reaction_time_ms": 0.0,
                    "min_reaction_time_ms": 0.0,
                    "max_reaction_time_ms": 0.0,
                }
            
            reaction_times = []
            for created_at, updated_at in incidents:
                if created_at and updated_at:
                    delta = (updated_at - created_at).total_seconds() * 1000
                    reaction_times.append(delta)
            
            if not reaction_times:
                return {
                    "avg_reaction_time_ms": 0.0,
                    "min_reaction_time_ms": 0.0,
                    "max_reaction_time_ms": 0.0,
                }
            
            return {
                "avg_reaction_time_ms": sum(reaction_times) / len(reaction_times),
                "min_reaction_time_ms": min(reaction_times),
                "max_reaction_time_ms": max(reaction_times),
            }
    
    async def get_leaderboard(self, limit: int = 3) -> List[Dict[str, any]]:
        """
        Get top N most valuable saves.
        
        Args:
            limit: Number of top saves to return
        
        Returns:
            List of top saves with name, amount, date
        """
        async with DatabaseManager.get_session() as session:
            query = select(
                PredictedIncidentModel.predicted_type,
                PredictedIncidentModel.protocol_id,
                PredictedIncidentModel.potential_loss_usd,
                PredictedIncidentModel.potential_loss_token_symbol,
                PredictedIncidentModel.created_at,
                PredictedIncidentModel.tx_hash
            ).where(
                and_(
                    PredictedIncidentModel.potential_loss_usd.isnot(None),
                    PredictedIncidentModel.potential_loss_usd > 0,
                    PredictedIncidentModel.status.in_(["OPEN", "CONFIRMED_MATCH"])
                )
            ).order_by(
                PredictedIncidentModel.potential_loss_usd.desc()
            ).limit(limit)
            
            result = await session.execute(query)
            incidents = result.all()
            
            leaderboard = []
            for incident in incidents:
                predicted_type, protocol_id, loss_usd, token_symbol, created_at, tx_hash = incident
                
                # Build name
                name_parts = []
                if protocol_id:
                    name_parts.append(protocol_id)
                name_parts.append(predicted_type.replace("_", " ").title())
                name = " - ".join(name_parts) if name_parts else predicted_type
                
                leaderboard.append({
                    "name": name,
                    "amount": float(loss_usd) if loss_usd else 0.0,
                    "date": created_at.isoformat() if created_at else None,
                    "token_symbol": token_symbol,
                    "tx_hash": tx_hash[:16] + "..." if tx_hash else None,
                })
            
            logger.info("leaderboard_generated", count=len(leaderboard))
            return leaderboard
    
    async def get_scorecard(
        self,
        timeframe_hours: int = 24
    ) -> Dict[str, any]:
        """
        Get complete scorecard with all metrics.
        
        Args:
            timeframe_hours: Time window for metrics
        
        Returns:
            Complete scorecard dictionary
        """
        total_saved, incidents_blocked, speed_metrics, leaderboard = await asyncio.gather(
            self.get_total_preserved_capital(timeframe_hours),
            self.get_incidents_blocked_count(timeframe_hours),
            self.get_speed_metrics(),
            self.get_leaderboard(limit=3),
        )
        
        top_save = leaderboard[0] if leaderboard else None
        
        scorecard = {
            "total_saved_usd": float(total_saved),
            "incidents_blocked": incidents_blocked,
            "avg_reaction_time_ms": speed_metrics["avg_reaction_time_ms"],
            "min_reaction_time_ms": speed_metrics["min_reaction_time_ms"],
            "max_reaction_time_ms": speed_metrics["max_reaction_time_ms"],
            "top_save": top_save,
            "leaderboard": leaderboard,
            "timeframe_hours": timeframe_hours,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        
        logger.info("scorecard_generated", total_saved_usd=str(total_saved), incidents_blocked=incidents_blocked)
        return scorecard


# Global instance
_scorecard_service: Optional[ScorecardService] = None


def get_scorecard_service() -> ScorecardService:
    """Get or create global ScorecardService instance."""
    global _scorecard_service
    if _scorecard_service is None:
        _scorecard_service = ScorecardService()
    return _scorecard_service

