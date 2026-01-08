"""
Database module for Sentinel3.
Provides PostgreSQL persistence and Redis caching for events, incidents, and violations.
"""

from .connection import DatabaseManager, get_db
from .models import Base, EventModel, IncidentModel, ViolationModel, ChainStatsModel
from .service import DatabaseService

# Redis manager (optional - graceful degradation if Redis unavailable)
try:
    from .redis_manager import (
        RedisStateManager,
        RedisConnectionConfig,
        RedisKeys,
        get_redis_manager,
    )
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    RedisStateManager = None
    RedisConnectionConfig = None
    RedisKeys = None
    get_redis_manager = None

__all__ = [
    # PostgreSQL
    "DatabaseManager",
    "get_db",
    "Base",
    "EventModel",
    "IncidentModel",
    "ViolationModel",
    "ChainStatsModel",
    "DatabaseService",
    # Redis
    "RedisStateManager",
    "RedisConnectionConfig",
    "RedisKeys",
    "get_redis_manager",
    "REDIS_AVAILABLE",
]

