"""
Database module for Sentinel3.
Provides PostgreSQL persistence for events, incidents, and violations.
"""

from .connection import DatabaseManager, get_db
from .models import Base, EventModel, IncidentModel, ViolationModel, ChainStatsModel
from .service import DatabaseService

__all__ = [
    "DatabaseManager",
    "get_db",
    "Base",
    "EventModel",
    "IncidentModel",
    "ViolationModel",
    "ChainStatsModel",
    "DatabaseService",
]

