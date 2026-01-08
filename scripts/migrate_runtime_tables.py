#!/usr/bin/env python3
"""
Migration Script for Runtime Security Plane Tables
===================================================

Creates simulation_runs and predicted_incidents tables.
Run this after deploying the Runtime Security Plane code.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.database.connection import DatabaseManager
from src.database.models import Base, SimulationRunModel, PredictedIncidentModel
import structlog

logger = structlog.get_logger(__name__)


async def migrate():
    """Create runtime security plane tables."""
    try:
        # Initialize database
        await DatabaseManager.initialize()
        
        logger.info("creating_runtime_tables")
        
        # Create tables (SQLAlchemy will only create missing ones)
        await DatabaseManager.create_tables()
        
        logger.info("runtime_tables_created_successfully")
        print("✅ Runtime Security Plane tables created successfully!")
        print("   - simulation_runs")
        print("   - predicted_incidents")
        
    except Exception as e:
        logger.error("migration_failed", error=str(e))
        print(f"❌ Migration failed: {e}")
        sys.exit(1)
    finally:
        await DatabaseManager.close()


if __name__ == "__main__":
    asyncio.run(migrate())

