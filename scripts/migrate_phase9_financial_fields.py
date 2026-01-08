#!/usr/bin/env python3
"""
Database Migration: Phase 9 - Financial Impact Fields
======================================================

Adds financial impact fields to predicted_incidents table.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import text
from src.database.connection import DatabaseManager
import structlog

logger = structlog.get_logger(__name__)


async def migrate():
    """Add financial impact fields to predicted_incidents table."""
    await DatabaseManager.initialize()
    
    async with DatabaseManager.get_session() as session:
        try:
            # Check if columns already exist
            check_query = text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'predicted_incidents' 
                AND column_name IN ('potential_loss_usd', 'potential_loss_token_symbol', 'financial_impact_json')
            """)
            result = await session.execute(check_query)
            existing_columns = {row[0] for row in result}
            
            # Add potential_loss_usd
            if 'potential_loss_usd' not in existing_columns:
                logger.info("adding_potential_loss_usd_column")
                await session.execute(text("""
                    ALTER TABLE predicted_incidents
                    ADD COLUMN potential_loss_usd NUMERIC(20, 2)
                """))
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_predicted_incidents_potential_loss_usd 
                    ON predicted_incidents(potential_loss_usd)
                """))
                logger.info("potential_loss_usd_column_added")
            
            # Add potential_loss_token_symbol
            if 'potential_loss_token_symbol' not in existing_columns:
                logger.info("adding_potential_loss_token_symbol_column")
                await session.execute(text("""
                    ALTER TABLE predicted_incidents
                    ADD COLUMN potential_loss_token_symbol VARCHAR(16)
                """))
                logger.info("potential_loss_token_symbol_column_added")
            
            # Add financial_impact_json
            if 'financial_impact_json' not in existing_columns:
                logger.info("adding_financial_impact_json_column")
                await session.execute(text("""
                    ALTER TABLE predicted_incidents
                    ADD COLUMN financial_impact_json JSONB
                """))
                logger.info("financial_impact_json_column_added")
            
            await session.commit()
            logger.info("migration_completed_successfully")
            
        except Exception as e:
            await session.rollback()
            logger.error("migration_failed", error=str(e))
            raise


if __name__ == "__main__":
    asyncio.run(migrate())

