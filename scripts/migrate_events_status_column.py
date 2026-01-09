#!/usr/bin/env python3
"""
Database Migration: Add Status Column to Events Table
======================================================

Adds missing columns to events table to match EventModel:
- status (VARCHAR(16), default 'PENDING')
- block_hash (VARCHAR(128))
- canonical_event_hash (VARCHAR(128))
- confirmed_at (TIMESTAMP WITH TIME ZONE)
- log_index (INTEGER)
- topics (ARRAY(VARCHAR))
- asset_type (VARCHAR(32))
- asset_address (VARCHAR(128))

Also adds indexes for the new columns.
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
    """Add missing columns to events table."""
    await DatabaseManager.initialize()
    
    async with DatabaseManager.get_session() as session:
        try:
            # Check existing columns
            check_query = text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'events'
            """)
            result = await session.execute(check_query)
            existing_columns = {row[0] for row in result}
            
            logger.info("checking_existing_columns", existing=existing_columns)
            
            # Add status column
            if 'status' not in existing_columns:
                logger.info("adding_status_column")
                await session.execute(text("""
                    ALTER TABLE events
                    ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'PENDING'
                """))
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_events_status 
                    ON events(status, chain_id)
                """))
                logger.info("status_column_added")
            
            # Add block_hash column
            if 'block_hash' not in existing_columns:
                logger.info("adding_block_hash_column")
                await session.execute(text("""
                    ALTER TABLE events
                    ADD COLUMN block_hash VARCHAR(128)
                """))
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_events_block_hash 
                    ON events(block_hash)
                """))
                logger.info("block_hash_column_added")
            
            # Add canonical_event_hash column
            if 'canonical_event_hash' not in existing_columns:
                logger.info("adding_canonical_event_hash_column")
                await session.execute(text("""
                    ALTER TABLE events
                    ADD COLUMN canonical_event_hash VARCHAR(128)
                """))
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_events_canonical_event_hash 
                    ON events(canonical_event_hash)
                """))
                logger.info("canonical_event_hash_column_added")
            
            # Add confirmed_at column
            if 'confirmed_at' not in existing_columns:
                logger.info("adding_confirmed_at_column")
                await session.execute(text("""
                    ALTER TABLE events
                    ADD COLUMN confirmed_at TIMESTAMP WITH TIME ZONE
                """))
                logger.info("confirmed_at_column_added")
            
            # Add log_index column (if not exists)
            if 'log_index' not in existing_columns:
                logger.info("adding_log_index_column")
                await session.execute(text("""
                    ALTER TABLE events
                    ADD COLUMN log_index INTEGER
                """))
                logger.info("log_index_column_added")
            
            # Add topics column (if not exists)
            if 'topics' not in existing_columns:
                logger.info("adding_topics_column")
                await session.execute(text("""
                    ALTER TABLE events
                    ADD COLUMN topics VARCHAR(128)[]
                """))
                logger.info("topics_column_added")
            
            # Add asset_type column (if not exists)
            if 'asset_type' not in existing_columns:
                logger.info("adding_asset_type_column")
                await session.execute(text("""
                    ALTER TABLE events
                    ADD COLUMN asset_type VARCHAR(32)
                """))
                logger.info("asset_type_column_added")
            
            # Add asset_address column (if not exists)
            if 'asset_address' not in existing_columns:
                logger.info("adding_asset_address_column")
                await session.execute(text("""
                    ALTER TABLE events
                    ADD COLUMN asset_address VARCHAR(128)
                """))
                logger.info("asset_address_column_added")
            
            # Add unique constraint for deduplication (if not exists)
            try:
                await session.execute(text("""
                    CREATE UNIQUE INDEX IF NOT EXISTS ix_events_unique_key 
                    ON events(chain_id, tx_hash, log_index)
                """))
                logger.info("unique_index_added")
            except Exception as e:
                # Index might already exist, ignore
                logger.debug("unique_index_already_exists", error=str(e))
            
            await session.commit()
            
            logger.info("migration_completed_successfully")
            print("✅ Migration completed successfully!")
            print("   Added columns: status, block_hash, canonical_event_hash, confirmed_at")
            print("   Added indexes: ix_events_status, ix_events_block_hash, ix_events_canonical_event_hash")
            
        except Exception as e:
            await session.rollback()
            logger.error("migration_failed", error=str(e))
            print(f"❌ Migration failed: {e}")
            sys.exit(1)
        finally:
            await DatabaseManager.close()


if __name__ == "__main__":
    asyncio.run(migrate())
