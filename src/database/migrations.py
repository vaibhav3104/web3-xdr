"""
Database migrations for Sentinel3 XDR.
Ensures database schema is up to date with the application models.
"""

import structlog
from sqlalchemy import text
from .connection import DatabaseManager

logger = structlog.get_logger(__name__)


async def run_migrations():
    """
    Run database migrations to ensure schema is up to date.
    This is idempotent - safe to run multiple times.
    """
    async with DatabaseManager.get_session() as session:
        try:
            # Add missing columns to incidents table
            migrations = [
                # cluster_key for deduplication
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS cluster_key VARCHAR(64)",
                "CREATE INDEX IF NOT EXISTS idx_incidents_cluster_key ON incidents(cluster_key)",
                
                # explanation_json for Phase 4 structured explanation
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS explanation_json JSONB",
                
                # event_count for Phase 4 event aggregation
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS event_count INTEGER DEFAULT 0",
                
                # affected_contracts and affected_addresses
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_contracts TEXT[]",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_addresses TEXT[]",
                
                # violation_ids and rule_ids
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS violation_ids TEXT[]",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS rule_ids TEXT[]",
                
                # detection_latency_blocks
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS detection_latency_blocks INTEGER",
                
                # first_event_time and last_event_time
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS first_event_time TIMESTAMP",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_event_time TIMESTAMP",
                
                # recommended_actions
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS recommended_actions TEXT[]",
                
                # acknowledged_by and acknowledged_at
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS acknowledged_by VARCHAR(255)",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP",
                
                # resolved_by and resolved_at
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolved_by VARCHAR(255)",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP",
                
                # resolution_notes
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolution_notes TEXT",
            ]
            
            for migration in migrations:
                try:
                    await session.execute(text(migration))
                    logger.debug("migration_executed", sql=migration[:50])
                except Exception as e:
                    # Log but don't fail - some migrations may already be applied
                    logger.warning("migration_skipped", sql=migration[:50], error=str(e)[:100])
            
            await session.commit()
            logger.info("database_migrations_completed", count=len(migrations))
            
        except Exception as e:
            logger.error("database_migrations_failed", error=str(e))
            await session.rollback()
            raise
