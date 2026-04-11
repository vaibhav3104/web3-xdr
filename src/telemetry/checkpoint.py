"""
Universal Checkpointing System
=============================

Phase 6: Ensures system can resume from last processed block after restart.
Uses Redis (primary) for fast access, Postgres (persistence) for durability.
"""

from typing import Optional, Dict
import structlog

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os

logger = structlog.get_logger(__name__)


class CheckpointManager:
    """
    Manages checkpoint state for all chains.
    
    Checkpoints are stored in:
    - Redis (primary): Fast access, key = "checkpoint:{chain_id}" -> block_height
    - Postgres (persistence): Durable storage, table = "checkpoints"
    
    Logic:
    - get_start_block(chain_id): Returns max(config_start_block, last_checkpoint)
    - update_checkpoint(chain_id, block_height): Called after events are published
    """
    
    def __init__(self, redis_url: Optional[str] = None, postgres_url: Optional[str] = None):
        """
        Initialize checkpoint manager.
        
        Args:
            redis_url: Redis connection URL (e.g., "redis://localhost:6379/0")
            postgres_url: Postgres connection URL (optional, for persistence)
        """
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.postgres_url = postgres_url or os.getenv("DATABASE_URL")
        
        # Initialize Redis
        self.redis_client = None
        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
                # Test connection
                self.redis_client.ping()
                logger.info("checkpoint_redis_connected", redis_url=self.redis_url)
            except Exception as e:
                logger.warning("checkpoint_redis_failed", error=str(e), fallback="postgres_only")
                self.redis_client = None
        
        # Initialize Postgres (for persistence)
        self.postgres_engine = None
        self.postgres_session_factory = None
        if self.postgres_url:
            try:
                self.postgres_engine = create_engine(self.postgres_url)
                self.postgres_session_factory = sessionmaker(bind=self.postgres_engine)
                self._ensure_checkpoint_table()
                logger.info("checkpoint_postgres_connected")
            except Exception as e:
                logger.warning("checkpoint_postgres_failed", error=str(e))
        
        if not self.redis_client and not self.postgres_session_factory:
            logger.error("checkpoint_no_storage", warning="Checkpointing disabled - no storage available")
    
    def _ensure_checkpoint_table(self):
        """Create checkpoints table if it doesn't exist."""
        if not self.postgres_engine:
            return
        
        try:
            with self.postgres_engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS checkpoints (
                        chain_id VARCHAR(64) PRIMARY KEY,
                        block_height BIGINT NOT NULL,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )
                """))
                conn.commit()
                logger.debug("checkpoint_table_ensured")
        except Exception as e:
            logger.error("checkpoint_table_creation_failed", error=str(e))
    
    def get_start_block(self, chain_id: str, config_start_block: int = 0) -> int:
        """
        Get the starting block for a chain.
        
        Returns max(config_start_block, last_checkpoint).
        If no checkpoint exists, returns config_start_block.
        
        Args:
            chain_id: Chain identifier
            config_start_block: Start block from config (default: 0)
        
        Returns:
            Block height to start from
        """
        checkpoint = self.get_checkpoint(chain_id)
        
        if checkpoint is None:
            logger.info(
                "checkpoint_not_found",
                chain_id=chain_id,
                using_config_start=config_start_block
            )
            return config_start_block
        
        start_block = max(config_start_block, checkpoint)
        
        logger.info(
            "checkpoint_resolved",
            chain_id=chain_id,
            checkpoint=checkpoint,
            config_start=config_start_block,
            resolved_start=start_block
        )
        
        return start_block
    
    def get_checkpoint(self, chain_id: str) -> Optional[int]:
        """
        Get checkpoint for a chain.
        
        Checks Redis first, then Postgres if Redis unavailable.
        
        Args:
            chain_id: Chain identifier
        
        Returns:
            Block height or None if no checkpoint exists
        """
        # Try Redis first
        if self.redis_client:
            try:
                key = f"checkpoint:{chain_id}"
                value = self.redis_client.get(key)
                if value:
                    return int(value)
            except Exception as e:
                logger.warning("checkpoint_redis_read_failed", chain_id=chain_id, error=str(e))
        
        # Fallback to Postgres
        if self.postgres_session_factory:
            try:
                session = self.postgres_session_factory()
                try:
                    result = session.execute(
                        text("SELECT block_height FROM checkpoints WHERE chain_id = :chain_id"),
                        {"chain_id": chain_id}
                    ).fetchone()
                    
                    if result:
                        block_height = result[0]
                        # Also update Redis cache if available
                        if self.redis_client:
                            try:
                                self.redis_client.set(f"checkpoint:{chain_id}", str(block_height))
                            except Exception:
                                pass
                        return block_height
                finally:
                    session.close()
            except Exception as e:
                logger.warning("checkpoint_postgres_read_failed", chain_id=chain_id, error=str(e))
        
        return None
    
    def update_checkpoint(self, chain_id: str, block_height: int):
        """
        Update checkpoint for a chain.
        
        Updates both Redis (primary) and Postgres (persistence).
        Should be called only after events are successfully published to EventBus.
        
        Args:
            chain_id: Chain identifier
            block_height: Block height to checkpoint
        """
        # Update Redis (primary)
        if self.redis_client:
            try:
                key = f"checkpoint:{chain_id}"
                self.redis_client.set(key, str(block_height))
                logger.debug("checkpoint_redis_updated", chain_id=chain_id, block_height=block_height)
            except Exception as e:
                logger.warning("checkpoint_redis_write_failed", chain_id=chain_id, error=str(e))
        
        # Update Postgres (persistence)
        if self.postgres_session_factory:
            try:
                session = self.postgres_session_factory()
                try:
                    session.execute(
                        text("""
                            INSERT INTO checkpoints (chain_id, block_height, updated_at)
                            VALUES (:chain_id, :block_height, NOW())
                            ON CONFLICT (chain_id)
                            DO UPDATE SET
                                block_height = :block_height,
                                updated_at = NOW()
                        """),
                        {"chain_id": chain_id, "block_height": block_height}
                    )
                    session.commit()
                    logger.debug("checkpoint_postgres_updated", chain_id=chain_id, block_height=block_height)
                finally:
                    session.close()
            except Exception as e:
                logger.error("checkpoint_postgres_write_failed", chain_id=chain_id, error=str(e))
        
        logger.info("checkpoint_updated", chain_id=chain_id, block_height=block_height)
    
    def get_all_checkpoints(self) -> Dict[str, int]:
        """
        Get all checkpoints (for monitoring/debugging).
        
        Returns:
            Dictionary mapping chain_id -> block_height
        """
        checkpoints = {}
        
        # Try Redis first
        if self.redis_client:
            try:
                keys = self.redis_client.keys("checkpoint:*")
                for key in keys:
                    chain_id = key.replace("checkpoint:", "")
                    value = self.redis_client.get(key)
                    if value:
                        checkpoints[chain_id] = int(value)
            except Exception as e:
                logger.warning("checkpoint_redis_list_failed", error=str(e))
        
        # Fallback to Postgres
        if not checkpoints and self.postgres_session_factory:
            try:
                session = self.postgres_session_factory()
                try:
                    results = session.execute(
                        text("SELECT chain_id, block_height FROM checkpoints")
                    ).fetchall()
                    
                    for chain_id, block_height in results:
                        checkpoints[chain_id] = block_height
                finally:
                    session.close()
            except Exception as e:
                logger.warning("checkpoint_postgres_list_failed", error=str(e))
        
        return checkpoints

