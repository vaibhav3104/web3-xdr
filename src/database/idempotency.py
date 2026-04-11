"""
Idempotency Service for Event Processing
Ensures exactly-once processing even with retries/failover.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import structlog

from .connection import DatabaseManager
from .models import EventProcessingModel
from sqlalchemy import select

logger = structlog.get_logger(__name__)


def generate_idempotency_key(chain_id: str, tx_hash: str, log_index: Optional[int] = None) -> str:
    """
    Generate a stable idempotency key for an event.
    
    Format: sha256(chain_id:tx_hash:log_index)
    """
    key_str = f"{chain_id}:{tx_hash}:{log_index or 0}"
    return hashlib.sha256(key_str.encode()).hexdigest()


def generate_incident_dedupe_key(
    incident_type: str,
    protocol_id: str,
    primary_chain: str,
    attacker_cluster: Optional[str] = None,
    time_bucket: Optional[str] = None
) -> str:
    """
    Generate a stable deduplication key for an incident.
    
    Format: sha256(incident_type:protocol_id:primary_chain:attacker_cluster:time_bucket)
    """
    time_bucket = time_bucket or datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")
    key_str = f"{incident_type}:{protocol_id}:{primary_chain}:{attacker_cluster or 'none'}:{time_bucket}"
    return hashlib.sha256(key_str.encode()).hexdigest()


class IdempotencyService:
    """Service for managing idempotency tracking."""
    
    @staticmethod
    async def check_idempotency(idempotency_key: str) -> Optional[Dict[str, Any]]:
        """
        Check if an idempotency key has already been processed.
        
        Returns:
            Dict with processing info if already processed, None if new
        """
        async with DatabaseManager.get_session() as session:
            result = await session.execute(
                select(EventProcessingModel).where(
                    EventProcessingModel.idempotency_key == idempotency_key
                )
            )
            record = result.scalar_one_or_none()
            
            if record:
                return {
                    "status": record.status,
                    "processed_at": record.processed_at,
                    "event_id": record.event_id,
                    "incident_id": record.incident_id,
                    "retry_count": record.retry_count,
                    "error_message": record.error_message,
                }
            return None
    
    @staticmethod
    async def mark_processing(
        idempotency_key: str,
        status: str = "PENDING",
        event_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Mark an idempotency key as being processed.
        
        Args:
            idempotency_key: The idempotency key
            status: PENDING, PROCESSED, or FAILED
            event_id: Associated event ID if created
            incident_id: Associated incident ID if created
            error_message: Error message if failed
        
        Returns:
            True if marked successfully, False if already exists and processed
        """
        async with DatabaseManager.get_session() as session:
            try:
                # Check if already exists
                result = await session.execute(
                    select(EventProcessingModel).where(
                        EventProcessingModel.idempotency_key == idempotency_key
                    )
                )
                existing = result.scalar_one_or_none()
                
                if existing:
                    # Update existing record
                    if existing.status == "PROCESSED":
                        # Already processed, don't update
                        logger.debug("idempotency_already_processed", key=idempotency_key[:16])
                        return False
                    
                    # Update status
                    existing.status = status
                    if status == "PROCESSED":
                        existing.processed_at = datetime.now(timezone.utc)
                    if event_id:
                        existing.event_id = event_id
                    if incident_id:
                        existing.incident_id = incident_id
                    if error_message:
                        existing.error_message = error_message
                    existing.retry_count += 1
                    
                    await session.commit()
                    logger.debug("idempotency_updated", key=idempotency_key[:16], status=status)
                    return True
                else:
                    # Create new record
                    record = EventProcessingModel(
                        idempotency_key=idempotency_key,
                        status=status,
                        event_id=event_id,
                        incident_id=incident_id,
                        error_message=error_message,
                        retry_count=0
                    )
                    session.add(record)
                    await session.commit()
                    logger.debug("idempotency_marked", key=idempotency_key[:16], status=status)
                    return True
                    
            except Exception as e:
                logger.error("idempotency_mark_failed", key=idempotency_key[:16], error=str(e))
                await session.rollback()
                return False
    
    @staticmethod
    async def mark_processed(
        idempotency_key: str,
        event_id: Optional[str] = None,
        incident_id: Optional[str] = None
    ) -> bool:
        """Mark an idempotency key as successfully processed."""
        return await IdempotencyService.mark_processing(
            idempotency_key=idempotency_key,
            status="PROCESSED",
            event_id=event_id,
            incident_id=incident_id
        )
    
    @staticmethod
    async def mark_failed(
        idempotency_key: str,
        error_message: str
    ) -> bool:
        """Mark an idempotency key as failed."""
        return await IdempotencyService.mark_processing(
            idempotency_key=idempotency_key,
            status="FAILED",
            error_message=error_message
        )
