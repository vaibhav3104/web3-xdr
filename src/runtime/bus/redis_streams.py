"""
Redis Streams Event Bus with Consumer Groups, DLQ, and Pending Recovery
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import hashlib

import structlog

from .base import EventBus, BusMessageEnvelope

logger = structlog.get_logger(__name__)

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "")
QUEUE_MAX_SIZE = int(os.getenv("QUEUE_MAX_SIZE", "10000"))
DLQ_MAX_SIZE = int(os.getenv("DLQ_MAX_SIZE", "1000"))
PENDING_RECOVERY_INTERVAL = int(os.getenv("PENDING_RECOVERY_INTERVAL", "300"))  # 5 minutes
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))


class RedisStreamsBus(EventBus):
    """
    Production-grade Redis Streams event bus.
    
    Features:
    - Consumer groups for distributed processing
    - Dead letter queue for poison messages
    - Pending message recovery (XCLAIM)
    - Metrics tracking
    - Idempotency support
    """
    
    def __init__(
        self,
        redis_url: str = REDIS_URL,
        stream_name: str = "sentinel3:events",
        consumer_group: str = "sentinel3-workers",
        consumer_name: Optional[str] = None
    ):
        if not redis_url:
            raise ValueError("REDIS_URL required for RedisStreamsBus")
        
        self.redis_url = redis_url
        self.stream_name = stream_name
        self.dlq_name = f"{stream_name}:dlq"
        self.consumer_group = consumer_group
        self.consumer_name = consumer_name or f"worker-{os.getpid()}-{int(time.time())}"
        self.redis_client = None
        self._metrics = {
            "publish_total": 0,
            "consume_total": 0,
            "ack_total": 0,
            "dlq_total": 0,
            "pending_count": 0,
        }
        self._last_pending_check = 0
        
        logger.info(
            "redis_streams_bus_initialized",
            stream=stream_name,
            consumer_group=consumer_group,
            consumer_name=self.consumer_name
        )
    
    async def _get_redis(self):
        """Get or create Redis client."""
        if self.redis_client is None:
            try:
                import redis.asyncio as aioredis
                self.redis_client = aioredis.from_url(
                    self.redis_url,
                    decode_responses=True
                )
                
                # Create consumer group if it doesn't exist
                try:
                    await self.redis_client.xgroup_create(
                        self.stream_name,
                        self.consumer_group,
                        id="0",
                        mkstream=True
                    )
                    logger.info("consumer_group_created", group=self.consumer_group)
                except Exception as e:
                    # Group already exists or other error
                    if "BUSYGROUP" not in str(e):
                        logger.warning("consumer_group_create_failed", error=str(e))
                    
            except ImportError:
                raise ImportError("redis package required. Install with: pip install redis")
        
        return self.redis_client
    
    async def publish(self, event: Dict[str, Any], idempotency_key: Optional[str] = None) -> bool:
        """Publish event to Redis stream."""
        try:
            redis = await self._get_redis()
            
            # Generate idempotency key if not provided
            if not idempotency_key:
                event_key = f"{event.get('chain_id')}:{event.get('tx_hash')}:{event.get('log_index', 0)}"
                idempotency_key = hashlib.sha256(event_key.encode()).hexdigest()
            
            # Publish to stream
            message_id = await redis.xadd(
                self.stream_name,
                {
                    "event": json.dumps(event),
                    "idempotency_key": idempotency_key,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                maxlen=QUEUE_MAX_SIZE  # Cap stream size
            )
            
            self._metrics["publish_total"] += 1
            logger.debug("event_published", stream=self.stream_name, message_id=message_id)
            return True
            
        except Exception as e:
            logger.error("redis_publish_failed", error=str(e))
            return False
    
    async def publish_batch(self, events: List[Dict[str, Any]]) -> int:
        """Publish multiple events. Returns count published."""
        if not events:
            return 0
        
        published = 0
        for event in events:
            if await self.publish(event):
                published += 1
        
        return published
    
    async def consume(self, batch_size: int = 10, block_ms: int = 5000) -> List[BusMessageEnvelope]:
        """Consume events from Redis stream using consumer group."""
        try:
            redis = await self._get_redis()
            
            # Recover pending messages periodically
            await self._recover_pending_messages(redis)
            
            # Read from consumer group
            messages_data = await redis.xreadgroup(
                self.consumer_group,
                self.consumer_name,
                {self.stream_name: ">"},
                count=batch_size,
                block=block_ms
            )
            
            envelopes = []
            
            for stream, stream_messages in messages_data:
                for message_id, fields in stream_messages:
                    try:
                        event_data = json.loads(fields["event"])
                        idempotency_key = fields.get("idempotency_key", "")
                        published_at_str = fields.get("timestamp", datetime.now(timezone.utc).isoformat())
                        
                        envelope = BusMessageEnvelope(
                            message_id=message_id,
                            idempotency_key=idempotency_key,
                            payload=event_data,
                            published_at=datetime.fromisoformat(published_at_str),
                            retry_count=0
                        )
                        envelopes.append(envelope)
                        
                    except Exception as e:
                        logger.error("message_parse_failed", message_id=message_id, error=str(e))
                        # Send to DLQ
                        await self._send_to_dlq(redis, message_id, fields, f"parse_error: {str(e)}")
            
            self._metrics["consume_total"] += len(envelopes)
            return envelopes
            
        except Exception as e:
            logger.error("redis_consume_failed", error=str(e))
            return []
    
    async def ack(self, envelope_ids: List[str]) -> None:
        """Acknowledge processed messages."""
        if not envelope_ids:
            return
        
        try:
            redis = await self._get_redis()
            await redis.xack(self.stream_name, self.consumer_group, *envelope_ids)
            self._metrics["ack_total"] += len(envelope_ids)
            logger.debug("messages_acked", count=len(envelope_ids))
        except Exception as e:
            logger.error("ack_failed", error=str(e))
    
    async def nack(self, envelope: BusMessageEnvelope, reason: str) -> None:
        """Negative acknowledge - send to dead letter queue."""
        try:
            redis = await self._get_redis()
            
            # Get original message fields
            message_data = await redis.xrange(self.stream_name, envelope.message_id, envelope.message_id, count=1)
            if not message_data:
                logger.warning("message_not_found_for_dlq", message_id=envelope.message_id)
                return
            
            _, fields = message_data[0]
            
            # Send to DLQ
            await self._send_to_dlq(redis, envelope.message_id, fields, reason)
            
            # ACK the original message (remove from pending)
            await redis.xack(self.stream_name, self.consumer_group, envelope.message_id)
            
            self._metrics["dlq_total"] += 1
            logger.warning("message_sent_to_dlq", message_id=envelope.message_id, reason=reason)
            
        except Exception as e:
            logger.error("nack_failed", error=str(e))
    
    async def _send_to_dlq(self, redis, original_message_id: str, fields: Dict, reason: str) -> None:
        """Send message to dead letter queue."""
        try:
            await redis.xadd(
                self.dlq_name,
                {
                    "original_message_id": original_message_id,
                    "reason": reason,
                    "payload": fields.get("event", ""),
                    "idempotency_key": fields.get("idempotency_key", ""),
                    "timestamp": fields.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "dlq_timestamp": datetime.now(timezone.utc).isoformat(),
                },
                maxlen=DLQ_MAX_SIZE
            )
        except Exception as e:
            logger.error("dlq_send_failed", error=str(e))
    
    async def _recover_pending_messages(self, redis) -> None:
        """Recover stuck pending messages using XCLAIM."""
        now = time.time()
        if now - self._last_pending_check < PENDING_RECOVERY_INTERVAL:
            return
        
        self._last_pending_check = now
        
        try:
            # Get pending messages older than 5 minutes
            pending = await redis.xpending_range(
                self.stream_name,
                self.consumer_group,
                min="-",
                max="+",
                count=100
            )
            
            if not pending:
                return
            
            # Claim messages that are stuck (idle > 5 minutes)
            min_idle_ms = 300000  # 5 minutes
            claimed = []
            
            for pending_msg in pending:
                if pending_msg["time_since_delivered"] > min_idle_ms:
                    message_id = pending_msg["message_id"]
                    try:
                        # Claim the message
                        claimed_msgs = await redis.xclaim(
                            self.stream_name,
                            self.consumer_group,
                            self.consumer_name,
                            min_idle_ms,
                            message_id
                        )
                        claimed.extend([msg[0] for msg in claimed_msgs])
                    except Exception as e:
                        logger.warning("claim_failed", message_id=message_id, error=str(e))
            
            if claimed:
                logger.info("pending_messages_recovered", count=len(claimed))
            
        except Exception as e:
            logger.error("pending_recovery_failed", error=str(e))
    
    async def get_queue_depth(self) -> int:
        """Get current queue depth."""
        try:
            redis = await self._get_redis()
            return await redis.xlen(self.stream_name)
        except Exception as e:
            logger.error("queue_depth_check_failed", error=str(e))
            return 0
    
    async def get_pending_count(self) -> int:
        """Get count of pending (unacked) messages."""
        try:
            redis = await self._get_redis()
            pending = await redis.xpending(self.stream_name, self.consumer_group)
            count = pending.get("pending", 0) if isinstance(pending, dict) else 0
            self._metrics["pending_count"] = count
            return count
        except Exception as e:
            logger.error("pending_count_check_failed", error=str(e))
            return 0
    
    def get_metrics(self) -> Dict[str, int]:
        """Get bus metrics."""
        return self._metrics.copy()
    
    async def close(self):
        """Close the bus."""
        if self.redis_client:
            await self.redis_client.close()
            self.redis_client = None
            logger.info("redis_streams_bus_closed")


def create_redis_streams_bus(redis_url: Optional[str] = None) -> RedisStreamsBus:
    """Factory function to create RedisStreamsBus."""
    return RedisStreamsBus(redis_url=redis_url or REDIS_URL)
