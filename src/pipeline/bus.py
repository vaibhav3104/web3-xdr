"""
Event Bus - Decoupled Event Ingestion and Processing
====================================================

Provides a message bus for decoupling chain listeners (ingestion)
from detection/processing pipelines.

Supports:
- Redis Streams (production, distributed)
- In-memory queue (development, single-instance)

Features:
- Idempotency keys for deduplication
- Backpressure handling
- Bounded queues
- Lag monitoring
"""

import asyncio
import json
import os
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import hashlib

import structlog

logger = structlog.get_logger(__name__)

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "")
QUEUE_MAX_SIZE = int(os.getenv("QUEUE_MAX_SIZE", "10000"))
QUEUE_DROP_POLICY = os.getenv("QUEUE_DROP_POLICY", "never")  # never, oldest, low_severity


@dataclass
class BusMessage:
    """Message in the event bus."""
    id: str
    event_data: Dict[str, Any]
    idempotency_key: str  # For deduplication
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retry_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "event_data": self.event_data,
            "idempotency_key": self.idempotency_key,
            "timestamp": self.timestamp.isoformat(),
            "retry_count": self.retry_count,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BusMessage":
        """Deserialize from dictionary."""
        return cls(
            id=data["id"],
            event_data=data["event_data"],
            idempotency_key=data["idempotency_key"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            retry_count=data.get("retry_count", 0),
        )


class EventBus(ABC):
    """Abstract event bus interface."""
    
    @abstractmethod
    async def publish(self, event: Dict[str, Any], idempotency_key: Optional[str] = None) -> bool:
        """Publish an event to the bus."""
        pass
    
    @abstractmethod
    async def consume(self, batch_size: int = 10, timeout_seconds: float = 5.0) -> List[BusMessage]:
        """Consume events from the bus."""
        pass
    
    @abstractmethod
    async def get_queue_depth(self) -> int:
        """Get current queue depth."""
        pass
    
    @abstractmethod
    async def close(self):
        """Close the bus."""
        pass


class InMemoryBus(EventBus):
    """
    In-memory event bus (development only).
    
    WARNING: Not suitable for production. Use RedisStreamsBus instead.
    """
    
    def __init__(self, max_size: int = QUEUE_MAX_SIZE):
        self.queue: deque = deque(maxlen=max_size)
        self.processed_keys: set = set()  # Track processed idempotency keys
        self.max_size = max_size
        self._lock = asyncio.Lock()
        
        logger.warning(
            "using_in_memory_bus",
            hint="Set REDIS_URL for production deployment"
        )
    
    async def publish(self, event: Dict[str, Any], idempotency_key: Optional[str] = None) -> bool:
        """Publish event to in-memory queue."""
        async with self._lock:
            # Generate idempotency key if not provided
            if not idempotency_key:
                event_key = f"{event.get('chain_id')}:{event.get('tx_hash')}:{event.get('log_index', 0)}"
                idempotency_key = hashlib.sha256(event_key.encode()).hexdigest()
            
            # Check if already processed (before adding to queue)
            if idempotency_key in self.processed_keys:
                logger.debug("duplicate_event_dropped", idempotency_key=idempotency_key[:16])
                return False
            
            # Mark as processed immediately to prevent duplicates
            self.processed_keys.add(idempotency_key)
            
            # Check queue capacity
            if len(self.queue) >= self.max_size:
                severity = event.get("severity", "INFO")
                
                if QUEUE_DROP_POLICY == "never":
                    logger.error("queue_full_dropping", queue_size=len(self.queue))
                    return False
                elif QUEUE_DROP_POLICY == "oldest":
                    self.queue.popleft()
                    logger.warning("queue_full_dropped_oldest")
                elif QUEUE_DROP_POLICY == "low_severity" and severity in ["INFO", "LOW"]:
                    logger.warning("queue_full_dropped_low_severity", severity=severity)
                    return False
                else:
                    logger.error("queue_full_dropping", queue_size=len(self.queue))
                    return False
            
            # Create message
            message = BusMessage(
                id=f"mem_{int(time.time() * 1000000)}",
                event_data=event,
                idempotency_key=idempotency_key
            )
            
            self.queue.append(message)
            return True
    
    async def consume(self, batch_size: int = 10, timeout_seconds: float = 5.0) -> List[BusMessage]:
        """Consume events from queue."""
        messages = []
        
        async with self._lock:
            while len(messages) < batch_size and self.queue:
                message = self.queue.popleft()
                messages.append(message)
                # Key already marked as processed during publish
        
        return messages
    
    async def get_queue_depth(self) -> int:
        """Get current queue depth."""
        return len(self.queue)
    
    async def close(self):
        """Close the bus."""
        self.queue.clear()
        self.processed_keys.clear()


class RedisStreamsBus(EventBus):
    """
    Redis Streams-based event bus (production).
    
    Uses Redis Streams for reliable, distributed message queuing.
    """
    
    def __init__(self, redis_url: str = REDIS_URL, stream_name: str = "sentinel3:events"):
        if not redis_url:
            raise ValueError("REDIS_URL required for RedisStreamsBus")
        
        self.redis_url = redis_url
        self.stream_name = stream_name
        self.consumer_group = "sentinel3-workers"
        self.consumer_name = f"worker-{os.getpid()}"
        self.redis_client = None
        self._processed_keys_key = f"{stream_name}:processed"
        
        logger.info(
            "redis_streams_bus_initialized",
            stream=stream_name,
            consumer_group=self.consumer_group
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
                except Exception:
                    # Group already exists
                    pass
                    
            except ImportError:
                raise ImportError("redis package required for RedisStreamsBus. Install with: pip install redis")
        
        return self.redis_client
    
    async def publish(self, event: Dict[str, Any], idempotency_key: Optional[str] = None) -> bool:
        """Publish event to Redis stream."""
        try:
            redis = await self._get_redis()
            
            # Generate idempotency key if not provided
            if not idempotency_key:
                event_key = f"{event.get('chain_id')}:{event.get('tx_hash')}:{event.get('log_index', 0)}"
                idempotency_key = hashlib.sha256(event_key.encode()).hexdigest()
            
            # Check if already processed (using Redis set)
            if await redis.sismember(self._processed_keys_key, idempotency_key):
                logger.debug("duplicate_event_dropped", idempotency_key=idempotency_key[:16])
                return False
            
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
            
            logger.debug("event_published", stream=self.stream_name, message_id=message_id)
            return True
            
        except Exception as e:
            logger.error("redis_publish_failed", error=str(e))
            return False
    
    async def consume(self, batch_size: int = 10, timeout_seconds: float = 5.0) -> List[BusMessage]:
        """Consume events from Redis stream."""
        try:
            redis = await self._get_redis()
            
            # Read from consumer group
            messages_data = await redis.xreadgroup(
                self.consumer_group,
                self.consumer_name,
                {self.stream_name: ">"},
                count=batch_size,
                block=int(timeout_seconds * 1000)  # milliseconds
            )
            
            messages = []
            
            for stream, stream_messages in messages_data:
                for message_id, fields in stream_messages:
                    try:
                        event_data = json.loads(fields["event"])
                        idempotency_key = fields.get("idempotency_key", "")
                        
                        # Mark as processed
                        await redis.sadd(self._processed_keys_key, idempotency_key)
                        
                        # Acknowledge message
                        await redis.xack(self.stream_name, self.consumer_group, message_id)
                        
                        message = BusMessage(
                            id=message_id,
                            event_data=event_data,
                            idempotency_key=idempotency_key,
                            timestamp=datetime.fromisoformat(fields.get("timestamp", datetime.now(timezone.utc).isoformat()))
                        )
                        messages.append(message)
                        
                    except Exception as e:
                        logger.error("message_parse_failed", message_id=message_id, error=str(e))
            
            return messages
            
        except Exception as e:
            logger.error("redis_consume_failed", error=str(e))
            return []
    
    async def get_queue_depth(self) -> int:
        """Get current queue depth."""
        try:
            redis = await self._get_redis()
            return await redis.xlen(self.stream_name)
        except Exception as e:
            logger.error("queue_depth_check_failed", error=str(e))
            return 0
    
    async def close(self):
        """Close the bus."""
        if self.redis_client:
            await self.redis_client.close()
            self.redis_client = None


def create_event_bus() -> EventBus:
    """
    Factory function to create appropriate event bus.
    
    Returns:
        RedisStreamsBus if REDIS_URL is set, otherwise InMemoryBus
    """
    if REDIS_URL:
        try:
            return RedisStreamsBus(redis_url=REDIS_URL)
        except Exception as e:
            logger.error("redis_bus_creation_failed", error=str(e), fallback="in_memory")
            return InMemoryBus()
    else:
        return InMemoryBus()

