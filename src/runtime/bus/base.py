"""
Base Event Bus Interface
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class BusMessage:
    """Message in the event bus."""
    id: str
    event_data: Dict[str, Any]
    idempotency_key: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retry_count: int = 0


@dataclass
class BusMessageEnvelope:
    """Message envelope with metadata for processing."""
    message_id: str  # Redis stream ID
    idempotency_key: str
    payload: Dict[str, Any]  # SecurityEvent JSON
    published_at: datetime
    retry_count: int = 0
    
    def to_bus_message(self) -> BusMessage:
        """Convert to BusMessage."""
        return BusMessage(
            id=self.message_id,
            event_data=self.payload,
            idempotency_key=self.idempotency_key,
            timestamp=self.published_at,
            retry_count=self.retry_count
        )


class EventBus(ABC):
    """Abstract event bus interface."""
    
    @abstractmethod
    async def publish(self, event: Dict[str, Any], idempotency_key: Optional[str] = None) -> bool:
        """Publish an event to the bus."""
        pass
    
    @abstractmethod
    async def publish_batch(self, events: List[Dict[str, Any]]) -> int:
        """Publish multiple events. Returns count published."""
        pass
    
    @abstractmethod
    async def consume(self, batch_size: int = 10, block_ms: int = 5000) -> List[BusMessageEnvelope]:
        """Consume events from the bus. Returns envelopes for ack/nack."""
        pass
    
    @abstractmethod
    async def ack(self, envelope_ids: List[str]) -> None:
        """Acknowledge processed messages."""
        pass
    
    @abstractmethod
    async def nack(self, envelope: BusMessageEnvelope, reason: str) -> None:
        """Negative acknowledge - send to dead letter queue."""
        pass
    
    @abstractmethod
    async def get_queue_depth(self) -> int:
        """Get current queue depth."""
        pass
    
    @abstractmethod
    async def get_pending_count(self) -> int:
        """Get count of pending (unacked) messages."""
        pass
    
    @abstractmethod
    async def close(self):
        """Close the bus."""
        pass
