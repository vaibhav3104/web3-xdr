"""
Base classes for invariant detection.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Type
import structlog

from ..models.events import SecurityEvent, EventType, Severity
from ..models.invariants import InvariantResult, InvariantType

logger = structlog.get_logger()


class InvariantContext:
    """
    Context for invariant evaluation.
    
    Provides access to:
    - Event history
    - Current state
    - Cross-chain data
    """
    
    def __init__(self):
        # Event storage by chain and type
        self._events: Dict[str, List[SecurityEvent]] = {}
        
        # Bridge state tracking
        self._bridge_state: Dict[str, Dict[str, Decimal]] = {}  # bridge_id -> {locked, minted, ...}
        
        # TVL snapshots
        self._tvl_snapshots: Dict[str, List[dict]] = {}  # bridge_id -> [{timestamp, tvl}, ...]
        
        # Message tracking
        self._pending_messages: Dict[str, SecurityEvent] = {}  # message_hash -> lock event
        
        # Timestamp of last update
        self._last_update: datetime = datetime.utcnow()
    
    def add_event(self, event: SecurityEvent):
        """Add an event to the context."""
        key = f"{event.chain_id}:{event.event_type.value}"
        if key not in self._events:
            self._events[key] = []
        self._events[key].append(event)
        
        # Update bridge state
        if event.bridge_id:
            self._update_bridge_state(event)
        
        # Track messages
        if event.message_hash:
            self._track_message(event)
        
        self._last_update = datetime.utcnow()
        
        # Prune old events
        self._prune_old_events(timedelta(hours=24))
    
    def _update_bridge_state(self, event: SecurityEvent):
        """Update bridge state based on event."""
        bridge_id = event.bridge_id
        if bridge_id not in self._bridge_state:
            self._bridge_state[bridge_id] = {
                "locked": Decimal("0"),
                "minted": Decimal("0"),
                "burned": Decimal("0"),
                "unlocked": Decimal("0"),
            }
        
        state = self._bridge_state[bridge_id]
        
        if event.event_type == EventType.LOCK:
            state["locked"] += event.amount
        elif event.event_type == EventType.MINT:
            state["minted"] += event.amount
        elif event.event_type == EventType.BURN:
            state["burned"] += event.amount
        elif event.event_type == EventType.UNLOCK:
            state["unlocked"] += event.amount
    
    def _track_message(self, event: SecurityEvent):
        """Track bridge messages for correlation."""
        if event.event_type == EventType.LOCK and event.message_hash:
            self._pending_messages[event.message_hash] = event
        elif event.event_type == EventType.MINT and event.message_hash:
            # Remove from pending when minted
            self._pending_messages.pop(event.message_hash, None)
    
    def _prune_old_events(self, max_age: timedelta):
        """Remove events older than max_age."""
        cutoff = datetime.utcnow() - max_age
        for key in list(self._events.keys()):
            self._events[key] = [
                e for e in self._events[key]
                if e.block_timestamp > cutoff
            ]
    
    async def get_events(
        self,
        chain: Optional[str] = None,
        event_type: Optional[EventType] = None,
        bridge_id: Optional[str] = None,
        window: Optional[timedelta] = None,
        limit: int = 1000
    ) -> List[SecurityEvent]:
        """
        Get events matching criteria.
        """
        results = []
        cutoff = datetime.utcnow() - window if window else None
        
        for key, events in self._events.items():
            for event in events:
                # Filter by chain
                if chain and event.chain_id != chain:
                    continue
                
                # Filter by event type
                if event_type and event.event_type != event_type:
                    continue
                
                # Filter by bridge
                if bridge_id and event.bridge_id != bridge_id:
                    continue
                
                # Filter by time window
                if cutoff and event.block_timestamp < cutoff:
                    continue
                
                results.append(event)
                
                if len(results) >= limit:
                    break
        
        return sorted(results, key=lambda e: e.block_timestamp)
    
    async def find_event(
        self,
        event_type: EventType,
        message_hash: Optional[str] = None,
        before: Optional[datetime] = None,
        after: Optional[datetime] = None
    ) -> Optional[SecurityEvent]:
        """
        Find a specific event.
        """
        for events in self._events.values():
            for event in events:
                if event.event_type != event_type:
                    continue
                
                if message_hash and event.message_hash != message_hash:
                    continue
                
                if before and event.block_timestamp >= before:
                    continue
                
                if after and event.block_timestamp <= after:
                    continue
                
                return event
        
        return None
    
    def get_bridge_state(self, bridge_id: str) -> Dict[str, Decimal]:
        """Get current state for a bridge."""
        return self._bridge_state.get(bridge_id, {
            "locked": Decimal("0"),
            "minted": Decimal("0"),
            "burned": Decimal("0"),
            "unlocked": Decimal("0"),
        })
    
    def get_pending_message(self, message_hash: str) -> Optional[SecurityEvent]:
        """Get a pending message (lock without corresponding mint)."""
        return self._pending_messages.get(message_hash)
    
    async def get_tvl(
        self,
        bridge_id: str,
        offset: Optional[timedelta] = None
    ) -> Decimal:
        """
        Get TVL for a bridge, optionally at a past time.
        """
        # In a real implementation, this would query actual TVL
        # For now, calculate from lock/unlock events
        state = self.get_bridge_state(bridge_id)
        current_tvl = state["locked"] - state["unlocked"]
        
        # TODO: Handle historical TVL
        
        return max(Decimal("0"), current_tvl)
    
    async def get_timelock_delay(self, contract_address: str) -> timedelta:
        """
        Get timelock delay for a contract.
        
        In production, this would query the contract.
        """
        # Default timelock delays
        return timedelta(hours=24)
    
    def get_recent_events(self, minutes: int = 30) -> List[SecurityEvent]:
        """Get recent events within time window."""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        results = []
        
        for events in self._events.values():
            for event in events:
                if event.block_timestamp >= cutoff:
                    results.append(event)
        
        return sorted(results, key=lambda e: e.block_timestamp)


class Invariant(ABC):
    """
    Base class for all invariants.
    
    An invariant is a property that should always hold true.
    When violated, it indicates a potential security issue.
    """
    
    # Invariant metadata
    name: str = "unnamed"
    description: str = ""
    invariant_type: InvariantType = InvariantType.ECONOMIC
    severity: Severity = Severity.HIGH
    
    # Evaluation settings
    enabled: bool = True
    cooldown_seconds: int = 60  # Minimum time between violations
    
    def __init__(self):
        self._last_violation: Optional[datetime] = None
    
    @abstractmethod
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Evaluate the invariant against current context.
        
        Returns InvariantResult with violated=True if invariant is broken.
        """
        pass
    
    def should_check(self) -> bool:
        """
        Check if invariant should be evaluated (respects cooldown).
        """
        if not self.enabled:
            return False
        
        if self._last_violation:
            elapsed = (datetime.utcnow() - self._last_violation).total_seconds()
            if elapsed < self.cooldown_seconds:
                return False
        
        return True
    
    def record_violation(self):
        """Record that a violation was detected."""
        self._last_violation = datetime.utcnow()
    
    def get_metadata(self) -> dict:
        """Get invariant metadata."""
        return {
            "name": self.name,
            "description": self.description,
            "type": self.invariant_type.value,
            "severity": self.severity.name,
            "enabled": self.enabled,
        }


@dataclass
class InvariantConfig:
    """Configuration for a specific invariant instance."""
    
    invariant_class: Type[Invariant]
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)


class InvariantRegistry:
    """
    Registry of all available invariants.
    """
    
    _invariants: Dict[str, Type[Invariant]] = {}
    
    @classmethod
    def register(cls, name: str):
        """Decorator to register an invariant class."""
        def decorator(invariant_class: Type[Invariant]):
            cls._invariants[name] = invariant_class
            invariant_class.name = name
            return invariant_class
        return decorator
    
    @classmethod
    def get(cls, name: str) -> Optional[Type[Invariant]]:
        """Get an invariant class by name."""
        return cls._invariants.get(name)
    
    @classmethod
    def list_all(cls) -> List[str]:
        """List all registered invariant names."""
        return list(cls._invariants.keys())
    
    @classmethod
    def create(cls, name: str, **kwargs) -> Optional[Invariant]:
        """Create an invariant instance by name."""
        invariant_class = cls.get(name)
        if invariant_class:
            return invariant_class(**kwargs)
        return None

