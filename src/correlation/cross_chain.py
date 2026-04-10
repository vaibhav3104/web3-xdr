"""
Cross-Chain Correlation Engine (Redis-Backed)
==============================================

This module implements distributed cross-chain correlation for bridge monitoring.
It links Lock events on source chains to Mint events on destination chains,
detecting economic invariant violations like "Mint without Lock".

Key Features:
1. Redis-backed state for distributed scaling
2. Atomic Lock/Mint correlation using Lua scripts
3. Message ID tracking with replay protection
4. Time-window based orphan detection
5. Graceful fallback to in-memory when Redis unavailable

Architecture:
- CrossChainCorrelator: High-level API for correlation
- Delegates storage to RedisStateManager
- Local fallback for single-instance deployments
"""

import asyncio
import hashlib
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

import structlog

logger = structlog.get_logger(__name__)

# Configuration
CORRELATION_WINDOW_MINUTES = int(os.getenv("CORRELATION_WINDOW_MINUTES", "30"))
AMOUNT_TOLERANCE_PERCENT = float(os.getenv("AMOUNT_TOLERANCE_PERCENT", "0.1"))
ORPHAN_CHECK_DELAY_SECONDS = int(os.getenv("ORPHAN_CHECK_DELAY_SECONDS", "60"))
MIN_ALERT_AMOUNT_USD = float(os.getenv("MIN_ALERT_AMOUNT_USD", "10000"))


class CrossChainEventType(Enum):
    """Types of cross-chain events."""
    LOCK = "lock"
    UNLOCK = "unlock"
    MINT = "mint"
    BURN = "burn"
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    TRANSFER = "transfer"


class CorrelationStatus(Enum):
    """Status of a correlation."""
    PENDING = "pending"
    MATCHED = "matched"
    ORPHAN = "orphan"
    EXPIRED = "expired"
    SUSPICIOUS = "suspicious"


class ViolationType(Enum):
    """Types of cross-chain violations."""
    MINT_WITHOUT_LOCK = "mint_without_lock"
    LOCK_WITHOUT_MINT = "lock_without_mint"
    AMOUNT_MISMATCH = "amount_mismatch"
    SEQUENCE_VIOLATION = "sequence_violation"
    REPLAY_ATTACK = "replay_attack"
    TIME_ANOMALY = "time_anomaly"


@dataclass
class CrossChainEvent:
    """Normalized cross-chain event."""
    event_id: str
    event_type: CrossChainEventType
    bridge_id: str
    source_chain: str
    dest_chain: str
    tx_hash: str
    block_number: int
    timestamp: datetime
    
    # Amount info
    token_address: str
    token_symbol: str
    amount: float
    amount_usd: float
    
    # Cross-chain identifiers
    message_id: Optional[str] = None
    nonce: Optional[int] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    
    # Raw data
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def get_correlation_key(self) -> str:
        """Generate key for correlation matching."""
        key_data = f"{self.bridge_id}:{self.token_address}:{self.sender}:{self.recipient}:{self.amount}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "bridge_id": self.bridge_id,
            "source_chain": self.source_chain,
            "dest_chain": self.dest_chain,
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "timestamp": self.timestamp.isoformat(),
            "token_address": self.token_address,
            "token_symbol": self.token_symbol,
            "amount": self.amount,
            "amount_usd": self.amount_usd,
            "message_id": self.message_id,
            "nonce": self.nonce,
            "sender": self.sender,
            "recipient": self.recipient,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CrossChainEvent":
        """Create from dictionary."""
        return cls(
            event_id=data["event_id"],
            event_type=CrossChainEventType(data["event_type"]),
            bridge_id=data["bridge_id"],
            source_chain=data["source_chain"],
            dest_chain=data["dest_chain"],
            tx_hash=data["tx_hash"],
            block_number=data["block_number"],
            timestamp=datetime.fromisoformat(data["timestamp"]) if isinstance(data["timestamp"], str) else data["timestamp"],
            token_address=data["token_address"],
            token_symbol=data["token_symbol"],
            amount=float(data["amount"]),
            amount_usd=float(data["amount_usd"]),
            message_id=data.get("message_id"),
            nonce=data.get("nonce"),
            sender=data.get("sender"),
            recipient=data.get("recipient"),
            raw_data=data.get("raw_data", {})
        )


@dataclass
class CorrelationPair:
    """A pair of correlated cross-chain events."""
    id: str
    bridge_id: str
    source_chain: str
    dest_chain: str
    
    lock_event: Optional[CrossChainEvent] = None
    mint_event: Optional[CrossChainEvent] = None
    
    status: CorrelationStatus = CorrelationStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    matched_at: Optional[datetime] = None
    
    violation: Optional[ViolationType] = None
    violation_details: Dict[str, Any] = field(default_factory=dict)
    
    def get_amount_difference(self) -> float:
        """Calculate difference between lock and mint amounts."""
        if self.lock_event and self.mint_event:
            return abs(self.lock_event.amount - self.mint_event.amount)
        return 0.0
    
    def get_time_difference(self) -> Optional[timedelta]:
        """Calculate time between lock and mint."""
        if self.lock_event and self.mint_event:
            return self.mint_event.timestamp - self.lock_event.timestamp
        return None


@dataclass
class CrossChainViolation:
    """A detected cross-chain violation."""
    id: str
    violation_type: ViolationType
    severity: str
    bridge_id: str
    source_chain: str
    dest_chain: str
    timestamp: datetime
    
    lock_event_id: Optional[str] = None
    mint_event_id: Optional[str] = None
    
    lock_amount: float = 0.0
    mint_amount: float = 0.0
    amount_difference: float = 0.0
    estimated_loss_usd: float = 0.0
    
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    acknowledged: bool = False
    resolved: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "violation_id": self.id,
            "violation_type": self.violation_type.value,
            "severity": self.severity,
            "bridge_id": self.bridge_id,
            "source_chain": self.source_chain,
            "dest_chain": self.dest_chain,
            "timestamp": self.timestamp.isoformat(),
            "lock_event_id": self.lock_event_id,
            "mint_event_id": self.mint_event_id,
            "lock_amount": self.lock_amount,
            "mint_amount": self.mint_amount,
            "amount_difference": self.amount_difference,
            "estimated_loss_usd": self.estimated_loss_usd,
            "description": self.description,
            "evidence": self.evidence,
            "acknowledged": self.acknowledged,
            "resolved": self.resolved,
        }


class CrossChainCorrelator:
    """
    Cross-Chain Correlation Engine (Redis-Backed).
    
    This is a stateless coordinator that delegates storage operations to
    the shared state manager (which uses Redis in production).
    
    For single-instance deployments, falls back to in-memory storage.
    """
    
    def __init__(
        self,
        correlation_window_minutes: int = CORRELATION_WINDOW_MINUTES,
        amount_tolerance_percent: float = AMOUNT_TOLERANCE_PERCENT,
        use_redis: bool = True
    ):
        # Configuration
        self.correlation_window = timedelta(minutes=correlation_window_minutes)
        self.amount_tolerance = amount_tolerance_percent / 100
        self._use_redis = use_redis
        
        # Local fallback storage (when Redis unavailable)
        self._local_pending_locks: Dict[str, List[CrossChainEvent]] = defaultdict(list)
        self._local_pending_mints: Dict[str, List[CrossChainEvent]] = defaultdict(list)
        self._local_processed_messages: Set[str] = set()
        self._local_violations: List[CrossChainViolation] = []
        
        # Callbacks
        self.violation_handlers: List[Callable[[CrossChainViolation], Awaitable[Any]]] = []
        
        # Statistics
        self._stats = {
            "events_processed": 0,
            "locks_received": 0,
            "mints_received": 0,
            "correlations_matched": 0,
            "violations_detected": 0,
            "orphan_mints": 0,
            "orphan_locks": 0,
            "replay_attempts": 0,
        }
        
        # State manager reference (lazy loaded)
        self._state_manager = None
    
    async def _get_state_manager(self):
        """Get or create state manager reference."""
        if self._state_manager is None:
            from ..shared_state import monitor_state
            self._state_manager = monitor_state
        return self._state_manager
    
    def add_violation_handler(self, handler: Callable[[CrossChainViolation], Awaitable[Any]]):
        """Add a handler for violations."""
        self.violation_handlers.append(handler)
    
    async def process_event(self, event: CrossChainEvent) -> Optional[CrossChainViolation]:
        """
        Process a cross-chain event.
        
        Returns a violation if detected.
        """
        self._stats["events_processed"] += 1
        
        # Check for replay attack first
        if event.message_id:
            is_replay = await self._check_replay(event.message_id)
            if is_replay:
                self._stats["replay_attempts"] += 1
                return await self._create_violation(
                    ViolationType.REPLAY_ATTACK,
                    bridge_id=event.bridge_id,
                    source_chain=event.source_chain,
                    dest_chain=event.dest_chain,
                    mint_event=event if event.event_type == CrossChainEventType.MINT else None,
                    description=f"Replay attack detected: message {event.message_id} already processed"
                )
        
        # Route based on event type
        if event.event_type in (CrossChainEventType.LOCK, CrossChainEventType.MESSAGE_SENT):
            return await self._process_lock(event)
        elif event.event_type in (CrossChainEventType.MINT, CrossChainEventType.MESSAGE_RECEIVED):
            return await self._process_mint(event)
        elif event.event_type == CrossChainEventType.BURN:
            return await self._process_burn(event)
        elif event.event_type == CrossChainEventType.UNLOCK:
            return await self._process_unlock(event)
        
        return None
    
    async def _check_replay(self, message_id: str) -> bool:
        """Check if message was already processed (replay protection)."""
        state = await self._get_state_manager()
        
        if state._backend.value == "redis" and state._redis_initialized:
            # Redis handles replay check in the atomic Lua script
            return False  # Will be checked atomically
        else:
            # Local fallback
            if message_id in self._local_processed_messages:
                return True
            self._local_processed_messages.add(message_id)
            return False
    
    async def _process_lock(self, event: CrossChainEvent) -> Optional[CrossChainViolation]:
        """Process a Lock event on source chain."""
        self._stats["locks_received"] += 1
        
        logger.info(
            "lock_event_received",
            bridge=event.bridge_id,
            chain=event.source_chain,
            amount=event.amount,
            token=event.token_symbol,
            tx=event.tx_hash[:16]
        )
        
        correlation_key = self._get_correlation_key(event)
        state = await self._get_state_manager()
        
        # Try Redis-backed correlation
        if state._backend.value == "redis" and state._redis_initialized:
            status, matched_data = await state.process_lock_event(
                event_id=event.event_id,
                event_data=event.to_dict(),
                correlation_key=correlation_key,
                amount=event.amount,
                timestamp=event.timestamp
            )
            
            if status == "MATCHED" and matched_data:
                self._stats["correlations_matched"] += 1
                mint_event = CrossChainEvent.from_dict(matched_data)
                return await self._validate_match(event, mint_event)
        else:
            # Local fallback
            self._local_pending_locks[correlation_key].append(event)
            
            # Check for pending mints
            violation = await self._try_match_local_mint(event, correlation_key)
            if violation:
                return violation
        
        return None
    
    async def _process_mint(self, event: CrossChainEvent) -> Optional[CrossChainViolation]:
        """
        Process a Mint event on destination chain.
        
        This is where we detect the CRITICAL "Mint without Lock" attack!
        """
        self._stats["mints_received"] += 1
        
        logger.info(
            "mint_event_received",
            bridge=event.bridge_id,
            chain=event.dest_chain,
            amount=event.amount,
            token=event.token_symbol,
            tx=event.tx_hash[:16]
        )
        
        correlation_key = self._get_correlation_key(event)
        state = await self._get_state_manager()
        
        # Try Redis-backed correlation
        if state._backend.value == "redis" and state._redis_initialized:
            status, matched_data = await state.process_mint_event(
                event_id=event.event_id,
                event_data=event.to_dict(),
                correlation_key=correlation_key,
                amount=event.amount,
                timestamp=event.timestamp,
                message_id=event.message_id
            )
            
            if status == "REPLAY":
                self._stats["replay_attempts"] += 1
                return await self._create_violation(
                    ViolationType.REPLAY_ATTACK,
                    bridge_id=event.bridge_id,
                    source_chain=event.source_chain,
                    dest_chain=event.dest_chain,
                    mint_event=event,
                    description=f"Replay attack: message {event.message_id} already processed"
                )
            elif status == "MATCHED" and matched_data:
                self._stats["correlations_matched"] += 1
                lock_event = CrossChainEvent.from_dict(matched_data)
                return await self._validate_match(lock_event, event)
            elif status == "ORPHAN":
                # Schedule delayed orphan check
                if event.amount_usd > MIN_ALERT_AMOUNT_USD:
                    asyncio.create_task(
                        self._delayed_orphan_check(event, correlation_key)
                    )
        else:
            # Local fallback
            matching_lock = self._find_local_matching_lock(event, correlation_key)
            
            if matching_lock:
                self._stats["correlations_matched"] += 1
                self._local_pending_locks[correlation_key].remove(matching_lock)
                return await self._validate_match(matching_lock, event)
            else:
                self._local_pending_mints[correlation_key].append(event)
                
                if event.amount_usd > MIN_ALERT_AMOUNT_USD:
                    asyncio.create_task(
                        self._delayed_orphan_check(event, correlation_key)
                    )
        
        return None
    
    async def _delayed_orphan_check(
        self,
        mint_event: CrossChainEvent,
        key: str,
        delay_seconds: int = ORPHAN_CHECK_DELAY_SECONDS
    ):
        """Check if mint is still orphan after delay."""
        await asyncio.sleep(delay_seconds)
        
        # Check if matched in the meantime
        state = await self._get_state_manager()
        
        if state._backend.value == "redis" and state._redis_initialized:
            # Redis handles this via TTL
            pass
        else:
            # Local check
            if mint_event not in self._local_pending_mints.get(key, []):
                return  # Already matched
        
        # Still orphan - this is critical!
        self._stats["orphan_mints"] += 1
        
        await self._create_violation(
            ViolationType.MINT_WITHOUT_LOCK,
            bridge_id=mint_event.bridge_id,
            source_chain=mint_event.source_chain,
            dest_chain=mint_event.dest_chain,
            mint_event=mint_event,
            estimated_loss_usd=mint_event.amount_usd,
            description=(
                f"CRITICAL: {mint_event.amount} {mint_event.token_symbol} minted on "
                f"{mint_event.dest_chain} without corresponding lock on {mint_event.source_chain}. "
                f"This matches the Wormhole attack pattern!"
            )
        )
    
    async def _validate_match(
        self,
        lock: CrossChainEvent,
        mint: CrossChainEvent
    ) -> Optional[CrossChainViolation]:
        """Validate matched lock/mint pair for violations."""
        logger.info(
            "cross_chain_match",
            bridge=lock.bridge_id,
            lock_tx=lock.tx_hash[:16],
            mint_tx=mint.tx_hash[:16],
            amount=lock.amount,
            token=lock.token_symbol
        )
        
        # Check amount mismatch
        amount_diff = abs(mint.amount - lock.amount)
        if lock.amount > 0 and amount_diff / lock.amount > self.amount_tolerance:
            return await self._create_violation(
                ViolationType.AMOUNT_MISMATCH,
                bridge_id=lock.bridge_id,
                source_chain=lock.source_chain,
                dest_chain=mint.dest_chain,
                lock_event=lock,
                mint_event=mint,
                lock_amount=lock.amount,
                mint_amount=mint.amount,
                description=f"Amount mismatch: locked {lock.amount} but minted {mint.amount}"
            )
        
        # Check time anomaly
        if mint.timestamp < lock.timestamp:
            return await self._create_violation(
                ViolationType.TIME_ANOMALY,
                bridge_id=lock.bridge_id,
                source_chain=lock.source_chain,
                dest_chain=mint.dest_chain,
                lock_event=lock,
                mint_event=mint,
                description=f"Time anomaly: mint at {mint.timestamp} before lock at {lock.timestamp}"
            )
        
        return None
    
    async def _process_burn(self, event: CrossChainEvent) -> Optional[CrossChainViolation]:
        """Process Burn event (reverse: dest → source)."""
        key = self._get_correlation_key(event)
        self._local_pending_locks[key].append(event)
        return None
    
    async def _process_unlock(self, event: CrossChainEvent) -> Optional[CrossChainViolation]:
        """Process Unlock event (reverse: dest → source)."""
        key = self._get_correlation_key(event)
        matching = self._find_local_matching_lock(event, key)
        
        if not matching and event.amount_usd > MIN_ALERT_AMOUNT_USD:
            self._stats["orphan_mints"] += 1
            return await self._create_violation(
                ViolationType.MINT_WITHOUT_LOCK,
                bridge_id=event.bridge_id,
                source_chain=event.dest_chain,
                dest_chain=event.source_chain,
                mint_event=event,
                estimated_loss_usd=event.amount_usd,
                description=f"Unlock without burn: {event.amount} unlocked without burn"
            )
        return None
    
    def _find_local_matching_lock(
        self,
        mint: CrossChainEvent,
        key: str
    ) -> Optional[CrossChainEvent]:
        """Find matching lock in local storage."""
        for lock in self._local_pending_locks.get(key, []):
            time_diff = mint.timestamp - lock.timestamp
            if time_diff > self.correlation_window or time_diff < timedelta(0):
                continue
            
            if lock.message_id and mint.message_id == lock.message_id:
                return lock
            
            if lock.amount > 0:
                diff = abs(mint.amount - lock.amount) / lock.amount
                if diff <= self.amount_tolerance:
                    return lock
        
        return None
    
    async def _try_match_local_mint(
        self,
        lock: CrossChainEvent,
        key: str
    ) -> Optional[CrossChainViolation]:
        """Try to match lock with pending local mints."""
        for mint in self._local_pending_mints.get(key, []):
            if self._events_match(lock, mint):
                self._local_pending_mints[key].remove(mint)
                self._stats["correlations_matched"] += 1
                return await self._validate_match(lock, mint)
        return None
    
    def _events_match(self, lock: CrossChainEvent, mint: CrossChainEvent) -> bool:
        """Check if lock and mint match."""
        if lock.message_id and mint.message_id == lock.message_id:
            return True
        
        if lock.amount <= 0:
            return False
        
        diff = abs(mint.amount - lock.amount) / lock.amount
        if diff > self.amount_tolerance:
            return False
        
        time_diff = mint.timestamp - lock.timestamp
        if time_diff > self.correlation_window or time_diff < timedelta(0):
            return False
        
        return True
    
    def _get_correlation_key(self, event: CrossChainEvent) -> str:
        """Generate correlation key."""
        parts = [
            event.bridge_id,
            event.source_chain,
            event.dest_chain,
            event.token_address.lower() if event.token_address else "native",
            event.sender.lower() if event.sender else "unknown",
            event.recipient.lower() if event.recipient else "unknown",
        ]
        return hashlib.sha256(":".join(parts).encode()).hexdigest()[:24]
    
    async def _create_violation(
        self,
        violation_type: ViolationType,
        bridge_id: str,
        source_chain: str,
        dest_chain: str,
        lock_event: Optional[CrossChainEvent] = None,
        mint_event: Optional[CrossChainEvent] = None,
        lock_amount: float = 0.0,
        mint_amount: float = 0.0,
        estimated_loss_usd: float = 0.0,
        description: str = ""
    ) -> CrossChainViolation:
        """Create and store a violation."""
        self._stats["violations_detected"] += 1
        
        severity_map = {
            ViolationType.MINT_WITHOUT_LOCK: "critical",
            ViolationType.REPLAY_ATTACK: "critical",
            ViolationType.TIME_ANOMALY: "critical",
            ViolationType.LOCK_WITHOUT_MINT: "high",
            ViolationType.AMOUNT_MISMATCH: "high",
            ViolationType.SEQUENCE_VIOLATION: "medium",
        }
        
        violation = CrossChainViolation(
            id=f"xc-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{len(self._local_violations)}",
            violation_type=violation_type,
            severity=severity_map.get(violation_type, "medium"),
            bridge_id=bridge_id,
            source_chain=source_chain,
            dest_chain=dest_chain,
            timestamp=datetime.now(timezone.utc),
            lock_event_id=lock_event.event_id if lock_event else None,
            mint_event_id=mint_event.event_id if mint_event else None,
            lock_amount=lock_amount or (lock_event.amount if lock_event else 0),
            mint_amount=mint_amount or (mint_event.amount if mint_event else 0),
            amount_difference=abs(lock_amount - mint_amount),
            estimated_loss_usd=estimated_loss_usd or (mint_event.amount_usd if mint_event else 0),
            description=description,
            evidence={
                "lock_tx": lock_event.tx_hash if lock_event else None,
                "mint_tx": mint_event.tx_hash if mint_event else None,
                "lock_block": lock_event.block_number if lock_event else None,
                "mint_block": mint_event.block_number if mint_event else None,
            }
        )
        
        # Store locally
        self._local_violations.append(violation)
        
        # Store in Redis/DB
        state = await self._get_state_manager()
        await state.add_violation(violation.id, violation.to_dict())
        
        logger.critical(
            "cross_chain_violation_detected",
            violation_type=violation_type.value,
            severity=violation.severity,
            bridge=bridge_id,
            estimated_loss=estimated_loss_usd,
            description=description
        )
        
        # Notify handlers
        await self._notify_handlers(violation)
        
        return violation
    
    async def _notify_handlers(self, violation: CrossChainViolation):
        """Notify all violation handlers."""
        await asyncio.gather(
            *[handler(violation) for handler in self.violation_handlers],
            return_exceptions=True
        )
    
    async def check_expired_correlations(self):
        """Check for expired pending locks/mints."""
        state = await self._get_state_manager()
        
        if state._backend.value == "redis" and state._redis_initialized:
            orphan_locks, orphan_mints = await state._redis_manager.check_orphan_events()
            
            for lock_id in orphan_locks:
                self._stats["orphan_locks"] += 1
            
            return {"orphan_locks": len(orphan_locks), "orphan_mints": len(orphan_mints)}
        else:
            # Local cleanup
            now = datetime.now(timezone.utc)
            expired = []
            
            for key, locks in self._local_pending_locks.items():
                for lock in locks:
                    if now - lock.timestamp > self.correlation_window:
                        expired.append((key, lock))
            
            for key, lock in expired:
                self._local_pending_locks[key].remove(lock)
                self._stats["orphan_locks"] += 1
                
                if lock.amount_usd > MIN_ALERT_AMOUNT_USD:
                    await self._create_violation(
                        ViolationType.LOCK_WITHOUT_MINT,
                        bridge_id=lock.bridge_id,
                        source_chain=lock.source_chain,
                        dest_chain=lock.dest_chain,
                        lock_event=lock,
                        estimated_loss_usd=lock.amount_usd,
                        description=f"Lock without mint after {self.correlation_window}"
                    )
            
            return {"orphan_locks": len(expired), "orphan_mints": 0}
    
    def get_pending_correlations(self) -> Dict[str, Any]:
        """Get pending correlation counts."""
        return {
            "pending_locks": sum(len(v) for v in self._local_pending_locks.values()),
            "pending_mints": sum(len(v) for v in self._local_pending_mints.values()),
        }
    
    def get_violations(
        self,
        severity: Optional[str] = None,
        bridge_id: Optional[str] = None,
        limit: int = 100
    ) -> List[CrossChainViolation]:
        """Get violations with optional filters."""
        violations = self._local_violations
        
        if severity:
            violations = [v for v in violations if v.severity == severity]
        if bridge_id:
            violations = [v for v in violations if v.bridge_id == bridge_id]
        
        return violations[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlator statistics."""
        return {
            **self._stats,
            "pending_locks": sum(len(v) for v in self._local_pending_locks.values()),
            "pending_mints": sum(len(v) for v in self._local_pending_mints.values()),
            "total_violations": len(self._local_violations),
            "critical_violations": len([v for v in self._local_violations if v.severity == "critical"]),
        }


# Global instance
cross_chain_correlator = CrossChainCorrelator()


# =============================================================================
# Bridge Event Parser (unchanged from original)
# =============================================================================

class BridgeEventParser:
    """
    Parses raw blockchain events into CrossChainEvent format.
    """
    
    BRIDGE_SIGNATURES = {
        # WORMHOLE
        "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2": {
            "name": "LogMessagePublished",
            "type": CrossChainEventType.LOCK,
            "bridge": "wormhole"
        },
        "0xcaf280c8cfeba144da67230d9b009c8f868a75bac9a528fa0474be1ba317c169": {
            "name": "TransferRedeemed",
            "type": CrossChainEventType.MINT,
            "bridge": "wormhole"
        },
        # LAYERZERO
        "0xe9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82": {
            "name": "Packet",
            "type": CrossChainEventType.MESSAGE_SENT,
            "bridge": "layerzero"
        },
        "0x32ed1a409ef04c7b0227189c3a103dc5ac10e775a15b785dcc510201f7c25ad3": {
            "name": "SendToChain",
            "type": CrossChainEventType.LOCK,
            "bridge": "layerzero"
        },
        "0xd81b6f2a5a0f1c0c5e8e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c": {
            "name": "ReceiveFromChain",
            "type": CrossChainEventType.MINT,
            "bridge": "layerzero"
        },
        # STARGATE
        "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f": {
            "name": "Swap",
            "type": CrossChainEventType.LOCK,
            "bridge": "stargate"
        },
        "0x44b559f101f8fbcc8a0ea43fa91a05a729a5ea6e14a7c75aa750374690137208": {
            "name": "SendCredits",
            "type": CrossChainEventType.LOCK,
            "bridge": "stargate"
        },
        # ACROSS
        "0x8ab9dc6c19fe88e69bc70221b339c84332752fdd49591b7c51e66bae3947b73c": {
            "name": "FilledRelay",
            "type": CrossChainEventType.MINT,
            "bridge": "across"
        },
        "0xafc4df6845a4ab948b492800d3d8a25d538a102a2bc07cd01f1cfa097fddcff6": {
            "name": "FundsDeposited",
            "type": CrossChainEventType.LOCK,
            "bridge": "across"
        },
        # HOP
        "0xe35dddd4ea75d7e9b3fe93af4f4e40e778c3da4074c9d93e7c6f3f94a7d0ec34": {
            "name": "TransferSent",
            "type": CrossChainEventType.LOCK,
            "bridge": "hop"
        },
        "0x320958176930804eb66c2343c7343fc0367dc16249590c0f195783bee199d094": {
            "name": "TransferCompleted",
            "type": CrossChainEventType.MINT,
            "bridge": "hop"
        },
        # SYNAPSE
        "0xda5273705dbef4bf1b902a131c2eac086b7e1476a8ab0cb4da08af1fe1bd8e3b": {
            "name": "TokenDeposit",
            "type": CrossChainEventType.LOCK,
            "bridge": "synapse"
        },
        "0xdc5bad4651c5fbe9977a696aadc65996c468cde1448dd468ec0d83bf61c4b57c": {
            "name": "TokenRedeem",
            "type": CrossChainEventType.MINT,
            "bridge": "synapse"
        },
        # CELER
        "0x89d8051e597ab4178a863a5190407b98abfeff406aa8db90c59af76612e58f01": {
            "name": "Send",
            "type": CrossChainEventType.LOCK,
            "bridge": "celer"
        },
        "0x79fa08de5149d912dce8e5e8da7a7c17ccdf23dd5d3bfe196802f6c6d471f3f9": {
            "name": "Relay",
            "type": CrossChainEventType.MINT,
            "bridge": "celer"
        },
    }
    
    CHAIN_IDS = {
        1: "ethereum",
        137: "polygon",
        42161: "arbitrum",
        43114: "avalanche",
        56: "bsc",
        10: "optimism",
        8453: "base",
    }
    
    @classmethod
    def parse_event(
        cls,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[CrossChainEvent]:
        """Parse raw blockchain event into CrossChainEvent."""
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        elif not topic0.startswith("0x"):
            topic0 = "0x" + topic0
        
        event_info = cls.BRIDGE_SIGNATURES.get(topic0.lower())
        if not event_info:
            return None
        
        try:
            return cls._parse_by_bridge(
                bridge=event_info["bridge"],
                event_type=event_info["type"],
                event_name=event_info["name"],
                event_data=event_data,
                chain_id=chain_id,
                block_timestamp=block_timestamp
            )
        except Exception as e:
            logger.warning("event_parse_error", bridge=event_info["bridge"], error=str(e))
            return None
    
    @classmethod
    def _parse_by_bridge(
        cls,
        bridge: str,
        event_type: CrossChainEventType,
        event_name: str,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> CrossChainEvent:
        """Parse event based on bridge type."""
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        contract_address = event_data.get("address", "")
        topics = event_data.get("topics", [])
        data = event_data.get("data", "0x")
        
        # Defaults
        amount = 0.0
        amount_usd = 0.0
        token_address = ""
        token_symbol = "UNKNOWN"
        message_id = None
        dest_chain = "unknown"
        sender = None
        recipient = None
        
        # Bridge-specific parsing (simplified)
        if len(topics) > 1:
            if bridge == "wormhole":
                dest_chain = cls._decode_wormhole_chain(topics[1])
            elif bridge in ("layerzero", "stargate"):
                chain_num = int(topics[1], 16) if isinstance(topics[1], str) else int.from_bytes(topics[1], 'big')
                dest_chain = cls.CHAIN_IDS.get(chain_num, f"chain_{chain_num}")
            elif bridge in ("across", "hop", "celer"):
                message_id = topics[1] if isinstance(topics[1], str) else "0x" + topics[1].hex()
        
        event_id = hashlib.sha256(f"{tx_hash}:{block_number}:{contract_address}".encode()).hexdigest()[:16]
        
        return CrossChainEvent(
            event_id=event_id,
            event_type=event_type,
            bridge_id=bridge,
            source_chain=chain_id,
            dest_chain=dest_chain,
            tx_hash=tx_hash,
            block_number=block_number,
            timestamp=block_timestamp,
            token_address=token_address,
            token_symbol=token_symbol,
            amount=amount,
            amount_usd=amount_usd,
            message_id=message_id,
            sender=sender,
            recipient=recipient,
            raw_data=event_data
        )
    
    @classmethod
    def _decode_wormhole_chain(cls, topic: str) -> str:
        """Decode Wormhole chain ID."""
        wormhole_chains = {
            1: "solana", 2: "ethereum", 4: "bsc", 5: "polygon",
            6: "avalanche", 10: "fantom", 23: "arbitrum", 24: "optimism", 30: "base"
        }
        chain_id = int(topic, 16) if isinstance(topic, str) else int.from_bytes(topic, 'big')
        return wormhole_chains.get(chain_id, f"wormhole_chain_{chain_id}")
