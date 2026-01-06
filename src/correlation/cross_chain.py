"""
Cross-Chain Correlation Engine
==============================

This module implements the core cross-chain correlation logic for bridge monitoring.
It links Lock events on source chains to Mint events on destination chains,
detecting economic invariant violations like "Mint without Lock".

Key Features:
1. Message ID tracking across chains
2. Lock/Mint parity verification
3. Time-window based correlation
4. Orphan detection (locks without mints, mints without locks)
5. Bridge-specific correlation rules
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Awaitable
from enum import Enum
from collections import defaultdict
import hashlib
import structlog

logger = structlog.get_logger(__name__)


class CrossChainEventType(Enum):
    """Types of cross-chain events."""
    LOCK = "lock"           # Assets locked on source chain
    UNLOCK = "unlock"       # Assets unlocked on source chain
    MINT = "mint"           # Wrapped assets minted on dest chain
    BURN = "burn"           # Wrapped assets burned on dest chain
    MESSAGE_SENT = "message_sent"      # Cross-chain message sent
    MESSAGE_RECEIVED = "message_received"  # Cross-chain message received
    TRANSFER = "transfer"   # Generic transfer


class CorrelationStatus(Enum):
    """Status of a correlation."""
    PENDING = "pending"           # Waiting for matching event
    MATCHED = "matched"           # Found matching event
    ORPHAN = "orphan"            # No matching event found (potential attack!)
    EXPIRED = "expired"          # Time window expired
    SUSPICIOUS = "suspicious"    # Amounts don't match


class ViolationType(Enum):
    """Types of cross-chain violations."""
    MINT_WITHOUT_LOCK = "mint_without_lock"       # Critical - Wormhole-style attack
    LOCK_WITHOUT_MINT = "lock_without_mint"       # Funds stuck or message failed
    AMOUNT_MISMATCH = "amount_mismatch"           # Lock and mint amounts differ
    SEQUENCE_VIOLATION = "sequence_violation"    # Message sequence out of order
    REPLAY_ATTACK = "replay_attack"              # Same message processed twice
    TIME_ANOMALY = "time_anomaly"                # Mint before lock (impossible!)


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
    message_id: Optional[str] = None      # Bridge message ID
    nonce: Optional[int] = None           # Message sequence number
    sender: Optional[str] = None
    recipient: Optional[str] = None
    
    # Raw data
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def get_correlation_key(self) -> str:
        """Generate key for correlation matching."""
        # Key based on: bridge + token + sender + recipient + amount
        key_data = f"{self.bridge_id}:{self.token_address}:{self.sender}:{self.recipient}:{self.amount}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]


@dataclass
class CorrelationPair:
    """A pair of correlated cross-chain events."""
    id: str
    bridge_id: str
    source_chain: str
    dest_chain: str
    
    # Events
    lock_event: Optional[CrossChainEvent] = None
    mint_event: Optional[CrossChainEvent] = None
    
    # Status
    status: CorrelationStatus = CorrelationStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    matched_at: Optional[datetime] = None
    
    # Violation info
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
    severity: str  # critical, high, medium, low
    bridge_id: str
    source_chain: str
    dest_chain: str
    timestamp: datetime
    
    # Event details
    lock_event_id: Optional[str] = None
    mint_event_id: Optional[str] = None
    
    # Amount
    lock_amount: float = 0.0
    mint_amount: float = 0.0
    amount_difference: float = 0.0
    estimated_loss_usd: float = 0.0
    
    # Details
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Response
    acknowledged: bool = False
    resolved: bool = False


class CrossChainCorrelator:
    """
    Cross-Chain Correlation Engine.
    
    Links events across chains and detects economic invariant violations.
    
    How it works:
    1. Events come in from multiple chains
    2. Lock events are stored, waiting for matching Mint
    3. Mint events are matched to pending Locks
    4. Orphan Mints (no Lock) = CRITICAL violation (Wormhole attack!)
    5. Orphan Locks (no Mint) = HIGH violation (funds stuck)
    """
    
    def __init__(
        self,
        correlation_window_minutes: int = 30,
        amount_tolerance_percent: float = 0.1,  # 0.1% tolerance for fees
    ):
        # Configuration
        self.correlation_window = timedelta(minutes=correlation_window_minutes)
        self.amount_tolerance = amount_tolerance_percent / 100
        
        # Storage
        self.pending_locks: Dict[str, List[CrossChainEvent]] = defaultdict(list)
        self.pending_mints: Dict[str, List[CrossChainEvent]] = defaultdict(list)
        self.correlations: Dict[str, CorrelationPair] = {}
        self.violations: List[CrossChainViolation] = []
        
        # Tracking
        self.processed_message_ids: Set[str] = set()  # Replay protection
        self.message_sequences: Dict[str, int] = {}   # Per-bridge sequence tracking
        
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
        }
    
    def add_violation_handler(self, handler: Callable[[CrossChainViolation], Awaitable[Any]]):
        """Add a handler for violations."""
        self.violation_handlers.append(handler)
    
    async def process_event(self, event: CrossChainEvent) -> Optional[CrossChainViolation]:
        """
        Process a cross-chain event.
        
        Returns a violation if detected.
        """
        self._stats["events_processed"] += 1
        
        # Check for replay attack
        if event.message_id and event.message_id in self.processed_message_ids:
            return await self._create_violation(
                ViolationType.REPLAY_ATTACK,
                bridge_id=event.bridge_id,
                source_chain=event.source_chain,
                dest_chain=event.dest_chain,
                mint_event=event if event.event_type == CrossChainEventType.MINT else None,
                description=f"Replay attack detected: message {event.message_id} already processed"
            )
        
        if event.message_id:
            self.processed_message_ids.add(event.message_id)
        
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
        
        # Store pending lock
        key = self._get_correlation_key(event)
        self.pending_locks[key].append(event)
        
        # Create correlation entry
        correlation = CorrelationPair(
            id=f"corr-{event.event_id[:8]}",
            bridge_id=event.bridge_id,
            source_chain=event.source_chain,
            dest_chain=event.dest_chain,
            lock_event=event,
            status=CorrelationStatus.PENDING
        )
        self.correlations[correlation.id] = correlation
        
        # Check if there's a pending mint that matches (out-of-order arrival)
        violation = await self._try_match_pending_mint(event, key)
        
        return violation
    
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
        
        # Try to find matching lock
        key = self._get_correlation_key(event)
        matching_lock = await self._find_matching_lock(event, key)
        
        if matching_lock:
            # ✅ MATCHED - This is normal operation
            return await self._match_events(matching_lock, event)
        else:
            # 🚨 NO MATCHING LOCK - Potential attack!
            # Store as pending, but also raise alert
            self.pending_mints[key].append(event)
            
            # Check if this is within correlation window
            # Give some time for lock to arrive (network delays)
            if event.amount_usd > 10000:  # Only alert for significant amounts
                logger.warning(
                    "mint_without_lock_detected",
                    bridge=event.bridge_id,
                    chain=event.dest_chain,
                    amount_usd=event.amount_usd,
                    tx=event.tx_hash
                )
                
                # Schedule a check after correlation window
                asyncio.create_task(
                    self._check_orphan_mint(event, key, delay_seconds=60)
                )
        
        return None
    
    async def _check_orphan_mint(
        self,
        mint_event: CrossChainEvent,
        key: str,
        delay_seconds: int
    ):
        """
        Check if a mint event is still orphan after delay.
        
        If no matching lock arrives, this is a critical violation!
        """
        await asyncio.sleep(delay_seconds)
        
        # Check if it was matched in the meantime
        if mint_event not in self.pending_mints.get(key, []):
            # Already matched, no violation
            return
        
        # Still orphan - this is the Wormhole-style attack!
        self._stats["orphan_mints"] += 1
        
        violation = await self._create_violation(
            ViolationType.MINT_WITHOUT_LOCK,
            bridge_id=mint_event.bridge_id,
            source_chain=mint_event.source_chain,
            dest_chain=mint_event.dest_chain,
            mint_event=mint_event,
            estimated_loss_usd=mint_event.amount_usd,
            description=f"CRITICAL: {mint_event.amount} {mint_event.token_symbol} minted on {mint_event.dest_chain} "
                       f"without corresponding lock on {mint_event.source_chain}. "
                       f"This matches the Wormhole attack pattern!"
        )
        
        # Remove from pending
        self.pending_mints[key].remove(mint_event)
    
    async def _find_matching_lock(
        self,
        mint_event: CrossChainEvent,
        key: str
    ) -> Optional[CrossChainEvent]:
        """
        Find a matching lock event for a mint.
        
        Matching criteria:
        1. Same bridge
        2. Same token
        3. Same/similar amount (within tolerance)
        4. Same sender/recipient
        5. Within time window
        6. Or matching message ID (most reliable)
        """
        pending = self.pending_locks.get(key, [])
        
        for lock in pending:
            # Check if within time window
            time_diff = mint_event.timestamp - lock.timestamp
            if time_diff > self.correlation_window or time_diff < timedelta(0):
                continue
            
            # Check message ID match (most reliable)
            if mint_event.message_id and lock.message_id:
                if mint_event.message_id == lock.message_id:
                    return lock
            
            # Check amount match (with tolerance for fees)
            amount_diff = abs(mint_event.amount - lock.amount) / max(lock.amount, 0.0001)
            if amount_diff <= self.amount_tolerance:
                # Check sender/recipient
                if (mint_event.sender == lock.sender or 
                    mint_event.recipient == lock.recipient):
                    return lock
        
        return None
    
    async def _try_match_pending_mint(
        self,
        lock_event: CrossChainEvent,
        key: str
    ) -> Optional[CrossChainViolation]:
        """Try to match a lock event with pending mints."""
        pending = self.pending_mints.get(key, [])
        
        for mint in pending:
            # Check if this lock matches the pending mint
            if self._events_match(lock_event, mint):
                # Found match - remove from pending and create correlation
                self.pending_mints[key].remove(mint)
                return await self._match_events(lock_event, mint)
        
        return None
    
    def _events_match(
        self,
        lock: CrossChainEvent,
        mint: CrossChainEvent
    ) -> bool:
        """Check if lock and mint events match."""
        # Message ID match
        if lock.message_id and mint.message_id:
            if lock.message_id == mint.message_id:
                return True
        
        # Amount match
        amount_diff = abs(mint.amount - lock.amount) / max(lock.amount, 0.0001)
        if amount_diff > self.amount_tolerance:
            return False
        
        # Time window
        time_diff = mint.timestamp - lock.timestamp
        if time_diff > self.correlation_window or time_diff < timedelta(0):
            return False
        
        return True
    
    async def _match_events(
        self,
        lock: CrossChainEvent,
        mint: CrossChainEvent
    ) -> Optional[CrossChainViolation]:
        """Match lock and mint events, checking for violations."""
        self._stats["correlations_matched"] += 1
        
        # Remove from pending
        key = self._get_correlation_key(lock)
        if lock in self.pending_locks.get(key, []):
            self.pending_locks[key].remove(lock)
        
        # Update correlation
        for corr in self.correlations.values():
            if corr.lock_event == lock:
                corr.mint_event = mint
                corr.status = CorrelationStatus.MATCHED
                corr.matched_at = datetime.now(timezone.utc)
                break
        
        logger.info(
            "cross_chain_match",
            bridge=lock.bridge_id,
            lock_tx=lock.tx_hash[:16],
            mint_tx=mint.tx_hash[:16],
            amount=lock.amount,
            token=lock.token_symbol
        )
        
        # Check for amount mismatch
        amount_diff = abs(mint.amount - lock.amount)
        if amount_diff / max(lock.amount, 0.0001) > self.amount_tolerance:
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
        
        # Check for time anomaly (mint before lock - impossible!)
        if mint.timestamp < lock.timestamp:
            return await self._create_violation(
                ViolationType.TIME_ANOMALY,
                bridge_id=lock.bridge_id,
                source_chain=lock.source_chain,
                dest_chain=mint.dest_chain,
                lock_event=lock,
                mint_event=mint,
                description=f"Time anomaly: mint timestamp {mint.timestamp} is before lock {lock.timestamp}"
            )
        
        return None
    
    async def _process_burn(self, event: CrossChainEvent) -> Optional[CrossChainViolation]:
        """Process a Burn event (reverse direction: dest → source)."""
        # Similar logic to lock, but for reverse transfers
        key = self._get_correlation_key(event)
        self.pending_locks[key].append(event)  # Burns are like locks for reverse
        return None
    
    async def _process_unlock(self, event: CrossChainEvent) -> Optional[CrossChainViolation]:
        """Process an Unlock event (reverse direction: dest → source)."""
        # Similar logic to mint, but for reverse transfers
        key = self._get_correlation_key(event)
        matching_burn = await self._find_matching_lock(event, key)
        
        if not matching_burn and event.amount_usd > 10000:
            # Unlock without burn - suspicious!
            self._stats["orphan_mints"] += 1
            
            return await self._create_violation(
                ViolationType.MINT_WITHOUT_LOCK,  # Same violation type
                bridge_id=event.bridge_id,
                source_chain=event.dest_chain,  # Reversed
                dest_chain=event.source_chain,
                mint_event=event,
                estimated_loss_usd=event.amount_usd,
                description=f"Unlock without burn: {event.amount} unlocked without corresponding burn"
            )
        
        return None
    
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
        
        # Determine severity
        severity_map = {
            ViolationType.MINT_WITHOUT_LOCK: "critical",
            ViolationType.REPLAY_ATTACK: "critical",
            ViolationType.TIME_ANOMALY: "critical",
            ViolationType.LOCK_WITHOUT_MINT: "high",
            ViolationType.AMOUNT_MISMATCH: "high",
            ViolationType.SEQUENCE_VIOLATION: "medium",
        }
        
        violation = CrossChainViolation(
            id=f"xc-viol-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{len(self.violations)}",
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
        
        self.violations.append(violation)
        
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
    
    def _get_correlation_key(self, event: CrossChainEvent) -> str:
        """Generate correlation key for an event."""
        # Key: bridge:source_chain:dest_chain:token:sender:recipient
        key_parts = [
            event.bridge_id,
            event.source_chain,
            event.dest_chain,
            event.token_address.lower() if event.token_address else "native",
            event.sender.lower() if event.sender else "unknown",
            event.recipient.lower() if event.recipient else "unknown",
        ]
        key = ":".join(key_parts)
        return hashlib.sha256(key.encode()).hexdigest()[:24]
    
    async def check_expired_correlations(self):
        """
        Check for expired pending locks/mints.
        
        Run this periodically to detect stuck transfers.
        """
        now = datetime.now(timezone.utc)
        expired_locks = []
        
        for key, locks in self.pending_locks.items():
            for lock in locks:
                age = now - lock.timestamp
                if age > self.correlation_window:
                    expired_locks.append((key, lock))
        
        for key, lock in expired_locks:
            self._stats["orphan_locks"] += 1
            self.pending_locks[key].remove(lock)
            
            # Create violation for stuck funds
            if lock.amount_usd > 10000:  # Only for significant amounts
                await self._create_violation(
                    ViolationType.LOCK_WITHOUT_MINT,
                    bridge_id=lock.bridge_id,
                    source_chain=lock.source_chain,
                    dest_chain=lock.dest_chain,
                    lock_event=lock,
                    estimated_loss_usd=lock.amount_usd,
                    description=f"Lock without mint after {self.correlation_window}: "
                               f"{lock.amount} {lock.token_symbol} may be stuck"
                )
    
    def get_pending_correlations(self) -> Dict[str, Any]:
        """Get all pending correlations."""
        return {
            "pending_locks": sum(len(v) for v in self.pending_locks.values()),
            "pending_mints": sum(len(v) for v in self.pending_mints.values()),
            "locks_by_bridge": {
                k: len(v) for k, v in self.pending_locks.items()
            },
            "mints_by_bridge": {
                k: len(v) for k, v in self.pending_mints.items()
            }
        }
    
    def get_violations(
        self,
        severity: Optional[str] = None,
        bridge_id: Optional[str] = None,
        limit: int = 100
    ) -> List[CrossChainViolation]:
        """Get violations with optional filters."""
        violations = self.violations
        
        if severity:
            violations = [v for v in violations if v.severity == severity]
        if bridge_id:
            violations = [v for v in violations if v.bridge_id == bridge_id]
        
        return violations[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlator statistics."""
        return {
            **self._stats,
            "pending_locks": sum(len(v) for v in self.pending_locks.values()),
            "pending_mints": sum(len(v) for v in self.pending_mints.values()),
            "total_correlations": len(self.correlations),
            "total_violations": len(self.violations),
            "critical_violations": len([v for v in self.violations if v.severity == "critical"]),
        }


# Global instance
cross_chain_correlator = CrossChainCorrelator()


# =============================================================================
# Bridge-Specific Event Parsers
# =============================================================================

class BridgeEventParser:
    """
    Parses raw blockchain events into CrossChainEvent format.
    
    Each bridge has different event structures, so we need
    bridge-specific parsing logic.
    """
    
    # Bridge event signatures
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
    
    # Chain ID mapping
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
        """
        Parse a raw blockchain event into CrossChainEvent.
        
        Args:
            event_data: Raw event from blockchain
            chain_id: Chain where event occurred
            block_timestamp: Block timestamp
            
        Returns:
            CrossChainEvent or None if not a bridge event
        """
        # Get topic0 (event signature)
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        elif not topic0.startswith("0x"):
            topic0 = "0x" + topic0
        
        # Look up event info
        event_info = cls.BRIDGE_SIGNATURES.get(topic0.lower())
        if not event_info:
            return None
        
        # Parse based on bridge type
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
            logger.warning(
                "event_parse_error",
                bridge=event_info["bridge"],
                error=str(e)
            )
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
        
        # Common fields
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        contract_address = event_data.get("address", "")
        
        topics = event_data.get("topics", [])
        data = event_data.get("data", "0x")
        
        # Default values
        amount = 0.0
        amount_usd = 0.0
        token_address = ""
        token_symbol = "UNKNOWN"
        message_id = None
        nonce = None
        sender = None
        recipient = None
        dest_chain = "unknown"
        
        # Bridge-specific parsing
        if bridge == "wormhole":
            # Wormhole has emitter chain and sequence in topics
            if len(topics) > 1:
                # Topic 1: emitter chain
                dest_chain = cls._decode_wormhole_chain(topics[1])
            if len(data) > 66:
                # Data contains amount and other info
                amount = cls._decode_amount(data[2:66])
        
        elif bridge == "layerzero":
            # LayerZero has destination chain in topics
            if len(topics) > 1:
                dest_chain_id = int(topics[1], 16) if isinstance(topics[1], str) else int.from_bytes(topics[1], 'big')
                dest_chain = cls.CHAIN_IDS.get(dest_chain_id, f"chain_{dest_chain_id}")
            if len(topics) > 2:
                recipient = topics[2][-40:] if len(topics[2]) >= 40 else topics[2]
        
        elif bridge == "stargate":
            # Stargate has pool ID and destination chain
            if len(topics) > 1:
                dest_chain_id = int(topics[1], 16) if isinstance(topics[1], str) else int.from_bytes(topics[1], 'big')
                dest_chain = cls.CHAIN_IDS.get(dest_chain_id, f"chain_{dest_chain_id}")
        
        elif bridge == "across":
            # Across has deposit ID and destination chain
            if len(topics) > 1:
                message_id = topics[1] if isinstance(topics[1], str) else "0x" + topics[1].hex()
        
        elif bridge == "hop":
            # Hop has transfer ID
            if len(topics) > 1:
                message_id = topics[1] if isinstance(topics[1], str) else "0x" + topics[1].hex()
        
        elif bridge == "synapse":
            # Synapse uses kappa as message ID
            if len(data) > 66:
                message_id = data[2:66]
        
        elif bridge == "celer":
            # Celer has transfer ID in topics
            if len(topics) > 1:
                message_id = topics[1] if isinstance(topics[1], str) else "0x" + topics[1].hex()
        
        # Generate event ID
        event_id = hashlib.sha256(
            f"{tx_hash}:{block_number}:{contract_address}".encode()
        ).hexdigest()[:16]
        
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
            nonce=nonce,
            sender=sender,
            recipient=recipient,
            raw_data=event_data
        )
    
    @classmethod
    def _decode_wormhole_chain(cls, topic: str) -> str:
        """Decode Wormhole chain ID."""
        wormhole_chains = {
            1: "solana",
            2: "ethereum",
            4: "bsc",
            5: "polygon",
            6: "avalanche",
            10: "fantom",
            13: "klaytn",
            14: "celo",
            16: "moonbeam",
            23: "arbitrum",
            24: "optimism",
            30: "base",
        }
        chain_id = int(topic, 16) if isinstance(topic, str) else int.from_bytes(topic, 'big')
        return wormhole_chains.get(chain_id, f"wormhole_chain_{chain_id}")
    
    @classmethod
    def _decode_amount(cls, hex_data: str) -> float:
        """Decode amount from hex data."""
        try:
            if hex_data.startswith("0x"):
                hex_data = hex_data[2:]
            amount = int(hex_data, 16)
            # Assume 18 decimals for now
            return amount / (10 ** 18)
        except:
            return 0.0

