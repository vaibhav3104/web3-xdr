"""
Temporal Invariants - Sequence and timing invariants.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Set
import structlog

from .base import Invariant, InvariantContext, InvariantRegistry
from ..models.events import EventType, Severity
from ..models.invariants import InvariantResult, InvariantType

logger = structlog.get_logger()


@InvariantRegistry.register("BRIDGE_SEQUENCE")
class SequenceInvariant(Invariant):
    """
    Bridge operations must follow correct sequence.
    
    INVARIANT: LOCK → MESSAGE → VERIFY → MINT (in order)
    
    Detects attempts to bypass verification steps.
    """
    
    description = "Bridge operations must follow lock → verify → mint sequence"
    invariant_type = InvariantType.TEMPORAL
    severity = Severity.CRITICAL
    
    def __init__(
        self,
        bridge_id: str,
        max_message_delay: timedelta = timedelta(hours=1)
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.max_message_delay = max_message_delay
        
        # Track validated sequences
        self._validated_sequences: Set[str] = set()
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check that mints follow proper sequence.
        """
        # Get recent mints
        mints = await context.get_events(
            event_type=EventType.MINT,
            bridge_id=self.bridge_id,
            window=timedelta(minutes=5)
        )
        
        violations = []
        
        for mint in mints:
            if mint.event_id in self._validated_sequences:
                continue
            
            if not mint.message_hash:
                violations.append({
                    "mint": mint.to_dict(),
                    "issue": "MISSING_MESSAGE_HASH",
                    "description": "Mint executed without message reference"
                })
                continue
            
            # Check for message verification before mint
            verification = await context.find_event(
                event_type=EventType.MESSAGE_VERIFIED,
                message_hash=mint.message_hash,
                before=mint.block_timestamp
            )
            
            if not verification:
                # Check if lock exists
                lock = await context.find_event(
                    event_type=EventType.LOCK,
                    message_hash=mint.message_hash,
                    before=mint.block_timestamp
                )
                
                if not lock:
                    violations.append({
                        "mint": mint.to_dict(),
                        "issue": "MISSING_LOCK",
                        "description": "Mint executed without lock event"
                    })
                else:
                    # Lock exists but no verification - suspicious
                    violations.append({
                        "mint": mint.to_dict(),
                        "lock": lock.to_dict(),
                        "issue": "MISSING_VERIFICATION",
                        "description": "Mint executed without message verification"
                    })
            else:
                # Valid sequence - cache it
                self._validated_sequences.add(mint.event_id)
        
        # Limit cache size
        if len(self._validated_sequences) > 10000:
            self._validated_sequences = set(list(self._validated_sequences)[-5000:])
        
        if violations:
            self.record_violation()
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                confidence=0.85,
                bridge_id=self.bridge_id,
                evidence={
                    "violations": violations,
                    "count": len(violations)
                },
                related_event_ids=[mint.event_id for mint in mints],
                description=f"Detected {len(violations)} sequence violations in bridge operations"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("TIMELOCK_RESPECTED")
class TimelockInvariant(Invariant):
    """
    Admin/governance actions must respect timelock periods.
    
    INVARIANT: execution_time - proposal_time >= required_delay
    
    Detects bypassed timelocks (e.g., compromised admin keys).
    """
    
    description = "Governance actions must respect timelock delays"
    invariant_type = InvariantType.TEMPORAL
    severity = Severity.CRITICAL
    
    def __init__(
        self,
        contract_addresses: List[str],
        min_timelock_hours: int = 24
    ):
        super().__init__()
        self.contract_addresses = [a.lower() for a in contract_addresses]
        self.min_timelock = timedelta(hours=min_timelock_hours)
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check that governance executions respect timelocks.
        """
        # Get recent executions
        executions = await context.get_events(
            event_type=EventType.PROPOSAL_EXECUTED,
            window=timedelta(hours=1)
        )
        
        violations = []
        
        for execution in executions:
            if execution.contract_address.lower() not in self.contract_addresses:
                continue
            
            if not execution.proposal_id:
                continue
            
            # Find corresponding proposal
            proposal = await context.find_event(
                event_type=EventType.PROPOSAL_CREATED,
                before=execution.block_timestamp
            )
            
            # Check in raw event for proposal ID match
            if proposal and proposal.proposal_id == execution.proposal_id:
                elapsed = execution.block_timestamp - proposal.block_timestamp
                required_delay = await context.get_timelock_delay(execution.contract_address)
                
                if elapsed < required_delay:
                    violations.append({
                        "execution": execution.to_dict(),
                        "proposal": proposal.to_dict(),
                        "elapsed_seconds": elapsed.total_seconds(),
                        "required_seconds": required_delay.total_seconds(),
                        "shortfall_seconds": (required_delay - elapsed).total_seconds()
                    })
            elif not proposal:
                # Execution without proposal - even more suspicious
                violations.append({
                    "execution": execution.to_dict(),
                    "issue": "NO_PROPOSAL_FOUND",
                    "description": "Execution without matching proposal"
                })
        
        if violations:
            self.record_violation()
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                evidence={
                    "violations": violations,
                    "count": len(violations)
                },
                description=f"Detected {len(violations)} timelock violations"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type
        )


@InvariantRegistry.register("MESSAGE_DELAY")
class MessageDelayInvariant(Invariant):
    """
    Bridge messages should not be delayed beyond threshold.
    
    INVARIANT: mint_time - lock_time <= max_delay
    
    Detects:
    - Stalled bridges (operational issue)
    - Delayed attack execution (attacker waiting)
    """
    
    description = "Bridge message processing should complete within expected timeframe"
    invariant_type = InvariantType.TEMPORAL
    severity = Severity.MEDIUM
    
    def __init__(
        self,
        bridge_id: str,
        max_delay: timedelta = timedelta(hours=1),
        min_delay_for_alert: timedelta = timedelta(minutes=30)
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.max_delay = max_delay
        self.min_delay_for_alert = min_delay_for_alert
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check for delayed messages.
        """
        # Get pending messages (locks without corresponding mints)
        delayed_messages = []
        now = datetime.now(timezone.utc)
        
        # Check all locks in the last few hours
        locks = await context.get_events(
            event_type=EventType.LOCK,
            bridge_id=self.bridge_id,
            window=timedelta(hours=6)
        )
        
        for lock in locks:
            if not lock.message_hash:
                continue
            
            # Check if this lock has been processed
            mint = await context.find_event(
                event_type=EventType.MINT,
                message_hash=lock.message_hash,
                after=lock.block_timestamp
            )
            
            if not mint:
                # Still pending
                delay = now - lock.block_timestamp
                if delay > self.min_delay_for_alert:
                    delayed_messages.append({
                        "lock": lock.to_dict(),
                        "delay_seconds": delay.total_seconds(),
                        "threshold_exceeded": delay > self.max_delay
                    })
        
        if delayed_messages:
            # Determine severity based on delay
            max_delay_found = max(m["delay_seconds"] for m in delayed_messages)
            severity = Severity.HIGH if max_delay_found > self.max_delay.total_seconds() else Severity.MEDIUM
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=severity,
                bridge_id=self.bridge_id,
                evidence={
                    "delayed_messages": delayed_messages,
                    "count": len(delayed_messages),
                    "max_delay_seconds": max_delay_found
                },
                description=f"Detected {len(delayed_messages)} delayed bridge messages"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("REPLAY_PROTECTION")
class ReplayProtectionInvariant(Invariant):
    """
    Bridge messages must not be replayed.
    
    INVARIANT: Each message_hash should result in exactly one mint.
    
    Detects replay attacks where same message is used multiple times.
    """
    
    description = "Bridge messages must not be replayed"
    invariant_type = InvariantType.TEMPORAL
    severity = Severity.CRITICAL
    
    def __init__(self, bridge_id: str):
        super().__init__()
        self.bridge_id = bridge_id
        self._seen_messages: dict = {}  # message_hash -> first mint event_id
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check for replayed messages.
        """
        mints = await context.get_events(
            event_type=EventType.MINT,
            bridge_id=self.bridge_id,
            window=timedelta(hours=24)
        )
        
        replays = []
        
        for mint in mints:
            if not mint.message_hash:
                continue
            
            if mint.message_hash in self._seen_messages:
                if self._seen_messages[mint.message_hash] != mint.event_id:
                    replays.append({
                        "message_hash": mint.message_hash,
                        "original_event_id": self._seen_messages[mint.message_hash],
                        "replay_event": mint.to_dict()
                    })
            else:
                self._seen_messages[mint.message_hash] = mint.event_id
        
        # Limit cache size
        if len(self._seen_messages) > 50000:
            # Keep only recent entries
            self._seen_messages = dict(list(self._seen_messages.items())[-25000:])
        
        if replays:
            self.record_violation()
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                confidence=0.99,  # Very high confidence
                bridge_id=self.bridge_id,
                evidence={
                    "replays": replays,
                    "count": len(replays)
                },
                description=f"Detected {len(replays)} replayed bridge messages"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )

