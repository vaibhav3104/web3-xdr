"""
Economic Invariants - Core financial invariants for bridge security.
"""

from datetime import timedelta
from decimal import Decimal
from typing import Optional
import structlog

from .base import Invariant, InvariantContext, InvariantRegistry
from ..models.events import EventType, Severity
from ..models.invariants import InvariantResult, InvariantType

logger = structlog.get_logger()


@InvariantRegistry.register("MINT_LOCK_PARITY")
class MintLockParityInvariant(Invariant):
    """
    Core economic invariant: minted tokens must not exceed locked tokens.
    
    INVARIANT: Σ(minted_on_dest) ≤ Σ(locked_on_source)
    
    This is THE fundamental invariant for bridge security.
    Violation indicates:
    - Forged bridge messages
    - Validator compromise
    - Contract vulnerability
    """
    
    description = "Tokens minted on destination chain must not exceed tokens locked on source chain"
    invariant_type = InvariantType.ECONOMIC
    severity = Severity.CRITICAL
    
    def __init__(
        self,
        bridge_id: str,
        source_chain: str,
        dest_chain: str,
        tolerance_window: timedelta = timedelta(minutes=10),
        tolerance_amount: Decimal = Decimal("0.01")  # Allow 0.01 token rounding
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.source_chain = source_chain
        self.dest_chain = dest_chain
        self.tolerance_window = tolerance_window
        self.tolerance_amount = tolerance_amount
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check that minted <= locked within tolerance window.
        """
        # Get all mints on destination chain in window
        mints = await context.get_events(
            chain=self.dest_chain,
            event_type=EventType.MINT,
            bridge_id=self.bridge_id,
            window=self.tolerance_window
        )
        
        # Get all locks on source chain in window
        locks = await context.get_events(
            chain=self.source_chain,
            event_type=EventType.LOCK,
            bridge_id=self.bridge_id,
            window=self.tolerance_window
        )
        
        total_minted = sum(e.amount for e in mints)
        total_locked = sum(e.amount for e in locks)
        
        # Also check cumulative state
        state = context.get_bridge_state(self.bridge_id)
        cumulative_minted = state.get("minted", Decimal("0"))
        cumulative_locked = state.get("locked", Decimal("0"))
        
        # Calculate imbalances
        window_imbalance = total_minted - total_locked
        cumulative_imbalance = cumulative_minted - cumulative_locked
        
        # Check for violation (either window or cumulative)
        violated = False
        imbalance = Decimal("0")
        
        if window_imbalance > self.tolerance_amount:
            violated = True
            imbalance = window_imbalance
        elif cumulative_imbalance > self.tolerance_amount:
            violated = True
            imbalance = cumulative_imbalance
        
        if violated:
            self.record_violation()
            
            # Calculate USD value (simplified)
            imbalance_usd = float(imbalance) * 1.0  # TODO: Use price oracle
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                confidence=0.95,  # High confidence for economic invariants
                violation_amount=imbalance,
                violation_amount_usd=imbalance_usd,
                chain_id=self.dest_chain,
                bridge_id=self.bridge_id,
                evidence={
                    "mints": [e.to_dict() for e in mints[-10:]],  # Last 10 mints
                    "locks": [e.to_dict() for e in locks[-10:]],  # Last 10 locks
                    "total_minted": str(total_minted),
                    "total_locked": str(total_locked),
                    "window_imbalance": str(window_imbalance),
                    "cumulative_minted": str(cumulative_minted),
                    "cumulative_locked": str(cumulative_locked),
                    "cumulative_imbalance": str(cumulative_imbalance),
                },
                related_event_ids=[e.event_id for e in mints + locks],
                description=f"Detected {imbalance} tokens minted without corresponding lock"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            severity=Severity.INFO,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("UNBACKED_MINT")
class UnbackedMintInvariant(Invariant):
    """
    Detects individual mints without corresponding lock events.
    
    More granular than MintLockParity - checks each mint has a lock.
    
    INVARIANT: ∀ mint, ∃ lock where lock.message_hash == mint.message_hash
    """
    
    description = "Every mint must have a corresponding lock event with matching message hash"
    invariant_type = InvariantType.ECONOMIC
    severity = Severity.CRITICAL
    
    def __init__(
        self,
        bridge_id: str,
        source_chain: str,
        dest_chain: str,
        message_verification_window: timedelta = timedelta(minutes=30)
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.source_chain = source_chain
        self.dest_chain = dest_chain
        self.message_verification_window = message_verification_window
        
        # Track verified messages
        self._verified_messages: set = set()
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check each recent mint has a corresponding lock.
        """
        # Get recent mints
        mints = await context.get_events(
            chain=self.dest_chain,
            event_type=EventType.MINT,
            bridge_id=self.bridge_id,
            window=timedelta(minutes=5)  # Check very recent mints
        )
        
        unbacked_mints = []
        
        for mint in mints:
            if not mint.message_hash:
                # Mint without message hash is suspicious
                unbacked_mints.append(mint)
                continue
            
            if mint.message_hash in self._verified_messages:
                continue
            
            # Look for corresponding lock
            lock = await context.find_event(
                event_type=EventType.LOCK,
                message_hash=mint.message_hash,
                before=mint.block_timestamp
            )
            
            if lock:
                # Verify amounts match
                if lock.amount == mint.amount:
                    self._verified_messages.add(mint.message_hash)
                else:
                    # Amount mismatch
                    unbacked_mints.append(mint)
            else:
                # No lock found - check if it exists anywhere
                pending = context.get_pending_message(mint.message_hash)
                if not pending:
                    unbacked_mints.append(mint)
        
        # Limit cache size
        if len(self._verified_messages) > 10000:
            self._verified_messages = set(list(self._verified_messages)[-5000:])
        
        if unbacked_mints:
            self.record_violation()
            
            total_unbacked = sum(m.amount for m in unbacked_mints)
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                confidence=0.90,
                violation_amount=total_unbacked,
                violation_amount_usd=float(total_unbacked),  # TODO: Price oracle
                chain_id=self.dest_chain,
                bridge_id=self.bridge_id,
                evidence={
                    "unbacked_mints": [m.to_dict() for m in unbacked_mints],
                    "count": len(unbacked_mints),
                    "total_amount": str(total_unbacked),
                },
                related_event_ids=[m.event_id for m in unbacked_mints],
                description=f"Detected {len(unbacked_mints)} mints without corresponding lock events"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("BURN_UNLOCK_PARITY")
class BurnUnlockParityInvariant(Invariant):
    """
    Tokens unlocked on source must not exceed tokens burned on destination.
    
    INVARIANT: Σ(unlocked_on_source) ≤ Σ(burned_on_dest)
    
    Prevents draining of bridge reserves without proper burns.
    """
    
    description = "Tokens unlocked on source chain must not exceed tokens burned on destination"
    invariant_type = InvariantType.ECONOMIC
    severity = Severity.CRITICAL
    
    def __init__(
        self,
        bridge_id: str,
        source_chain: str,
        dest_chain: str,
        tolerance_window: timedelta = timedelta(minutes=10)
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.source_chain = source_chain
        self.dest_chain = dest_chain
        self.tolerance_window = tolerance_window
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check that unlocked <= burned.
        """
        # Get unlocks on source chain
        unlocks = await context.get_events(
            chain=self.source_chain,
            event_type=EventType.UNLOCK,
            bridge_id=self.bridge_id,
            window=self.tolerance_window
        )
        
        # Get burns on destination chain
        burns = await context.get_events(
            chain=self.dest_chain,
            event_type=EventType.BURN,
            bridge_id=self.bridge_id,
            window=self.tolerance_window
        )
        
        total_unlocked = sum(e.amount for e in unlocks)
        total_burned = sum(e.amount for e in burns)
        
        imbalance = total_unlocked - total_burned
        
        if imbalance > Decimal("0.01"):  # Small tolerance
            self.record_violation()
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                violation_amount=imbalance,
                chain_id=self.source_chain,
                bridge_id=self.bridge_id,
                evidence={
                    "unlocks": [e.to_dict() for e in unlocks[-10:]],
                    "burns": [e.to_dict() for e in burns[-10:]],
                    "total_unlocked": str(total_unlocked),
                    "total_burned": str(total_burned),
                    "imbalance": str(imbalance),
                },
                description=f"Detected {imbalance} tokens unlocked without corresponding burn"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("TOTAL_SUPPLY_INVARIANT")
class TotalSupplyInvariant(Invariant):
    """
    Total supply of bridged tokens should equal locked tokens.
    
    INVARIANT: total_supply_dest == locked_source - unlocked_source
    
    Catches any supply inflation attacks.
    """
    
    description = "Total supply of bridged tokens must equal net locked tokens"
    invariant_type = InvariantType.ECONOMIC
    severity = Severity.CRITICAL
    cooldown_seconds = 300  # Check every 5 minutes
    
    def __init__(
        self,
        bridge_id: str,
        source_chain: str,
        dest_chain: str,
        tolerance_percent: float = 0.001  # 0.1% tolerance
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.source_chain = source_chain
        self.dest_chain = dest_chain
        self.tolerance_percent = tolerance_percent
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check total supply matches locked balance.
        """
        state = context.get_bridge_state(self.bridge_id)
        
        # Net locked = locked - unlocked
        net_locked = state.get("locked", Decimal("0")) - state.get("unlocked", Decimal("0"))
        
        # Total supply = minted - burned
        total_supply = state.get("minted", Decimal("0")) - state.get("burned", Decimal("0"))
        
        if net_locked == 0:
            return InvariantResult(
                violated=False,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                bridge_id=self.bridge_id
            )
        
        # Calculate deviation
        deviation = abs(total_supply - net_locked)
        deviation_percent = float(deviation / net_locked) if net_locked > 0 else 0
        
        if deviation_percent > self.tolerance_percent:
            self.record_violation()
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                violation_amount=deviation,
                bridge_id=self.bridge_id,
                evidence={
                    "net_locked": str(net_locked),
                    "total_supply": str(total_supply),
                    "deviation": str(deviation),
                    "deviation_percent": deviation_percent * 100,
                },
                description=f"Total supply deviates from locked balance by {deviation_percent:.2%}"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )

