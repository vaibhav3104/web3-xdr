"""
Protocol-Specific Bridge Invariants
===================================

Phase 3: Invariants that are protocol-aware and use bridge adapters.
"""

from decimal import Decimal
from typing import Dict
import structlog

from .base import Invariant, InvariantContext, InvariantType
from ..models.events import SecurityEvent, EventStatus
from ..models.invariants import InvariantResult, ViolationSeverity
from ..bridges.registry import BridgeAdapterRegistry
from ..bridges.adapters.base import BridgeEventSemantic

logger = structlog.get_logger(__name__)


class MintBurnInvariant(Invariant):
    """
    Mint/Burn Parity Invariant (for Wormhole-style bridges).

    Applies ONLY to protocols that use canonical mint/burn:
    - Lock on source → Mint on dest
    - Burn on dest → Unlock on source

    Checks: Mint Amount <= Lock Amount (with tolerance)
    """

    def __init__(
        self,
        protocol_id: str,
        tolerance_bps: int = 50,
        max_latency_seconds: int = 900
    ):
        super().__init__(
            name=f"MINT_BURN_PARITY_{protocol_id}",
            invariant_type=InvariantType.ECONOMIC,
            description=f"Mint/burn parity for {protocol_id}"
        )
        self.protocol_id = protocol_id
        self.tolerance_bps = tolerance_bps
        self.max_latency_seconds = max_latency_seconds
        self.adapter_registry = BridgeAdapterRegistry()
    
    def should_check(self) -> bool:
        """Check if invariant should be evaluated."""
        return True
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Evaluate mint/burn parity.
        
        Only applies to events classified as LOCK/MINT by adapters.
        """
        # Get adapter
        adapter = self.adapter_registry.get_adapter_by_protocol(self.protocol_id)
        if not adapter:
            return InvariantResult(
                invariant_name=self.name,
                violated=False,
                confidence=0.0,
                message="Adapter not found"
            )
        
        # Get recent events for this protocol
        recent_events = [
            e for e in context.get_recent_events(minutes=30)
            if e.status == EventStatus.CONFIRMED
            and adapter.identify_protocol(e)
        ]
        
        if len(recent_events) < 2:
            return InvariantResult(
                invariant_name=self.name,
                violated=False,
                confidence=0.0,
                message="Insufficient events"
            )
        
        # Group by correlation key
        lock_events: Dict[str, SecurityEvent] = {}
        mint_events: Dict[str, SecurityEvent] = {}
        
        for event in recent_events:
            semantic = adapter.classify_event(event)
            if not semantic:
                continue
            
            corr_key = adapter.extract_correlation_key(event)
            if not corr_key:
                continue
            
            key_str = corr_key.key
            
            if semantic == BridgeEventSemantic.LOCK:
                lock_events[key_str] = event
            elif semantic == BridgeEventSemantic.MINT:
                mint_events[key_str] = event
        
        # Check for violations
        violations = []
        
        # Check: MINT without LOCK
        for key, mint_event in mint_events.items():
            if key not in lock_events:
                violations.append({
                    "type": "MINT_WITHOUT_LOCK",
                    "mint_event": mint_event.event_id,
                    "correlation_key": key,
                    "amount": mint_event.amount
                })
        
        # Check: Amount mismatch
        for key in set(lock_events.keys()) & set(mint_events.keys()):
            lock_event = lock_events[key]
            mint_event = mint_events[key]
            
            expected = adapter.expected_amounts(lock_event, mint_event)
            if not expected:
                continue
            
            lock_amount = lock_event.amount
            mint_amount = mint_event.amount
            
            # Calculate tolerance
            tolerance = lock_amount * Decimal(self.tolerance_bps) / Decimal(10000)
            max_allowed = lock_amount - expected.fee_amount + tolerance
            
            if mint_amount > max_allowed:
                violations.append({
                    "type": "AMOUNT_MISMATCH",
                    "lock_event": lock_event.event_id,
                    "mint_event": mint_event.event_id,
                    "lock_amount": lock_amount,
                    "mint_amount": mint_amount,
                    "expected_max": max_allowed,
                    "deviation": mint_amount - max_allowed
                })
        
        if violations:
            return InvariantResult(
                invariant_name=self.name,
                violated=True,
                severity=ViolationSeverity.CRITICAL,
                confidence=0.9,
                message=f"Found {len(violations)} mint/burn violations",
                details={"violations": violations}
            )
        
        return InvariantResult(
            invariant_name=self.name,
            violated=False,
            confidence=0.8
        )


class LiquidityInvariant(Invariant):
    """
    Liquidity Bridge Parity (for Stargate/Across/Hop).

    Applies ONLY to liquidity bridges:
    - Deposit → Fill (with fees)
    - NOT mint/burn - uses existing pool liquidity

    Checks: Fill Amount <= Deposit Amount * (1 - MaxFee) + tolerance
    """

    def __init__(
        self,
        protocol_id: str,
        tolerance_bps: int = 50,
        max_latency_seconds: int = 300
    ):
        super().__init__(
            name=f"LIQUIDITY_PARITY_{protocol_id}",
            invariant_type=InvariantType.ECONOMIC,
            description=f"Liquidity parity for {protocol_id}"
        )
        self.protocol_id = protocol_id
        self.tolerance_bps = tolerance_bps
        self.max_latency_seconds = max_latency_seconds
        self.adapter_registry = BridgeAdapterRegistry()
    
    def should_check(self) -> bool:
        return True
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """Evaluate liquidity bridge parity."""
        adapter = self.adapter_registry.get_adapter_by_protocol(self.protocol_id)
        if not adapter:
            return InvariantResult(
                invariant_name=self.name,
                violated=False,
                confidence=0.0
            )
        
        # Get recent events
        recent_events = [
            e for e in context.get_recent_events(minutes=30)
            if e.status == EventStatus.CONFIRMED
            and adapter.identify_protocol(e)
        ]
        
        # Group by correlation
        deposit_events: Dict[str, SecurityEvent] = {}
        fill_events: Dict[str, SecurityEvent] = {}
        
        for event in recent_events:
            semantic = adapter.classify_event(event)
            if not semantic:
                continue
            
            corr_key = adapter.extract_correlation_key(event)
            if not corr_key:
                continue
            
            key_str = corr_key.key
            
            if semantic == BridgeEventSemantic.DEPOSIT:
                deposit_events[key_str] = event
            elif semantic in [BridgeEventSemantic.FILL, BridgeEventSemantic.WITHDRAW]:
                fill_events[key_str] = event
        
        violations = []
        
        # Check: FILL without DEPOSIT
        for key, fill_event in fill_events.items():
            if key not in deposit_events:
                violations.append({
                    "type": "FILL_WITHOUT_DEPOSIT",
                    "fill_event": fill_event.event_id,
                    "correlation_key": key
                })
        
        # Check: Amount mismatch (with fee tolerance)
        for key in set(deposit_events.keys()) & set(fill_events.keys()):
            deposit_event = deposit_events[key]
            fill_event = fill_events[key]
            
            expected = adapter.expected_amounts(deposit_event, fill_event)
            if not expected:
                continue
            
            deposit_amount = deposit_event.amount
            fill_amount = fill_event.amount
            
            # Expected: deposit - fee - tolerance
            max_fee = deposit_amount * Decimal(expected.fee_bps) / Decimal(10000)
            tolerance = deposit_amount * Decimal(self.tolerance_bps) / Decimal(10000)
            min_expected = deposit_amount - max_fee - tolerance
            
            if fill_amount < min_expected:
                violations.append({
                    "type": "FILL_AMOUNT_TOO_LOW",
                    "deposit_event": deposit_event.event_id,
                    "fill_event": fill_event.event_id,
                    "deposit_amount": deposit_amount,
                    "fill_amount": fill_amount,
                    "min_expected": min_expected,
                    "deviation": min_expected - fill_amount
                })
        
        if violations:
            return InvariantResult(
                invariant_name=self.name,
                violated=True,
                severity=ViolationSeverity.HIGH,
                confidence=0.85,
                message=f"Found {len(violations)} liquidity violations",
                details={"violations": violations}
            )
        
        return InvariantResult(
            invariant_name=self.name,
            violated=False,
            confidence=0.8
        )


class SequenceInvariant(Invariant):
    """
    Sequence Continuity Invariant (for messaging protocols).

    Checks for skipped nonces/sequences in messaging protocols.
    """

    def __init__(self, protocol_id: str):
        super().__init__(
            name=f"SEQUENCE_CONTINUITY_{protocol_id}",
            invariant_type=InvariantType.TEMPORAL,
            description=f"Sequence continuity for {protocol_id}"
        )
        self.protocol_id = protocol_id
        self.adapter_registry = BridgeAdapterRegistry()
        self._last_sequences: Dict[str, int] = {}  # chain -> last sequence
    
    def should_check(self) -> bool:
        return True
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """Check for sequence gaps."""
        adapter = self.adapter_registry.get_adapter_by_protocol(self.protocol_id)
        if not adapter:
            return InvariantResult(
                invariant_name=self.name,
                violated=False,
                confidence=0.0
            )
        
        recent_events = [
            e for e in context.get_recent_events(minutes=60)
            if e.status == EventStatus.CONFIRMED
            and adapter.identify_protocol(e)
        ]
        
        gaps = []
        
        for event in recent_events:
            corr_key = adapter.extract_correlation_key(event)
            if not corr_key:
                continue
            
            # Extract sequence from correlation key
            # Format: "chain:address:sequence" or similar
            key_parts = corr_key.key.split(":")
            if len(key_parts) < 3:
                continue
            
            try:
                sequence = int(key_parts[-1])  # Last part is sequence
                chain_key = f"{corr_key.src_chain}:{key_parts[1]}"  # chain:address
                
                if chain_key in self._last_sequences:
                    last_seq = self._last_sequences[chain_key]
                    if sequence != last_seq + 1:
                        gaps.append({
                            "chain": corr_key.src_chain,
                            "expected": last_seq + 1,
                            "actual": sequence,
                            "gap": sequence - last_seq - 1
                        })
                
                self._last_sequences[chain_key] = sequence
                
            except (ValueError, IndexError):
                continue
        
        if gaps:
            return InvariantResult(
                invariant_name=self.name,
                violated=True,
                severity=ViolationSeverity.MEDIUM,
                confidence=0.7,
                message=f"Found {len(gaps)} sequence gaps",
                details={"gaps": gaps}
            )
        
        return InvariantResult(
            invariant_name=self.name,
            violated=False,
            confidence=0.8
        )

