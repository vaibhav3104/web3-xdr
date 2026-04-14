"""
MEV (Maximal Extractable Value) detection invariants.

Detects sandwich attacks, frontrunning, backrunning, and JIT liquidity patterns
by analyzing transaction ordering within blocks and cross-block patterns.
"""

from datetime import timedelta
from decimal import Decimal
from typing import Dict, List, Optional
from collections import defaultdict
import structlog

from .base import Invariant, InvariantContext, InvariantRegistry
from ..models.events import EventType, SecurityEvent, Severity
from ..models.invariants import InvariantResult, InvariantType

logger = structlog.get_logger()


@InvariantRegistry.register("MEV_SANDWICH_ATTACK")
class SandwichAttackDetector(Invariant):
    """
    Detects sandwich attacks: frontrun -> victim swap -> backrun in same block.

    Pattern:
    1. Attacker buys token X (frontrun) -- raises price
    2. Victim swaps token X at inflated price
    3. Attacker sells token X (backrun) -- profits from price impact

    All three transactions appear in the same block, often with the attacker's
    transactions having higher/lower gas to ensure ordering.

    INVARIANT: No single block should contain a buy-victim-sell pattern from the
    same attacker address targeting the same contract.
    """

    description = "No sandwich attack pattern (frontrun-victim-backrun) in a single block"
    invariant_type = InvariantType.ECONOMIC
    severity = Severity.HIGH

    def __init__(self):
        super().__init__()
        self._detected_sandwiches: set = set()  # Dedup by block+chain

    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """Check recent blocks for sandwich attack patterns."""
        # Get recent swap/transfer events
        events = await context.get_events(
            event_type=EventType.SWAP,
            window=timedelta(minutes=10),
        )
        # Also include transfers and bridge deposits as potential sandwich targets
        transfers = await context.get_events(
            event_type=EventType.TRANSFER,
            window=timedelta(minutes=10),
        )
        events.extend(transfers)

        if len(events) < 3:
            return InvariantResult(
                violated=False,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
            )

        # Group by (chain, block)
        block_events: Dict[str, Dict[int, List[SecurityEvent]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for evt in events:
            block_events[evt.chain_id][evt.block_number].append(evt)

        # Search each block for the sandwich pattern
        for chain, blocks in block_events.items():
            for block_num, block_txs in blocks.items():
                if len(block_txs) < 3:
                    continue

                dedup_key = f"{chain}:{block_num}"
                if dedup_key in self._detected_sandwiches:
                    continue

                sandwich = self._find_sandwich_pattern(block_txs)
                if not sandwich:
                    continue

                self._detected_sandwiches.add(dedup_key)
                self.record_violation()

                frontrun, victim, backrun = sandwich
                profit_estimate = abs(
                    float(backrun.amount_usd or 0) - float(frontrun.amount_usd or 0)
                )

                return InvariantResult(
                    violated=True,
                    invariant_name=self.name,
                    invariant_type=self.invariant_type,
                    severity=Severity.HIGH if profit_estimate > 10000 else Severity.MEDIUM,
                    confidence=0.85,
                    violation_amount=Decimal(str(profit_estimate)),
                    violation_amount_usd=profit_estimate,
                    chain_id=chain,
                    description=(
                        f"Sandwich attack detected in block {block_num}: "
                        f"frontrun->victim->backrun pattern. "
                        f"Estimated profit: ${profit_estimate:,.2f}"
                    ),
                    related_event_ids=[
                        frontrun.event_id,
                        victim.event_id,
                        backrun.event_id,
                    ],
                    evidence={
                        "attack_type": "sandwich",
                        "block_number": block_num,
                        "frontrun_tx": frontrun.tx_hash,
                        "victim_tx": victim.tx_hash,
                        "backrun_tx": backrun.tx_hash,
                        "frontrun_address": frontrun.source_address,
                        "victim_address": victim.source_address,
                        "estimated_profit_usd": profit_estimate,
                        "frontrun_amount_usd": float(frontrun.amount_usd or 0),
                        "backrun_amount_usd": float(backrun.amount_usd or 0),
                    },
                )

        # Prune old dedup entries
        self._prune_dedup(block_events)

        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
        )

    def _find_sandwich_pattern(
        self, block_txs: List[SecurityEvent]
    ) -> Optional[tuple]:
        """Look for frontrun-victim-backrun pattern in a block's transactions."""
        # Group by source address
        by_sender: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for tx in block_txs:
            addr = (tx.source_address or "").lower()
            by_sender[addr].append(tx)

        # Find addresses with 2+ transactions (potential attacker)
        for addr, txs in by_sender.items():
            if len(txs) < 2 or not addr:
                continue

            # Look for buy-then-sell pattern (same-asset transactions)
            for i, potential_front in enumerate(txs):
                for j, potential_back in enumerate(txs):
                    if i >= j:
                        continue

                    # Find a different-sender tx (the victim)
                    other_txs = [
                        t
                        for t in block_txs
                        if (t.source_address or "").lower() != addr
                    ]
                    for victim_tx in other_txs:
                        # Same contract interaction suggests sandwich
                        if (
                            potential_front.contract_address
                            and potential_front.contract_address
                            == potential_back.contract_address
                            == victim_tx.contract_address
                        ):
                            return (potential_front, victim_tx, potential_back)

                        # Or amounts suggest profitable wrapping
                        front_amt = float(potential_front.amount_usd or 0)
                        back_amt = float(potential_back.amount_usd or 0)
                        if front_amt > 0 and back_amt > front_amt:
                            return (potential_front, victim_tx, potential_back)

        return None

    def _prune_dedup(
        self, block_events: Dict[str, Dict[int, List[SecurityEvent]]]
    ):
        """Remove stale dedup entries for chains/blocks no longer in view."""
        active_keys = set()
        for chain, blocks in block_events.items():
            for block_num in blocks:
                active_keys.add(f"{chain}:{block_num}")
        stale = self._detected_sandwiches - active_keys
        self._detected_sandwiches -= stale


@InvariantRegistry.register("MEV_FRONTRUNNING")
class FrontrunningDetector(Invariant):
    """
    Detects frontrunning: someone copies a pending transaction with higher gas.

    Pattern:
    - Two similar transactions to the same contract in the same block
    - From different senders with the same event type
    - The higher-gas transaction executes first (position ordering)

    INVARIANT: A block should not contain duplicate-intent transactions from
    different senders targeting the same contract and event type.
    """

    description = "No duplicate-intent transactions from different senders in the same block"
    invariant_type = InvariantType.TEMPORAL
    severity = Severity.MEDIUM

    def __init__(self):
        super().__init__()
        self._detected: set = set()

    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """Check recent blocks for frontrunning patterns."""
        events = await context.get_events(window=timedelta(minutes=10))

        if len(events) < 2:
            return InvariantResult(
                violated=False,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
            )

        # Group by (chain, block)
        block_events: Dict[str, Dict[int, List[SecurityEvent]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for evt in events:
            block_events[evt.chain_id][evt.block_number].append(evt)

        for chain, blocks in block_events.items():
            for block_num, block_txs in blocks.items():
                if len(block_txs) < 2:
                    continue

                dedup_key = f"{chain}:{block_num}:front"
                if dedup_key in self._detected:
                    continue

                # Group by contract
                by_contract: Dict[str, List[SecurityEvent]] = defaultdict(list)
                for tx in block_txs:
                    if tx.contract_address:
                        by_contract[tx.contract_address.lower()].append(tx)

                for contract, contract_txs in by_contract.items():
                    if len(contract_txs) < 2:
                        continue

                    # Group by event type
                    type_groups: Dict[str, List[SecurityEvent]] = defaultdict(list)
                    for tx in contract_txs:
                        et = (
                            tx.event_type.value
                            if hasattr(tx.event_type, "value")
                            else str(tx.event_type)
                        )
                        type_groups[et].append(tx)

                    for event_type, same_type_txs in type_groups.items():
                        if len(same_type_txs) < 2:
                            continue

                        senders = set(
                            (tx.source_address or "").lower()
                            for tx in same_type_txs
                        )
                        if len(senders) < 2:
                            continue

                        self._detected.add(dedup_key)
                        self.record_violation()

                        amounts = [
                            float(tx.amount_usd or 0) for tx in same_type_txs
                        ]
                        max_amount = max(amounts) if amounts else 0

                        return InvariantResult(
                            violated=True,
                            invariant_name=self.name,
                            invariant_type=self.invariant_type,
                            severity=(
                                Severity.HIGH
                                if max_amount >= 50000
                                else Severity.MEDIUM
                            ),
                            confidence=0.7,
                            violation_amount=Decimal(str(max_amount)),
                            violation_amount_usd=max_amount,
                            chain_id=chain,
                            description=(
                                f"Potential frontrunning in block {block_num}: "
                                f"{len(same_type_txs)} similar {event_type} transactions "
                                f"to {contract[:10]}... from {len(senders)} different senders"
                            ),
                            related_event_ids=[
                                tx.event_id for tx in same_type_txs
                            ],
                            evidence={
                                "attack_type": "frontrunning",
                                "block_number": block_num,
                                "contract": contract,
                                "event_type": event_type,
                                "tx_count": len(same_type_txs),
                                "unique_senders": len(senders),
                                "tx_hashes": [
                                    tx.tx_hash for tx in same_type_txs
                                ],
                            },
                        )

        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
        )


@InvariantRegistry.register("MEV_BACKRUNNING")
class BackrunningDetector(Invariant):
    """
    Detects backrunning: transactions immediately following oracle updates or
    large trades.

    Pattern:
    - Large swap or price oracle update occurs
    - Immediately followed by arbitrage transactions exploiting the new price
    - Same contract, within 0-2 blocks

    INVARIANT: Transactions on the same contract should not consistently follow
    large trades within 1-2 blocks.
    """

    description = "No arbitrage transactions immediately following large trades on same contract"
    invariant_type = InvariantType.TEMPORAL
    severity = Severity.MEDIUM

    def __init__(self, large_trade_threshold_usd: float = 100000):
        super().__init__()
        self.large_trade_threshold = large_trade_threshold_usd

    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """Check for backrunning patterns in recent events."""
        events = await context.get_events(window=timedelta(minutes=10))

        if len(events) < 2:
            return InvariantResult(
                violated=False,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
            )

        # Split into large trades and regular transactions
        large_trades: List[SecurityEvent] = []
        regular_txs: List[SecurityEvent] = []

        for evt in events:
            amount = float(evt.amount_usd or 0)
            if amount >= self.large_trade_threshold:
                large_trades.append(evt)
            else:
                regular_txs.append(evt)

        # Check if any regular tx follows a large trade on the same contract
        for large_trade in large_trades:
            for tx in regular_txs:
                if tx.chain_id != large_trade.chain_id:
                    continue

                block_diff = tx.block_number - large_trade.block_number
                if not (0 <= block_diff <= 2):
                    continue

                # Same contract suggests arbitrage
                if (
                    tx.contract_address
                    and large_trade.contract_address
                    and tx.contract_address.lower()
                    == large_trade.contract_address.lower()
                ):
                    self.record_violation()
                    amount = float(tx.amount_usd or 0)

                    return InvariantResult(
                        violated=True,
                        invariant_name=self.name,
                        invariant_type=self.invariant_type,
                        severity=Severity.MEDIUM,
                        confidence=0.65,
                        violation_amount=Decimal(str(amount)),
                        violation_amount_usd=amount,
                        chain_id=tx.chain_id,
                        description=(
                            f"Potential backrunning: transaction in block "
                            f"{tx.block_number} follows large "
                            f"${float(large_trade.amount_usd or 0):,.0f} trade "
                            f"in block {large_trade.block_number} on same contract"
                        ),
                        related_event_ids=[
                            large_trade.event_id,
                            tx.event_id,
                        ],
                        evidence={
                            "attack_type": "backrunning",
                            "trigger_tx": large_trade.tx_hash,
                            "trigger_amount_usd": float(
                                large_trade.amount_usd or 0
                            ),
                            "backrun_tx": tx.tx_hash,
                            "backrun_amount_usd": amount,
                            "block_distance": block_diff,
                            "contract": tx.contract_address,
                        },
                    )

        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
        )


@InvariantRegistry.register("MEV_JIT_LIQUIDITY")
class JITLiquidityDetector(Invariant):
    """
    Detects Just-In-Time (JIT) liquidity provision.

    Pattern:
    - Add liquidity immediately before a large swap
    - Remove liquidity immediately after the swap
    - All within 1-3 blocks

    INVARIANT: No address should add and remove liquidity around a large swap
    within a narrow block window.
    """

    description = "No JIT liquidity provision around large swaps"
    invariant_type = InvariantType.ECONOMIC
    severity = Severity.MEDIUM

    def __init__(self):
        super().__init__()
        self._detected: set = set()

    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """Check for JIT liquidity patterns in recent events."""
        # Gather liquidity-related event types
        all_events: List[SecurityEvent] = []
        for etype in (
            EventType.SWAP,
            EventType.TRANSFER,
            EventType.MINT,
            EventType.BURN,
            EventType.LOCK,
            EventType.UNLOCK,
            EventType.LIQUIDITY_ADD,
            EventType.LIQUIDITY_REMOVE,
        ):
            found = await context.get_events(
                event_type=etype,
                window=timedelta(minutes=10),
            )
            all_events.extend(found)

        if len(all_events) < 3:
            return InvariantResult(
                violated=False,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
            )

        # Sort by block number for pattern analysis
        all_events.sort(key=lambda e: (e.chain_id, e.block_number))

        # Group by chain
        by_chain: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for evt in all_events:
            by_chain[evt.chain_id].append(evt)

        for chain, chain_events in by_chain.items():
            # Group by sender
            by_sender: Dict[str, List[SecurityEvent]] = defaultdict(list)
            for evt in chain_events:
                addr = (evt.source_address or "").lower()
                if addr:
                    by_sender[addr].append(evt)

            for addr, sender_txs in by_sender.items():
                if len(sender_txs) < 2:
                    continue

                types = set()
                for evt in sender_txs:
                    et = (
                        evt.event_type.value
                        if hasattr(evt.event_type, "value")
                        else str(evt.event_type)
                    ).upper()
                    types.add(et)

                add_types = {"MINT", "LOCK", "LIQUIDITY_ADD"}
                remove_types = {"BURN", "UNLOCK", "LIQUIDITY_REMOVE"}

                has_add = bool(types & add_types)
                has_remove = bool(types & remove_types)

                if not (has_add and has_remove):
                    continue

                # Check block span is narrow (1-3 blocks)
                blocks = [e.block_number for e in sender_txs]
                block_span = max(blocks) - min(blocks)
                if block_span > 3:
                    continue

                dedup_key = f"{chain}:{min(blocks)}:jit:{addr[:16]}"
                if dedup_key in self._detected:
                    continue

                # Check if there's a large swap from another user in this range
                other_swaps = [
                    e
                    for e in chain_events
                    if (e.source_address or "").lower() != addr
                    and float(e.amount_usd or 0) > 10000
                    and min(blocks) <= e.block_number <= max(blocks)
                ]

                if not other_swaps:
                    continue

                self._detected.add(dedup_key)
                self.record_violation()

                total_value = sum(float(e.amount_usd or 0) for e in sender_txs)

                return InvariantResult(
                    violated=True,
                    invariant_name=self.name,
                    invariant_type=self.invariant_type,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    violation_amount=Decimal(str(total_value)),
                    violation_amount_usd=total_value,
                    chain_id=chain,
                    description=(
                        f"Potential JIT liquidity: address {addr[:10]}... "
                        f"added and removed liquidity around a "
                        f"${float(other_swaps[0].amount_usd or 0):,.0f} swap "
                        f"within {block_span + 1} blocks"
                    ),
                    related_event_ids=[
                        e.event_id for e in sender_txs + other_swaps[:1]
                    ],
                    evidence={
                        "attack_type": "jit_liquidity",
                        "provider_address": addr,
                        "provider_tx_count": len(sender_txs),
                        "swap_tx": other_swaps[0].tx_hash,
                        "swap_amount_usd": float(
                            other_swaps[0].amount_usd or 0
                        ),
                        "block_span": block_span,
                    },
                )

        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
        )


# Registry of MEV invariant classes for bulk registration
MEV_INVARIANTS = [
    SandwichAttackDetector,
    FrontrunningDetector,
    BackrunningDetector,
    JITLiquidityDetector,
]
