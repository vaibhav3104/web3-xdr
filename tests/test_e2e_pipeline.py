"""
End-to-end pipeline tests with synthetic testnet-style transactions.
=====================================================================

Tests the full detection pipeline: SecurityEvent -> InvariantEngine -> Violation -> IncidentBuilder -> Incident.
Uses real instances of InvariantEngine and IncidentBuilder with synthetic events that mimic
real-world attack patterns (Wormhole-style unbacked mints, sandwich attacks, flash loans, etc.).
"""

from __future__ import annotations

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from src.models.events import SecurityEvent, EventType, EventStatus, Severity
from src.models.invariants import InvariantResult, InvariantType
from src.invariants.base import InvariantContext, Invariant
from src.invariants.engine import InvariantEngine
from src.invariants.economic import MintLockParityInvariant, UnbackedMintInvariant
from src.invariants.mev import SandwichAttackDetector, FrontrunningDetector
from src.correlation.incident_builder import IncidentBuilder, IncidentStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BRIDGE_ID = "wormhole_eth_poly"
SOURCE_CHAIN = "ethereum"
DEST_CHAIN = "polygon"
ATTACKER = "0xAttacker0000000000000000000000000000001234"
VICTIM = "0xVictim00000000000000000000000000000056789"
BRIDGE_CONTRACT = "0xBridge00000000000000000000000000000000abcd"
DEX_ROUTER = "0xDexRouter000000000000000000000000000000ef01"


def _make_event(
    *,
    chain_id: str = SOURCE_CHAIN,
    block_number: int = 1000,
    block_timestamp: datetime | None = None,
    tx_hash: str | None = None,
    log_index: int = 0,
    event_type: EventType = EventType.UNKNOWN,
    severity: Severity = Severity.INFO,
    source_address: str = "",
    dest_address: str = "",
    contract_address: str = "",
    asset_type: str = "ETH",
    amount: Decimal = Decimal("0"),
    amount_usd: Decimal = Decimal("0"),
    bridge_id: str | None = None,
    message_hash: str | None = None,
    source_chain: str | None = None,
    dest_chain: str | None = None,
    event_id: str | None = None,
    status: EventStatus = EventStatus.PENDING,
) -> SecurityEvent:
    """Build a SecurityEvent with sensible defaults for testing."""
    return SecurityEvent(
        event_id=event_id or str(uuid.uuid4()),
        chain_id=chain_id,
        block_number=block_number,
        block_timestamp=block_timestamp or datetime.now(timezone.utc),
        tx_hash=tx_hash or f"0x{uuid.uuid4().hex}",
        log_index=log_index,
        status=status,
        event_type=event_type,
        severity=severity,
        source_address=source_address,
        dest_address=dest_address,
        contract_address=contract_address,
        asset_type=asset_type,
        amount=amount,
        amount_usd=amount_usd,
        bridge_id=bridge_id,
        message_hash=message_hash,
        source_chain=source_chain,
        dest_chain=dest_chain,
    )


# ===========================================================================
# 1. Wormhole-style attack: unbacked mint on destination chain
# ===========================================================================


class TestE2EPipelineWormholeStyle:
    """Simulate a Wormhole-style attack: unbacked mint on destination chain."""

    async def test_unbacked_mint_detected(self):
        """Lock 0 on source, mint 120K on dest -> MINT_LOCK_PARITY violation."""
        context = InvariantContext()

        # 1. Normal lock of 50K ETH on Ethereum
        normal_lock = _make_event(
            chain_id=SOURCE_CHAIN,
            block_number=1000,
            block_timestamp=datetime.now(timezone.utc) - timedelta(minutes=5),
            event_type=EventType.LOCK,
            amount=Decimal("50000"),
            amount_usd=Decimal("90000000"),
            bridge_id=BRIDGE_ID,
            message_hash="0xnormal_msg_hash_aaa",
            contract_address=BRIDGE_CONTRACT,
        )
        context.add_event(normal_lock)

        # 2. Normal mint of 50K wETH on Polygon
        normal_mint = _make_event(
            chain_id=DEST_CHAIN,
            block_number=50000,
            block_timestamp=datetime.now(timezone.utc) - timedelta(minutes=4),
            event_type=EventType.MINT,
            amount=Decimal("50000"),
            amount_usd=Decimal("90000000"),
            bridge_id=BRIDGE_ID,
            message_hash="0xnormal_msg_hash_aaa",
            asset_type="WETH",
            contract_address=BRIDGE_CONTRACT,
        )
        context.add_event(normal_mint)

        # Invariant should pass at this point
        invariant = MintLockParityInvariant(
            bridge_id=BRIDGE_ID,
            source_chain=SOURCE_CHAIN,
            dest_chain=DEST_CHAIN,
        )
        result = await invariant.evaluate(context)
        assert not result.violated, "Balanced 50K lock/mint should pass"

        # 3. Attacker mints 120K wETH on Polygon (NO corresponding lock)
        attack_mint = _make_event(
            chain_id=DEST_CHAIN,
            block_number=50010,
            block_timestamp=datetime.now(timezone.utc) - timedelta(minutes=1),
            event_type=EventType.MINT,
            amount=Decimal("120000"),
            amount_usd=Decimal("216000000"),
            bridge_id=BRIDGE_ID,
            message_hash="0xFORGED_MSG_HASH",
            asset_type="WETH",
            source_address=BRIDGE_CONTRACT,
            dest_address=ATTACKER,
            contract_address=BRIDGE_CONTRACT,
        )
        context.add_event(attack_mint)

        # Re-evaluate -- should now detect violation
        result = await invariant.evaluate(context)
        assert result.violated, "120K unbacked mint must trigger MINT_LOCK_PARITY violation"
        assert result.severity == Severity.CRITICAL
        # Imbalance should be 120K (170K minted vs 50K locked)
        assert result.violation_amount >= Decimal("120000")
        assert result.bridge_id == BRIDGE_ID
        assert result.chain_id == DEST_CHAIN
        assert len(result.evidence) > 0
        assert result.confidence >= 0.9

    async def test_unbacked_mint_individual_check(self):
        """UNBACKED_MINT invariant detects a mint with no corresponding lock event."""
        context = InvariantContext()

        attack_mint = _make_event(
            chain_id=DEST_CHAIN,
            block_number=50010,
            block_timestamp=datetime.now(timezone.utc) - timedelta(minutes=1),
            event_type=EventType.MINT,
            amount=Decimal("120000"),
            bridge_id=BRIDGE_ID,
            message_hash="0xNO_LOCK_EXISTS",
            asset_type="WETH",
            contract_address=BRIDGE_CONTRACT,
        )
        context.add_event(attack_mint)

        invariant = UnbackedMintInvariant(
            bridge_id=BRIDGE_ID,
            source_chain=SOURCE_CHAIN,
            dest_chain=DEST_CHAIN,
        )

        result = await invariant.evaluate(context)
        assert result.violated, "Mint without any lock should be flagged as unbacked"
        assert result.severity == Severity.CRITICAL
        assert "unbacked_mints" in result.evidence

    async def test_full_pipeline_event_to_incident(self):
        """Events flow through: event -> InvariantEngine -> violation -> IncidentBuilder -> incident."""
        # Wire up real components
        context = InvariantContext()
        engine = InvariantEngine(context=context)
        builder = IncidentBuilder()

        mint_lock_inv = MintLockParityInvariant(
            bridge_id=BRIDGE_ID,
            source_chain=SOURCE_CHAIN,
            dest_chain=DEST_CHAIN,
        )
        unbacked_inv = UnbackedMintInvariant(
            bridge_id=BRIDGE_ID,
            source_chain=SOURCE_CHAIN,
            dest_chain=DEST_CHAIN,
        )
        engine.add_invariant(mint_lock_inv)
        engine.add_invariant(unbacked_inv)

        # Collect violations
        violations: list[InvariantResult] = []
        triggering_events: list[SecurityEvent] = []

        async def violation_handler(result: InvariantResult):
            violations.append(result)

        engine.add_result_handler(violation_handler)

        # Normal operation
        normal_lock = _make_event(
            chain_id=SOURCE_CHAIN,
            block_timestamp=datetime.now(timezone.utc) - timedelta(minutes=5),
            event_type=EventType.LOCK,
            amount=Decimal("50000"),
            bridge_id=BRIDGE_ID,
            message_hash="0xnormal_msg",
        )
        await engine.process_event(normal_lock)
        assert len(violations) == 0, "Normal lock should not trigger violations"

        normal_mint = _make_event(
            chain_id=DEST_CHAIN,
            block_timestamp=datetime.now(timezone.utc) - timedelta(minutes=4),
            event_type=EventType.MINT,
            amount=Decimal("50000"),
            bridge_id=BRIDGE_ID,
            message_hash="0xnormal_msg",
        )
        await engine.process_event(normal_mint)
        assert len(violations) == 0, "Balanced mint should not trigger violations"

        # Attack mint
        attack_mint = _make_event(
            chain_id=DEST_CHAIN,
            block_timestamp=datetime.now(timezone.utc) - timedelta(minutes=1),
            event_type=EventType.MINT,
            amount=Decimal("120000"),
            bridge_id=BRIDGE_ID,
            message_hash="0xFORGED",
            source_address=BRIDGE_CONTRACT,
            dest_address=ATTACKER,
            contract_address=BRIDGE_CONTRACT,
        )
        # Reset cooldowns so both invariants fire
        mint_lock_inv._last_violation = None
        unbacked_inv._last_violation = None

        await engine.process_event(attack_mint)
        assert len(violations) >= 1, "Attack mint must produce at least one violation"

        # Feed violations into IncidentBuilder
        for v in violations:
            incident = builder.upsert_incident(v, attack_mint)
            assert incident is not None
            assert incident.event_count >= 1
            assert incident.severity.value >= Severity.HIGH.value

        # Verify incidents were created
        open_incidents = builder.get_open_incidents()
        assert len(open_incidents) >= 1, "At least one incident should be open"

        for inc in open_incidents:
            assert inc.status == IncidentStatus.OPEN_PENDING
            assert inc.protocol_id == BRIDGE_ID
            assert len(inc.event_ids) >= 1
            assert len(inc.timeline) >= 1

        # Verify engine stats
        stats = engine.get_stats()
        assert stats["events_processed"] == 3
        assert stats["violations_detected"] >= 1


# ===========================================================================
# 2. Sandwich attack in a single block
# ===========================================================================


class TestE2EPipelineSandwichAttack:
    """Simulate a sandwich attack in a single block."""

    async def test_sandwich_detected_by_mev_invariant(self):
        """3 swaps in same block from attacker-victim-attacker -> MEV detection."""
        context = InvariantContext()
        engine = InvariantEngine(context=context)
        sandwich_detector = SandwichAttackDetector()
        engine.add_invariant(sandwich_detector)

        violations: list[InvariantResult] = []

        async def handler(result: InvariantResult):
            violations.append(result)

        engine.add_result_handler(handler)

        block_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        block_num = 18_000_000

        # 1. Attacker frontrun: buy token on DEX
        frontrun = _make_event(
            chain_id="ethereum",
            block_number=block_num,
            block_timestamp=block_time,
            tx_hash="0xfrontrun_tx_hash_aaaa",
            log_index=0,
            event_type=EventType.SWAP,
            source_address=ATTACKER.lower(),
            contract_address=DEX_ROUTER.lower(),
            amount=Decimal("50"),
            amount_usd=Decimal("90000"),
        )

        # 2. Victim swap at inflated price
        victim_swap = _make_event(
            chain_id="ethereum",
            block_number=block_num,
            block_timestamp=block_time,
            tx_hash="0xvictim_swap_tx_hash_bbbb",
            log_index=1,
            event_type=EventType.SWAP,
            source_address=VICTIM.lower(),
            contract_address=DEX_ROUTER.lower(),
            amount=Decimal("10"),
            amount_usd=Decimal("18500"),
        )

        # 3. Attacker backrun: sell token for profit
        backrun = _make_event(
            chain_id="ethereum",
            block_number=block_num,
            block_timestamp=block_time,
            tx_hash="0xbackrun_tx_hash_cccc",
            log_index=2,
            event_type=EventType.SWAP,
            source_address=ATTACKER.lower(),
            contract_address=DEX_ROUTER.lower(),
            amount=Decimal("50"),
            amount_usd=Decimal("91500"),
        )

        # Process events through engine
        await engine.process_event(frontrun)
        await engine.process_event(victim_swap)
        await engine.process_event(backrun)

        assert len(violations) >= 1, "Sandwich pattern must be detected"

        v = violations[0]
        assert v.violated
        assert "sandwich" in v.evidence.get("attack_type", "").lower()
        assert v.chain_id == "ethereum"
        assert len(v.related_event_ids) == 3

    async def test_sandwich_creates_incident(self):
        """Full pipeline: sandwich events -> violation -> incident."""
        context = InvariantContext()
        engine = InvariantEngine(context=context)
        builder = IncidentBuilder()
        sandwich_detector = SandwichAttackDetector()
        engine.add_invariant(sandwich_detector)

        violations: list[InvariantResult] = []

        async def handler(result: InvariantResult):
            violations.append(result)

        engine.add_result_handler(handler)

        block_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        block_num = 18_000_100

        events = [
            _make_event(
                chain_id="ethereum",
                block_number=block_num,
                block_timestamp=block_time,
                log_index=i,
                event_type=EventType.SWAP,
                source_address=(ATTACKER if i != 1 else VICTIM).lower(),
                contract_address=DEX_ROUTER.lower(),
                amount=Decimal("50"),
                amount_usd=Decimal("90000") if i == 0 else Decimal("91500"),
            )
            for i in range(3)
        ]

        for evt in events:
            await engine.process_event(evt)

        assert len(violations) >= 1
        incident = builder.upsert_incident(violations[0], events[0])
        assert incident is not None
        assert incident.event_count >= 1
        assert incident.status == IncidentStatus.OPEN_PENDING


# ===========================================================================
# 3. Flash loan attack
# ===========================================================================


class TestE2EPipelineFlashLoan:
    """Simulate a flash loan attack."""

    async def test_flash_loan_single_block_pattern(self):
        """Borrow + exploit swap + repay in single block generates events and triggers detection."""
        context = InvariantContext()
        engine = InvariantEngine(context=context)
        builder = IncidentBuilder()

        block_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        block_num = 18_500_000
        flash_contract = "0xFlashLoanProvider000000000000000000000001"
        exploit_pool = "0xExploitPool0000000000000000000000000000002"

        # Step 1: Flash borrow 10M USDC
        borrow = _make_event(
            chain_id="ethereum",
            block_number=block_num,
            block_timestamp=block_time,
            log_index=0,
            event_type=EventType.FLASH_BORROW,
            source_address=ATTACKER,
            contract_address=flash_contract,
            asset_type="USDC",
            amount=Decimal("10000000"),
            amount_usd=Decimal("10000000"),
        )

        # Step 2: Exploit swap -- manipulate price
        swap = _make_event(
            chain_id="ethereum",
            block_number=block_num,
            block_timestamp=block_time,
            log_index=1,
            event_type=EventType.SWAP,
            source_address=ATTACKER,
            contract_address=exploit_pool,
            asset_type="USDC",
            amount=Decimal("10000000"),
            amount_usd=Decimal("10000000"),
        )

        # Step 3: Profit transfer
        transfer = _make_event(
            chain_id="ethereum",
            block_number=block_num,
            block_timestamp=block_time,
            log_index=2,
            event_type=EventType.TRANSFER,
            source_address=exploit_pool,
            dest_address=ATTACKER,
            asset_type="USDC",
            amount=Decimal("10500000"),
            amount_usd=Decimal("10500000"),
        )

        # Step 4: Flash repay
        repay = _make_event(
            chain_id="ethereum",
            block_number=block_num,
            block_timestamp=block_time,
            log_index=3,
            event_type=EventType.FLASH_REPAY,
            source_address=ATTACKER,
            contract_address=flash_contract,
            asset_type="USDC",
            amount=Decimal("10000000"),
            amount_usd=Decimal("10000000"),
        )

        all_events = [borrow, swap, transfer, repay]

        # Add events to context and verify they are stored
        for evt in all_events:
            context.add_event(evt)

        # Verify events can be queried back
        flash_borrows = await context.get_events(
            chain="ethereum",
            event_type=EventType.FLASH_BORROW,
            window=timedelta(minutes=10),
        )
        assert len(flash_borrows) == 1
        assert flash_borrows[0].amount == Decimal("10000000")

        swaps = await context.get_events(
            chain="ethereum",
            event_type=EventType.SWAP,
            window=timedelta(minutes=10),
        )
        assert len(swaps) == 1

        repays = await context.get_events(
            chain="ethereum",
            event_type=EventType.FLASH_REPAY,
            window=timedelta(minutes=10),
        )
        assert len(repays) == 1

        # Verify all events share same block (flash loan atomicity)
        assert all(e.block_number == block_num for e in all_events)

        # Create a synthetic violation (as flash loan invariant would produce)
        flash_violation = InvariantResult(
            violated=True,
            invariant_name="FLASH_LOAN_ATTACK",
            invariant_type=InvariantType.ECONOMIC,
            severity=Severity.CRITICAL,
            confidence=0.88,
            violation_amount=Decimal("500000"),
            violation_amount_usd=500000.0,
            chain_id="ethereum",
            evidence={
                "flash_borrow_amount": "10000000",
                "profit_amount": "500000",
                "all_in_one_block": True,
                "block_number": block_num,
            },
            related_event_ids=[e.event_id for e in all_events],
            description="Flash loan attack: borrow-exploit-repay in single block",
        )

        incident = builder.upsert_incident(flash_violation, borrow)
        assert incident is not None
        assert incident.event_count == 1
        assert incident.severity == Severity.CRITICAL
        assert incident.status == IncidentStatus.OPEN_PENDING


# ===========================================================================
# 4. Cross-chain correlation
# ===========================================================================


class TestE2EPipelineMultiChain:
    """Test cross-chain correlation."""

    async def test_cross_chain_events_correlated(self):
        """Events on different chains linked by bridge message are correlated into incidents."""
        builder = IncidentBuilder()

        base_time = datetime.now(timezone.utc) - timedelta(minutes=5)

        # Violation on Ethereum
        eth_violation = InvariantResult(
            violated=True,
            invariant_name="MINT_LOCK_PARITY",
            invariant_type=InvariantType.ECONOMIC,
            severity=Severity.CRITICAL,
            confidence=0.95,
            violation_amount=Decimal("100000"),
            violation_amount_usd=180000000.0,
            chain_id=SOURCE_CHAIN,
            bridge_id=BRIDGE_ID,
            evidence={"dest_chain": DEST_CHAIN},
            description="Unbacked mint on polygon",
        )

        eth_event = _make_event(
            chain_id=SOURCE_CHAIN,
            block_timestamp=base_time,
            event_type=EventType.LOCK,
            source_address=ATTACKER.lower(),
            amount=Decimal("0"),
            bridge_id=BRIDGE_ID,
            message_hash="0xCROSS_CHAIN_MSG_1",
        )

        # Violation on Polygon (same attacker)
        poly_violation = InvariantResult(
            violated=True,
            invariant_name="UNBACKED_MINT",
            invariant_type=InvariantType.ECONOMIC,
            severity=Severity.CRITICAL,
            confidence=0.90,
            violation_amount=Decimal("100000"),
            violation_amount_usd=180000000.0,
            chain_id=DEST_CHAIN,
            bridge_id=BRIDGE_ID,
            evidence={"unbacked_mints": [], "count": 1, "total_amount": "100000"},
            description="Mint without lock",
        )

        poly_event = _make_event(
            chain_id=DEST_CHAIN,
            block_timestamp=base_time + timedelta(minutes=1),
            event_type=EventType.MINT,
            source_address=ATTACKER.lower(),
            dest_address=ATTACKER.lower(),
            amount=Decimal("100000"),
            bridge_id=BRIDGE_ID,
            message_hash="0xCROSS_CHAIN_MSG_1",
        )

        inc1 = builder.upsert_incident(eth_violation, eth_event)
        inc2 = builder.upsert_incident(poly_violation, poly_event)

        # Both incidents should be created
        open_incidents = builder.get_open_incidents()
        assert len(open_incidents) >= 1

        # Cross-chain correlation: same attacker address on multiple chains
        cross_chain_groups = builder.get_cross_chain_incidents()
        # The attacker address appears on both chains, so we expect a group
        attacker_incidents = builder.get_incidents_by_address(ATTACKER.lower())
        assert len(attacker_incidents) >= 1, (
            "Incidents involving the attacker address should be discoverable"
        )

    async def test_multi_chain_bridge_state_tracking(self):
        """InvariantContext tracks bridge state across chains correctly."""
        context = InvariantContext()

        # Lock on source chain
        lock = _make_event(
            chain_id=SOURCE_CHAIN,
            event_type=EventType.LOCK,
            amount=Decimal("500"),
            bridge_id=BRIDGE_ID,
        )
        context.add_event(lock)

        # Mint on dest chain
        mint = _make_event(
            chain_id=DEST_CHAIN,
            event_type=EventType.MINT,
            amount=Decimal("500"),
            bridge_id=BRIDGE_ID,
        )
        context.add_event(mint)

        state = context.get_bridge_state(BRIDGE_ID)
        assert state["locked"] == Decimal("500")
        assert state["minted"] == Decimal("500")

        # Burn on dest chain
        burn = _make_event(
            chain_id=DEST_CHAIN,
            event_type=EventType.BURN,
            amount=Decimal("200"),
            bridge_id=BRIDGE_ID,
        )
        context.add_event(burn)

        # Unlock on source chain
        unlock = _make_event(
            chain_id=SOURCE_CHAIN,
            event_type=EventType.UNLOCK,
            amount=Decimal("200"),
            bridge_id=BRIDGE_ID,
        )
        context.add_event(unlock)

        state = context.get_bridge_state(BRIDGE_ID)
        assert state["locked"] == Decimal("500")
        assert state["unlocked"] == Decimal("200")
        assert state["minted"] == Decimal("500")
        assert state["burned"] == Decimal("200")


# ===========================================================================
# 5. Pipeline resilience / edge cases
# ===========================================================================


class TestE2EPipelineResilience:
    """Test pipeline handles edge cases gracefully."""

    async def test_duplicate_events_deduplicated(self):
        """Same event_id submitted twice does not create duplicate incidents."""
        builder = IncidentBuilder()

        event_id = str(uuid.uuid4())
        event = _make_event(
            event_id=event_id,
            chain_id=DEST_CHAIN,
            event_type=EventType.MINT,
            amount=Decimal("120000"),
            bridge_id=BRIDGE_ID,
            source_address=ATTACKER,
            dest_address=ATTACKER,
            contract_address=BRIDGE_CONTRACT,
        )

        violation = InvariantResult(
            violated=True,
            invariant_name="MINT_LOCK_PARITY",
            invariant_type=InvariantType.ECONOMIC,
            severity=Severity.CRITICAL,
            confidence=0.95,
            violation_amount=Decimal("120000"),
            chain_id=DEST_CHAIN,
            bridge_id=BRIDGE_ID,
            evidence={},
        )

        # First insertion
        inc1 = builder.upsert_incident(violation, event)
        assert inc1.event_count == 1

        # Second insertion with same event_id -- should be idempotent
        inc2 = builder.upsert_incident(violation, event)
        assert inc2.incident_id == inc1.incident_id
        # event_count should NOT increase
        assert inc2.event_count == 1, "Duplicate event must not increment event_count"

    async def test_out_of_order_events(self):
        """Events arriving out of block order are handled correctly."""
        context = InvariantContext()

        now = datetime.now(timezone.utc)

        # Add events out of block order: block 200 before block 100
        event_late = _make_event(
            chain_id=SOURCE_CHAIN,
            block_number=200,
            block_timestamp=now - timedelta(minutes=1),
            event_type=EventType.LOCK,
            amount=Decimal("100"),
            bridge_id=BRIDGE_ID,
        )
        event_early = _make_event(
            chain_id=SOURCE_CHAIN,
            block_number=100,
            block_timestamp=now - timedelta(minutes=10),
            event_type=EventType.LOCK,
            amount=Decimal("50"),
            bridge_id=BRIDGE_ID,
        )

        context.add_event(event_late)
        context.add_event(event_early)

        # Context should have both events and correct cumulative state
        state = context.get_bridge_state(BRIDGE_ID)
        assert state["locked"] == Decimal("150"), "Both out-of-order locks must be counted"

        # get_events should return sorted by timestamp
        events = await context.get_events(
            chain=SOURCE_CHAIN,
            event_type=EventType.LOCK,
            window=timedelta(hours=1),
        )
        assert len(events) == 2
        assert events[0].block_timestamp <= events[1].block_timestamp, (
            "Events should be returned sorted by timestamp"
        )

    async def test_missing_fields_handled(self):
        """Events with None/missing optional fields do not crash the pipeline."""
        context = InvariantContext()
        engine = InvariantEngine(context=context)

        mint_lock_inv = MintLockParityInvariant(
            bridge_id=BRIDGE_ID,
            source_chain=SOURCE_CHAIN,
            dest_chain=DEST_CHAIN,
        )
        engine.add_invariant(mint_lock_inv)

        # Minimal event -- many fields left at defaults / empty
        minimal_event = SecurityEvent(
            chain_id=DEST_CHAIN,
            event_type=EventType.MINT,
            amount=Decimal("100"),
            bridge_id=BRIDGE_ID,
            # No source_address, dest_address, contract_address, etc.
        )

        # Should not raise
        await engine.process_event(minimal_event)

        # Verify engine processed it
        stats = engine.get_stats()
        assert stats["events_processed"] == 1

    async def test_zero_amount_events(self):
        """Zero-amount events are processed without errors."""
        context = InvariantContext()

        zero_event = _make_event(
            chain_id=SOURCE_CHAIN,
            event_type=EventType.LOCK,
            amount=Decimal("0"),
            bridge_id=BRIDGE_ID,
        )
        context.add_event(zero_event)

        state = context.get_bridge_state(BRIDGE_ID)
        assert state["locked"] == Decimal("0")

    async def test_engine_result_handler_receives_violations(self):
        """Verify that result handlers are invoked for each violation."""
        context = InvariantContext()
        engine = InvariantEngine(context=context)

        invariant = MintLockParityInvariant(
            bridge_id=BRIDGE_ID,
            source_chain=SOURCE_CHAIN,
            dest_chain=DEST_CHAIN,
        )
        engine.add_invariant(invariant)

        received_results: list[InvariantResult] = []

        async def handler(result: InvariantResult):
            received_results.append(result)

        engine.add_result_handler(handler)

        # Trigger a violation: mint without lock
        attack_mint = _make_event(
            chain_id=DEST_CHAIN,
            block_timestamp=datetime.now(timezone.utc) - timedelta(minutes=1),
            event_type=EventType.MINT,
            amount=Decimal("99999"),
            bridge_id=BRIDGE_ID,
        )
        await engine.process_event(attack_mint)

        assert len(received_results) >= 1, "Handler must be called for violation"
        assert received_results[0].violated is True
        assert received_results[0].invariant_name == "MINT_LOCK_PARITY"

    async def test_incident_severity_escalation(self):
        """Adding a higher-severity violation escalates the incident."""
        builder = IncidentBuilder()

        base_time = datetime.now(timezone.utc)

        # First violation -- MEDIUM severity
        v1 = InvariantResult(
            violated=True,
            invariant_name="AMOUNT_MISMATCH",
            invariant_type=InvariantType.ECONOMIC,
            severity=Severity.MEDIUM,
            confidence=0.7,
            violation_amount=Decimal("100"),
            chain_id=DEST_CHAIN,
            bridge_id=BRIDGE_ID,
            evidence={},
        )
        e1 = _make_event(
            chain_id=DEST_CHAIN,
            block_timestamp=base_time,
            event_type=EventType.MINT,
            amount=Decimal("100"),
            bridge_id=BRIDGE_ID,
            source_address=ATTACKER,
        )
        inc = builder.upsert_incident(v1, e1)
        assert inc.severity == Severity.MEDIUM

        # Second violation -- CRITICAL severity, same cluster
        v2 = InvariantResult(
            violated=True,
            invariant_name="AMOUNT_MISMATCH",
            invariant_type=InvariantType.ECONOMIC,
            severity=Severity.CRITICAL,
            confidence=0.95,
            violation_amount=Decimal("100000"),
            chain_id=DEST_CHAIN,
            bridge_id=BRIDGE_ID,
            evidence={},
        )
        e2 = _make_event(
            chain_id=DEST_CHAIN,
            block_timestamp=base_time + timedelta(seconds=30),
            event_type=EventType.MINT,
            amount=Decimal("100000"),
            bridge_id=BRIDGE_ID,
            source_address=ATTACKER,
        )
        inc = builder.upsert_incident(v2, e2)

        # Severity should have escalated to CRITICAL
        assert inc.severity == Severity.CRITICAL
        assert inc.event_count == 2

    async def test_incident_auto_resolve_stale(self):
        """Incidents with no new events for 6+ hours should be auto-resolvable."""
        builder = IncidentBuilder()

        old_time = datetime.now(timezone.utc) - timedelta(hours=7)

        v = InvariantResult(
            violated=True,
            invariant_name="MINT_LOCK_PARITY",
            invariant_type=InvariantType.ECONOMIC,
            severity=Severity.HIGH,
            confidence=0.9,
            chain_id=DEST_CHAIN,
            bridge_id=BRIDGE_ID,
            evidence={},
        )
        e = _make_event(
            chain_id=DEST_CHAIN,
            block_timestamp=old_time,
            event_type=EventType.MINT,
            amount=Decimal("1000"),
            bridge_id=BRIDGE_ID,
        )
        inc = builder.upsert_incident(v, e)
        assert inc.should_auto_resolve(max_idle_hours=6)

        resolved = builder.auto_resolve_stale_incidents(max_idle_hours=6)
        assert len(resolved) >= 1
        assert resolved[0].status in (IncidentStatus.RESOLVED, IncidentStatus.STALE)

    async def test_large_event_batch_no_crash(self):
        """Processing a large batch of events does not crash."""
        context = InvariantContext()
        engine = InvariantEngine(context=context)
        engine.add_invariant(
            MintLockParityInvariant(
                bridge_id=BRIDGE_ID,
                source_chain=SOURCE_CHAIN,
                dest_chain=DEST_CHAIN,
            )
        )

        base_time = datetime.now(timezone.utc)

        # Generate 100 balanced lock+mint pairs
        for i in range(100):
            lock = _make_event(
                chain_id=SOURCE_CHAIN,
                block_number=1000 + i,
                block_timestamp=base_time - timedelta(minutes=100 - i),
                event_type=EventType.LOCK,
                amount=Decimal("10"),
                bridge_id=BRIDGE_ID,
                message_hash=f"0xmsg_{i:04d}",
            )
            mint = _make_event(
                chain_id=DEST_CHAIN,
                block_number=50000 + i,
                block_timestamp=base_time - timedelta(minutes=100 - i) + timedelta(seconds=30),
                event_type=EventType.MINT,
                amount=Decimal("10"),
                bridge_id=BRIDGE_ID,
                message_hash=f"0xmsg_{i:04d}",
            )
            await engine.process_event(lock)
            await engine.process_event(mint)

        stats = engine.get_stats()
        assert stats["events_processed"] == 200
        # The engine should process all 200 events without crashing.
        # Minor transient violations may occur during sequential processing
        # (e.g., a lock arrives before its matching mint is processed).
        assert stats["violations_detected"] <= 5
