"""
Tests for Invariant Detection Engine.
"""

import pytest
from datetime import datetime, timedelta
from decimal import Decimal

from src.models.events import SecurityEvent, EventType, Severity
from src.invariants.base import InvariantContext
from src.invariants.economic import MintLockParityInvariant, UnbackedMintInvariant


@pytest.fixture
def context():
    """Create a fresh invariant context."""
    return InvariantContext()


@pytest.fixture
def bridge_config():
    """Standard bridge configuration."""
    return {
        "bridge_id": "test_bridge",
        "source_chain": "ethereum",
        "dest_chain": "polygon",
    }


class TestMintLockParityInvariant:
    """Tests for MINT_LOCK_PARITY invariant."""
    
    @pytest.mark.asyncio
    async def test_balanced_mint_lock_passes(self, context, bridge_config):
        """Test that balanced mint/lock passes invariant."""
        # Add lock event
        lock = SecurityEvent(
            chain_id=bridge_config["source_chain"],
            block_timestamp=datetime.utcnow() - timedelta(minutes=5),
            event_type=EventType.LOCK,
            amount=Decimal("100"),
            bridge_id=bridge_config["bridge_id"],
            message_hash="0xtest123",
        )
        context.add_event(lock)
        
        # Add matching mint event
        mint = SecurityEvent(
            chain_id=bridge_config["dest_chain"],
            block_timestamp=datetime.utcnow(),
            event_type=EventType.MINT,
            amount=Decimal("100"),
            bridge_id=bridge_config["bridge_id"],
            message_hash="0xtest123",
        )
        context.add_event(mint)
        
        # Check invariant
        invariant = MintLockParityInvariant(
            bridge_id=bridge_config["bridge_id"],
            source_chain=bridge_config["source_chain"],
            dest_chain=bridge_config["dest_chain"],
        )
        
        result = await invariant.evaluate(context)
        assert not result.violated, "Balanced mint/lock should pass"
    
    @pytest.mark.asyncio
    async def test_unbacked_mint_fails(self, context, bridge_config):
        """Test that mint without lock fails invariant."""
        # Add only mint event (no lock)
        mint = SecurityEvent(
            chain_id=bridge_config["dest_chain"],
            block_timestamp=datetime.utcnow(),
            event_type=EventType.MINT,
            amount=Decimal("100"),
            bridge_id=bridge_config["bridge_id"],
        )
        context.add_event(mint)
        
        # Check invariant
        invariant = MintLockParityInvariant(
            bridge_id=bridge_config["bridge_id"],
            source_chain=bridge_config["source_chain"],
            dest_chain=bridge_config["dest_chain"],
        )
        
        result = await invariant.evaluate(context)
        assert result.violated, "Unbacked mint should fail"
        assert result.severity == Severity.CRITICAL
        assert result.violation_amount == Decimal("100")
    
    @pytest.mark.asyncio
    async def test_partial_backing_fails(self, context, bridge_config):
        """Test that partially backed mint fails."""
        # Add small lock
        lock = SecurityEvent(
            chain_id=bridge_config["source_chain"],
            block_timestamp=datetime.utcnow() - timedelta(minutes=5),
            event_type=EventType.LOCK,
            amount=Decimal("50"),
            bridge_id=bridge_config["bridge_id"],
        )
        context.add_event(lock)
        
        # Add larger mint
        mint = SecurityEvent(
            chain_id=bridge_config["dest_chain"],
            block_timestamp=datetime.utcnow(),
            event_type=EventType.MINT,
            amount=Decimal("100"),
            bridge_id=bridge_config["bridge_id"],
        )
        context.add_event(mint)
        
        invariant = MintLockParityInvariant(
            bridge_id=bridge_config["bridge_id"],
            source_chain=bridge_config["source_chain"],
            dest_chain=bridge_config["dest_chain"],
        )
        
        result = await invariant.evaluate(context)
        assert result.violated
        assert result.violation_amount == Decimal("50")


class TestUnbackedMintInvariant:
    """Tests for UNBACKED_MINT invariant."""
    
    @pytest.mark.asyncio
    async def test_mint_with_lock_passes(self, context, bridge_config):
        """Test mint with corresponding lock passes."""
        message_hash = "0xtest_message_123"
        
        # Lock first
        lock = SecurityEvent(
            chain_id=bridge_config["source_chain"],
            block_timestamp=datetime.utcnow() - timedelta(minutes=5),
            event_type=EventType.LOCK,
            amount=Decimal("100"),
            bridge_id=bridge_config["bridge_id"],
            message_hash=message_hash,
        )
        context.add_event(lock)
        
        # Then mint
        mint = SecurityEvent(
            chain_id=bridge_config["dest_chain"],
            block_timestamp=datetime.utcnow(),
            event_type=EventType.MINT,
            amount=Decimal("100"),
            bridge_id=bridge_config["bridge_id"],
            message_hash=message_hash,
        )
        context.add_event(mint)
        
        invariant = UnbackedMintInvariant(
            bridge_id=bridge_config["bridge_id"],
            source_chain=bridge_config["source_chain"],
            dest_chain=bridge_config["dest_chain"],
        )
        
        result = await invariant.evaluate(context)
        assert not result.violated
    
    @pytest.mark.asyncio
    async def test_mint_without_lock_fails(self, context, bridge_config):
        """Test mint without lock fails."""
        mint = SecurityEvent(
            chain_id=bridge_config["dest_chain"],
            block_timestamp=datetime.utcnow(),
            event_type=EventType.MINT,
            amount=Decimal("100"),
            bridge_id=bridge_config["bridge_id"],
            message_hash="0xfake_message",
        )
        context.add_event(mint)
        
        invariant = UnbackedMintInvariant(
            bridge_id=bridge_config["bridge_id"],
            source_chain=bridge_config["source_chain"],
            dest_chain=bridge_config["dest_chain"],
        )
        
        result = await invariant.evaluate(context)
        assert result.violated
        assert result.severity == Severity.CRITICAL


class TestInvariantContext:
    """Tests for InvariantContext."""
    
    def test_add_event_updates_state(self):
        """Test that adding events updates bridge state."""
        context = InvariantContext()
        
        event = SecurityEvent(
            chain_id="ethereum",
            event_type=EventType.LOCK,
            amount=Decimal("100"),
            bridge_id="test_bridge",
        )
        context.add_event(event)
        
        state = context.get_bridge_state("test_bridge")
        assert state["locked"] == Decimal("100")
    
    @pytest.mark.asyncio
    async def test_get_events_filters_correctly(self):
        """Test event filtering."""
        context = InvariantContext()
        
        # Add multiple events
        for i in range(5):
            event = SecurityEvent(
                chain_id="ethereum" if i % 2 == 0 else "polygon",
                block_timestamp=datetime.utcnow() - timedelta(minutes=i),
                event_type=EventType.LOCK if i % 2 == 0 else EventType.MINT,
                amount=Decimal(str(i * 10)),
                bridge_id="test_bridge",
            )
            context.add_event(event)
        
        # Filter by chain
        eth_events = await context.get_events(chain="ethereum")
        assert len(eth_events) == 3
        
        # Filter by type
        locks = await context.get_events(event_type=EventType.LOCK)
        assert len(locks) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

