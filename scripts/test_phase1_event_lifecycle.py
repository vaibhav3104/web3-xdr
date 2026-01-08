#!/usr/bin/env python3
"""
Test Phase 1: Event Lifecycle
==============================

Tests SecurityEvent lifecycle (PENDING/CONFIRMED/DROPPED).
"""

import sys
from pathlib import Path
from decimal import Decimal

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models.events import (
    SecurityEvent,
    EventType,
    EventStatus,
    Severity
)
from datetime import datetime, timezone


def test_event_lifecycle_status():
    """Test event lifecycle status."""
    print("\n" + "="*70)
    print("TEST 1: Event Lifecycle Status")
    print("="*70)
    
    # Create event with PENDING status (default)
    event = SecurityEvent(
        event_id="test-1",
        chain_id="ethereum",
        tx_hash="0x1234",
        block_number=100,
        event_type=EventType.TRANSFER,
        severity=Severity.MEDIUM
    )
    
    assert event.status == EventStatus.PENDING, "Default status should be PENDING"
    assert event.confirmed_at is None, "Confirmed at should be None initially"
    print(f"✅ Initial status: {event.status.value}")
    
    # Mark as CONFIRMED
    event.status = EventStatus.CONFIRMED
    event.confirmed_at = datetime.now(timezone.utc)
    
    assert event.status == EventStatus.CONFIRMED, "Status should be CONFIRMED"
    assert event.confirmed_at is not None, "Confirmed at should be set"
    print(f"✅ Confirmed status: {event.status.value}")
    
    # Mark as DROPPED (reorg)
    event.status = EventStatus.DROPPED
    assert event.status == EventStatus.DROPPED, "Status should be DROPPED"
    print(f"✅ Dropped status: {event.status.value}")
    
    print("✅ Event lifecycle status: PASSED")
    return True


def test_unique_key():
    """Test unique key generation."""
    print("\n" + "="*70)
    print("TEST 2: Unique Key Generation")
    print("="*70)
    
    event1 = SecurityEvent(
        chain_id="ethereum",
        tx_hash="0xabcd",
        log_index=0
    )
    
    event2 = SecurityEvent(
        chain_id="ethereum",
        tx_hash="0xabcd",
        log_index=0
    )
    
    event3 = SecurityEvent(
        chain_id="ethereum",
        tx_hash="0xabcd",
        log_index=1  # Different log index
    )
    
    key1 = event1.get_unique_key()
    key2 = event2.get_unique_key()
    key3 = event3.get_unique_key()
    
    assert key1 == key2, "Same events should have same key"
    assert key1 != key3, "Different log index should have different key"
    
    print(f"✅ Key 1: {key1}")
    print(f"✅ Key 2: {key2} (matches key 1)")
    print(f"✅ Key 3: {key3} (different)")
    
    print("✅ Unique key generation: PASSED")
    return True


def test_serialization():
    """Test event serialization/deserialization."""
    print("\n" + "="*70)
    print("TEST 3: Event Serialization")
    print("="*70)
    
    event = SecurityEvent(
        event_id="test-serial",
        chain_id="ethereum",
        tx_hash="0x5678",
        block_number=200,
        log_index=5,
        block_hash="0xhash123",
        status=EventStatus.CONFIRMED,
        confirmed_at=datetime.now(timezone.utc),
        canonical_event_hash="0xcanonical",
        event_type=EventType.LOCK,
        severity=Severity.HIGH,
        amount=Decimal("1000.5"),
        bridge_id="wormhole"
    )
    
    # Serialize
    data = event.to_dict()
    assert "status" in data, "Should have status field"
    assert "block_hash" in data, "Should have block_hash field"
    assert "confirmed_at" in data, "Should have confirmed_at field"
    assert data["status"] == "confirmed", "Status should be serialized"
    print("✅ Event serialized with lifecycle fields")
    
    # Deserialize
    event2 = SecurityEvent.from_dict(data)
    assert event2.status == EventStatus.CONFIRMED, "Status should deserialize correctly"
    assert event2.block_hash == "0xhash123", "Block hash should match"
    assert event2.confirmed_at is not None, "Confirmed at should be set"
    print("✅ Event deserialized correctly")
    
    print("✅ Event serialization: PASSED")
    return True


def test_block_hash_tracking():
    """Test block hash tracking for reorg detection."""
    print("\n" + "="*70)
    print("TEST 4: Block Hash Tracking")
    print("="*70)
    
    event = SecurityEvent(
        chain_id="ethereum",
        tx_hash="0x9999",
        block_number=300,
        block_hash="0xblockhash1"
    )
    
    assert event.block_hash == "0xblockhash1", "Block hash should be set"
    
    # Simulate reorg - different block hash
    event.block_hash = "0xblockhash2"  # Reorg detected
    assert event.block_hash == "0xblockhash2", "Block hash should update"
    
    print(f"✅ Block hash: {event.block_hash}")
    print("✅ Block hash tracking: PASSED")
    return True


def test_canonical_hash():
    """Test canonical event hash for deduplication."""
    print("\n" + "="*70)
    print("TEST 5: Canonical Event Hash")
    print("="*70)
    
    event = SecurityEvent(
        chain_id="ethereum",
        tx_hash="0xaaaa",
        log_index=0,
        canonical_event_hash="0xcanonical123"
    )
    
    assert event.canonical_event_hash == "0xcanonical123", "Canonical hash should be set"
    
    # Same event should have same canonical hash
    event2 = SecurityEvent(
        chain_id="ethereum",
        tx_hash="0xaaaa",
        log_index=0,
        canonical_event_hash="0xcanonical123"
    )
    
    assert event.canonical_event_hash == event2.canonical_event_hash, "Same events should have same canonical hash"
    
    print(f"✅ Canonical hash: {event.canonical_event_hash}")
    print("✅ Canonical hash: PASSED")
    return True


def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("  🛡️  Sentinel3 Phase 1: Event Lifecycle Tests")
    print("="*70)
    
    tests = [
        test_event_lifecycle_status,
        test_unique_key,
        test_serialization,
        test_block_hash_tracking,
        test_canonical_hash,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test.__name__}: FAILED - {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "="*70)
    print(f"  RESULTS: {passed} passed, {failed} failed")
    print("="*70)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

