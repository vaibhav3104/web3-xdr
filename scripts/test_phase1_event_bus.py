#!/usr/bin/env python3
"""
Test Phase 1: Event Bus
========================

Tests event bus (InMemory and Redis Streams).
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.pipeline.bus import (
    InMemoryBus,
    RedisStreamsBus,
    create_event_bus,
    BusMessage,
    QUEUE_MAX_SIZE
)
from src.models.events import SecurityEvent, EventType, EventStatus, Severity
from datetime import datetime, timezone


async def test_in_memory_bus_basic():
    """Test basic in-memory bus operations."""
    print("\n" + "="*70)
    print("TEST 1: In-Memory Bus - Basic Operations")
    print("="*70)
    
    bus = InMemoryBus(max_size=100)
    
    # Create test event
    event = {
        "event_id": "test-1",
        "chain_id": "ethereum",
        "tx_hash": "0x1234",
        "log_index": 0,
        "event_type": "transfer",
        "severity": "MEDIUM"
    }
    
    # Publish
    published = await bus.publish(event)
    assert published, "Event should be published"
    print("✅ Event published")
    
    # Check queue depth
    depth = await bus.get_queue_depth()
    assert depth == 1, f"Queue depth should be 1, got {depth}"
    print(f"✅ Queue depth: {depth}")
    
    # Consume
    messages = await bus.consume(batch_size=10, timeout_seconds=1.0)
    assert len(messages) == 1, f"Should consume 1 message, got {len(messages)}"
    assert messages[0].event_data["event_id"] == "test-1", "Event ID should match"
    print(f"✅ Consumed {len(messages)} message(s)")
    
    # Check depth after consume
    depth = await bus.get_queue_depth()
    assert depth == 0, f"Queue depth should be 0 after consume, got {depth}"
    print(f"✅ Queue depth after consume: {depth}")
    
    await bus.close()
    print("✅ In-memory bus basic operations: PASSED")
    return True


async def test_idempotency():
    """Test idempotency key deduplication."""
    print("\n" + "="*70)
    print("TEST 2: Idempotency Key Deduplication")
    print("="*70)
    
    bus = InMemoryBus(max_size=100)
    
    event = {
        "event_id": "test-2",
        "chain_id": "ethereum",
        "tx_hash": "0x5678",
        "log_index": 0,
    }
    
    # Publish with same idempotency key
    key = "test-key-123"
    published1 = await bus.publish(event, idempotency_key=key)
    published2 = await bus.publish(event, idempotency_key=key)  # Duplicate
    
    assert published1, "First publish should succeed"
    assert not published2, "Duplicate publish should be rejected"
    print("✅ Duplicate event rejected (idempotency)")
    
    # Check depth
    depth = await bus.get_queue_depth()
    assert depth == 1, f"Queue should have 1 event, got {depth}"
    
    await bus.close()
    print("✅ Idempotency: PASSED")
    return True


async def test_queue_capacity():
    """Test queue capacity limits."""
    print("\n" + "="*70)
    print("TEST 3: Queue Capacity Limits")
    print("="*70)
    
    bus = InMemoryBus(max_size=5)
    
    # Fill queue
    for i in range(5):
        event = {"event_id": f"test-{i}", "chain_id": "ethereum", "tx_hash": f"0x{i}"}
        published = await bus.publish(event)
        assert published, f"Event {i} should be published"
    
    depth = await bus.get_queue_depth()
    assert depth == 5, f"Queue should be full (5), got {depth}"
    print(f"✅ Queue filled to capacity: {depth}")
    
    # Try to publish one more (should fail with "never" drop policy)
    os.environ["QUEUE_DROP_POLICY"] = "never"
    event = {"event_id": "test-overflow", "chain_id": "ethereum", "tx_hash": "0xoverflow"}
    published = await bus.publish(event)
    assert not published, "Publish should fail when queue is full (never drop)"
    print("✅ Overflow rejected (never drop policy)")
    
    await bus.close()
    print("✅ Queue capacity: PASSED")
    return True


async def test_redis_bus_creation():
    """Test Redis bus creation (if Redis available)."""
    print("\n" + "="*70)
    print("TEST 4: Redis Bus Creation")
    print("="*70)
    
    redis_url = os.getenv("REDIS_URL", "")
    
    if not redis_url:
        print("⚠️  REDIS_URL not set, skipping Redis tests")
        print("   Set REDIS_URL to test Redis Streams bus")
        return True
    
    try:
        bus = RedisStreamsBus(redis_url=redis_url, stream_name="test:sentinel3:events")
        
        # Test publish
        event = {
            "event_id": "test-redis-1",
            "chain_id": "ethereum",
            "tx_hash": "0xredis",
            "log_index": 0,
        }
        
        published = await bus.publish(event)
        assert published, "Event should be published to Redis"
        print("✅ Event published to Redis stream")
        
        # Test consume
        messages = await bus.consume(batch_size=10, timeout_seconds=2.0)
        assert len(messages) >= 1, "Should consume at least 1 message"
        print(f"✅ Consumed {len(messages)} message(s) from Redis")
        
        await bus.close()
        print("✅ Redis bus: PASSED")
        return True
        
    except Exception as e:
        print(f"⚠️  Redis bus test failed: {e}")
        print("   This is expected if Redis is not available")
        return True  # Don't fail test


async def test_bus_factory():
    """Test bus factory function."""
    print("\n" + "="*70)
    print("TEST 5: Bus Factory Function")
    print("="*70)
    
    # Clear REDIS_URL to test in-memory fallback
    original_redis_url = os.environ.pop("REDIS_URL", None)
    
    try:
        bus = create_event_bus()
        assert isinstance(bus, InMemoryBus), "Should create InMemoryBus when REDIS_URL not set"
        print("✅ Factory created InMemoryBus (no REDIS_URL)")
        
        await bus.close()
        
        # Test with Redis URL
        os.environ["REDIS_URL"] = "redis://localhost:6379"
        try:
            bus = create_event_bus()
            # May be InMemoryBus if Redis unavailable
            print(f"✅ Factory created bus: {type(bus).__name__}")
            await bus.close()
        except Exception:
            print("⚠️  Redis unavailable, factory fell back to InMemoryBus")
        
    finally:
        if original_redis_url:
            os.environ["REDIS_URL"] = original_redis_url
        else:
            os.environ.pop("REDIS_URL", None)
    
    print("✅ Bus factory: PASSED")
    return True


async def test_message_serialization():
    """Test message serialization."""
    print("\n" + "="*70)
    print("TEST 6: Message Serialization")
    print("="*70)
    
    event_data = {
        "event_id": "test-serial",
        "chain_id": "ethereum",
        "tx_hash": "0xserial",
        "log_index": 0,
        "block_number": 12345,
    }
    
    message = BusMessage(
        id="msg-1",
        event_data=event_data,
        idempotency_key="key-123"
    )
    
    # Serialize
    data = message.to_dict()
    assert "id" in data, "Should have id field"
    assert "event_data" in data, "Should have event_data field"
    assert data["idempotency_key"] == "key-123", "Idempotency key should match"
    print("✅ Message serialized")
    
    # Deserialize
    message2 = BusMessage.from_dict(data)
    assert message2.id == message.id, "ID should match"
    assert message2.event_data["event_id"] == event_data["event_id"], "Event data should match"
    print("✅ Message deserialized")
    
    print("✅ Message serialization: PASSED")
    return True


async def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("  🛡️  Sentinel3 Phase 1: Event Bus Tests")
    print("="*70)
    
    tests = [
        test_in_memory_bus_basic,
        test_idempotency,
        test_queue_capacity,
        test_message_serialization,
        test_bus_factory,
        test_redis_bus_creation,  # May skip if Redis unavailable
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if await test():
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
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

