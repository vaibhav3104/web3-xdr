#!/usr/bin/env python3
"""
Test Phase 2: Worker Component
================================

Quick test to verify worker initialization and basic functionality.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.worker.main import Sentinel3Worker
from src.pipeline.bus import create_event_bus


async def test_worker_initialization():
    """Test worker initialization."""
    print("\n" + "="*70)
    print("TEST: Worker Initialization")
    print("="*70)
    
    worker = Sentinel3Worker()
    
    # Test config loading
    assert worker.config is not None, "Config should be loaded"
    assert "chains" in worker.config, "Config should have chains"
    print(f"✅ Config loaded: {len(worker.config.get('chains', []))} chains")
    
    # Test initialization (without actually starting loops)
    try:
        await worker.initialize()
        print("✅ Worker initialized successfully")
        print(f"✅ RPC providers: {len(worker.rpc_providers)}")
        print(f"✅ Listeners: {len(worker.listeners)}")
        print(f"✅ Event bus: {type(worker.bus).__name__}")
        
        # Cleanup
        await worker.stop()
        return True
    except Exception as e:
        print(f"❌ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_event_bus_integration():
    """Test event bus integration."""
    print("\n" + "="*70)
    print("TEST: Event Bus Integration")
    print("="*70)
    
    bus = create_event_bus()
    print(f"✅ Event bus created: {type(bus).__name__}")
    
    # Test publish
    event = {
        "event_id": "test-worker-1",
        "chain_id": "ethereum",
        "tx_hash": "0xtest",
        "status": "pending"
    }
    
    published = await bus.publish(event)
    assert published, "Event should be published"
    print("✅ Event published to bus")
    
    # Test queue depth
    depth = await bus.get_queue_depth()
    print(f"✅ Queue depth: {depth}")
    
    # Test consume
    messages = await bus.consume(batch_size=1, timeout_seconds=1.0)
    assert len(messages) > 0, "Should consume message"
    print(f"✅ Consumed {len(messages)} message(s)")
    
    await bus.close()
    return True


async def test_metrics_availability():
    """Test metrics are available."""
    print("\n" + "="*70)
    print("TEST: Metrics Availability")
    print("="*70)
    
    from src.telemetry.metrics import (
        events_ingested_total,
        head_lag_blocks,
        bus_queue_depth,
    )
    
    # Test metric labels
    events_ingested_total.labels(chain="ethereum", status="pending").inc()
    head_lag_blocks.labels(chain="ethereum").set(10)
    bus_queue_depth.labels(bus_type="memory").set(5)
    
    print("✅ Metrics available and working")
    return True


async def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("  🛡️  Sentinel3 Phase 2: Worker Component Tests")
    print("="*70)
    
    tests = [
        test_worker_initialization,
        test_event_bus_integration,
        test_metrics_availability,
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

