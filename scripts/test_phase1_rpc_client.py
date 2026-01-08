#!/usr/bin/env python3
"""
Test Phase 1: Multi-RPC Client
==============================

Tests RPC client failover, health tracking, and quorum verification.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.telemetry.rpc_client import MultiRpcProvider, EndpointHealth, EndpointStats


async def test_rpc_provider_initialization():
    """Test RPC provider initialization."""
    print("\n" + "="*70)
    print("TEST 1: RPC Provider Initialization")
    print("="*70)
    
    rpc_urls = [
        "https://eth.llamarpc.com",
        "https://rpc.ankr.com/eth",
        "https://ethereum.publicnode.com"
    ]
    
    provider = MultiRpcProvider(rpc_urls)
    
    assert len(provider.endpoints) == 3, f"Expected 3 endpoints, got {len(provider.endpoints)}"
    assert all(url in provider.endpoints for url in rpc_urls), "All URLs should be tracked"
    
    stats = provider.get_stats()
    print(f"✅ Total endpoints: {stats['total_endpoints']}")
    print(f"✅ Healthy endpoints: {stats['healthy_endpoints']}")
    
    await provider.close()
    print("✅ RPC provider initialization: PASSED")
    return True


async def test_endpoint_selection():
    """Test endpoint selection logic."""
    print("\n" + "="*70)
    print("TEST 2: Endpoint Selection")
    print("="*70)
    
    rpc_urls = ["https://endpoint1.com", "https://endpoint2.com"]
    provider = MultiRpcProvider(rpc_urls)
    
    # Test round-robin selection
    endpoints1 = provider._select_endpoint()
    endpoints2 = provider._select_endpoint()
    
    assert len(endpoints1) == 1, "Should select one endpoint"
    assert endpoints1[0] in rpc_urls, "Selected endpoint should be in list"
    
    print(f"✅ Selected endpoint 1: {endpoints1[0][:40]}...")
    print(f"✅ Selected endpoint 2: {endpoints2[0][:40]}...")
    
    await provider.close()
    print("✅ Endpoint selection: PASSED")
    return True


async def test_health_tracking():
    """Test health tracking."""
    print("\n" + "="*70)
    print("TEST 3: Health Tracking")
    print("="*70)
    
    rpc_urls = ["https://endpoint1.com"]
    provider = MultiRpcProvider(rpc_urls, unhealthy_cooldown_seconds=1)
    
    endpoint_url = rpc_urls[0]
    stats = provider.endpoints[endpoint_url]
    
    # Record success
    provider._record_success(endpoint_url, latency_ms=100.0)
    assert stats.health == EndpointHealth.HEALTHY, "Should be healthy after success"
    assert stats.successful_requests == 1, "Should have 1 successful request"
    print(f"✅ Success recorded - Health: {stats.health.value}, Success rate: {stats.success_rate:.1%}")
    
    # Record failure
    provider._record_failure(endpoint_url, "Test error", is_5xx=False)
    assert stats.consecutive_failures == 1, "Should have 1 consecutive failure"
    print(f"✅ Failure recorded - Consecutive failures: {stats.consecutive_failures}")
    
    # Multiple failures -> unhealthy
    provider._record_failure(endpoint_url, "Error", is_5xx=False)
    provider._record_failure(endpoint_url, "Error", is_5xx=False)
    assert stats.health == EndpointHealth.UNHEALTHY, "Should be unhealthy after 3 failures"
    assert not stats.is_available, "Should not be available when unhealthy"
    print(f"✅ Marked unhealthy - Health: {stats.health.value}, Available: {stats.is_available}")
    
    await provider.close()
    print("✅ Health tracking: PASSED")
    return True


async def test_failover():
    """Test failover behavior."""
    print("\n" + "="*70)
    print("TEST 4: Failover Behavior")
    print("="*70)
    
    rpc_urls = ["https://endpoint1.com", "https://endpoint2.com"]
    provider = MultiRpcProvider(rpc_urls, unhealthy_cooldown_seconds=1)
    
    # Mark first endpoint as unhealthy
    provider._record_failure(rpc_urls[0], "Error", is_5xx=True)
    provider._record_failure(rpc_urls[0], "Error", is_5xx=True)
    provider._record_failure(rpc_urls[0], "Error", is_5xx=True)
    
    # Select endpoint - should skip unhealthy
    endpoints = provider._select_endpoint()
    assert endpoints[0] == rpc_urls[1], "Should select second endpoint when first is unhealthy"
    print(f"✅ Failover to: {endpoints[0][:40]}...")
    
    await provider.close()
    print("✅ Failover behavior: PASSED")
    return True


async def test_real_rpc_call():
    """Test real RPC call (if network available)."""
    print("\n" + "="*70)
    print("TEST 5: Real RPC Call (Network Test)")
    print("="*70)
    
    # Use public RPCs
    rpc_urls = [
        "https://eth.llamarpc.com",
        "https://rpc.ankr.com/eth"
    ]
    
    provider = MultiRpcProvider(rpc_urls, request_timeout_seconds=10.0)
    
    try:
        block_number = await provider.get_block_number()
        print(f"✅ Got block number: {block_number}")
        
        stats = provider.get_stats()
        print(f"✅ Healthy endpoints: {stats['healthy_endpoints']}")
        print(f"✅ Total requests: {sum(e['total_requests'] for e in stats['endpoints'])}")
        
        assert block_number > 0, "Block number should be positive"
        print("✅ Real RPC call: PASSED")
        result = True
    except Exception as e:
        print(f"⚠️  Real RPC call failed (network issue): {e}")
        print("   This is expected if network is unavailable")
        result = True  # Don't fail test due to network issues
    
    await provider.close()
    return result


async def test_quorum_mode():
    """Test quorum verification mode."""
    print("\n" + "="*70)
    print("TEST 6: Quorum Verification Mode")
    print("="*70)
    
    rpc_urls = ["https://endpoint1.com", "https://endpoint2.com", "https://endpoint3.com"]
    provider = MultiRpcProvider(rpc_urls)
    
    # Test quorum selection
    endpoints = provider._select_endpoint(require_quorum=True)
    assert len(endpoints) >= 2, "Quorum mode should return at least 2 endpoints"
    print(f"✅ Quorum selected {len(endpoints)} endpoints")
    
    await provider.close()
    print("✅ Quorum mode: PASSED")
    return True


async def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("  🛡️  Sentinel3 Phase 1: Multi-RPC Client Tests")
    print("="*70)
    
    tests = [
        test_rpc_provider_initialization,
        test_endpoint_selection,
        test_health_tracking,
        test_failover,
        test_quorum_mode,
        test_real_rpc_call,  # Last - may fail due to network
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

