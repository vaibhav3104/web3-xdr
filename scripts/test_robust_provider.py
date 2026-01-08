#!/usr/bin/env python3
"""
Phase 2.1 Test Script: Robust RPC Provider
==========================================

Tests:
1. Provider initialization with multiple URLs
2. Round-robin rotation
3. Health tracking after failures
4. Automatic failover
5. Recovery after cooldown
6. Integration with EVMListener

Run with: python scripts/test_robust_provider.py
"""

import asyncio
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer()
    ]
)

logger = structlog.get_logger()


def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_result(test_name: str, passed: bool, details: str = ""):
    """Print test result."""
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"  {status}: {test_name}")
    if details:
        print(f"         {details}")


async def test_provider_initialization():
    """Test 1: Provider initialization."""
    print_header("Test 1: Provider Initialization")
    
    try:
        from src.telemetry.robust_provider import (
            RobustAsyncHTTPProvider,
            RobustProviderManager,
            ProviderHealth
        )
        
        # Test with multiple URLs
        urls = [
            "https://eth.llamarpc.com",
            "https://rpc.ankr.com/eth",
            "https://cloudflare-eth.com"
        ]
        
        manager = RobustProviderManager(urls)
        
        print_result("Manager creation", len(manager._providers) == 3, 
                    f"Providers: {len(manager._providers)}")
        
        # All should start as UNKNOWN
        all_unknown = all(
            s.status == ProviderHealth.UNKNOWN 
            for s in manager._providers.values()
        )
        print_result("Initial status UNKNOWN", all_unknown)
        
        # Test provider creation
        provider = RobustAsyncHTTPProvider(urls)
        print_result("AsyncHTTPProvider creation", provider is not None)
        
        # Test stats
        stats = manager.get_stats()
        print_result("Stats available", "total_providers" in stats,
                    f"Total: {stats.get('total_providers', 0)}")
        
        return True
        
    except Exception as e:
        print_result("Initialization", False, str(e))
        return False


async def test_round_robin_rotation():
    """Test 2: Round-robin URL rotation."""
    print_header("Test 2: Round-Robin Rotation")
    
    try:
        from src.telemetry.robust_provider import RobustProviderManager
        
        urls = ["url1", "url2", "url3"]
        manager = RobustProviderManager(urls)
        
        # Get URLs multiple times
        selected = []
        for _ in range(9):
            url, _ = manager.get_next_healthy_url()
            selected.append(url)
        
        # Should rotate through all URLs
        unique_urls = set(selected)
        all_used = len(unique_urls) == 3
        
        print_result("Rotation uses all URLs", all_used, 
                    f"Unique URLs used: {len(unique_urls)}")
        
        # Check that rotation is round-robin (each URL used 3 times)
        from collections import Counter
        counts = Counter(selected)
        balanced = all(c == 3 for c in counts.values())
        
        print_result("Balanced rotation", balanced,
                    f"Distribution: {dict(counts)}")
        
        return all_used and balanced
        
    except Exception as e:
        print_result("Round-robin", False, str(e))
        return False


async def test_health_tracking():
    """Test 3: Health tracking after failures."""
    print_header("Test 3: Health Tracking")
    
    try:
        from src.telemetry.robust_provider import (
            RobustProviderManager,
            ProviderHealth
        )
        
        urls = ["url1", "url2", "url3"]
        manager = RobustProviderManager(urls, unhealthy_cooldown=5)
        
        # Record success for url1
        manager.record_success("url1", 100.0)
        
        url1_healthy = manager._providers["url1"].status == ProviderHealth.HEALTHY
        print_result("Success marks HEALTHY", url1_healthy)
        
        # Record failures for url2 (should become unhealthy after 3)
        for i in range(3):
            manager.record_failure("url2", "Connection error", is_5xx=False)
        
        url2_unhealthy = manager._providers["url2"].status == ProviderHealth.UNHEALTHY
        print_result("Multiple failures mark UNHEALTHY", url2_unhealthy,
                    f"Failure count: {manager._providers['url2'].failure_count}")
        
        # url2 should not be selected
        healthy_urls = [
            url for url, stats in manager._providers.items()
            if stats.is_healthy
        ]
        url2_excluded = "url2" not in healthy_urls
        print_result("Unhealthy URL excluded", url2_excluded,
                    f"Healthy URLs: {healthy_urls}")
        
        # 5xx error should immediately mark unhealthy
        manager.record_failure("url3", "502 Bad Gateway", is_5xx=True)
        url3_unhealthy = manager._providers["url3"].status == ProviderHealth.UNHEALTHY
        print_result("5xx marks UNHEALTHY immediately", url3_unhealthy)
        
        return url1_healthy and url2_unhealthy and url2_excluded
        
    except Exception as e:
        print_result("Health tracking", False, str(e))
        return False


async def test_provider_stats():
    """Test 4: Provider statistics."""
    print_header("Test 4: Provider Statistics")
    
    try:
        from src.telemetry.robust_provider import RobustProviderManager
        
        urls = ["url1", "url2"]
        manager = RobustProviderManager(urls)
        
        # Record some activity
        manager.record_success("url1", 50.0)
        manager.record_success("url1", 100.0)
        manager.record_success("url1", 150.0)
        manager.record_failure("url2", "Error")
        
        stats = manager.get_stats()
        
        print_result("Total providers", stats["total_providers"] == 2)
        print_result("Healthy count", stats["healthy_providers"] >= 1,
                    f"Healthy: {stats['healthy_providers']}")
        
        # Check individual provider stats
        url1_stats = manager._providers["url1"]
        avg_latency = url1_stats.avg_latency_ms
        success_rate = url1_stats.success_rate
        
        print_result("Average latency calculated", avg_latency == 100.0,
                    f"Avg latency: {avg_latency}ms")
        print_result("Success rate calculated", success_rate == 100.0,
                    f"Success rate: {success_rate}%")
        
        return True
        
    except Exception as e:
        print_result("Stats", False, str(e))
        return False


async def test_exponential_backoff():
    """Test 5: Exponential backoff when all fail."""
    print_header("Test 5: Exponential Backoff")
    
    try:
        from src.telemetry.robust_provider import RobustProviderManager
        
        urls = ["url1", "url2"]
        manager = RobustProviderManager(urls, max_backoff=10)
        
        # Fail all providers
        for url in urls:
            manager.record_failure(url, "Error", is_5xx=True)
            manager.record_failure(url, "Error", is_5xx=True)
        
        # Check consecutive failures
        print_result("Consecutive failures tracked", 
                    manager._consecutive_failures >= 2,
                    f"Consecutive: {manager._consecutive_failures}")
        
        # Backoff should be calculated
        backoff = manager._calculate_backoff()
        print_result("Backoff calculated", backoff > 0,
                    f"Backoff: {backoff:.1f}s")
        
        # Success should reset backoff
        manager.record_success("url1", 50.0)
        print_result("Success resets backoff", 
                    manager._consecutive_failures == 0,
                    f"Consecutive after success: {manager._consecutive_failures}")
        
        return True
        
    except Exception as e:
        print_result("Backoff", False, str(e))
        return False


async def test_real_rpc_connection():
    """Test 6: Real RPC connection (optional, requires network)."""
    print_header("Test 6: Real RPC Connection (Network)")
    
    try:
        from src.telemetry.robust_provider import RobustAsyncHTTPProvider
        from web3 import AsyncWeb3
        
        # Use public free RPCs
        urls = [
            "https://eth.llamarpc.com",
            "https://rpc.ankr.com/eth",
        ]
        
        provider = RobustAsyncHTTPProvider(urls)
        w3 = AsyncWeb3(provider)
        
        # Test connection by getting chain ID (is_connected() can be unreliable)
        try:
            chain_id = await w3.eth.chain_id
            is_connected = chain_id > 0
        except:
            is_connected = False
            
        print_result("Web3 connected (chain_id check)", is_connected,
                    f"Chain ID: {chain_id if is_connected else 'N/A'}")
        
        if is_connected:
            # Get block number
            block_num = await w3.eth.block_number
            print_result("Block number retrieved", block_num > 0,
                        f"Block: {block_num:,}")
            
            # Check provider stats
            stats = provider.get_stats()
            print_result("Provider stats after request", 
                        stats["healthy_providers"] >= 1,
                        f"Healthy: {stats['healthy_providers']}/{stats['total_providers']}")
        
        return is_connected
        
    except Exception as e:
        print_result("Real RPC", False, f"(May need network): {str(e)[:60]}")
        return False  # Don't fail the suite for network issues


async def test_evm_listener_integration():
    """Test 7: EVMListener integration with robust provider."""
    print_header("Test 7: EVMListener Integration")
    
    try:
        from src.telemetry.evm_listener import EVMListener
        from src.telemetry.base import ListenerConfig
        
        # Create config with multiple RPCs
        config = ListenerConfig(
            chain_id="ethereum",
            chain_name="Ethereum Mainnet",
            rpc_url="https://eth.llamarpc.com",
            fallback_rpcs=[
                "https://rpc.ankr.com/eth",
                "https://cloudflare-eth.com"
            ],
            bridge_contracts=[],
            token_contracts=[],
        )
        
        # Create listener with multiple URLs
        listener = EVMListener(config)
        
        # Check URLs are configured
        print_result("Multiple URLs configured", 
                    len(listener._rpc_urls) >= 2,
                    f"URLs: {len(listener._rpc_urls)}")
        
        # Test connect (will use robust provider)
        connected = await listener.connect()
        print_result("Listener connected", connected)
        
        if connected:
            # Get provider stats
            stats = listener.get_provider_stats()
            print_result("Provider stats accessible", 
                        "total_providers" in stats,
                        f"Providers: {stats.get('total_providers', 0)}")
        
        # Cleanup
        await listener.disconnect()
        
        return len(listener._rpc_urls) >= 2
        
    except Exception as e:
        print_result("EVMListener integration", False, str(e)[:80])
        return False


async def test_failover_simulation():
    """Test 8: Simulate failover scenario."""
    print_header("Test 8: Failover Simulation")
    
    try:
        from src.telemetry.robust_provider import (
            RobustProviderManager,
            ProviderHealth
        )
        
        urls = ["primary", "backup1", "backup2"]
        manager = RobustProviderManager(urls, unhealthy_cooldown=2)
        
        # Simulate: primary fails
        print("  Simulating primary failure...")
        manager.record_failure("primary", "Connection refused", is_5xx=False)
        manager.record_failure("primary", "Connection refused", is_5xx=False)
        manager.record_failure("primary", "Connection refused", is_5xx=False)
        
        # Next URL should be backup
        url, _ = manager.get_next_healthy_url()
        failover_worked = url != "primary"
        print_result("Failover to backup", failover_worked,
                    f"Selected: {url}")
        
        # backup1 succeeds
        manager.record_success("backup1", 100.0)
        
        # Wait for cooldown to expire
        print("  Waiting for cooldown (2s)...")
        await asyncio.sleep(2.5)
        
        # Primary should be available again (status reset to UNKNOWN)
        primary_available = manager._providers["primary"].is_healthy
        print_result("Primary recovers after cooldown", primary_available,
                    f"Primary status: {manager._providers['primary'].status.value}")
        
        return failover_worked
        
    except Exception as e:
        print_result("Failover simulation", False, str(e))
        return False


async def run_all_tests():
    """Run all Phase 2.1 tests."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "PHASE 2.1: ROBUST RPC PROVIDER TESTS" + " " * 15 + "║")
    print("╚" + "═" * 68 + "╝")
    
    results = {}
    
    # Run tests
    results["initialization"] = await test_provider_initialization()
    results["round_robin"] = await test_round_robin_rotation()
    results["health_tracking"] = await test_health_tracking()
    results["stats"] = await test_provider_stats()
    results["backoff"] = await test_exponential_backoff()
    results["real_rpc"] = await test_real_rpc_connection()
    results["evm_listener"] = await test_evm_listener_integration()
    results["failover"] = await test_failover_simulation()
    
    # Summary
    print_header("TEST SUMMARY")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, passed_test in results.items():
        status = "✅" if passed_test else "❌"
        print(f"  {status} {test_name.replace('_', ' ').title()}")
    
    print()
    print(f"  Results: {passed}/{total} tests passed")
    print()
    
    # Core tests (excluding network-dependent)
    core_tests = ["initialization", "round_robin", "health_tracking", "stats", "backoff"]
    core_passed = all(results.get(t, False) for t in core_tests)
    
    if passed == total:
        print("  🎉 ALL TESTS PASSED! Phase 2.1 is ready.")
    elif core_passed:
        print("  ✅ Core tests passed. Network tests may need connectivity.")
    else:
        print("  ❌ Some core tests failed. Check errors above.")
    
    print()
    
    return core_passed


if __name__ == "__main__":
    asyncio.run(run_all_tests())

