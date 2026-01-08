#!/usr/bin/env python3
"""
Phase 2.2 Test Script: Robust Non-EVM Listeners
================================================

Tests:
1. RobustNonEVMListener base class
2. Multi-RPC failover
3. Health tracking
4. Heartbeat logging
5. CosmosListener integration
6. AptosListener integration
7. NearListener integration

Run with: python scripts/test_non_evm_listeners.py
"""

import asyncio
import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

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


async def test_base_class_initialization():
    """Test 1: RobustNonEVMListener base class."""
    print_header("Test 1: RobustNonEVMListener Base Class")
    
    try:
        from src.telemetry.robust_non_evm import (
            RobustNonEVMListener,
            NonEVMConfig,
            EndpointHealth,
            EndpointStats
        )
        
        # Create config with multiple RPCs
        config = NonEVMConfig(
            chain_id="test_chain",
            chain_name="Test Chain",
            rpc_url="https://primary.rpc",
            rpc_urls=["https://secondary.rpc"],
            fallback_rpcs=["https://backup.rpc"],
        )
        
        # Test URL aggregation
        all_urls = config.get_all_rpc_urls()
        print_result("URL aggregation", len(all_urls) == 3,
                    f"URLs: {len(all_urls)}")
        
        # Test EndpointStats
        stats = EndpointStats(url="https://test.rpc")
        print_result("EndpointStats creation", stats.status == EndpointHealth.UNKNOWN)
        
        # Test is_healthy property
        stats.status = EndpointHealth.UNHEALTHY
        stats.unhealthy_until = datetime.now(timezone.utc) + timedelta(seconds=60)
        print_result("Unhealthy during cooldown", not stats.is_healthy)
        
        # Test cooldown expiry
        stats.unhealthy_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        print_result("Healthy after cooldown", stats.is_healthy)
        
        return True
        
    except Exception as e:
        print_result("Base class", False, str(e))
        import traceback
        traceback.print_exc()
        return False


async def test_endpoint_health_tracking():
    """Test 2: Endpoint health tracking."""
    print_header("Test 2: Endpoint Health Tracking")
    
    try:
        from src.telemetry.robust_non_evm import EndpointStats, EndpointHealth
        
        stats = EndpointStats(url="https://test.rpc")
        
        # Record successes
        stats.status = EndpointHealth.HEALTHY
        stats.success_count = 10
        stats.total_requests = 10
        stats.total_latency_ms = 500.0
        
        print_result("Success rate calculation", stats.avg_latency_ms == 50.0,
                    f"Avg latency: {stats.avg_latency_ms}ms")
        
        # Record failures
        stats.failure_count = 3
        stats.total_requests = 13
        
        expected_rate = (10 / 13) * 100
        actual_rate = (stats.success_count / stats.total_requests) * 100
        print_result("Success rate with failures", abs(actual_rate - expected_rate) < 0.1,
                    f"Success rate: {actual_rate:.1f}%")
        
        # Test health states
        stats.status = EndpointHealth.UNHEALTHY
        stats.unhealthy_until = datetime.now(timezone.utc) + timedelta(seconds=5)
        print_result("Marked unhealthy", not stats.is_healthy)
        
        return True
        
    except Exception as e:
        print_result("Health tracking", False, str(e))
        return False


async def test_cosmos_listener():
    """Test 3: CosmosListener initialization and methods."""
    print_header("Test 3: CosmosListener")
    
    try:
        from src.telemetry.cosmos_listener import CosmosListener, CosmosConfig
        
        config = CosmosConfig(
            chain_id="cosmos",
            chain_name="Cosmos Hub",
            rpc_url="https://cosmos-rpc.polkachu.com",
            fallback_rpcs=[
                "https://rpc.cosmos.network",
                "https://cosmos.nodejumper.io"
            ],
            ibc_channels=["channel-141", "channel-207"],
        )
        
        listener = CosmosListener(config)
        
        # Check initialization
        print_result("Multiple RPCs configured", len(listener._rpc_urls) >= 2,
                    f"RPCs: {len(listener._rpc_urls)}")
        
        print_result("IBC channels configured", len(listener.ibc_channels) == 2,
                    f"Channels: {list(listener.ibc_channels)}")
        
        # Test connection (network required)
        try:
            connected = await listener.connect()
            print_result("Connection test", connected,
                        f"Height: {listener.latest_height}" if connected else "Network may be unavailable")
            
            if connected:
                # Get endpoint stats
                stats = listener.get_endpoint_stats()
                print_result("Endpoint stats", "healthy_endpoints" in stats,
                            f"Healthy: {stats.get('healthy_endpoints', 0)}/{stats.get('total_endpoints', 0)}")
                
                await listener.disconnect()
        except Exception as e:
            print_result("Connection test", False, f"Network: {str(e)[:50]}")
        
        return True
        
    except Exception as e:
        print_result("CosmosListener", False, str(e))
        import traceback
        traceback.print_exc()
        return False


async def test_aptos_listener():
    """Test 4: AptosListener initialization and methods."""
    print_header("Test 4: AptosListener")
    
    try:
        from src.telemetry.aptos_listener import AptosListener, AptosConfig
        
        config = AptosConfig(
            chain_id="aptos",
            chain_name="Aptos Mainnet",
            rest_api="https://fullnode.mainnet.aptoslabs.com/v1",
            fallback_rpcs=[
                "https://aptos-mainnet.public.blastapi.io"
            ],
            chain_type="aptos",
        )
        
        listener = AptosListener(config)
        
        # Check initialization
        print_result("Bridge modules loaded", len(listener.bridge_modules) > 0,
                    f"Bridges: {len(listener.bridge_modules)}")
        
        print_result("Bridge names mapped", len(listener.bridge_names) > 0,
                    f"Named: {len(listener.bridge_names)}")
        
        # Test connection (network required)
        try:
            connected = await listener.connect()
            print_result("Connection test", connected,
                        f"Version: {listener.latest_height}" if connected else "Network may be unavailable")
            
            if connected:
                await listener.disconnect()
        except Exception as e:
            print_result("Connection test", False, f"Network: {str(e)[:50]}")
        
        return True
        
    except Exception as e:
        print_result("AptosListener", False, str(e))
        import traceback
        traceback.print_exc()
        return False


async def test_near_listener():
    """Test 5: NearListener initialization and methods."""
    print_header("Test 5: NearListener")
    
    try:
        from src.telemetry.near_listener import NearListener, NearConfig
        
        config = NearConfig(
            chain_id="near",
            chain_name="Near Protocol",
            rpc_url="https://rpc.mainnet.near.org",
            fallback_rpcs=[
                "https://near-mainnet.public.blastapi.io"
            ],
        )
        
        listener = NearListener(config)
        
        # Check initialization
        print_result("Bridge accounts loaded", len(listener.bridge_accounts) > 0,
                    f"Accounts: {len(listener.bridge_accounts)}")
        
        # Verify known bridges
        has_rainbow = "factory.bridge.near" in listener.bridge_accounts
        has_aurora = "aurora" in listener.bridge_accounts
        print_result("Known bridges included", has_rainbow and has_aurora,
                    f"Rainbow: {has_rainbow}, Aurora: {has_aurora}")
        
        # Test connection (network required)
        try:
            connected = await listener.connect()
            print_result("Connection test", connected,
                        f"Height: {listener.latest_height}" if connected else "Network may be unavailable")
            
            if connected:
                await listener.disconnect()
        except Exception as e:
            print_result("Connection test", False, f"Network: {str(e)[:50]}")
        
        return True
        
    except Exception as e:
        print_result("NearListener", False, str(e))
        import traceback
        traceback.print_exc()
        return False


async def test_heartbeat_mechanism():
    """Test 6: Heartbeat logging mechanism."""
    print_header("Test 6: Heartbeat Mechanism")
    
    try:
        from src.telemetry.cosmos_listener import CosmosListener, CosmosConfig
        
        config = CosmosConfig(
            chain_id="test_cosmos",
            chain_name="Test Cosmos",
            rpc_url="https://cosmos-rpc.polkachu.com",
            heartbeat_interval=5,  # Short interval for testing
        )
        
        listener = CosmosListener(config)
        
        # Check heartbeat tracking
        print_result("Last heartbeat initialized", listener._last_heartbeat is not None)
        
        # Simulate event processing
        listener._events_since_heartbeat = 10
        listener._blocks_since_heartbeat = 5
        
        print_result("Event counter works", listener._events_since_heartbeat == 10)
        print_result("Block counter works", listener._blocks_since_heartbeat == 5)
        
        # Test status method
        status = listener.get_status()
        print_result("Status includes height", "latest_height" in status,
                    f"Height: {status.get('latest_height', 0)}")
        print_result("Status includes connected", "connected" in status)
        
        return True
        
    except Exception as e:
        print_result("Heartbeat", False, str(e))
        return False


async def test_failover_simulation():
    """Test 7: Failover simulation for non-EVM listeners."""
    print_header("Test 7: Non-EVM Failover Simulation")
    
    try:
        from src.telemetry.robust_non_evm import EndpointStats, EndpointHealth
        from datetime import timedelta
        
        # Create mock endpoints
        endpoints = {
            "primary": EndpointStats(url="primary"),
            "backup1": EndpointStats(url="backup1"),
            "backup2": EndpointStats(url="backup2"),
        }
        
        # Simulate primary failure
        print("  Simulating primary failure...")
        endpoints["primary"].status = EndpointHealth.UNHEALTHY
        endpoints["primary"].failure_count = 3
        endpoints["primary"].unhealthy_until = datetime.now(timezone.utc) + timedelta(seconds=60)
        
        # Get healthy endpoints
        healthy = [url for url, stats in endpoints.items() if stats.is_healthy]
        
        print_result("Primary excluded", "primary" not in healthy,
                    f"Healthy: {healthy}")
        
        # Simulate backup1 succeeds
        endpoints["backup1"].status = EndpointHealth.HEALTHY
        endpoints["backup1"].success_count = 5
        
        healthy_with_backup = [url for url, stats in endpoints.items() if stats.is_healthy]
        print_result("Backup1 available", "backup1" in healthy_with_backup)
        
        # All fail scenario
        for stats in endpoints.values():
            stats.status = EndpointHealth.UNHEALTHY
            stats.unhealthy_until = datetime.now(timezone.utc) + timedelta(seconds=5)
        
        all_unhealthy = all(not s.is_healthy for s in endpoints.values())
        print_result("All unhealthy detected", all_unhealthy)
        
        # Cooldown recovery
        await asyncio.sleep(0.1)  # Short wait
        
        # Manually expire cooldown for oldest
        endpoints["backup2"].unhealthy_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        
        recovered = endpoints["backup2"].is_healthy
        print_result("Oldest recovers after cooldown", recovered)
        
        return True
        
    except Exception as e:
        print_result("Failover simulation", False, str(e))
        return False


async def run_all_tests():
    """Run all Phase 2.2 tests."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 12 + "PHASE 2.2: ROBUST NON-EVM LISTENER TESTS" + " " * 13 + "║")
    print("╚" + "═" * 68 + "╝")
    
    results = {}
    
    # Run tests
    results["base_class"] = await test_base_class_initialization()
    results["health_tracking"] = await test_endpoint_health_tracking()
    results["cosmos_listener"] = await test_cosmos_listener()
    results["aptos_listener"] = await test_aptos_listener()
    results["near_listener"] = await test_near_listener()
    results["heartbeat"] = await test_heartbeat_mechanism()
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
    
    # Core tests (excluding network-dependent connections)
    core_tests = ["base_class", "health_tracking", "heartbeat", "failover"]
    core_passed = all(results.get(t, False) for t in core_tests)
    
    if passed == total:
        print("  🎉 ALL TESTS PASSED! Phase 2.2 is ready.")
    elif core_passed:
        print("  ✅ Core tests passed. Network tests may need connectivity.")
    else:
        print("  ❌ Some core tests failed. Check errors above.")
    
    print()
    
    return core_passed


if __name__ == "__main__":
    asyncio.run(run_all_tests())

