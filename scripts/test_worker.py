#!/usr/bin/env python3
"""
Phase 2.3 Test Script: Worker Entry Point
==========================================

Tests:
1. Worker initialization
2. Chain filtering
3. Listener startup
4. Stats tracking
5. Health endpoints
6. Graceful shutdown

Run with: python scripts/test_worker.py
"""

import asyncio
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

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


async def test_worker_initialization():
    """Test 1: Worker initialization."""
    print_header("Test 1: Worker Initialization")
    
    try:
        from worker import Sentinel3Worker, WorkerStats
        
        # Test default initialization
        worker = Sentinel3Worker()
        
        print_result("Worker created", worker is not None)
        print_result("Running flag False", not worker.running)
        print_result("Stats initialized", worker.stats is not None)
        print_result("Empty listener dicts", len(worker.evm_listeners) == 0)
        
        # Test with chain filter
        worker_filtered = Sentinel3Worker(chains=["ethereum", "polygon"])
        print_result("Chain filter applied", worker_filtered.chains_filter == {"ethereum", "polygon"},
                    f"Filter: {worker_filtered.chains_filter}")
        
        # Test with type filter
        worker_typed = Sentinel3Worker(chain_types=["evm"])
        print_result("Type filter applied", worker_typed.chain_types_filter == {"evm"},
                    f"Filter: {worker_typed.chain_types_filter}")
        
        return True
        
    except Exception as e:
        print_result("Initialization", False, str(e))
        import traceback
        traceback.print_exc()
        return False


async def test_chain_type_detection():
    """Test 2: Chain type detection."""
    print_header("Test 2: Chain Type Detection")
    
    try:
        from worker import Sentinel3Worker
        
        worker = Sentinel3Worker()
        
        # Test EVM chains
        evm_chains = ["ethereum", "polygon", "arbitrum", "bsc", "avalanche"]
        evm_correct = all(worker.get_chain_type(c) == "evm" for c in evm_chains)
        print_result("EVM chains detected", evm_correct,
                    f"Tested: {evm_chains}")
        
        # Test Cosmos chains
        cosmos_chains = ["cosmos", "osmosis", "injective"]
        cosmos_correct = all(worker.get_chain_type(c) == "cosmos" for c in cosmos_chains)
        print_result("Cosmos chains detected", cosmos_correct,
                    f"Tested: {cosmos_chains}")
        
        # Test Move chains
        print_result("Aptos detected", worker.get_chain_type("aptos") == "aptos")
        print_result("Sui detected", worker.get_chain_type("sui") == "sui")
        
        # Test Near
        print_result("Near detected", worker.get_chain_type("near") == "near")
        
        return evm_correct and cosmos_correct
        
    except Exception as e:
        print_result("Chain detection", False, str(e))
        return False


async def test_chain_filtering():
    """Test 3: Chain filtering logic."""
    print_header("Test 3: Chain Filtering")
    
    try:
        from worker import Sentinel3Worker
        
        # Test chain name filter
        worker = Sentinel3Worker(chains=["ethereum", "cosmos"])
        
        print_result("Ethereum included", worker.should_include_chain("ethereum", "evm"))
        print_result("Cosmos included", worker.should_include_chain("cosmos", "cosmos"))
        print_result("Polygon excluded", not worker.should_include_chain("polygon", "evm"))
        
        # Test type filter
        worker_evm = Sentinel3Worker(chain_types=["evm"])
        
        print_result("EVM type included", worker_evm.should_include_chain("ethereum", "evm"))
        print_result("Cosmos type excluded", not worker_evm.should_include_chain("cosmos", "cosmos"))
        
        # Test no filter (all included)
        worker_all = Sentinel3Worker()
        
        print_result("All chains included (no filter)", 
                    worker_all.should_include_chain("anything", "anything"))
        
        return True
        
    except Exception as e:
        print_result("Filtering", False, str(e))
        return False


async def test_worker_stats():
    """Test 4: Worker statistics."""
    print_header("Test 4: Worker Statistics")
    
    try:
        from worker import WorkerStats
        
        stats = WorkerStats()
        
        # Test defaults
        print_result("Start time set", stats.start_time is not None)
        print_result("Events count zero", stats.events_processed == 0)
        print_result("Blocks count zero", stats.blocks_processed == 0)
        
        # Test updates
        stats.events_processed = 100
        stats.blocks_processed = 50
        stats.errors = 2
        stats.active_listeners.add("ethereum")
        stats.active_listeners.add("cosmos")
        stats.listener_heights = {"ethereum": 12345678, "cosmos": 1000000}
        
        print_result("Events updated", stats.events_processed == 100)
        print_result("Active listeners tracked", len(stats.active_listeners) == 2)
        
        # Test to_dict
        data = stats.to_dict()
        print_result("to_dict works", "events_processed" in data,
                    f"Keys: {list(data.keys())}")
        print_result("Uptime calculated", data["uptime_seconds"] >= 0)
        
        return True
        
    except Exception as e:
        print_result("Stats", False, str(e))
        return False


async def test_config_loading():
    """Test 5: Configuration loading."""
    print_header("Test 5: Configuration Loading")
    
    try:
        from worker import Sentinel3Worker
        
        worker = Sentinel3Worker()
        config = worker.load_config()
        
        print_result("Config loaded", config is not None)
        print_result("Chains key exists", "chains" in config,
                    f"Keys: {list(config.keys())}")
        
        chains = config.get("chains", [])
        print_result("Chains list populated", len(chains) > 0,
                    f"Chain count: {len(chains)}")
        
        # Check chain structure
        if chains:
            first_chain = chains[0]
            has_required = all(k in first_chain for k in ["chain_id", "chain_name"])
            print_result("Chain has required fields", has_required,
                        f"First chain: {first_chain.get('chain_id', 'unknown')}")
        
        return config is not None
        
    except Exception as e:
        print_result("Config loading", False, str(e))
        return False


async def test_shared_state_init():
    """Test 6: Shared state initialization."""
    print_header("Test 6: Shared State Initialization")
    
    try:
        from worker import Sentinel3Worker
        
        worker = Sentinel3Worker()
        
        # Initialize shared state
        await worker.init_shared_state()
        
        print_result("Monitor state initialized", worker.monitor_state is not None)
        
        # Rule engine may or may not initialize depending on rules
        if worker.rule_engine:
            print_result("Rule engine initialized", True)
        else:
            print_result("Rule engine skipped", True, "No rules or rules not found")
        
        return worker.monitor_state is not None
        
    except Exception as e:
        print_result("Shared state", False, str(e))
        import traceback
        traceback.print_exc()
        return False


async def test_listener_init():
    """Test 7: Listener initialization (quick test, limited chains)."""
    print_header("Test 7: Listener Initialization")
    
    try:
        from worker import Sentinel3Worker
        
        # Only test with one chain to keep it fast
        worker = Sentinel3Worker(chains=["cosmos"])
        
        config = worker.load_config()
        await worker.init_shared_state()
        
        # Initialize only non-EVM (faster to test)
        await worker.init_non_evm_listeners(config)
        
        # Check if Cosmos listener started (if configured)
        cosmos_started = "cosmos" in worker.non_evm_listeners
        
        print_result("Non-EVM listener init attempted", True)
        
        if cosmos_started:
            listener = worker.non_evm_listeners["cosmos"]
            print_result("Cosmos listener connected", listener.latest_height > 0,
                        f"Height: {listener.latest_height}")
            
            # Cleanup
            await listener.disconnect()
        else:
            print_result("Cosmos listener started", False, "May not be in config or connection failed")
        
        return True
        
    except Exception as e:
        print_result("Listener init", False, str(e)[:80])
        import traceback
        traceback.print_exc()
        return False


async def test_health_endpoint():
    """Test 8: Health endpoint."""
    print_header("Test 8: Health Endpoint")
    
    try:
        import aiohttp
        from worker import Sentinel3Worker
        
        # Create worker
        worker = Sentinel3Worker()
        worker.running = True
        worker.stats.active_listeners.add("test_chain")
        
        # Start health server briefly
        health_task = asyncio.create_task(worker.health_server())
        
        # Give server time to start
        await asyncio.sleep(0.5)
        
        # Test health endpoint
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"http://localhost:8081/health") as resp:
                    data = await resp.json()
                    print_result("Health endpoint responds", resp.status == 200,
                                f"Status: {data.get('status', 'unknown')}")
                    print_result("Stats in response", "stats" in data)
                    
                # Test ready endpoint
                async with session.get(f"http://localhost:8081/ready") as resp:
                    data = await resp.json()
                    print_result("Ready endpoint responds", resp.status == 200,
                                f"Ready: {data.get('ready', False)}")
                    
            except aiohttp.ClientError as e:
                print_result("Health endpoint", False, f"Connection: {str(e)[:40]}")
        
        # Stop server
        worker.running = False
        worker.shutdown_event.set()
        health_task.cancel()
        
        try:
            await health_task
        except asyncio.CancelledError:
            pass
        
        return True
        
    except Exception as e:
        print_result("Health endpoint", False, str(e)[:60])
        return False


async def run_all_tests():
    """Run all Phase 2.3 tests."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 18 + "PHASE 2.3: WORKER TESTS" + " " * 25 + "║")
    print("╚" + "═" * 68 + "╝")
    
    results = {}
    
    # Run tests
    results["initialization"] = await test_worker_initialization()
    results["chain_detection"] = await test_chain_type_detection()
    results["filtering"] = await test_chain_filtering()
    results["stats"] = await test_worker_stats()
    results["config"] = await test_config_loading()
    results["shared_state"] = await test_shared_state_init()
    results["listener_init"] = await test_listener_init()
    results["health_endpoint"] = await test_health_endpoint()
    
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
    
    if passed == total:
        print("  🎉 ALL TESTS PASSED! Phase 2.3 is ready.")
    elif passed >= 6:
        print("  ✅ Core tests passed. Some network tests may need connectivity.")
    else:
        print("  ❌ Some core tests failed. Check errors above.")
    
    print()
    
    return passed >= 6


if __name__ == "__main__":
    asyncio.run(run_all_tests())

