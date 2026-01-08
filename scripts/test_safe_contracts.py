#!/usr/bin/env python3
"""
Phase 3.1 Test Script: Safe Contracts Collection
=================================================

Tests:
1. Output directory creation
2. Known protocols collection
3. Bytecode file saving
4. Metadata generation
5. Category distribution
6. Bytecode hash uniqueness

Run with: python scripts/test_safe_contracts.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

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


def test_output_directory():
    """Test 1: Output directory exists."""
    print_header("Test 1: Output Directory")
    
    output_dir = Path(__file__).parent.parent / "src" / "ai" / "data" / "safe_samples"
    
    print_result("Directory exists", output_dir.exists(),
                f"Path: {output_dir}")
    
    if output_dir.exists():
        files = list(output_dir.glob("*.bin"))
        print_result("Bytecode files present", len(files) > 0,
                    f"Files: {len(files)}")
        
        metadata_file = output_dir / "metadata.json"
        print_result("Metadata file exists", metadata_file.exists())
        
        return len(files) > 0 and metadata_file.exists()
    return False


def test_metadata_structure():
    """Test 2: Metadata structure."""
    print_header("Test 2: Metadata Structure")
    
    metadata_file = Path(__file__).parent.parent / "src" / "ai" / "data" / "safe_samples" / "metadata.json"
    
    if not metadata_file.exists():
        print_result("Metadata file", False, "File not found")
        return False
    
    try:
        with open(metadata_file) as f:
            data = json.load(f)
        
        required_keys = ["version", "collected_at", "total_contracts", "contracts"]
        has_keys = all(k in data for k in required_keys)
        print_result("Required keys present", has_keys,
                    f"Keys: {list(data.keys())}")
        
        print_result("Total contracts count", data["total_contracts"] > 0,
                    f"Count: {data['total_contracts']}")
        
        # Check contract structure
        if data["contracts"]:
            sample_addr = list(data["contracts"].keys())[0]
            sample = data["contracts"][sample_addr]
            
            contract_keys = ["address", "chain", "bytecode_hash", "bytecode_length", "category"]
            has_contract_keys = all(k in sample for k in contract_keys)
            print_result("Contract has required fields", has_contract_keys,
                        f"Sample: {sample.get('name', sample_addr[:20])}")
        
        return has_keys and data["total_contracts"] > 0
        
    except Exception as e:
        print_result("Metadata parsing", False, str(e))
        return False


def test_category_distribution():
    """Test 3: Category distribution."""
    print_header("Test 3: Category Distribution")
    
    metadata_file = Path(__file__).parent.parent / "src" / "ai" / "data" / "safe_samples" / "metadata.json"
    
    try:
        with open(metadata_file) as f:
            data = json.load(f)
        
        by_category = data.get("by_category", {})
        
        print_result("Categories tracked", len(by_category) > 0,
                    f"Categories: {list(by_category.keys())}")
        
        # Check for expected categories
        expected = {"dex", "lending", "token"}
        found = set(by_category.keys())
        has_expected = len(expected.intersection(found)) >= 2
        
        print_result("Expected categories present", has_expected,
                    f"Found: {found}")
        
        # Check distribution
        total = sum(by_category.values())
        print_result("Category counts sum correctly", total == data["total_contracts"],
                    f"Sum: {total}, Total: {data['total_contracts']}")
        
        return len(by_category) > 0
        
    except Exception as e:
        print_result("Category test", False, str(e))
        return False


def test_bytecode_files():
    """Test 4: Bytecode files."""
    print_header("Test 4: Bytecode Files")
    
    output_dir = Path(__file__).parent.parent / "src" / "ai" / "data" / "safe_samples"
    metadata_file = output_dir / "metadata.json"
    
    try:
        with open(metadata_file) as f:
            data = json.load(f)
        
        # Check that bytecode files exist for contracts in metadata
        missing = []
        present = []
        
        for addr, contract in list(data["contracts"].items())[:10]:  # Check first 10
            chain = contract["chain"]
            expected_file = output_dir / f"{chain}_{addr}.bin"
            
            if expected_file.exists():
                present.append(addr)
            else:
                missing.append(addr)
        
        print_result("Bytecode files match metadata", len(missing) == 0,
                    f"Present: {len(present)}, Missing: {len(missing)}")
        
        # Check file sizes
        if present:
            test_file = output_dir / f"{data['contracts'][present[0]]['chain']}_{present[0]}.bin"
            with open(test_file) as f:
                content = f.read()
            
            starts_with_0x = content.startswith("0x")
            print_result("Bytecode format correct", starts_with_0x,
                        f"Length: {len(content)} chars")
            
            return starts_with_0x
        
        return False
        
    except Exception as e:
        print_result("Bytecode test", False, str(e))
        return False


def test_hash_uniqueness():
    """Test 5: Bytecode hash uniqueness."""
    print_header("Test 5: Hash Uniqueness")
    
    metadata_file = Path(__file__).parent.parent / "src" / "ai" / "data" / "safe_samples" / "metadata.json"
    
    try:
        with open(metadata_file) as f:
            data = json.load(f)
        
        hashes = [c["bytecode_hash"] for c in data["contracts"].values()]
        unique_hashes = set(hashes)
        
        # Allow some duplicates (proxy contracts may share implementation)
        duplicate_rate = 1 - (len(unique_hashes) / len(hashes)) if hashes else 0
        
        print_result("Hashes collected", len(hashes) > 0,
                    f"Total: {len(hashes)}, Unique: {len(unique_hashes)}")
        
        print_result("Low duplicate rate", duplicate_rate < 0.3,
                    f"Duplicate rate: {duplicate_rate:.1%}")
        
        return len(unique_hashes) > 0
        
    except Exception as e:
        print_result("Hash test", False, str(e))
        return False


async def test_collector_class():
    """Test 6: Collector class functionality."""
    print_header("Test 6: Collector Class")
    
    try:
        from scripts.collect_safe_contracts import (
            SafeContractCollector,
            KNOWN_SAFE_PROTOCOLS,
            ContractCategory
        )
        
        # Test initialization
        collector = SafeContractCollector(chains=["ethereum"])
        print_result("Collector initialized", collector is not None)
        
        # Test known protocols
        eth_protocols = KNOWN_SAFE_PROTOCOLS.get("ethereum", {})
        print_result("Known protocols loaded", len(eth_protocols) > 0,
                    f"Ethereum: {len(eth_protocols)} protocols")
        
        # Test categories
        categories = list(ContractCategory)
        print_result("Categories defined", len(categories) >= 5,
                    f"Categories: {[c.value for c in categories]}")
        
        # Test stats
        stats = collector.get_stats()
        print_result("Stats method works", "total" in stats,
                    f"Total: {stats.get('total', 0)}")
        
        return True
        
    except Exception as e:
        print_result("Collector class", False, str(e))
        import traceback
        traceback.print_exc()
        return False


async def run_all_tests():
    """Run all Phase 3.1 tests."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 12 + "PHASE 3.1: SAFE CONTRACTS TESTS" + " " * 21 + "║")
    print("╚" + "═" * 68 + "╝")
    
    results = {}
    
    # Run tests
    results["output_dir"] = test_output_directory()
    results["metadata"] = test_metadata_structure()
    results["categories"] = test_category_distribution()
    results["bytecode_files"] = test_bytecode_files()
    results["hash_uniqueness"] = test_hash_uniqueness()
    results["collector_class"] = await test_collector_class()
    
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
        print("  🎉 ALL TESTS PASSED! Phase 3.1 is ready.")
    elif passed >= 4:
        print("  ✅ Core tests passed.")
    else:
        print("  ❌ Some tests failed. Run collection first.")
    
    print()
    
    return passed >= 4


if __name__ == "__main__":
    asyncio.run(run_all_tests())

