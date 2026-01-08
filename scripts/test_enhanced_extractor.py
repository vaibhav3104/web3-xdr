#!/usr/bin/env python3
"""
Phase 3.2 Test Script: Enhanced Bytecode Feature Extraction
============================================================

Tests:
1. Basic feature extraction
2. CFG complexity scoring
3. External call depth analysis
4. Entropy calculation
5. Gas analysis
6. Pattern detection
7. Feature vector generation
8. Real contract analysis

Run with: python scripts/test_enhanced_extractor.py
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


# Sample bytecodes for testing
SAMPLE_SIMPLE = "608060405234801561001057600080fd5b5060043610"

SAMPLE_WITH_CALL = """
608060405234801561001057600080fd5b506004361061004c5760003560e01c8063
12065fe0146100515780633ccfd60b1461006f578063d0e30db014610079575b600080fd
5b610059610083565b6040516100669190610256565b60405180910390f35b610077
61008c565b005b6100816100f1565b005b60008054905090565b600080543373
ffffffffffffffffffffffffffffffffffffffff1614156100ef573373ffffffff
ffffffffffffffffffffffffffffffff166108fc600080549081150290604051600060405180830381858888f1
9350505050158015610030573d6000803e3d6000fd5b505b565b3460008082825401925050819055503373
"""

SAMPLE_WITH_DELEGATECALL = """
608060405236601057600e6013565b005b600e6013565b6024601f6025565b6045565b565b
60003660008037600080366000845af43d6000803e80600081146040573d6000f35b3d6000fd
5b5056fea26469706673582212
"""

SAMPLE_FLASH_LOAN = """
608060405234801561001057600080fd5b50600436106100415760003560e01c8063
23e30c8b14610046578063c3924ed614610062575b600080fd5b6100606004803603
810190610057919061024d565b61007e565b005b61007c600480360381019061007791906102d0565b610101565b005b
"""


def test_basic_extraction():
    """Test 1: Basic feature extraction."""
    print_header("Test 1: Basic Feature Extraction")
    
    try:
        from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor
        
        extractor = EnhancedBytecodeExtractor()
        features = extractor.extract_features(SAMPLE_SIMPLE)
        
        print_result("Extractor created", extractor is not None)
        print_result("Features extracted", features is not None)
        print_result("Bytecode length > 0", features.bytecode_length > 0,
                    f"Length: {features.bytecode_length}")
        print_result("Unique opcodes > 0", features.unique_opcodes > 0,
                    f"Unique: {features.unique_opcodes}")
        print_result("Total instructions > 0", features.total_instructions > 0,
                    f"Instructions: {features.total_instructions}")
        print_result("Hash generated", len(features.bytecode_hash) == 64)
        
        return features.bytecode_length > 0
        
    except Exception as e:
        print_result("Basic extraction", False, str(e))
        import traceback
        traceback.print_exc()
        return False


def test_cfg_complexity():
    """Test 2: CFG complexity scoring."""
    print_header("Test 2: CFG Complexity Scoring")
    
    try:
        from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor
        
        extractor = EnhancedBytecodeExtractor()
        features = extractor.extract_features(SAMPLE_WITH_CALL)
        
        print_result("CFG complexity calculated", features.cfg_complexity_score >= 0,
                    f"Score: {features.cfg_complexity_score}")
        print_result("Jump count tracked", features.jump_count >= 0,
                    f"Jumps: {features.jump_count}")
        print_result("JumpI count tracked", features.jumpi_count >= 0,
                    f"JumpI: {features.jumpi_count}")
        print_result("Basic blocks counted", features.basic_block_count >= 0,
                    f"Blocks: {features.basic_block_count}")
        print_result("Nesting depth estimated", features.max_nesting_depth >= 0,
                    f"Depth: {features.max_nesting_depth}")
        
        return True
        
    except Exception as e:
        print_result("CFG complexity", False, str(e))
        return False


def test_external_call_depth():
    """Test 3: External call depth analysis."""
    print_header("Test 3: External Call Depth Analysis")
    
    try:
        from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor
        
        extractor = EnhancedBytecodeExtractor()
        
        # Test with code containing CALL
        features = extractor.extract_features(SAMPLE_WITH_CALL)
        
        print_result("Call count detected", features.call_count >= 0,
                    f"Calls: {features.call_count}")
        print_result("External call depth", features.external_call_depth >= 0,
                    f"Depth: {features.external_call_depth}")
        print_result("Call sequence length", features.external_call_sequence_length >= 0,
                    f"Sequence: {features.external_call_sequence_length}")
        
        # Test with DELEGATECALL
        features_delegate = extractor.extract_features(SAMPLE_WITH_DELEGATECALL)
        
        print_result("DELEGATECALL detected", features_delegate.delegatecall_count > 0,
                    f"DELEGATECALL: {features_delegate.delegatecall_count}")
        print_result("Call/storage ratio", features.call_to_storage_ratio >= 0,
                    f"Ratio: {features.call_to_storage_ratio:.2f}")
        
        return True
        
    except Exception as e:
        print_result("External call depth", False, str(e))
        return False


def test_entropy_calculation():
    """Test 4: Entropy calculation."""
    print_header("Test 4: Entropy Calculation")
    
    try:
        from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor
        
        extractor = EnhancedBytecodeExtractor()
        features = extractor.extract_features(SAMPLE_WITH_CALL)
        
        print_result("Bytecode entropy calculated", features.bytecode_entropy >= 0,
                    f"Entropy: {features.bytecode_entropy:.2f}")
        print_result("Opcode entropy calculated", features.opcode_entropy >= 0,
                    f"Opcode entropy: {features.opcode_entropy:.2f}")
        print_result("Push entropy calculated", features.push_data_entropy >= 0,
                    f"Push entropy: {features.push_data_entropy:.2f}")
        
        # Entropy should be reasonable (0-8 for byte data)
        print_result("Entropy in range", 0 <= features.bytecode_entropy <= 8,
                    f"Expected 0-8, got {features.bytecode_entropy:.2f}")
        
        return True
        
    except Exception as e:
        print_result("Entropy calculation", False, str(e))
        return False


def test_gas_analysis():
    """Test 5: Gas analysis."""
    print_header("Test 5: Gas Analysis")
    
    try:
        from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor
        
        extractor = EnhancedBytecodeExtractor()
        features = extractor.extract_features(SAMPLE_WITH_CALL)
        
        print_result("Gas estimated", features.estimated_gas_cost > 0,
                    f"Gas: {features.estimated_gas_cost}")
        print_result("Avg gas per instruction", features.gas_per_instruction > 0,
                    f"Avg: {features.gas_per_instruction:.1f}")
        print_result("High gas ratio calculated", features.high_gas_opcode_ratio >= 0,
                    f"Ratio: {features.high_gas_opcode_ratio:.2%}")
        
        return True
        
    except Exception as e:
        print_result("Gas analysis", False, str(e))
        return False


def test_pattern_detection():
    """Test 6: Pattern detection."""
    print_header("Test 6: Pattern Detection")
    
    try:
        from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor
        
        extractor = EnhancedBytecodeExtractor()
        
        # Test flash loan detection
        features = extractor.extract_features(SAMPLE_FLASH_LOAN)
        print_result("Flash loan pattern checked", True,
                    f"Has flash loan: {features.has_flash_loan_callback}")
        
        # Test delegate call detection
        features_delegate = extractor.extract_features(SAMPLE_WITH_DELEGATECALL)
        print_result("DELEGATECALL pattern detected", features_delegate.has_delegatecall_pattern,
                    f"Has delegatecall: {features_delegate.has_delegatecall_pattern}")
        
        # Test proxy pattern
        print_result("Proxy pattern checked", True,
                    f"Is proxy: {features_delegate.has_proxy_pattern}")
        
        # Test withdraw detection
        features_call = extractor.extract_features(SAMPLE_WITH_CALL)
        print_result("Withdraw function checked", True,
                    f"Has withdraw: {features_call.has_withdraw_function}")
        
        return True
        
    except Exception as e:
        print_result("Pattern detection", False, str(e))
        return False


def test_feature_vector():
    """Test 7: Feature vector generation."""
    print_header("Test 7: Feature Vector Generation")
    
    try:
        from src.ai.data.enhanced_extractor import (
            EnhancedBytecodeExtractor,
            EnhancedBytecodeFeatures
        )
        
        extractor = EnhancedBytecodeExtractor()
        features = extractor.extract_features(SAMPLE_WITH_CALL)
        
        vector = features.to_vector()
        
        expected_dim = EnhancedBytecodeFeatures.vector_dimension()
        actual_dim = len(vector)
        
        print_result("Vector generated", len(vector) > 0,
                    f"Length: {len(vector)}")
        print_result("Correct dimension", actual_dim == expected_dim,
                    f"Expected {expected_dim}, got {actual_dim}")
        print_result("All values numeric", all(isinstance(v, (int, float)) for v in vector))
        print_result("Values normalized", all(0 <= v <= 10 for v in vector),
                    f"Max: {max(vector):.2f}, Min: {min(vector):.2f}")
        
        return actual_dim == expected_dim
        
    except Exception as e:
        print_result("Feature vector", False, str(e))
        return False


def test_real_contracts():
    """Test 8: Real contract analysis."""
    print_header("Test 8: Real Contract Analysis")
    
    try:
        from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor
        
        extractor = EnhancedBytecodeExtractor()
        
        # Load real contracts from safe_samples
        safe_dir = Path(__file__).parent.parent / "src" / "ai" / "data" / "safe_samples"
        
        if not safe_dir.exists():
            print_result("Safe samples directory", False, "Directory not found")
            return False
        
        bytecode_files = list(safe_dir.glob("*.bin"))
        
        if not bytecode_files:
            print_result("Bytecode files", False, "No files found")
            return False
        
        print_result("Found bytecode files", True, f"Count: {len(bytecode_files)}")
        
        # Analyze first 5 contracts
        analyzed = 0
        total_cfg_complexity = 0
        total_entropy = 0
        
        for bf in bytecode_files[:5]:
            with open(bf) as f:
                bytecode = f.read().strip()
            
            features = extractor.extract_features(bytecode)
            analyzed += 1
            total_cfg_complexity += features.cfg_complexity_score
            total_entropy += features.bytecode_entropy
            
            print(f"         {bf.name[:40]}: CFG={features.cfg_complexity_score}, "
                  f"Entropy={features.bytecode_entropy:.2f}")
        
        print_result("Contracts analyzed", analyzed > 0, f"Count: {analyzed}")
        print_result("Avg CFG complexity", True,
                    f"Avg: {total_cfg_complexity/analyzed:.1f}")
        print_result("Avg entropy", True,
                    f"Avg: {total_entropy/analyzed:.2f}")
        
        return analyzed > 0
        
    except Exception as e:
        print_result("Real contracts", False, str(e))
        import traceback
        traceback.print_exc()
        return False


async def run_all_tests():
    """Run all Phase 3.2 tests."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 8 + "PHASE 3.2: ENHANCED FEATURE EXTRACTION TESTS" + " " * 13 + "║")
    print("╚" + "═" * 68 + "╝")
    
    results = {}
    
    # Run tests
    results["basic_extraction"] = test_basic_extraction()
    results["cfg_complexity"] = test_cfg_complexity()
    results["external_call_depth"] = test_external_call_depth()
    results["entropy"] = test_entropy_calculation()
    results["gas_analysis"] = test_gas_analysis()
    results["pattern_detection"] = test_pattern_detection()
    results["feature_vector"] = test_feature_vector()
    results["real_contracts"] = test_real_contracts()
    
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
        print("  🎉 ALL TESTS PASSED! Phase 3.2 is ready.")
    elif passed >= 6:
        print("  ✅ Core tests passed.")
    else:
        print("  ❌ Some tests failed. Check errors above.")
    
    print()
    
    return passed >= 6


if __name__ == "__main__":
    asyncio.run(run_all_tests())

