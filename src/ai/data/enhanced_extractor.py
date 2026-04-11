"""
Enhanced Bytecode Feature Extractor
===================================

Phase 3.2: Adds advanced features for ML classification:
- CFG (Control Flow Graph) complexity score
- External call depth analysis
- Loop detection
- Code entropy/randomness
- Gas-based heuristics
- Advanced pattern detection

These features improve ML model accuracy for detecting:
- Flash loan exploits
- Reentrancy attacks
- Price manipulation
- Bridge exploits
"""

import re
import math
from collections import Counter
from typing import Dict, List, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib


# =============================================================================
# EVM OPCODES
# =============================================================================

class Opcode(Enum):
    """EVM Opcodes with gas costs and categories."""
    # Arithmetic
    ADD = ("01", 3, "arithmetic")
    MUL = ("02", 5, "arithmetic")
    SUB = ("03", 3, "arithmetic")
    DIV = ("04", 5, "arithmetic")
    MOD = ("06", 5, "arithmetic")
    EXP = ("0a", 10, "arithmetic")
    
    # Comparison
    LT = ("10", 3, "comparison")
    GT = ("11", 3, "comparison")
    EQ = ("14", 3, "comparison")
    ISZERO = ("15", 3, "comparison")
    
    # Bitwise
    AND = ("16", 3, "bitwise")
    OR = ("17", 3, "bitwise")
    XOR = ("18", 3, "bitwise")
    NOT = ("19", 3, "bitwise")
    SHL = ("1b", 3, "bitwise")
    SHR = ("1c", 3, "bitwise")
    
    # Crypto
    SHA3 = ("20", 30, "crypto")
    
    # Environment
    ADDRESS = ("30", 2, "environment")
    BALANCE = ("31", 400, "environment")
    ORIGIN = ("32", 2, "environment")
    CALLER = ("33", 2, "environment")
    CALLVALUE = ("34", 2, "environment")
    CALLDATALOAD = ("35", 3, "environment")
    CALLDATASIZE = ("36", 2, "environment")
    CODESIZE = ("38", 2, "environment")
    GASPRICE = ("3a", 2, "environment")
    EXTCODESIZE = ("3b", 700, "environment")
    EXTCODECOPY = ("3c", 700, "environment")
    SELFBALANCE = ("47", 5, "environment")
    
    # Block
    BLOCKHASH = ("40", 20, "block")
    COINBASE = ("41", 2, "block")
    TIMESTAMP = ("42", 2, "block")
    NUMBER = ("43", 2, "block")
    
    # Storage
    SLOAD = ("54", 800, "storage")
    SSTORE = ("55", 20000, "storage")
    
    # Memory
    MLOAD = ("51", 3, "memory")
    MSTORE = ("52", 3, "memory")
    MSTORE8 = ("53", 3, "memory")
    
    # Control flow
    JUMP = ("56", 8, "control")
    JUMPI = ("57", 10, "control")
    JUMPDEST = ("5b", 1, "control")
    PC = ("58", 2, "control")
    
    # Stack
    POP = ("50", 2, "stack")
    DUP1 = ("80", 3, "stack")
    SWAP1 = ("90", 3, "stack")
    
    # Log
    LOG0 = ("a0", 375, "log")
    LOG1 = ("a1", 750, "log")
    LOG2 = ("a2", 1125, "log")
    LOG3 = ("a3", 1500, "log")
    LOG4 = ("a4", 1875, "log")
    
    # Calls (External interactions)
    CALL = ("f1", 700, "call")
    CALLCODE = ("f2", 700, "call")
    DELEGATECALL = ("f4", 700, "call")
    STATICCALL = ("fa", 700, "call")
    
    # Create
    CREATE = ("f0", 32000, "create")
    CREATE2 = ("f5", 32000, "create")
    
    # Return/Revert
    RETURN = ("f3", 0, "return")
    REVERT = ("fd", 0, "return")
    INVALID = ("fe", 0, "return")
    SELFDESTRUCT = ("ff", 5000, "destroy")


# Opcode lookup tables
OPCODE_TO_NAME = {op.value[0]: op.name for op in Opcode}
OPCODE_GAS = {op.value[0]: op.value[1] for op in Opcode}
OPCODE_CATEGORY = {op.value[0]: op.value[2] for op in Opcode}


# =============================================================================
# ENHANCED FEATURES
# =============================================================================

@dataclass
class EnhancedBytecodeFeatures:
    """Enhanced features for ML classification."""
    
    # ===== Basic Metrics =====
    bytecode_length: int = 0
    unique_opcodes: int = 0
    total_instructions: int = 0
    
    # ===== Opcode Counts =====
    call_count: int = 0
    delegatecall_count: int = 0
    staticcall_count: int = 0
    create_count: int = 0
    create2_count: int = 0
    sload_count: int = 0
    sstore_count: int = 0
    selfdestruct_count: int = 0
    
    # ===== CFG Complexity (NEW) =====
    cfg_complexity_score: float = 0.0  # Cyclomatic complexity estimate
    jump_count: int = 0
    jumpi_count: int = 0
    jumpdest_count: int = 0
    basic_block_count: int = 0
    max_nesting_depth: int = 0
    loop_count: int = 0
    
    # ===== External Call Depth (NEW) =====
    external_call_depth: int = 0  # Max depth of nested calls
    external_call_sequence_length: int = 0  # Longest call sequence
    call_to_storage_ratio: float = 0.0  # CALLs / (SLOADs + SSTOREs)
    
    # ===== Code Entropy (NEW) =====
    bytecode_entropy: float = 0.0  # Shannon entropy
    opcode_entropy: float = 0.0  # Opcode distribution entropy
    push_data_entropy: float = 0.0  # Entropy of PUSH data
    
    # ===== Gas Analysis (NEW) =====
    estimated_gas_cost: int = 0
    gas_per_instruction: float = 0.0
    high_gas_opcode_ratio: float = 0.0  # Ratio of expensive opcodes
    
    # ===== Pattern Detection =====
    function_count: int = 0
    has_flash_loan_callback: bool = False
    has_withdraw_function: bool = False
    has_mint_function: bool = False
    has_burn_function: bool = False
    has_admin_functions: bool = False
    has_proxy_pattern: bool = False  # NEW
    has_factory_pattern: bool = False  # NEW
    
    # ===== Risk Analysis =====
    has_reentrancy_pattern: bool = False
    has_delegatecall_pattern: bool = False
    has_selfdestruct: bool = False
    has_unchecked_call: bool = False  # NEW
    has_timestamp_dependency: bool = False  # NEW
    
    # ===== Advanced Metrics (NEW) =====
    code_density: float = 0.0  # Instructions / bytecode length
    storage_intensity: float = 0.0  # Storage ops / total ops
    external_interaction_ratio: float = 0.0  # Calls / total ops
    
    # ===== Risk Scoring =====
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    
    # ===== Metadata =====
    bytecode_hash: str = ""
    
    def to_vector(self) -> List[float]:
        """Convert to normalized feature vector for ML."""
        return [
            # Basic (4)
            self.bytecode_length / 50000,
            self.unique_opcodes / 100,
            self.total_instructions / 10000,
            min(self.code_density, 1.0),  # Cap at 1.0
            
            # Opcode counts (8)
            self.call_count / 50,
            self.delegatecall_count / 10,
            self.staticcall_count / 20,
            self.create_count / 5,
            self.create2_count / 5,
            self.sload_count / 200,
            self.sstore_count / 200,
            self.selfdestruct_count,
            
            # CFG Complexity (6)
            self.cfg_complexity_score / 100,
            self.jump_count / 100,
            self.jumpi_count / 50,
            self.basic_block_count / 200,
            self.max_nesting_depth / 10,
            self.loop_count / 20,
            
            # External Call Depth (3)
            self.external_call_depth / 5,
            self.external_call_sequence_length / 10,
            self.call_to_storage_ratio,
            
            # Entropy (3)
            self.bytecode_entropy / 8,  # Max ~8 for byte entropy
            self.opcode_entropy / 8,
            self.push_data_entropy / 8,
            
            # Gas (3)
            self.estimated_gas_cost / 1000000,
            self.gas_per_instruction / 1000,
            self.high_gas_opcode_ratio,
            
            # Patterns (8)
            self.function_count / 50,
            float(self.has_flash_loan_callback),
            float(self.has_withdraw_function),
            float(self.has_mint_function),
            float(self.has_burn_function),
            float(self.has_admin_functions),
            float(self.has_proxy_pattern),
            float(self.has_factory_pattern),
            
            # Risk patterns (5)
            float(self.has_reentrancy_pattern),
            float(self.has_delegatecall_pattern),
            float(self.has_selfdestruct),
            float(self.has_unchecked_call),
            float(self.has_timestamp_dependency),
            
            # Advanced (3)
            min(self.storage_intensity, 1.0),
            min(self.external_interaction_ratio, 1.0),
            self.risk_score / 100,
        ]
    
    @staticmethod
    def vector_dimension() -> int:
        """Return the dimension of the feature vector."""
        # Basic(4) + Opcodes(8) + CFG(6) + Calls(3) + Entropy(3) + Gas(3) + 
        # Patterns(8) + Risk(5) + Advanced(3) = 43
        return 43


class EnhancedBytecodeExtractor:
    """
    Enhanced bytecode feature extractor with CFG analysis.
    
    New Features:
    1. CFG Complexity Score - Estimates cyclomatic complexity
    2. External Call Depth - Measures nested call patterns
    3. Code Entropy - Detects obfuscation/packing
    4. Gas Analysis - Identifies expensive operations
    5. Advanced Pattern Detection - Proxy, factory patterns
    """
    
    def __init__(self):
        self.opcode_map = OPCODE_TO_NAME
        self.gas_map = OPCODE_GAS
        self.category_map = OPCODE_CATEGORY
        
        # Dangerous function signatures
        self.flash_loan_sigs = {
            "c3924ed6", "23e30c8b", "fa461e33", "e9cbafb0",
            "d9caed12", "920f5c84"
        }
        self.withdraw_sigs = {"3ccfd60b", "2e1a7d4d", "f3fef3a3"}
        self.mint_sigs = {"9c0f3929", "40c10f19", "a0712d68"}
        self.burn_sigs = {"42966c68", "79cc6790"}
        self.admin_sigs = {"13af4035", "f2fde38b", "8456cb59", "3f4ba83a"}
    
    def extract_features(self, bytecode: str) -> EnhancedBytecodeFeatures:
        """Extract all enhanced features from bytecode."""
        # Normalize bytecode
        bytecode = bytecode.lower().replace("0x", "").strip()
        
        if len(bytecode) < 4:
            return EnhancedBytecodeFeatures(bytecode_hash="empty")
        
        features = EnhancedBytecodeFeatures()
        
        # Parse bytecode into instructions
        instructions = self._parse_instructions(bytecode)
        opcodes = [inst["opcode"] for inst in instructions]
        
        # Basic metrics
        features.bytecode_length = len(bytecode) // 2
        features.unique_opcodes = len(set(opcodes))
        features.total_instructions = len(instructions)
        features.bytecode_hash = hashlib.sha256(bytecode.encode()).hexdigest()
        
        # Opcode counts
        opcode_counts = Counter(opcodes)
        features.call_count = opcode_counts.get("f1", 0)
        features.delegatecall_count = opcode_counts.get("f4", 0)
        features.staticcall_count = opcode_counts.get("fa", 0)
        features.create_count = opcode_counts.get("f0", 0)
        features.create2_count = opcode_counts.get("f5", 0)
        features.sload_count = opcode_counts.get("54", 0)
        features.sstore_count = opcode_counts.get("55", 0)
        features.selfdestruct_count = opcode_counts.get("ff", 0)
        
        # CFG Complexity
        cfg_features = self._analyze_cfg(instructions, opcode_counts)
        features.cfg_complexity_score = cfg_features["complexity"]
        features.jump_count = opcode_counts.get("56", 0)
        features.jumpi_count = opcode_counts.get("57", 0)
        features.jumpdest_count = opcode_counts.get("5b", 0)
        features.basic_block_count = cfg_features["basic_blocks"]
        features.max_nesting_depth = cfg_features["max_depth"]
        features.loop_count = cfg_features["loops"]
        
        # External Call Depth
        call_features = self._analyze_external_calls(instructions)
        features.external_call_depth = call_features["max_depth"]
        features.external_call_sequence_length = call_features["sequence_length"]
        
        storage_ops = features.sload_count + features.sstore_count
        if storage_ops > 0:
            features.call_to_storage_ratio = features.call_count / storage_ops
        
        # Entropy Analysis
        features.bytecode_entropy = self._calculate_entropy(bytecode)
        features.opcode_entropy = self._calculate_opcode_entropy(opcodes)
        features.push_data_entropy = self._calculate_push_entropy(instructions)
        
        # Gas Analysis
        gas_features = self._analyze_gas(instructions)
        features.estimated_gas_cost = gas_features["total_gas"]
        features.gas_per_instruction = gas_features["avg_gas"]
        features.high_gas_opcode_ratio = gas_features["high_gas_ratio"]
        
        # Function signatures
        signatures = self._extract_function_signatures(bytecode)
        features.function_count = len(signatures)
        
        # Pattern Detection
        patterns = self._detect_patterns(bytecode, signatures, instructions)
        features.has_flash_loan_callback = patterns["flash_loan"]
        features.has_withdraw_function = patterns["withdraw"]
        features.has_mint_function = patterns["mint"]
        features.has_burn_function = patterns["burn"]
        features.has_admin_functions = patterns["admin"]
        features.has_proxy_pattern = patterns["proxy"]
        features.has_factory_pattern = patterns["factory"]
        features.has_reentrancy_pattern = patterns["reentrancy"]
        features.has_delegatecall_pattern = features.delegatecall_count > 0
        features.has_selfdestruct = features.selfdestruct_count > 0
        features.has_unchecked_call = patterns["unchecked_call"]
        features.has_timestamp_dependency = patterns["timestamp"]
        
        # Advanced Metrics
        if features.bytecode_length > 0:
            features.code_density = features.total_instructions / features.bytecode_length
        
        if features.total_instructions > 0:
            features.storage_intensity = storage_ops / features.total_instructions
            call_ops = features.call_count + features.delegatecall_count + features.staticcall_count
            features.external_interaction_ratio = call_ops / features.total_instructions
        
        # Risk Score
        risk_score, risk_factors = self._calculate_risk_score(features, patterns)
        features.risk_score = risk_score
        features.risk_factors = risk_factors
        
        return features
    
    def _parse_instructions(self, bytecode: str) -> List[Dict]:
        """Parse bytecode into instructions with positions."""
        instructions = []
        i = 0
        
        while i < len(bytecode):
            opcode = bytecode[i:i+2]
            inst = {
                "position": i // 2,
                "opcode": opcode,
                "data": None
            }
            
            # Handle PUSH instructions (60-7f)
            if opcode >= "60" and opcode <= "7f":
                push_bytes = int(opcode, 16) - 0x5f
                data_start = i + 2
                data_end = data_start + push_bytes * 2
                inst["data"] = bytecode[data_start:data_end]
                i = data_end
            else:
                i += 2
            
            instructions.append(inst)
        
        return instructions
    
    def _analyze_cfg(self, instructions: List[Dict], opcode_counts: Counter) -> Dict:
        """Analyze Control Flow Graph complexity."""
        # Basic block boundaries
        jumpdest_positions = set()
        jump_targets = set()
        
        for inst in instructions:
            if inst["opcode"] == "5b":  # JUMPDEST
                jumpdest_positions.add(inst["position"])
            elif inst["opcode"] in ("56", "57"):  # JUMP, JUMPI
                if inst.get("data"):
                    try:
                        target = int(inst["data"], 16)
                        jump_targets.add(target)
                    except:
                        pass
        
        # Count basic blocks (sequences between jumps)
        basic_blocks = opcode_counts.get("5b", 0) + 1
        
        # Estimate cyclomatic complexity: E - N + 2P
        # Simplified: jumpi_count + 1 (each conditional adds one path)
        jumpi_count = opcode_counts.get("57", 0)
        complexity = jumpi_count + 1
        
        # Estimate max nesting depth
        max_depth = min(jumpi_count // 2, 10)  # Heuristic
        
        # Detect loops (back-edges: jumps to earlier positions)
        loops = 0
        for inst in instructions:
            if inst["opcode"] == "56" and inst.get("data"):
                try:
                    target = int(inst["data"], 16)
                    if target < inst["position"]:
                        loops += 1
                except:
                    pass
        
        return {
            "complexity": complexity,
            "basic_blocks": basic_blocks,
            "max_depth": max_depth,
            "loops": loops
        }
    
    def _analyze_external_calls(self, instructions: List[Dict]) -> Dict:
        """Analyze external call patterns."""
        call_opcodes = {"f1", "f2", "f4", "fa"}  # CALL, CALLCODE, DELEGATECALL, STATICCALL
        
        # Find call positions
        call_positions = []
        for inst in instructions:
            if inst["opcode"] in call_opcodes:
                call_positions.append(inst["position"])
        
        if not call_positions:
            return {"max_depth": 0, "sequence_length": 0}
        
        # Estimate call depth (heuristic: max consecutive calls within 50 instructions)
        max_depth = 1
        current_depth = 1
        last_pos = call_positions[0]
        
        for pos in call_positions[1:]:
            if pos - last_pos < 100:  # Within 100 bytes
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            else:
                current_depth = 1
            last_pos = pos
        
        # Sequence length (longest chain of calls)
        return {
            "max_depth": max_depth,
            "sequence_length": len(call_positions)
        }
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of hex string."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter()
        for i in range(0, len(data) - 1, 2):
            byte = data[i:i+2]
            byte_counts[byte] += 1
        
        total = sum(byte_counts.values())
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _calculate_opcode_entropy(self, opcodes: List[str]) -> float:
        """Calculate entropy of opcode distribution."""
        if not opcodes:
            return 0.0
        
        counts = Counter(opcodes)
        total = len(opcodes)
        
        entropy = 0.0
        for count in counts.values():
            prob = count / total
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _calculate_push_entropy(self, instructions: List[Dict]) -> float:
        """Calculate entropy of PUSH data (detect packed/obfuscated code)."""
        push_data = ""
        for inst in instructions:
            if inst.get("data"):
                push_data += inst["data"]
        
        return self._calculate_entropy(push_data)
    
    def _analyze_gas(self, instructions: List[Dict]) -> Dict:
        """Analyze gas consumption patterns."""
        total_gas = 0
        high_gas_count = 0
        high_gas_threshold = 500  # Opcodes costing >500 gas
        
        for inst in instructions:
            gas = self.gas_map.get(inst["opcode"], 3)  # Default 3 for unknown
            total_gas += gas
            if gas > high_gas_threshold:
                high_gas_count += 1
        
        total_instructions = len(instructions)
        avg_gas = total_gas / total_instructions if total_instructions > 0 else 0
        high_gas_ratio = high_gas_count / total_instructions if total_instructions > 0 else 0
        
        return {
            "total_gas": total_gas,
            "avg_gas": avg_gas,
            "high_gas_ratio": high_gas_ratio
        }
    
    def _extract_function_signatures(self, bytecode: str) -> List[str]:
        """Extract 4-byte function signatures."""
        # Pattern: PUSH4 <4bytes> followed by EQ
        pattern = r'63([0-9a-f]{8})'
        matches = re.findall(pattern, bytecode)
        return list(set(matches))
    
    def _detect_patterns(
        self,
        bytecode: str,
        signatures: List[str],
        instructions: List[Dict]
    ) -> Dict[str, bool]:
        """Detect code patterns."""
        patterns = {
            "flash_loan": False,
            "withdraw": False,
            "mint": False,
            "burn": False,
            "admin": False,
            "proxy": False,
            "factory": False,
            "reentrancy": False,
            "unchecked_call": False,
            "timestamp": False,
        }
        
        sig_set = set(signatures)
        
        # Check function signatures
        patterns["flash_loan"] = bool(sig_set & self.flash_loan_sigs)
        patterns["withdraw"] = bool(sig_set & self.withdraw_sigs)
        patterns["mint"] = bool(sig_set & self.mint_sigs)
        patterns["burn"] = bool(sig_set & self.burn_sigs)
        patterns["admin"] = bool(sig_set & self.admin_sigs)
        
        # Proxy pattern: DELEGATECALL + minimal code + no SSTORE
        if "f4" in bytecode and len(bytecode) < 2000:
            sstore_count = bytecode.count("55")
            if sstore_count == 0:
                patterns["proxy"] = True
        
        # Factory pattern: CREATE2 + loop
        if "f5" in bytecode:  # CREATE2
            patterns["factory"] = True
        
        # Reentrancy pattern: CALL before SSTORE
        call_positions = [i for i, inst in enumerate(instructions) if inst["opcode"] == "f1"]
        sstore_positions = [i for i, inst in enumerate(instructions) if inst["opcode"] == "55"]
        
        for call_pos in call_positions:
            for sstore_pos in sstore_positions:
                if sstore_pos > call_pos and sstore_pos - call_pos < 50:
                    patterns["reentrancy"] = True
                    break
        
        # Unchecked call: CALL without ISZERO check
        for i, inst in enumerate(instructions):
            if inst["opcode"] == "f1":  # CALL
                # Check next few instructions for ISZERO
                next_opcodes = [instructions[j]["opcode"] for j in range(i+1, min(i+5, len(instructions)))]
                if "15" not in next_opcodes:  # No ISZERO
                    patterns["unchecked_call"] = True
                    break
        
        # Timestamp dependency
        if "42" in bytecode:  # TIMESTAMP
            patterns["timestamp"] = True
        
        return patterns
    
    def _calculate_risk_score(
        self,
        features: EnhancedBytecodeFeatures,
        patterns: Dict[str, bool]
    ) -> Tuple[float, List[str]]:
        """Calculate comprehensive risk score."""
        risk_score = 0.0
        risk_factors = []
        
        # Flash loan callback (high risk)
        if patterns["flash_loan"]:
            risk_score += 30
            risk_factors.append("Contains flash loan callback")
        
        # Reentrancy pattern
        if patterns["reentrancy"]:
            risk_score += 25
            risk_factors.append("Potential reentrancy pattern")
        
        # Unchecked call
        if patterns["unchecked_call"]:
            risk_score += 15
            risk_factors.append("Unchecked external call return")
        
        # DELEGATECALL
        if features.delegatecall_count > 0:
            risk_score += 15
            risk_factors.append(f"Uses DELEGATECALL ({features.delegatecall_count}x)")
        
        # SELFDESTRUCT
        if features.selfdestruct_count > 0:
            risk_score += 15
            risk_factors.append("Contains SELFDESTRUCT")
        
        # High CFG complexity
        if features.cfg_complexity_score > 50:
            risk_score += 10
            risk_factors.append(f"High CFG complexity ({features.cfg_complexity_score:.0f})")
        
        # Deep external calls
        if features.external_call_depth > 3:
            risk_score += 10
            risk_factors.append(f"Deep call nesting ({features.external_call_depth})")
        
        # CREATE2
        if features.create2_count > 0:
            risk_score += 8
            risk_factors.append("Uses CREATE2")
        
        # Many external calls
        if features.call_count > 15:
            risk_score += 8
            risk_factors.append(f"High call count ({features.call_count})")
        
        # Low entropy (potential packed/obfuscated)
        if features.bytecode_entropy < 3.0 and features.bytecode_length > 1000:
            risk_score += 5
            risk_factors.append("Low bytecode entropy (possibly obfuscated)")
        
        # Timestamp dependency
        if patterns["timestamp"]:
            risk_score += 5
            risk_factors.append("Timestamp dependency")
        
        # Mint + Burn (bridge-like)
        if patterns["mint"] and patterns["burn"]:
            risk_score += 5
            risk_factors.append("Has mint/burn operations")
        
        return min(risk_score, 100), risk_factors


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def extract_enhanced_features(bytecode: str) -> EnhancedBytecodeFeatures:
    """Convenience function to extract enhanced features."""
    extractor = EnhancedBytecodeExtractor()
    return extractor.extract_features(bytecode)


def features_to_dict(features: EnhancedBytecodeFeatures) -> Dict:
    """Convert features to dictionary."""
    return asdict(features)


def compare_features(features1: EnhancedBytecodeFeatures, features2: EnhancedBytecodeFeatures) -> float:
    """Compare two feature sets, return similarity score (0-1)."""
    vec1 = features1.to_vector()
    vec2 = features2.to_vector()
    
    # Cosine similarity
    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = math.sqrt(sum(a * a for a in vec1))
    norm2 = math.sqrt(sum(b * b for b in vec2))
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
    
    return dot_product / (norm1 * norm2)


# =============================================================================
# CLI TEST
# =============================================================================

if __name__ == "__main__":
    # Test with sample bytecode
    sample_bytecode = """
    608060405234801561001057600080fd5b506040516104a03803806104a0833981810160405281019061003291906100f8565b
    336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffff
    1602179055508060018190555050610125565b600080fd5b6000819050919050565b6100958161007f565b81146100a057600080fd5b
    50565b6000815190506100b28161008c565b92915050565b6000602082840312156100ce576100cd61007a565b5b60006100dc848285
    016100a3565b91505092915050565b6100ee8161007f565b82525050565b600060208201905061010960008301846100e5565b9291
    5050565b61036c806101346000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c806312
    065fe0146100465780633ccfd60b14610064578063d0e30db01461006e575b600080fd5b61004e610078565b60405161005b9190610
    """
    
    extractor = EnhancedBytecodeExtractor()
    features = extractor.extract_features(sample_bytecode)
    
    print()
    print("=" * 70)
    print("  ENHANCED BYTECODE ANALYSIS")
    print("=" * 70)
    print()
    print("  📊 Basic Metrics")
    print(f"     Bytecode Length:     {features.bytecode_length} bytes")
    print(f"     Unique Opcodes:      {features.unique_opcodes}")
    print(f"     Total Instructions:  {features.total_instructions}")
    print()
    print("  🔀 CFG Complexity (NEW)")
    print(f"     Complexity Score:    {features.cfg_complexity_score}")
    print(f"     Basic Blocks:        {features.basic_block_count}")
    print(f"     Max Nesting Depth:   {features.max_nesting_depth}")
    print(f"     Loop Count:          {features.loop_count}")
    print()
    print("  📞 External Calls (NEW)")
    print(f"     CALL Count:          {features.call_count}")
    print(f"     Call Depth:          {features.external_call_depth}")
    print(f"     Call/Storage Ratio:  {features.call_to_storage_ratio:.2f}")
    print()
    print("  🎲 Entropy Analysis (NEW)")
    print(f"     Bytecode Entropy:    {features.bytecode_entropy:.2f}")
    print(f"     Opcode Entropy:      {features.opcode_entropy:.2f}")
    print(f"     PUSH Data Entropy:   {features.push_data_entropy:.2f}")
    print()
    print("  ⛽ Gas Analysis (NEW)")
    print(f"     Estimated Gas:       {features.estimated_gas_cost}")
    print(f"     Avg Gas/Instruction: {features.gas_per_instruction:.1f}")
    print(f"     High Gas Ratio:      {features.high_gas_opcode_ratio:.2%}")
    print()
    print("  ⚠️  Risk Analysis")
    print(f"     Risk Score:          {features.risk_score}/100")
    print(f"     Risk Factors:        {features.risk_factors}")
    print()
    print("  📐 Feature Vector")
    vector = features.to_vector()
    print(f"     Dimensions:          {len(vector)}")
    print(f"     Sample Values:       {vector[:5]}")
    print()
    print("=" * 70)

