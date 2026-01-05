"""
Bytecode Feature Extractor
Extracts features from smart contract bytecode for ML classification
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib

class Opcode(Enum):
    """EVM Opcodes relevant to security analysis"""
    # Calls
    CALL = "f1"
    CALLCODE = "f2"
    DELEGATECALL = "f4"
    STATICCALL = "fa"
    CREATE = "f0"
    CREATE2 = "f5"
    
    # Storage
    SLOAD = "54"
    SSTORE = "55"
    
    # Memory
    MLOAD = "51"
    MSTORE = "52"
    
    # Control flow
    JUMP = "56"
    JUMPI = "57"
    JUMPDEST = "5b"
    
    # Value transfer
    BALANCE = "31"
    SELFBALANCE = "47"
    
    # Dangerous
    SELFDESTRUCT = "ff"

# Known function signatures for dangerous operations
DANGEROUS_SIGNATURES = {
    # Flash loan callbacks
    "0xc3924ed6": "receiveFlashLoan(address[],uint256[],uint256[],bytes)",  # Balancer
    "0x23e30c8b": "onFlashLoan(address,address,uint256,uint256,bytes)",  # EIP-3156
    "0xfa461e33": "uniswapV3FlashCallback(uint256,uint256,bytes)",  # Uniswap V3
    "0xe9cbafb0": "pancakeV3FlashCallback(uint256,uint256,bytes)",  # PancakeSwap
    "0xd9caed12": "executeOperation(address,uint256,uint256,bytes)",  # Aave V1
    "0x920f5c84": "executeOperation(address[],uint256[],uint256[],address,bytes)",  # Aave V2
    
    # Reentrancy patterns
    "0x3ccfd60b": "withdraw()",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0xf3fef3a3": "withdraw(address,uint256)",
    
    # Bridge operations
    "0x9c0f3929": "mint(address,uint256)",
    "0x40c10f19": "mint(address,uint256)",
    "0x42966c68": "burn(uint256)",
    "0x79cc6790": "burnFrom(address,uint256)",
    "0xb6b55f25": "deposit(uint256)",
    "0xd0e30db0": "deposit()",
    
    # Dangerous admin
    "0x13af4035": "setOwner(address)",
    "0xf2fde38b": "transferOwnership(address)",
    "0x8456cb59": "pause()",
    "0x3f4ba83a": "unpause()",
}

# Known malicious patterns
MALICIOUS_PATTERNS = {
    "flash_loan_arb": [
        ("c3924ed6", "Balancer flash loan callback"),
        ("23e30c8b", "EIP-3156 flash loan callback"),
    ],
    "reentrancy": [
        ("f1", "CALL before state update"),
        ("54", "SLOAD after CALL"),
        ("55", "SSTORE after CALL"),
    ],
    "selfdestruct": [
        ("ff", "SELFDESTRUCT opcode"),
    ],
    "delegatecall": [
        ("f4", "DELEGATECALL to unknown"),
    ],
}

@dataclass
class BytecodeFeatures:
    """Features extracted from bytecode"""
    # Size metrics
    bytecode_length: int
    unique_opcodes: int
    
    # Opcode frequencies
    call_count: int
    delegatecall_count: int
    staticcall_count: int
    create_count: int
    create2_count: int
    sload_count: int
    sstore_count: int
    selfdestruct_count: int
    
    # Function signatures
    function_count: int
    has_flash_loan_callback: bool
    has_withdraw_function: bool
    has_mint_function: bool
    has_burn_function: bool
    has_admin_functions: bool
    
    # Pattern detection
    has_reentrancy_pattern: bool
    has_delegatecall_pattern: bool
    has_selfdestruct: bool
    
    # External calls
    external_call_targets: List[str]
    
    # Risk indicators
    risk_score: float
    risk_factors: List[str]

class BytecodeExtractor:
    """Extract features from EVM bytecode"""
    
    def __init__(self):
        self.opcode_map = {op.value: op.name for op in Opcode}
    
    def extract_features(self, bytecode: str) -> BytecodeFeatures:
        """
        Extract all features from bytecode
        
        Args:
            bytecode: Hex string of contract bytecode (with or without 0x prefix)
        
        Returns:
            BytecodeFeatures object with all extracted features
        """
        # Normalize bytecode
        bytecode = bytecode.lower().replace("0x", "")
        
        # Extract opcode frequencies
        opcode_counts = self._count_opcodes(bytecode)
        
        # Extract function signatures
        signatures = self._extract_function_signatures(bytecode)
        
        # Analyze patterns
        patterns = self._analyze_patterns(bytecode, signatures)
        
        # Extract external call targets
        call_targets = self._extract_call_targets(bytecode)
        
        # Calculate risk score
        risk_score, risk_factors = self._calculate_risk_score(
            opcode_counts, signatures, patterns
        )
        
        return BytecodeFeatures(
            bytecode_length=len(bytecode) // 2,  # bytes
            unique_opcodes=len(set(self._get_opcodes(bytecode))),
            call_count=opcode_counts.get("CALL", 0),
            delegatecall_count=opcode_counts.get("DELEGATECALL", 0),
            staticcall_count=opcode_counts.get("STATICCALL", 0),
            create_count=opcode_counts.get("CREATE", 0),
            create2_count=opcode_counts.get("CREATE2", 0),
            sload_count=opcode_counts.get("SLOAD", 0),
            sstore_count=opcode_counts.get("SSTORE", 0),
            selfdestruct_count=opcode_counts.get("SELFDESTRUCT", 0),
            function_count=len(signatures),
            has_flash_loan_callback=patterns["has_flash_loan"],
            has_withdraw_function=patterns["has_withdraw"],
            has_mint_function=patterns["has_mint"],
            has_burn_function=patterns["has_burn"],
            has_admin_functions=patterns["has_admin"],
            has_reentrancy_pattern=patterns["has_reentrancy"],
            has_delegatecall_pattern=opcode_counts.get("DELEGATECALL", 0) > 0,
            has_selfdestruct=opcode_counts.get("SELFDESTRUCT", 0) > 0,
            external_call_targets=call_targets,
            risk_score=risk_score,
            risk_factors=risk_factors,
        )
    
    def _count_opcodes(self, bytecode: str) -> Dict[str, int]:
        """Count occurrences of each opcode"""
        counts = {}
        opcodes = self._get_opcodes(bytecode)
        
        for opcode in opcodes:
            if opcode in self.opcode_map:
                name = self.opcode_map[opcode]
                counts[name] = counts.get(name, 0) + 1
        
        return counts
    
    def _get_opcodes(self, bytecode: str) -> List[str]:
        """Extract opcodes from bytecode (simplified)"""
        opcodes = []
        i = 0
        while i < len(bytecode):
            opcode = bytecode[i:i+2]
            opcodes.append(opcode)
            
            # Handle PUSH instructions (60-7f push 1-32 bytes)
            if opcode >= "60" and opcode <= "7f":
                push_bytes = int(opcode, 16) - 0x5f
                i += push_bytes * 2
            
            i += 2
        
        return opcodes
    
    def _extract_function_signatures(self, bytecode: str) -> List[str]:
        """Extract 4-byte function signatures from bytecode"""
        # Look for patterns: PUSH4 <4bytes> EQ
        pattern = r'63([0-9a-f]{8})'
        matches = re.findall(pattern, bytecode)
        return list(set(matches))
    
    def _analyze_patterns(
        self, 
        bytecode: str, 
        signatures: List[str]
    ) -> Dict[str, bool]:
        """Analyze bytecode for known patterns"""
        patterns = {
            "has_flash_loan": False,
            "has_withdraw": False,
            "has_mint": False,
            "has_burn": False,
            "has_admin": False,
            "has_reentrancy": False,
        }
        
        # Check function signatures
        for sig in signatures:
            sig_with_prefix = "0x" + sig
            if sig_with_prefix in DANGEROUS_SIGNATURES:
                func_name = DANGEROUS_SIGNATURES[sig_with_prefix]
                
                if "FlashLoan" in func_name or "flashCallback" in func_name:
                    patterns["has_flash_loan"] = True
                if "withdraw" in func_name.lower():
                    patterns["has_withdraw"] = True
                if "mint" in func_name.lower():
                    patterns["has_mint"] = True
                if "burn" in func_name.lower():
                    patterns["has_burn"] = True
                if "Owner" in func_name or "pause" in func_name.lower():
                    patterns["has_admin"] = True
        
        # Check for reentrancy pattern (CALL followed by SSTORE)
        # Simplified check - real implementation would do control flow analysis
        if "f1" in bytecode and "55" in bytecode:
            call_pos = bytecode.find("f1")
            sstore_pos = bytecode.find("55", call_pos)
            if sstore_pos > call_pos and sstore_pos - call_pos < 100:
                patterns["has_reentrancy"] = True
        
        return patterns
    
    def _extract_call_targets(self, bytecode: str) -> List[str]:
        """Extract potential external call targets (addresses)"""
        # Look for PUSH20 (address) followed by CALL-like opcodes
        # Pattern: 73 <20 bytes address>
        pattern = r'73([0-9a-f]{40})'
        matches = re.findall(pattern, bytecode)
        return ["0x" + addr for addr in set(matches)]
    
    def _calculate_risk_score(
        self,
        opcode_counts: Dict[str, int],
        signatures: List[str],
        patterns: Dict[str, bool]
    ) -> Tuple[float, List[str]]:
        """Calculate overall risk score (0-100)"""
        risk_score = 0.0
        risk_factors = []
        
        # Flash loan callback = high risk
        if patterns["has_flash_loan"]:
            risk_score += 30
            risk_factors.append("Contains flash loan callback")
        
        # Reentrancy pattern
        if patterns["has_reentrancy"]:
            risk_score += 25
            risk_factors.append("Potential reentrancy pattern")
        
        # DELEGATECALL
        if opcode_counts.get("DELEGATECALL", 0) > 0:
            risk_score += 20
            risk_factors.append(f"Uses DELEGATECALL ({opcode_counts.get('DELEGATECALL', 0)} times)")
        
        # SELFDESTRUCT
        if opcode_counts.get("SELFDESTRUCT", 0) > 0:
            risk_score += 15
            risk_factors.append("Contains SELFDESTRUCT")
        
        # CREATE2 (can deploy at predictable addresses)
        if opcode_counts.get("CREATE2", 0) > 0:
            risk_score += 10
            risk_factors.append("Uses CREATE2")
        
        # Multiple external calls
        call_count = opcode_counts.get("CALL", 0)
        if call_count > 10:
            risk_score += 10
            risk_factors.append(f"High external call count ({call_count})")
        
        # Mint/burn operations (bridge-like)
        if patterns["has_mint"] and patterns["has_burn"]:
            risk_score += 5
            risk_factors.append("Has mint/burn operations")
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        return risk_score, risk_factors
    
    def get_bytecode_hash(self, bytecode: str) -> str:
        """Get unique hash of bytecode (for similarity matching)"""
        bytecode = bytecode.lower().replace("0x", "")
        return hashlib.sha256(bytecode.encode()).hexdigest()
    
    def compare_similarity(self, bytecode1: str, bytecode2: str) -> float:
        """
        Compare similarity between two bytecodes
        Returns: 0.0 (completely different) to 1.0 (identical)
        """
        bc1 = bytecode1.lower().replace("0x", "")
        bc2 = bytecode2.lower().replace("0x", "")
        
        # Simple similarity based on opcode sequence
        opcodes1 = set(self._get_opcodes(bc1))
        opcodes2 = set(self._get_opcodes(bc2))
        
        if not opcodes1 or not opcodes2:
            return 0.0
        
        intersection = opcodes1 & opcodes2
        union = opcodes1 | opcodes2
        
        return len(intersection) / len(union)

# Feature vector for ML
def features_to_vector(features: BytecodeFeatures) -> List[float]:
    """Convert features to numerical vector for ML"""
    return [
        features.bytecode_length / 10000,  # Normalize
        features.unique_opcodes / 100,
        features.call_count / 50,
        features.delegatecall_count / 10,
        features.staticcall_count / 20,
        features.create_count / 5,
        features.create2_count / 5,
        features.sload_count / 100,
        features.sstore_count / 100,
        features.selfdestruct_count,
        features.function_count / 50,
        float(features.has_flash_loan_callback),
        float(features.has_withdraw_function),
        float(features.has_mint_function),
        float(features.has_burn_function),
        float(features.has_admin_functions),
        float(features.has_reentrancy_pattern),
        float(features.has_delegatecall_pattern),
        float(features.has_selfdestruct),
        features.risk_score / 100,
    ]

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
    
    extractor = BytecodeExtractor()
    features = extractor.extract_features(sample_bytecode)
    
    print("=" * 60)
    print("BYTECODE ANALYSIS RESULTS")
    print("=" * 60)
    print(f"Bytecode Length:     {features.bytecode_length} bytes")
    print(f"Unique Opcodes:      {features.unique_opcodes}")
    print(f"CALL Count:          {features.call_count}")
    print(f"DELEGATECALL Count:  {features.delegatecall_count}")
    print(f"Function Count:      {features.function_count}")
    print(f"Has Flash Loan:      {features.has_flash_loan_callback}")
    print(f"Has Reentrancy:      {features.has_reentrancy_pattern}")
    print(f"Risk Score:          {features.risk_score}/100")
    print(f"Risk Factors:        {features.risk_factors}")
    print("=" * 60)
    
    # Convert to vector
    vector = features_to_vector(features)
    print(f"Feature Vector:      {len(vector)} dimensions")
