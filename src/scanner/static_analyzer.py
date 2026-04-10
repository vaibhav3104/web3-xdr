"""
Static Analysis Engine for Smart Contract Security

Performs pattern-based analysis on bytecode and source code to detect:
- Known vulnerability patterns
- Dangerous function usage
- Access control issues
- Code quality issues
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum
import hashlib
import structlog

logger = structlog.get_logger()


@dataclass
class Pattern:
    """Represents a vulnerability pattern to match"""
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    bytecode_pattern: Optional[str] = None  # Hex pattern to match
    opcode_sequence: Optional[List[str]] = None  # Sequence of opcodes
    source_pattern: Optional[str] = None  # Regex for source code
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    confidence: float = 0.8


class StaticAnalyzer:
    """
    Static analysis engine for smart contracts
    
    Analyzes bytecode and source code for known vulnerability patterns.
    """
    
    # Known vulnerability patterns
    PATTERNS: List[Pattern] = [
        # Integer Overflow (Pre-0.8.0)
        Pattern(
            name="integer_overflow_add",
            description="Addition without overflow check in pre-0.8.0 Solidity",
            severity="CRITICAL",
            opcode_sequence=["ADD"],  # Simplified - real check is more complex
            recommendation="Use SafeMath or upgrade to Solidity 0.8+",
            references=["https://swcregistry.io/docs/SWC-101"],
            confidence=0.6
        ),
        
        # Reentrancy Pattern
        Pattern(
            name="reentrancy_call_before_state",
            description="External CALL before SSTORE (state update)",
            severity="CRITICAL",
            opcode_sequence=["CALL", "SSTORE"],  # CALL followed eventually by SSTORE
            recommendation="Use checks-effects-interactions pattern",
            references=["https://swcregistry.io/docs/SWC-107"],
            confidence=0.7
        ),
        
        # Delegatecall to user input
        Pattern(
            name="delegatecall_to_user_input",
            description="DELEGATECALL with target from CALLDATALOAD",
            severity="CRITICAL",
            opcode_sequence=["CALLDATALOAD", "DELEGATECALL"],
            recommendation="Never delegatecall to user-controlled addresses",
            references=["https://swcregistry.io/docs/SWC-112"],
            confidence=0.8
        ),
        
        # tx.origin authentication
        Pattern(
            name="tx_origin_auth",
            description="tx.origin used for authentication",
            severity="HIGH",
            opcode_sequence=["ORIGIN", "EQ"],
            source_pattern=r"require\s*\(\s*tx\.origin\s*==",
            recommendation="Use msg.sender instead of tx.origin",
            references=["https://swcregistry.io/docs/SWC-115"],
            confidence=0.9
        ),
        
        # Unchecked call return
        Pattern(
            name="unchecked_call_return",
            description="CALL return value not checked",
            severity="MEDIUM",
            opcode_sequence=["CALL", "POP"],  # CALL followed by POP (ignoring return)
            recommendation="Always check return value of external calls",
            references=["https://swcregistry.io/docs/SWC-104"],
            confidence=0.7
        ),
        
        # Unprotected selfdestruct
        Pattern(
            name="unprotected_selfdestruct",
            description="SELFDESTRUCT without access control",
            severity="CRITICAL",
            opcode_sequence=["SELFDESTRUCT"],  # Need to check for missing CALLER check
            recommendation="Add access control to selfdestruct",
            references=["https://swcregistry.io/docs/SWC-106"],
            confidence=0.6
        ),
        
        # Timestamp dependence
        Pattern(
            name="timestamp_dependence",
            description="Block timestamp used in critical logic",
            severity="LOW",
            opcode_sequence=["TIMESTAMP", "LT"],
            source_pattern=r"block\.timestamp\s*[<>=]",
            recommendation="Avoid timestamp for critical logic",
            references=["https://swcregistry.io/docs/SWC-116"],
            confidence=0.6
        ),
        
        # Weak randomness
        Pattern(
            name="weak_randomness",
            description="Predictable randomness source",
            severity="MEDIUM",
            opcode_sequence=["BLOCKHASH", "TIMESTAMP"],
            source_pattern=r"keccak256\s*\(\s*abi\.encode.*block\.",
            recommendation="Use Chainlink VRF for randomness",
            references=["https://swcregistry.io/docs/SWC-120"],
            confidence=0.7
        ),
        
        # Floating pragma
        Pattern(
            name="floating_pragma",
            description="Floating pragma version",
            severity="INFO",
            source_pattern=r"pragma\s+solidity\s*\^",
            recommendation="Lock pragma to specific version",
            references=["https://swcregistry.io/docs/SWC-103"],
            confidence=0.95
        ),
        
        # Outdated compiler
        Pattern(
            name="outdated_compiler",
            description="Using outdated Solidity version",
            severity="HIGH",
            source_pattern=r"pragma\s+solidity\s*[\^~]?\s*0\.[4-7]\.",
            recommendation="Upgrade to Solidity 0.8+",
            references=["https://swcregistry.io/docs/SWC-102"],
            confidence=0.95
        ),
        
        # Arbitrary jump
        Pattern(
            name="arbitrary_jump",
            description="Jump to user-controlled destination",
            severity="CRITICAL",
            opcode_sequence=["CALLDATALOAD", "JUMP"],
            recommendation="Validate jump destinations",
            references=["https://swcregistry.io/docs/SWC-127"],
            confidence=0.8
        ),
        
        # DoS with block gas limit
        Pattern(
            name="dos_gas_limit",
            description="Unbounded loop that could exceed gas limit",
            severity="MEDIUM",
            source_pattern=r"for\s*\([^)]*\.length",
            recommendation="Implement pagination for loops over dynamic arrays",
            references=["https://swcregistry.io/docs/SWC-128"],
            confidence=0.6
        ),
        
        # Signature replay
        Pattern(
            name="signature_replay",
            description="Missing nonce in signature verification",
            severity="HIGH",
            source_pattern=r"ecrecover\s*\(",
            recommendation="Include nonce and chain ID in signed messages",
            references=["https://swcregistry.io/docs/SWC-121"],
            confidence=0.5
        ),
    ]
    
    # Known safe patterns (to reduce false positives)
    SAFE_PATTERNS = [
        # SafeMath usage
        "SafeMath",
        # OpenZeppelin
        "@openzeppelin",
        # Reentrancy guard
        "nonReentrant",
        "ReentrancyGuard",
        # Access control
        "onlyOwner",
        "Ownable",
        "AccessControl",
    ]
    
    # Known malicious bytecode signatures (from known exploits)
    MALICIOUS_SIGNATURES: Dict[str, str] = {
        # Honeypot patterns
        "6080604052600436106100": "Common honeypot prefix",
        # Known exploit contracts (simplified)
        "363d3d373d3d3d363d73": "Minimal proxy (EIP-1167)",
    }
    
    def __init__(self):
        """Initialize the static analyzer"""
        self.findings: List[Dict] = []
    
    def analyze_bytecode(self, bytecode: str) -> List[Dict]:
        """
        Analyze bytecode for vulnerability patterns
        
        Args:
            bytecode: Contract bytecode (hex string)
        
        Returns:
            List of findings
        """
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        
        self.findings = []
        
        # Parse to opcodes
        opcodes = self._parse_to_opcodes(bytecode)
        
        # Check each pattern
        for pattern in self.PATTERNS:
            if pattern.opcode_sequence:
                matches = self._find_opcode_sequence(opcodes, pattern.opcode_sequence)
                if matches:
                    for match_idx in matches:
                        self.findings.append({
                            "pattern": pattern.name,
                            "description": pattern.description,
                            "severity": pattern.severity,
                            "location": f"Bytecode offset ~{match_idx}",
                            "confidence": pattern.confidence,
                            "recommendation": pattern.recommendation,
                            "references": pattern.references
                        })
            
            if pattern.bytecode_pattern:
                if pattern.bytecode_pattern.lower() in bytecode.lower():
                    self.findings.append({
                        "pattern": pattern.name,
                        "description": pattern.description,
                        "severity": pattern.severity,
                        "location": "Bytecode pattern match",
                        "confidence": pattern.confidence,
                        "recommendation": pattern.recommendation,
                        "references": pattern.references
                    })
        
        # Check for known malicious signatures
        for sig, description in self.MALICIOUS_SIGNATURES.items():
            if sig.lower() in bytecode.lower():
                self.findings.append({
                    "pattern": "known_malicious_signature",
                    "description": f"Known pattern detected: {description}",
                    "severity": "INFO",
                    "location": "Bytecode signature",
                    "confidence": 0.7
                })
        
        # Analyze bytecode characteristics
        self._analyze_bytecode_characteristics(bytecode, opcodes)
        
        return self.findings
    
    def analyze_source(self, source_code: str) -> List[Dict]:
        """
        Analyze Solidity source code for vulnerability patterns
        
        Args:
            source_code: Solidity source code
        
        Returns:
            List of findings
        """
        self.findings = []
        
        # Check for safe patterns (reduces false positives)
        has_safe_patterns = any(
            safe in source_code for safe in self.SAFE_PATTERNS
        )
        
        # Check each pattern
        for pattern in self.PATTERNS:
            if pattern.source_pattern:
                matches = re.finditer(pattern.source_pattern, source_code)
                for match in matches:
                    # Adjust confidence if safe patterns present
                    confidence = pattern.confidence
                    if has_safe_patterns and pattern.severity in ["CRITICAL", "HIGH"]:
                        confidence *= 0.5  # Reduce confidence
                    
                    # Find line number
                    line_num = source_code[:match.start()].count('\n') + 1
                    
                    self.findings.append({
                        "pattern": pattern.name,
                        "description": pattern.description,
                        "severity": pattern.severity,
                        "location": f"Line {line_num}",
                        "match": match.group(0)[:100],  # First 100 chars
                        "confidence": confidence,
                        "recommendation": pattern.recommendation,
                        "references": pattern.references
                    })
        
        # Additional source-specific checks
        self._analyze_source_characteristics(source_code)
        
        return self.findings
    
    def _parse_to_opcodes(self, bytecode: str) -> List[Tuple[int, str]]:
        """Parse bytecode to list of (offset, opcode_name) tuples"""
        OPCODES = {
            0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
            0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
            0x0A: "EXP", 0x0B: "SIGNEXTEND",
            0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
            0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
            0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
            0x20: "SHA3",
            0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
            0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
            0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
            0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
            0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
            0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER",
            0x44: "DIFFICULTY", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE",
            0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
            0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
            0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
            0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN",
            0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
            0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
        }
        
        opcodes = []
        try:
            bytecode_bytes = bytes.fromhex(bytecode)
        except ValueError:
            return opcodes
        
        i = 0
        while i < len(bytecode_bytes):
            opcode = bytecode_bytes[i]
            opcode_name = OPCODES.get(opcode, f"UNKNOWN_{hex(opcode)}")
            opcodes.append((i, opcode_name))
            
            # Handle PUSH instructions
            if 0x60 <= opcode <= 0x7F:
                push_size = opcode - 0x5F
                i += push_size
            
            i += 1
        
        return opcodes
    
    def _find_opcode_sequence(
        self,
        opcodes: List[Tuple[int, str]],
        sequence: List[str],
        max_gap: int = 50
    ) -> List[int]:
        """
        Find occurrences of opcode sequence in bytecode
        
        Args:
            opcodes: List of (offset, opcode_name) tuples
            sequence: Sequence of opcodes to find
            max_gap: Maximum gap between opcodes in sequence
        
        Returns:
            List of offsets where sequence starts
        """
        matches = []
        opcode_names = [op[1] for op in opcodes]
        
        for i, (offset, op) in enumerate(opcodes):
            if op == sequence[0]:
                # Try to match rest of sequence
                matched = True
                last_match_idx = i
                
                for j, target_op in enumerate(sequence[1:], 1):
                    # Look for target_op within max_gap
                    found = False
                    for k in range(last_match_idx + 1, min(last_match_idx + max_gap + 1, len(opcodes))):
                        if opcodes[k][1] == target_op:
                            last_match_idx = k
                            found = True
                            break
                    
                    if not found:
                        matched = False
                        break
                
                if matched:
                    matches.append(offset)
        
        return matches
    
    def _analyze_bytecode_characteristics(self, bytecode: str, opcodes: List[Tuple[int, str]]):
        """Analyze overall bytecode characteristics"""
        
        opcode_names = [op[1] for op in opcodes]
        
        # Count dangerous opcodes
        dangerous_counts = {
            "SELFDESTRUCT": opcode_names.count("SELFDESTRUCT"),
            "DELEGATECALL": opcode_names.count("DELEGATECALL"),
            "CALL": opcode_names.count("CALL"),
            "CREATE": opcode_names.count("CREATE"),
            "CREATE2": opcode_names.count("CREATE2"),
        }
        
        # High number of external calls is suspicious
        if dangerous_counts["CALL"] > 10:
            self.findings.append({
                "pattern": "high_external_calls",
                "description": f"Contract has {dangerous_counts['CALL']} external CALL operations",
                "severity": "INFO",
                "confidence": 0.5
            })
        
        # Multiple SELFDESTRUCT is very suspicious
        if dangerous_counts["SELFDESTRUCT"] > 1:
            self.findings.append({
                "pattern": "multiple_selfdestruct",
                "description": f"Contract has {dangerous_counts['SELFDESTRUCT']} SELFDESTRUCT operations",
                "severity": "HIGH",
                "confidence": 0.7
            })
        
        # Very small bytecode with DELEGATECALL = likely proxy
        if len(bytecode) < 500 and dangerous_counts["DELEGATECALL"] > 0:
            self.findings.append({
                "pattern": "minimal_proxy",
                "description": "Small contract with DELEGATECALL - likely a proxy",
                "severity": "INFO",
                "confidence": 0.8
            })
    
    def _analyze_source_characteristics(self, source_code: str):
        """Analyze overall source code characteristics"""
        
        # Check for missing visibility
        if re.search(r"function\s+\w+\s*\([^)]*\)\s*{", source_code):
            self.findings.append({
                "pattern": "missing_visibility",
                "description": "Function without explicit visibility specifier",
                "severity": "LOW",
                "confidence": 0.6,
                "recommendation": "Always specify function visibility"
            })
        
        # Check for assembly usage
        if "assembly" in source_code:
            self.findings.append({
                "pattern": "inline_assembly",
                "description": "Contract uses inline assembly",
                "severity": "INFO",
                "confidence": 0.9,
                "recommendation": "Review assembly code carefully"
            })
        
        # Check for unchecked blocks (Solidity 0.8+)
        if "unchecked" in source_code:
            self.findings.append({
                "pattern": "unchecked_math",
                "description": "Contract uses unchecked math blocks",
                "severity": "MEDIUM",
                "confidence": 0.7,
                "recommendation": "Ensure unchecked operations cannot overflow"
            })
    
    def get_risk_score(self) -> float:
        """Calculate overall risk score from findings"""
        if not self.findings:
            return 0.0
        
        severity_weights = {
            "CRITICAL": 40,
            "HIGH": 25,
            "MEDIUM": 10,
            "LOW": 3,
            "INFO": 1
        }
        
        total_score = 0
        for finding in self.findings:
            weight = severity_weights.get(finding.get("severity", "INFO"), 1)
            confidence = finding.get("confidence", 0.5)
            total_score += weight * confidence
        
        return min(100, total_score)
    
    def get_summary(self) -> Dict:
        """Get summary of analysis results"""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for finding in self.findings:
            severity = finding.get("severity", "INFO")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "risk_score": self.get_risk_score(),
            "findings": self.findings
        }
