"""
LLM Bytecode Analyzer
======================

Decompiles contract bytecode into opcode sequences and sends them to
Claude for natural-language analysis. Catches novel exploit patterns
that rule-based and ML classifiers miss.

Usage:
    analyzer = BytecodeAnalyzer()
    analysis = analyzer.analyze("0x608060405234801561001057...")
    print(analysis.summary)
    print(analysis.threat_assessment)
"""

import json
from dataclasses import dataclass
from typing import Dict, Any, Optional, List
import structlog

from .client import get_client, get_async_client, MODEL

logger = structlog.get_logger(__name__)

# Known function signatures for decompilation context
KNOWN_SELECTORS = {
    "a9059cbb": "transfer(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "70a08231": "balanceOf(address)",
    "18160ddd": "totalSupply()",
    "dd62ed3e": "allowance(address,address)",
    "23e30c8b": "executeOperation(address,uint256,uint256,address,bytes)",  # Aave flash loan
    "ab803a65": "onFlashLoan(address,address,uint256,uint256,bytes)",  # ERC-3156
    "ee872558": "uniswapV2Call(address,uint256,uint256,bytes)",
    "c3924ed6": "executeOperation(address[],uint256[],uint256[],bytes)",
    "715018a6": "renounceOwnership()",
    "f2fde38b": "transferOwnership(address)",
    "8456cb59": "pause()",
    "3f4ba83a": "unpause()",
    "40c10f19": "mint(address,uint256)",
    "42966c68": "burn(uint256)",
    "5c60da1b": "implementation()",
    "3659cfe6": "upgradeTo(address)",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "d09de08a": "increment()",
    "3ccfd60b": "withdraw()",
    "2e1a7d4d": "withdraw(uint256)",
    "e8e33700": "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
    "baa2abde": "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
    "38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
}

# EVM opcode names
OPCODE_NAMES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x06: "MOD", 0x10: "LT", 0x11: "GT", 0x14: "EQ", 0x15: "ISZERO",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE",
    0x1B: "SHL", 0x1C: "SHR", 0x20: "SHA3",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
    0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
    0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP",
    0x43: "NUMBER", 0x44: "DIFFICULTY", 0x45: "GASLIMIT",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
    0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
    0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE",
    0xF3: "RETURN", 0xF4: "DELEGATECALL", 0xF5: "CREATE2",
    0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}


@dataclass
class ContractAnalysis:
    """Result of LLM bytecode analysis."""

    contract_address: Optional[str]
    summary: str  # What this contract does in plain English
    threat_assessment: str  # "safe", "suspicious", "malicious", "unknown"
    threat_level: float  # 0.0 - 1.0
    identified_functions: List[str]
    attack_vectors: List[str]  # Potential attack patterns found
    similar_to: List[str]  # Known exploits this resembles
    recommendations: List[str]
    decompiled_highlights: str  # Key opcodes/patterns found

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_address": self.contract_address,
            "summary": self.summary,
            "threat_assessment": self.threat_assessment,
            "threat_level": self.threat_level,
            "identified_functions": self.identified_functions,
            "attack_vectors": self.attack_vectors,
            "similar_to": self.similar_to,
            "recommendations": self.recommendations,
            "decompiled_highlights": self.decompiled_highlights,
        }


ANALYZER_SYSTEM_PROMPT = """You are an expert EVM bytecode reverse engineer and Web3 security auditor.

You will receive disassembled EVM bytecode with:
- Opcode sequences with identified function selectors
- Pattern flags (reentrancy, flash loan callbacks, delegatecall, etc.)
- Statistical analysis (opcode counts, complexity metrics)

Your job is to:
1. Explain what this contract does in plain English
2. Identify specific functions and their purposes
3. Assess whether this contract could be used for attacks
4. Compare against known exploit patterns (flash loans, reentrancy, oracle manipulation, governance attacks)

Known exploit patterns to watch for:
- Flash loan callback (executeOperation/onFlashLoan) + large token movements + profit extraction
- CALL before SSTORE without reentrancy guard = reentrancy vulnerability
- STATICCALL (read price) → CALL (swap) → STATICCALL (read again) → CALL (profit) = oracle manipulation
- DELEGATECALL to user-controlled address = proxy exploit
- SELFDESTRUCT with ownership transfer = rug pull
- TIMESTAMP/BLOCKHASH dependency in conditional logic = randomness exploit

Respond with ONLY valid JSON:
{
  "summary": "2-3 sentence description of what this contract does",
  "threat_assessment": "safe" | "suspicious" | "malicious" | "unknown",
  "threat_level": 0.0-1.0,
  "identified_functions": ["function signatures found"],
  "attack_vectors": ["specific attack patterns identified"],
  "similar_to": ["known exploits this resembles, if any"],
  "recommendations": ["what to do about this contract"]
}"""


class BytecodeAnalyzer:
    """
    LLM-powered bytecode analyzer for novel exploit detection.
    """

    def _disassemble(self, bytecode: str, max_opcodes: int = 500) -> str:
        """Disassemble bytecode into human-readable opcode listing."""
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]

        bc_bytes = bytes.fromhex(bytecode.lower())
        lines = []
        idx = 0
        opcode_count = 0

        while idx < len(bc_bytes) and opcode_count < max_opcodes:
            op = bc_bytes[idx]
            name = OPCODE_NAMES.get(op)

            if 0x60 <= op <= 0x7F:
                # PUSH1 through PUSH32
                push_size = op - 0x5F
                data = bc_bytes[idx + 1 : idx + 1 + push_size].hex()
                name = f"PUSH{push_size}"

                # Check if this is a function selector (4 bytes after PUSH4)
                if push_size == 4 and data in KNOWN_SELECTORS:
                    lines.append(
                        f"  {idx:04x}: {name} 0x{data}  ; {KNOWN_SELECTORS[data]}"
                    )
                else:
                    lines.append(f"  {idx:04x}: {name} 0x{data}")

                idx += 1 + push_size
            elif 0x80 <= op <= 0x8F:
                dup_n = op - 0x7F
                lines.append(f"  {idx:04x}: DUP{dup_n}")
                idx += 1
            elif 0x90 <= op <= 0x9F:
                swap_n = op - 0x8F
                lines.append(f"  {idx:04x}: SWAP{swap_n}")
                idx += 1
            elif 0xA0 <= op <= 0xA4:
                log_n = op - 0xA0
                lines.append(f"  {idx:04x}: LOG{log_n}")
                idx += 1
            elif name:
                lines.append(f"  {idx:04x}: {name}")
                idx += 1
            else:
                lines.append(f"  {idx:04x}: UNKNOWN(0x{op:02x})")
                idx += 1

            opcode_count += 1

        if idx < len(bc_bytes):
            lines.append(f"  ... ({len(bc_bytes) - idx} more bytes)")

        return "\n".join(lines)

    def _extract_patterns(self, bytecode: str) -> Dict[str, Any]:
        """Extract high-level patterns from bytecode."""
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]

        bc_lower = bytecode.lower()
        patterns = {
            "has_flash_loan_callback": any(
                sig in bc_lower for sig in ["23e30c8b", "ab803a65", "c3924ed6", "ee872558"]
            ),
            "has_selfdestruct": "ff" in [
                bc_lower[i : i + 2] for i in range(0, len(bc_lower), 2)
            ],
            "has_delegatecall": "f4" in bc_lower,
            "has_create2": "f5" in bc_lower,
            "has_admin_functions": any(
                sig in bc_lower for sig in ["715018a6", "f2fde38b", "8456cb59"]
            ),
            "has_proxy_pattern": any(
                sig in bc_lower for sig in ["5c60da1b", "3659cfe6", "4f1ef286"]
            ),
            "bytecode_size": len(bytecode) // 2,
        }

        # Count key opcodes
        try:
            bc_bytes = bytes.fromhex(bc_lower)
            idx = 0
            call_count = 0
            sstore_count = 0
            sload_count = 0

            while idx < len(bc_bytes):
                op = bc_bytes[idx]
                if op == 0xF1:
                    call_count += 1
                elif op == 0x55:
                    sstore_count += 1
                elif op == 0x54:
                    sload_count += 1

                if 0x60 <= op <= 0x7F:
                    idx += op - 0x5F + 1
                else:
                    idx += 1

            patterns["call_count"] = call_count
            patterns["sstore_count"] = sstore_count
            patterns["sload_count"] = sload_count
        except ValueError:
            pass

        # Find function selectors
        selectors_found = []
        for sig, name in KNOWN_SELECTORS.items():
            if sig in bc_lower:
                selectors_found.append(f"{name} (0x{sig})")
        patterns["detected_functions"] = selectors_found

        return patterns

    def analyze(
        self,
        bytecode: str,
        contract_address: Optional[str] = None,
    ) -> Optional[ContractAnalysis]:
        """
        Analyze contract bytecode using LLM.

        Args:
            bytecode: Hex bytecode string (with or without 0x prefix)
            contract_address: Optional address for tracking

        Returns:
            ContractAnalysis or None if LLM unavailable
        """
        client = get_client()
        if not client:
            return None

        # Disassemble
        disassembly = self._disassemble(bytecode, max_opcodes=400)
        patterns = self._extract_patterns(bytecode)

        # Build prompt
        context_parts = []
        if contract_address:
            context_parts.append(f"Contract Address: {contract_address}")
        context_parts.append(f"Bytecode Size: {patterns['bytecode_size']} bytes")
        context_parts.append("")
        context_parts.append("=== DETECTED PATTERNS ===")
        for k, v in patterns.items():
            if k not in ("bytecode_size", "detected_functions"):
                context_parts.append(f"  {k}: {v}")

        if patterns.get("detected_functions"):
            context_parts.append("\n=== KNOWN FUNCTION SELECTORS ===")
            for fn in patterns["detected_functions"]:
                context_parts.append(f"  {fn}")

        context_parts.append("\n=== DISASSEMBLED OPCODES ===")
        context_parts.append(disassembly)

        context = "\n".join(context_parts)

        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=1500,
                system=ANALYZER_SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": f"Analyze this EVM contract:\n\n{context}",
                    }
                ],
            )

            raw = response.content[0].text.strip()
            if "```" in raw:
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            result = json.loads(raw)

            analysis = ContractAnalysis(
                contract_address=contract_address,
                summary=result.get("summary", "Analysis unavailable"),
                threat_assessment=result.get("threat_assessment", "unknown"),
                threat_level=float(result.get("threat_level", 0.5)),
                identified_functions=result.get("identified_functions", []),
                attack_vectors=result.get("attack_vectors", []),
                similar_to=result.get("similar_to", []),
                recommendations=result.get("recommendations", []),
                decompiled_highlights=disassembly[:500],
            )

            logger.info(
                "bytecode_analyzed",
                contract=contract_address or "unknown",
                assessment=analysis.threat_assessment,
                threat_level=analysis.threat_level,
                attack_vectors=len(analysis.attack_vectors),
            )

            return analysis

        except Exception as e:
            logger.error(
                "bytecode_analysis_failed",
                contract=contract_address or "unknown",
                error=str(e),
            )
            return None

    async def analyze_async(
        self,
        bytecode: str,
        contract_address: Optional[str] = None,
    ) -> Optional[ContractAnalysis]:
        """Async version of analyze() — uses AsyncAnthropic for non-blocking calls."""
        client = get_async_client()
        if not client:
            return None

        disassembly = self._disassemble(bytecode, max_opcodes=400)
        patterns = self._extract_patterns(bytecode)

        context_parts = []
        if contract_address:
            context_parts.append(f"Contract Address: {contract_address}")
        context_parts.append(f"Bytecode Size: {patterns['bytecode_size']} bytes")
        context_parts.append("")
        context_parts.append("=== DETECTED PATTERNS ===")
        for k, v in patterns.items():
            if k not in ("bytecode_size", "detected_functions"):
                context_parts.append(f"  {k}: {v}")

        if patterns.get("detected_functions"):
            context_parts.append("\n=== KNOWN FUNCTION SELECTORS ===")
            for fn in patterns["detected_functions"]:
                context_parts.append(f"  {fn}")

        context_parts.append("\n=== DISASSEMBLED OPCODES ===")
        context_parts.append(disassembly)
        context = "\n".join(context_parts)

        try:
            response = await client.messages.create(
                model=MODEL,
                max_tokens=1500,
                system=ANALYZER_SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": f"Analyze this EVM contract:\n\n{context}",
                    }
                ],
            )

            raw = response.content[0].text.strip()
            if "```" in raw:
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            result = json.loads(raw)

            analysis = ContractAnalysis(
                contract_address=contract_address,
                summary=result.get("summary", "Analysis unavailable"),
                threat_assessment=result.get("threat_assessment", "unknown"),
                threat_level=float(result.get("threat_level", 0.5)),
                identified_functions=result.get("identified_functions", []),
                attack_vectors=result.get("attack_vectors", []),
                similar_to=result.get("similar_to", []),
                recommendations=result.get("recommendations", []),
                decompiled_highlights=disassembly[:500],
            )

            logger.info(
                "bytecode_analyzed_async",
                contract=contract_address or "unknown",
                assessment=analysis.threat_assessment,
                threat_level=analysis.threat_level,
            )
            return analysis

        except Exception as e:
            logger.error(
                "bytecode_analysis_async_failed",
                contract=contract_address or "unknown",
                error=str(e),
            )
            return None

    def analyze_batch(
        self, contracts: List[Dict[str, str]]
    ) -> List[ContractAnalysis]:
        """
        Analyze multiple contracts.

        Args:
            contracts: List of {"address": "0x...", "bytecode": "0x..."} dicts
        """
        results = []
        for contract in contracts:
            analysis = self.analyze(
                bytecode=contract["bytecode"],
                contract_address=contract.get("address"),
            )
            if analysis:
                results.append(analysis)
        return results
