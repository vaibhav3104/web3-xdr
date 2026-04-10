"""
Solidity Source Code Vulnerability Analyzer

Analyzes parsed Solidity AST for vulnerabilities.
Provides precise line-number locations and context.

Detects:
- Integer overflow/underflow (pre-0.8.0)
- Reentrancy
- Access control issues
- Unchecked external calls
- tx.origin usage
- Timestamp dependence
- Uninitialized storage
- And more...
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum
import structlog

from .solidity_parser import (
    SolidityParser, ParsedSource, ContractNode, FunctionNode, 
    VariableNode, Visibility, Mutability, get_solidity_parser
)
from .vulnerability_scanner import Vulnerability, VulnerabilityType, Severity

logger = structlog.get_logger()


@dataclass
class SourceVulnerability:
    """Vulnerability found in source code with precise location"""
    vuln_type: VulnerabilityType
    severity: Severity
    title: str
    description: str
    
    # Precise location
    file: str
    line: int
    column: int = 0
    end_line: int = 0
    
    # Context
    function_name: str = ""
    contract_name: str = ""
    code_snippet: str = ""
    
    # Analysis details
    confidence: float = 0.8
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.vuln_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": {
                "file": self.file,
                "line": self.line,
                "column": self.column,
                "end_line": self.end_line
            },
            "context": {
                "function": self.function_name,
                "contract": self.contract_name,
                "code_snippet": self.code_snippet
            },
            "confidence": self.confidence,
            "recommendation": self.recommendation,
            "references": self.references
        }


class SourceAnalyzer:
    """
    Analyzes Solidity source code for vulnerabilities
    """
    
    # Patterns for vulnerability detection
    PATTERNS = {
        # Reentrancy: external call before state change
        "reentrancy_call": re.compile(
            r'\.call\{.*?\}\(|\.call\(|\.send\(|\.transfer\(',
            re.MULTILINE | re.DOTALL
        ),
        
        # State changes
        "state_change": re.compile(
            r'\b(\w+)\s*=\s*[^=]|'
            r'\b(\w+)\s*\+=|'
            r'\b(\w+)\s*-=|'
            r'\b(\w+)\s*\*=|'
            r'\b(\w+)\s*/=',
            re.MULTILINE
        ),
        
        # tx.origin usage
        "tx_origin": re.compile(
            r'\btx\.origin\b',
            re.MULTILINE
        ),
        
        # Timestamp dependence
        "timestamp": re.compile(
            r'\bblock\.timestamp\b|\bnow\b',
            re.MULTILINE
        ),
        
        # Low-level call (we check for unchecked separately)
        "low_level_call": re.compile(
            r'\b\w+\.call\{?[^}]*\}?\([^)]*\)',
            re.MULTILINE
        ),
        
        # Integer arithmetic (pre-0.8.0)
        "arithmetic": re.compile(
            r'(\+|\-|\*|\/)\s*(?!=)',
            re.MULTILINE
        ),
        
        # SafeMath usage
        "safemath": re.compile(
            r'\.add\(|\.sub\(|\.mul\(|\.div\(|SafeMath',
            re.MULTILINE
        ),
        
        # Delegatecall
        "delegatecall": re.compile(
            r'\.delegatecall\(',
            re.MULTILINE
        ),
        
        # Selfdestruct
        "selfdestruct": re.compile(
            r'\bselfdestruct\(|\bsuicide\(',
            re.MULTILINE
        ),
        
        # Assembly
        "assembly": re.compile(
            r'\bassembly\s*\{',
            re.MULTILINE
        ),
        
        # Unchecked block (0.8+)
        "unchecked": re.compile(
            r'\bunchecked\s*\{',
            re.MULTILINE
        ),
        
        # Floating pragma
        "floating_pragma": re.compile(
            r'pragma\s+solidity\s*[\^~]',
            re.MULTILINE
        ),
        
        # Multiple pragma
        "pragma_version": re.compile(
            r'pragma\s+solidity\s*([^;]+)',
            re.MULTILINE
        ),
        
        # Private function without underscore
        "naming_private": re.compile(
            r'function\s+(?!_)(\w+)[^{]*\bprivate\b',
            re.MULTILINE
        ),
        
        # Public state variable
        "public_state": re.compile(
            r'^\s*(\w+(?:\[\w+\])?)\s+public\s+(\w+)',
            re.MULTILINE
        ),
        
        # External call in loop
        "loop_call": re.compile(
            r'for\s*\([^)]*\)\s*\{[^}]*\.(?:call|send|transfer)\(',
            re.MULTILINE | re.DOTALL
        ),
        
        # Division before multiplication
        "div_before_mul": re.compile(
            r'\/[^;]*\*',
            re.MULTILINE
        ),
    }
    
    def __init__(self):
        """Initialize the analyzer"""
        self.parser = get_solidity_parser()
        self.vulnerabilities: List[SourceVulnerability] = []
    
    def analyze(self, source_code: str, filename: str = "main.sol") -> List[SourceVulnerability]:
        """
        Analyze source code for vulnerabilities
        
        Args:
            source_code: Solidity source code
            filename: Source file name
        
        Returns:
            List of vulnerabilities found
        """
        self.vulnerabilities = []
        
        # Parse source code
        parsed = self.parser.parse(source_code, filename)
        
        if parsed.errors:
            logger.warning("parse_errors", errors=parsed.errors)
        
        # Extract Solidity version
        solidity_version = self._extract_version(parsed.pragma)
        is_pre_0_8 = self._is_pre_0_8(solidity_version)
        
        # Run all detectors
        self._check_pragma(source_code, filename)
        self._check_reentrancy(source_code, filename, parsed)
        self._check_integer_overflow(source_code, filename, parsed, is_pre_0_8)
        self._check_tx_origin(source_code, filename, parsed)
        self._check_timestamp_dependence(source_code, filename, parsed)
        self._check_unchecked_calls(source_code, filename, parsed)
        self._check_delegatecall(source_code, filename, parsed)
        self._check_selfdestruct(source_code, filename, parsed)
        self._check_access_control(source_code, filename, parsed)
        self._check_dos_patterns(source_code, filename, parsed)
        self._check_precision_loss(source_code, filename, parsed)
        
        # NEW: DeFi-specific detectors
        self._check_flash_loan_vulnerabilities(source_code, filename, parsed)
        self._check_oracle_manipulation(source_code, filename, parsed)
        self._check_signature_replay(source_code, filename, parsed)
        self._check_front_running(source_code, filename, parsed)
        
        # NEW: Proxy/Upgradeable detectors
        self._check_uninitialized_proxy(source_code, filename, parsed)
        self._check_storage_collision(source_code, filename, parsed)
        
        # NEW: Token safety detectors
        self._check_unsafe_erc20(source_code, filename, parsed)
        self._check_hardcoded_addresses(source_code, filename, parsed)
        
        return self.vulnerabilities
    
    def _extract_version(self, pragma: str) -> Optional[str]:
        """Extract Solidity version from pragma"""
        if not pragma:
            return None
        
        # Handle ranges like ^0.8.0, >=0.7.0 <0.9.0
        match = re.search(r'(\d+\.\d+\.\d+)', pragma)
        if match:
            return match.group(1)
        
        match = re.search(r'(\d+\.\d+)', pragma)
        if match:
            return match.group(1) + ".0"
        
        return None
    
    def _is_pre_0_8(self, version: Optional[str]) -> bool:
        """Check if version is before 0.8.0"""
        if not version:
            return True  # Assume worst case
        
        try:
            parts = version.split('.')
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            return major == 0 and minor < 8
        except (ValueError, IndexError):
            return True
    
    def _get_line_number(self, source: str, position: int) -> int:
        """Get line number from character position"""
        return source[:position].count('\n') + 1
    
    def _get_code_snippet(self, source: str, line: int, context: int = 2) -> str:
        """Get code snippet around a line"""
        lines = source.split('\n')
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line - 1 else "    "
            snippet_lines.append(f"{i + 1:4d} {prefix}{lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _find_function_at_line(self, parsed: ParsedSource, line: int) -> Tuple[str, str]:
        """Find function and contract name at a given line"""
        for contract in parsed.contracts:
            contract_start = contract.location.line if contract.location else 0
            
            for func in contract.functions:
                func_line = func.location.line if func.location else 0
                # Estimate function end (simplified)
                func_end = func_line + func.body.count('\n') + 1 if func.body else func_line + 10
                
                if func_line <= line <= func_end:
                    return func.name, contract.name
        
        return "", ""
    
    # =========================================================================
    # VULNERABILITY DETECTORS
    # =========================================================================
    
    def _check_pragma(self, source: str, filename: str):
        """Check pragma statement for issues"""
        
        # Check for floating pragma
        match = self.PATTERNS["floating_pragma"].search(source)
        if match:
            line = self._get_line_number(source, match.start())
            self.vulnerabilities.append(SourceVulnerability(
                vuln_type=VulnerabilityType.FLOATING_PRAGMA,
                severity=Severity.LOW,
                title="Floating Pragma",
                description="Contract uses a floating pragma version. This can lead to "
                           "inconsistent behavior across different compiler versions.",
                file=filename,
                line=line,
                code_snippet=self._get_code_snippet(source, line),
                confidence=0.95,
                recommendation="Lock pragma to a specific version: pragma solidity 0.8.19;",
                references=["https://swcregistry.io/docs/SWC-103"]
            ))
        
        # Check for outdated version
        version_match = self.PATTERNS["pragma_version"].search(source)
        if version_match:
            version_str = version_match.group(1)
            version = self._extract_version(version_str)
            
            if version and self._is_pre_0_8(version):
                line = self._get_line_number(source, version_match.start())
                self.vulnerabilities.append(SourceVulnerability(
                    vuln_type=VulnerabilityType.OUTDATED_COMPILER,
                    severity=Severity.HIGH,
                    title=f"Outdated Solidity Version ({version})",
                    description=f"Contract uses Solidity {version} which does not have "
                               f"built-in overflow/underflow protection. This is the same "
                               f"vulnerability class that led to the Truebit $26M hack.",
                    file=filename,
                    line=line,
                    code_snippet=self._get_code_snippet(source, line),
                    confidence=0.95,
                    recommendation="Upgrade to Solidity 0.8.x or later for built-in overflow checks",
                    references=[
                        "https://docs.soliditylang.org/en/v0.8.0/080-breaking-changes.html",
                        "https://www.quillaudits.com/blog/hack-analysis/truebit-26m-hack-explained"
                    ]
                ))
    
    def _check_reentrancy(self, source: str, filename: str, parsed: ParsedSource):
        """Check for reentrancy vulnerabilities"""
        
        for contract in parsed.contracts:
            for func in contract.functions:
                if not func.body:
                    continue
                
                body = func.body
                
                # Find external calls
                call_matches = list(self.PATTERNS["reentrancy_call"].finditer(body))
                if not call_matches:
                    continue
                
                # Find state changes
                state_matches = list(self.PATTERNS["state_change"].finditer(body))
                
                # Check for call before state change (classic reentrancy)
                for call_match in call_matches:
                    call_pos = call_match.start()
                    
                    for state_match in state_matches:
                        state_pos = state_match.start()
                        
                        # State change AFTER call = potential reentrancy
                        if state_pos > call_pos:
                            # Check if function has reentrancy guard
                            has_guard = any(
                                mod in ['nonReentrant', 'reentrancyGuard', 'lock']
                                for mod in func.modifiers
                            )
                            
                            if not has_guard:
                                func_line = func.location.line if func.location else 0
                                call_line = func_line + body[:call_pos].count('\n')
                                
                                self.vulnerabilities.append(SourceVulnerability(
                                    vuln_type=VulnerabilityType.REENTRANCY,
                                    severity=Severity.CRITICAL,
                                    title="Reentrancy Vulnerability",
                                    description=f"External call in function '{func.name}' occurs before "
                                               f"state variable update. An attacker could re-enter the "
                                               f"function before state is updated.",
                                    file=filename,
                                    line=call_line,
                                    function_name=func.name,
                                    contract_name=contract.name,
                                    code_snippet=self._get_code_snippet(source, call_line),
                                    confidence=0.85,
                                    recommendation="1. Use checks-effects-interactions pattern\n"
                                                 "2. Add ReentrancyGuard modifier\n"
                                                 "3. Update state BEFORE external calls",
                                    references=[
                                        "https://swcregistry.io/docs/SWC-107",
                                        "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/"
                                    ]
                                ))
                                break
    
    def _check_integer_overflow(self, source: str, filename: str, parsed: ParsedSource, is_pre_0_8: bool):
        """Check for integer overflow vulnerabilities"""
        
        if not is_pre_0_8:
            # Check for unchecked blocks in 0.8+
            for match in self.PATTERNS["unchecked"].finditer(source):
                line = self._get_line_number(source, match.start())
                func_name, contract_name = self._find_function_at_line(parsed, line)
                
                self.vulnerabilities.append(SourceVulnerability(
                    vuln_type=VulnerabilityType.INTEGER_OVERFLOW,
                    severity=Severity.MEDIUM,
                    title="Unchecked Arithmetic Block",
                    description="Contract uses 'unchecked' block which disables overflow checks. "
                               "Ensure this is intentional and values cannot overflow.",
                    file=filename,
                    line=line,
                    function_name=func_name,
                    contract_name=contract_name,
                    code_snippet=self._get_code_snippet(source, line),
                    confidence=0.7,
                    recommendation="Verify that unchecked arithmetic cannot overflow"
                ))
            return
        
        # Pre-0.8.0: Check for arithmetic without SafeMath
        has_safemath = bool(self.PATTERNS["safemath"].search(source))
        
        if not has_safemath:
            # Find arithmetic operations
            for contract in parsed.contracts:
                for func in contract.functions:
                    if not func.body:
                        continue
                    
                    # Count arithmetic operations in function
                    arith_matches = list(self.PATTERNS["arithmetic"].finditer(func.body))
                    
                    if arith_matches:
                        func_line = func.location.line if func.location else 0
                        
                        self.vulnerabilities.append(SourceVulnerability(
                            vuln_type=VulnerabilityType.INTEGER_OVERFLOW,
                            severity=Severity.CRITICAL,
                            title="Integer Overflow Vulnerability (Truebit-style)",
                            description=f"Function '{func.name}' contains {len(arith_matches)} "
                                       f"arithmetic operations without SafeMath protection. "
                                       f"This is the same vulnerability class that caused the "
                                       f"Truebit $26M hack in January 2026.",
                            file=filename,
                            line=func_line,
                            function_name=func.name,
                            contract_name=contract.name,
                            code_snippet=self._get_code_snippet(source, func_line),
                            confidence=0.9,
                            recommendation="1. Upgrade to Solidity 0.8+ for built-in checks\n"
                                         "2. Use OpenZeppelin SafeMath library\n"
                                         "3. Add require() checks for input validation",
                            references=[
                                "https://www.quillaudits.com/blog/hack-analysis/truebit-26m-hack-explained",
                                "https://swcregistry.io/docs/SWC-101"
                            ]
                        ))
    
    def _check_tx_origin(self, source: str, filename: str, parsed: ParsedSource):
        """Check for tx.origin usage"""
        
        for match in self.PATTERNS["tx_origin"].finditer(source):
            line = self._get_line_number(source, match.start())
            func_name, contract_name = self._find_function_at_line(parsed, line)
            
            # Check if used in comparison (authentication)
            context = source[max(0, match.start() - 50):match.end() + 50]
            is_auth = '==' in context or 'require' in context.lower()
            
            severity = Severity.HIGH if is_auth else Severity.MEDIUM
            
            self.vulnerabilities.append(SourceVulnerability(
                vuln_type=VulnerabilityType.TX_ORIGIN_AUTH,
                severity=severity,
                title="tx.origin Usage" + (" for Authentication" if is_auth else ""),
                description="Contract uses tx.origin" + 
                           (". Using tx.origin for authentication is vulnerable to phishing attacks "
                            "where a malicious contract tricks users into calling it." if is_auth 
                            else ". Consider if msg.sender would be more appropriate."),
                file=filename,
                line=line,
                function_name=func_name,
                contract_name=contract_name,
                code_snippet=self._get_code_snippet(source, line),
                confidence=0.9 if is_auth else 0.6,
                recommendation="Use msg.sender instead of tx.origin for authentication",
                references=["https://swcregistry.io/docs/SWC-115"]
            ))
    
    def _check_timestamp_dependence(self, source: str, filename: str, parsed: ParsedSource):
        """Check for timestamp dependence"""
        
        for match in self.PATTERNS["timestamp"].finditer(source):
            line = self._get_line_number(source, match.start())
            func_name, contract_name = self._find_function_at_line(parsed, line)
            
            # Check context for critical usage
            context = source[max(0, match.start() - 100):match.end() + 100]
            is_critical = any(kw in context.lower() for kw in 
                            ['require', 'if', 'random', 'seed', 'winner', 'lottery'])
            
            self.vulnerabilities.append(SourceVulnerability(
                vuln_type=VulnerabilityType.TIMESTAMP_DEPENDENCE,
                severity=Severity.MEDIUM if is_critical else Severity.LOW,
                title="Timestamp Dependence",
                description="Contract uses block.timestamp which can be manipulated by miners "
                           "within a ~15 second window.",
                file=filename,
                line=line,
                function_name=func_name,
                contract_name=contract_name,
                code_snippet=self._get_code_snippet(source, line),
                confidence=0.7,
                recommendation="Avoid using block.timestamp for critical logic. "
                             "Use block.number for time-based logic or Chainlink VRF for randomness.",
                references=["https://swcregistry.io/docs/SWC-116"]
            ))
    
    def _check_unchecked_calls(self, source: str, filename: str, parsed: ParsedSource):
        """Check for unchecked low-level calls"""
        
        # Look for .call() without checking return value
        call_pattern = re.compile(r'(\w+)?\.call\{?[^}]*\}?\([^)]*\)')
        
        for match in call_pattern.finditer(source):
            line = self._get_line_number(source, match.start())
            
            # Check if return value is captured
            line_start = source.rfind('\n', 0, match.start()) + 1
            line_content = source[line_start:source.find('\n', match.end())]
            
            # Check for (bool success, ) = ... pattern
            has_check = re.search(r'\(\s*bool\s+\w+\s*,?\s*\)', line_content)
            
            if not has_check:
                func_name, contract_name = self._find_function_at_line(parsed, line)
                
                self.vulnerabilities.append(SourceVulnerability(
                    vuln_type=VulnerabilityType.UNCHECKED_CALL,
                    severity=Severity.MEDIUM,
                    title="Unchecked Low-Level Call",
                    description="Low-level call return value is not checked. "
                               "Failed calls will not revert the transaction.",
                    file=filename,
                    line=line,
                    function_name=func_name,
                    contract_name=contract_name,
                    code_snippet=self._get_code_snippet(source, line),
                    confidence=0.8,
                    recommendation="Check return value: (bool success, ) = addr.call(...); require(success);",
                    references=["https://swcregistry.io/docs/SWC-104"]
                ))
    
    def _check_delegatecall(self, source: str, filename: str, parsed: ParsedSource):
        """Check for dangerous delegatecall usage"""
        
        for match in self.PATTERNS["delegatecall"].finditer(source):
            line = self._get_line_number(source, match.start())
            func_name, contract_name = self._find_function_at_line(parsed, line)
            
            # Check if target comes from user input
            context = source[max(0, match.start() - 200):match.end()]
            is_user_controlled = any(kw in context for kw in 
                                    ['msg.data', 'calldata', '_target', '_implementation'])
            
            self.vulnerabilities.append(SourceVulnerability(
                vuln_type=VulnerabilityType.DELEGATECALL_INJECTION,
                severity=Severity.CRITICAL if is_user_controlled else Severity.MEDIUM,
                title="Delegatecall Usage" + (" to User-Controlled Address" if is_user_controlled else ""),
                description="Contract uses delegatecall" +
                           (". The target appears to come from user input, allowing arbitrary "
                            "code execution in this contract's context." if is_user_controlled
                            else ". Ensure the target is a trusted, immutable address."),
                file=filename,
                line=line,
                function_name=func_name,
                contract_name=contract_name,
                code_snippet=self._get_code_snippet(source, line),
                confidence=0.85 if is_user_controlled else 0.6,
                recommendation="Never delegatecall to user-controlled addresses. "
                             "Use immutable implementation addresses.",
                references=["https://swcregistry.io/docs/SWC-112"]
            ))
    
    def _check_selfdestruct(self, source: str, filename: str, parsed: ParsedSource):
        """Check for selfdestruct usage"""
        
        for match in self.PATTERNS["selfdestruct"].finditer(source):
            line = self._get_line_number(source, match.start())
            func_name, contract_name = self._find_function_at_line(parsed, line)
            
            # Check for access control
            for contract in parsed.contracts:
                for func in contract.functions:
                    if func.location and func.location.line <= line:
                        has_access_control = any(
                            mod in ['onlyOwner', 'onlyAdmin', 'authorized']
                            for mod in func.modifiers
                        )
                        
                        if not has_access_control:
                            self.vulnerabilities.append(SourceVulnerability(
                                vuln_type=VulnerabilityType.SELF_DESTRUCT,
                                severity=Severity.CRITICAL,
                                title="Unprotected Selfdestruct",
                                description="Contract has selfdestruct without apparent access control. "
                                           "Anyone could potentially destroy the contract.",
                                file=filename,
                                line=line,
                                function_name=func_name,
                                contract_name=contract_name,
                                code_snippet=self._get_code_snippet(source, line),
                                confidence=0.8,
                                recommendation="Add access control (onlyOwner) to selfdestruct",
                                references=["https://swcregistry.io/docs/SWC-106"]
                            ))
                        break
    
    def _check_access_control(self, source: str, filename: str, parsed: ParsedSource):
        """Check for access control issues"""
        
        # Check for public/external functions that modify state without access control
        dangerous_patterns = ['withdraw', 'transfer', 'mint', 'burn', 'set', 'update', 'change']
        
        for contract in parsed.contracts:
            for func in contract.functions:
                if func.visibility not in [Visibility.PUBLIC, Visibility.EXTERNAL]:
                    continue
                
                if func.mutability in [Mutability.VIEW, Mutability.PURE]:
                    continue
                
                # Check if function name suggests sensitive operation
                is_sensitive = any(p in func.name.lower() for p in dangerous_patterns)
                
                if is_sensitive and not func.modifiers:
                    func_line = func.location.line if func.location else 0
                    
                    self.vulnerabilities.append(SourceVulnerability(
                        vuln_type=VulnerabilityType.MISSING_ACCESS_CONTROL,
                        severity=Severity.HIGH,
                        title=f"Missing Access Control on '{func.name}'",
                        description=f"Function '{func.name}' appears to perform a sensitive operation "
                                   f"but has no access control modifiers.",
                        file=filename,
                        line=func_line,
                        function_name=func.name,
                        contract_name=contract.name,
                        code_snippet=self._get_code_snippet(source, func_line),
                        confidence=0.7,
                        recommendation="Add access control modifier (onlyOwner, onlyRole, etc.)",
                        references=["https://swcregistry.io/docs/SWC-105"]
                    ))
    
    def _check_dos_patterns(self, source: str, filename: str, parsed: ParsedSource):
        """Check for denial of service patterns"""
        
        # Check for external calls in loops
        for match in self.PATTERNS["loop_call"].finditer(source):
            line = self._get_line_number(source, match.start())
            func_name, contract_name = self._find_function_at_line(parsed, line)
            
            self.vulnerabilities.append(SourceVulnerability(
                vuln_type=VulnerabilityType.DOS_GAS_LIMIT,
                severity=Severity.MEDIUM,
                title="External Call in Loop",
                description="External call inside a loop can lead to DoS if the loop iterates "
                           "many times or if one call fails.",
                file=filename,
                line=line,
                function_name=func_name,
                contract_name=contract_name,
                code_snippet=self._get_code_snippet(source, line),
                confidence=0.75,
                recommendation="Use pull pattern instead of push. Let users withdraw individually.",
                references=["https://swcregistry.io/docs/SWC-128"]
            ))
    
    def _check_precision_loss(self, source: str, filename: str, parsed: ParsedSource):
        """Check for precision loss in arithmetic"""
        
        # Division before multiplication
        for match in self.PATTERNS["div_before_mul"].finditer(source):
            line = self._get_line_number(source, match.start())
            func_name, contract_name = self._find_function_at_line(parsed, line)
            
            self.vulnerabilities.append(SourceVulnerability(
                vuln_type=VulnerabilityType.LOGIC_ERROR,
                severity=Severity.LOW,
                title="Division Before Multiplication",
                description="Division performed before multiplication can lead to precision loss "
                           "due to integer truncation.",
                file=filename,
                line=line,
                function_name=func_name,
                contract_name=contract_name,
                code_snippet=self._get_code_snippet(source, line),
                confidence=0.6,
                recommendation="Perform multiplication before division to preserve precision",
                references=[]
            ))
    
    def _check_flash_loan_vulnerabilities(self, source: str, filename: str, parsed: ParsedSource):
        """Check for flash loan attack vulnerabilities"""
        
        # Pattern: Price calculation in same transaction as swap
        flash_patterns = [
            (r'flashLoan|flashBorrow|flash\(', 'Flash Loan Usage'),
            (r'getReserves\(\).*swap|swap.*getReserves\(\)', 'Price Before Swap'),
            (r'balanceOf\([^)]+\).*transfer|transfer.*balanceOf', 'Balance Check Before Transfer'),
        ]
        
        for pattern, name in flash_patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE | re.DOTALL):
                line = self._get_line_number(source, match.start())
                func_name, contract_name = self._find_function_at_line(parsed, line)
                
                self.vulnerabilities.append(SourceVulnerability(
                    vuln_type=VulnerabilityType.FLASH_LOAN_ATTACK,
                    severity=Severity.HIGH,
                    title=f"Potential Flash Loan Vulnerability: {name}",
                    description="Contract may be vulnerable to flash loan attacks. "
                               "Price or balance calculations in the same transaction as "
                               "swaps can be manipulated.",
                    file=filename,
                    line=line,
                    function_name=func_name,
                    contract_name=contract_name,
                    code_snippet=self._get_code_snippet(source, line),
                    confidence=0.7,
                    recommendation="Use time-weighted average prices (TWAP) or Chainlink oracles. "
                                 "Implement flash loan guards.",
                    references=[
                        "https://www.paradigm.xyz/2020/11/so-you-want-to-use-a-price-oracle"
                    ]
                ))
    
    def _check_oracle_manipulation(self, source: str, filename: str, parsed: ParsedSource):
        """Check for oracle manipulation vulnerabilities"""
        
        # Spot price patterns
        spot_patterns = [
            (r'getReserves\(\)', 'Using AMM Reserves as Price'),
            (r'balanceOf\([^)]+\)\s*/\s*totalSupply', 'Share Price from Balance'),
            (r'slot0\(\)', 'Using Uniswap V3 Spot Price'),
        ]
        
        for pattern, name in spot_patterns:
            for match in re.finditer(pattern, source):
                line = self._get_line_number(source, match.start())
                func_name, contract_name = self._find_function_at_line(parsed, line)
                
                # Check if there's a TWAP or oracle nearby
                context = source[max(0, match.start() - 500):match.end() + 500]
                has_protection = any(p in context.lower() for p in 
                                   ['twap', 'chainlink', 'oracle', 'observe', 'consult'])
                
                if not has_protection:
                    self.vulnerabilities.append(SourceVulnerability(
                        vuln_type=VulnerabilityType.ORACLE_MANIPULATION,
                        severity=Severity.HIGH,
                        title=f"Oracle Manipulation Risk: {name}",
                        description="Contract uses spot price that can be manipulated within "
                                   "a single transaction. Flash loan attacks can exploit this.",
                        file=filename,
                        line=line,
                        function_name=func_name,
                        contract_name=contract_name,
                        code_snippet=self._get_code_snippet(source, line),
                        confidence=0.75,
                        recommendation="Use Chainlink price feeds or implement TWAP with sufficient period",
                        references=[
                            "https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles"
                        ]
                    ))
    
    def _check_signature_replay(self, source: str, filename: str, parsed: ParsedSource):
        """Check for signature replay vulnerabilities"""
        
        # ecrecover without nonce/deadline
        ecrecover_pattern = re.compile(r'ecrecover\s*\(', re.IGNORECASE)
        
        for match in ecrecover_pattern.finditer(source):
            line = self._get_line_number(source, match.start())
            func_name, contract_name = self._find_function_at_line(parsed, line)
            
            # Check for nonce/deadline in context
            context = source[max(0, match.start() - 300):match.end() + 300]
            has_nonce = any(p in context.lower() for p in ['nonce', 'deadline', 'expiry', 'validuntil'])
            
            if not has_nonce:
                self.vulnerabilities.append(SourceVulnerability(
                    vuln_type=VulnerabilityType.SIGNATURE_REPLAY,
                    severity=Severity.HIGH,
                    title="Signature Replay Vulnerability",
                    description="Contract uses ecrecover without apparent nonce or deadline. "
                               "Signatures may be replayed across transactions or chains.",
                    file=filename,
                    line=line,
                    function_name=func_name,
                    contract_name=contract_name,
                    code_snippet=self._get_code_snippet(source, line),
                    confidence=0.7,
                    recommendation="Include nonce, deadline, and chain ID in signed messages. "
                                 "Use EIP-712 for structured data signing.",
                    references=[
                        "https://swcregistry.io/docs/SWC-117",
                        "https://eips.ethereum.org/EIPS/eip-712"
                    ]
                ))
    
    def _check_front_running(self, source: str, filename: str, parsed: ParsedSource):
        """Check for front-running vulnerabilities"""
        
        # Patterns susceptible to front-running
        frontrun_patterns = [
            (r'approve\s*\([^)]+,\s*[^0]', 'Non-zero Approval'),
            (r'commit.*reveal|reveal.*commit', 'Commit-Reveal (check implementation)'),
            (r'firstCome|firstServe|auction', 'First-Come-First-Serve Pattern'),
        ]
        
        for pattern, name in frontrun_patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line = self._get_line_number(source, match.start())
                func_name, contract_name = self._find_function_at_line(parsed, line)
                
                self.vulnerabilities.append(SourceVulnerability(
                    vuln_type=VulnerabilityType.FRONT_RUNNING,
                    severity=Severity.MEDIUM,
                    title=f"Front-Running Risk: {name}",
                    description="This pattern may be vulnerable to front-running attacks where "
                               "miners or MEV bots can see and front-run transactions.",
                    file=filename,
                    line=line,
                    function_name=func_name,
                    contract_name=contract_name,
                    code_snippet=self._get_code_snippet(source, line),
                    confidence=0.6,
                    recommendation="Use commit-reveal schemes, submarine sends, or Flashbots protect",
                    references=[
                        "https://swcregistry.io/docs/SWC-114"
                    ]
                ))
    
    def _check_uninitialized_proxy(self, source: str, filename: str, parsed: ParsedSource):
        """Check for uninitialized proxy vulnerabilities"""
        
        # Check for initializer pattern without protection
        if 'initializer' in source.lower() or 'initialize' in source.lower():
            # Check if initialize is protected
            init_pattern = re.compile(r'function\s+initialize[^{]*\{', re.IGNORECASE)
            
            for match in init_pattern.finditer(source):
                line = self._get_line_number(source, match.start())
                
                # Check for initializer modifier
                func_def = source[match.start():match.end() + 200]
                has_protection = any(p in func_def for p in 
                                   ['initializer', 'onlyOnce', 'initialized', 'require(!_initialized'])
                
                if not has_protection:
                    func_name, contract_name = self._find_function_at_line(parsed, line)
                    
                    self.vulnerabilities.append(SourceVulnerability(
                        vuln_type=VulnerabilityType.UNINITIALIZED_PROXY,
                        severity=Severity.CRITICAL,
                        title="Unprotected Initialize Function",
                        description="Initialize function appears to lack protection against "
                                   "being called multiple times. This could allow attackers "
                                   "to take ownership of the contract.",
                        file=filename,
                        line=line,
                        function_name=func_name,
                        contract_name=contract_name,
                        code_snippet=self._get_code_snippet(source, line),
                        confidence=0.75,
                        recommendation="Use OpenZeppelin's Initializable contract with initializer modifier",
                        references=[
                            "https://blog.openzeppelin.com/the-state-of-smart-contract-upgrades"
                        ]
                    ))
    
    def _check_storage_collision(self, source: str, filename: str, parsed: ParsedSource):
        """Check for storage collision in upgradeable contracts"""
        
        # Check for proxy patterns
        if 'delegatecall' in source.lower() or 'upgradeable' in source.lower():
            # Check for ERC1967 slot usage
            has_erc1967 = 'erc1967' in source.lower() or '0x360894a13ba1a3210667c828492db98dca3e2076' in source.lower()
            
            if not has_erc1967 and 'implementation' in source.lower():
                line = 1  # General warning
                self.vulnerabilities.append(SourceVulnerability(
                    vuln_type=VulnerabilityType.STORAGE_COLLISION,
                    severity=Severity.HIGH,
                    title="Potential Storage Collision in Proxy",
                    description="Upgradeable contract may not use ERC1967 storage slots. "
                               "This could lead to storage collision between proxy and implementation.",
                    file=filename,
                    line=line,
                    code_snippet="",
                    confidence=0.6,
                    recommendation="Use ERC1967 storage slots or OpenZeppelin's proxy contracts",
                    references=[
                        "https://eips.ethereum.org/EIPS/eip-1967"
                    ]
                ))
    
    def _check_unsafe_erc20(self, source: str, filename: str, parsed: ParsedSource):
        """Check for unsafe ERC20 operations"""
        
        # Direct transfer without return check
        unsafe_patterns = [
            (r'\.transfer\s*\([^)]+\)\s*;', 'Unchecked transfer()'),
            (r'\.transferFrom\s*\([^)]+\)\s*;', 'Unchecked transferFrom()'),
            (r'\.approve\s*\([^)]+\)\s*;', 'Unchecked approve()'),
        ]
        
        for pattern, name in unsafe_patterns:
            for match in re.finditer(pattern, source):
                line = self._get_line_number(source, match.start())
                
                # Check if it's wrapped in require or if
                context_start = max(0, match.start() - 50)
                context = source[context_start:match.end()]
                is_checked = any(p in context for p in ['require(', 'if (', 'if(', 'assert('])
                
                # Check if using SafeERC20
                has_safe = 'SafeERC20' in source or 'safeTransfer' in source
                
                if not is_checked and not has_safe:
                    func_name, contract_name = self._find_function_at_line(parsed, line)
                    
                    self.vulnerabilities.append(SourceVulnerability(
                        vuln_type=VulnerabilityType.UNSAFE_ERC20,
                        severity=Severity.MEDIUM,
                        title=f"Unsafe ERC20 Operation: {name}",
                        description="ERC20 operation may fail silently. Some tokens don't return "
                                   "a boolean or may return false on failure.",
                        file=filename,
                        line=line,
                        function_name=func_name,
                        contract_name=contract_name,
                        code_snippet=self._get_code_snippet(source, line),
                        confidence=0.7,
                        recommendation="Use OpenZeppelin's SafeERC20 library for all token operations",
                        references=[
                            "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol"
                        ]
                    ))
    
    def _check_hardcoded_addresses(self, source: str, filename: str, parsed: ParsedSource):
        """Check for hardcoded addresses that might be problematic"""
        
        # Pattern for Ethereum addresses
        address_pattern = re.compile(r'0x[a-fA-F0-9]{40}')
        
        for match in address_pattern.finditer(source):
            address = match.group(0).lower()
            line = self._get_line_number(source, match.start())
            
            # Check if it's a known problematic address
            # (zero address is often intentional)
            if address == '0x' + '0' * 40:
                continue
            
            # Check context - is it a constant?
            context_start = source.rfind('\n', 0, match.start()) + 1
            context_end = source.find('\n', match.end())
            line_content = source[context_start:context_end]
            
            is_constant = 'constant' in line_content or 'immutable' in line_content
            
            if not is_constant:
                func_name, contract_name = self._find_function_at_line(parsed, line)
                
                self.vulnerabilities.append(SourceVulnerability(
                    vuln_type=VulnerabilityType.HARDCODED_ADDRESS,
                    severity=Severity.LOW,
                    title="Hardcoded Address",
                    description=f"Address {address[:10]}...{address[-6:]} is hardcoded. "
                               "Consider if this should be configurable or constant.",
                    file=filename,
                    line=line,
                    function_name=func_name,
                    contract_name=contract_name,
                    code_snippet=self._get_code_snippet(source, line),
                    confidence=0.5,
                    recommendation="Use immutable or constant for fixed addresses, "
                                 "or make configurable via constructor/setter",
                    references=[]
                ))
    
    def get_summary(self) -> Dict:
        """Get analysis summary"""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity.value] = \
                severity_counts.get(vuln.severity.value, 0) + 1
        
        return {
            "total": len(self.vulnerabilities),
            "by_severity": severity_counts,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }


# Singleton instance
_analyzer_instance: Optional[SourceAnalyzer] = None


def get_source_analyzer() -> SourceAnalyzer:
    """Get singleton analyzer instance"""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = SourceAnalyzer()
    return _analyzer_instance
