"""
Dynamic Smart Contract Vulnerability Scanner

A comprehensive scanner that combines:
1. Bytecode Analysis - Pattern matching on deployed bytecode
2. Source Code Analysis - AST-based vulnerability detection
3. Taint Analysis - Track untrusted inputs
4. Symbolic Execution - Path exploration (requires z3)

Detects:
- Integer Overflow/Underflow (Truebit-style)
- Reentrancy
- Access Control Issues
- Flash Loan Vulnerabilities
- Oracle Manipulation
- Unchecked External Calls
- Delegatecall Injection
- Self-Destruct Vulnerabilities
- Timestamp Dependence
- Front-Running Vulnerabilities
"""

# Core scanner (bytecode-based)
from .vulnerability_scanner import VulnerabilityScanner, ScanResult, Vulnerability, get_vulnerability_scanner
from .static_analyzer import StaticAnalyzer
from .taint_tracker import TaintTracker

# Source code analysis
from .source_fetcher import SourceFetcher, ContractSource, get_source_fetcher
from .solidity_parser import SolidityParser, ParsedSource, get_solidity_parser
from .source_analyzer import SourceAnalyzer, SourceVulnerability, get_source_analyzer

# Symbolic executor is optional (requires z3)
try:
    from .symbolic_executor import SymbolicExecutor
    SYMBOLIC_AVAILABLE = True
except ImportError:
    SymbolicExecutor = None
    SYMBOLIC_AVAILABLE = False

__all__ = [
    # Bytecode scanner
    'VulnerabilityScanner',
    'ScanResult', 
    'Vulnerability',
    'get_vulnerability_scanner',
    
    # Source code scanner
    'SourceFetcher',
    'ContractSource',
    'get_source_fetcher',
    'SolidityParser',
    'ParsedSource',
    'get_solidity_parser',
    'SourceAnalyzer',
    'SourceVulnerability',
    'get_source_analyzer',
    
    # Other analyzers
    'SymbolicExecutor',
    'StaticAnalyzer',
    'TaintTracker',
    'SYMBOLIC_AVAILABLE'
]
