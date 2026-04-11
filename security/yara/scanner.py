#!/usr/bin/env python3
"""
Sentinel3 YARA Scanner
======================
Integrates YARA rules into the Sentinel3 detection pipeline.

Features:
- Smart contract bytecode scanning
- Container runtime file scanning
- Configuration tampering detection
- Log file forensics
- Memory dump analysis

Usage:
    # Scan contract bytecode
    scanner = YARAScanner()
    results = scanner.scan_bytecode("0x608060405234801561001057600080fd5b50...")
    
    # Scan container filesystem
    results = scanner.scan_directory("/app/")
    
    # Real-time monitoring integration
    from security.yara.scanner import YARAScanner
    scanner = YARAScanner()
    # Hook into event processing pipeline
"""

import os
import sys
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime

try:
    import yara
except ImportError:
    print("YARA Python bindings not installed. Run: pip install yara-python")
    sys.exit(1)

logger = logging.getLogger(__name__)


class ScanCategory(Enum):
    """YARA rule categories"""
    WEB3_CONTRACTS = "web3"
    CONTAINER_RUNTIME = "container"
    CONFIG_TAMPERING = "config"
    INCIDENT_RESPONSE = "incident_response"
    MALWARE = "malware"


class Severity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class YARAMatch:
    """Represents a YARA rule match"""
    rule_name: str
    category: str
    severity: str
    description: str
    confidence: int
    strings_matched: List[Dict[str, Any]]
    meta: Dict[str, Any]
    file_path: Optional[str] = None
    offset: Optional[int] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_alert(self) -> Dict[str, Any]:
        """Convert to Sentinel3 alert format"""
        return {
            "type": "yara_detection",
            "rule_id": self.rule_name,
            "severity": self.severity,
            "confidence": self.confidence / 100.0,
            "description": self.description,
            "category": self.category,
            "evidence": {
                "strings_matched": self.strings_matched,
                "file_path": self.file_path,
                "meta": self.meta
            },
            "timestamp": self.timestamp
        }


@dataclass
class ScanResult:
    """Result of a YARA scan"""
    target: str
    target_type: str  # bytecode, file, directory, memory
    scan_time_ms: float
    matches: List[YARAMatch]
    errors: List[str]
    
    @property
    def has_critical(self) -> bool:
        return any(m.severity == "CRITICAL" for m in self.matches)
    
    @property
    def has_matches(self) -> bool:
        return len(self.matches) > 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "scan_time_ms": self.scan_time_ms,
            "match_count": len(self.matches),
            "has_critical": self.has_critical,
            "matches": [m.to_dict() for m in self.matches],
            "errors": self.errors
        }


class YARAScanner:
    """
    YARA rule scanner for Sentinel3.
    
    Loads and compiles YARA rules from the rules directory,
    provides methods to scan various artifact types.
    """
    
    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize the YARA scanner.
        
        Args:
            rules_dir: Path to YARA rules directory. Defaults to ./rules/
        """
        if rules_dir is None:
            rules_dir = Path(__file__).parent / "rules"
        
        self.rules_dir = Path(rules_dir)
        self.compiled_rules: Dict[ScanCategory, yara.Rules] = {}
        self._load_rules()
    
    def _load_rules(self) -> None:
        """Load and compile all YARA rules"""
        for category in ScanCategory:
            category_dir = self.rules_dir / category.value
            if not category_dir.exists():
                logger.warning(f"Rules directory not found: {category_dir}")
                continue
            
            rule_files = list(category_dir.glob("*.yar"))
            if not rule_files:
                logger.warning(f"No .yar files found in {category_dir}")
                continue
            
            try:
                # Compile all rules in the category together
                filepaths = {f.stem: str(f) for f in rule_files}
                self.compiled_rules[category] = yara.compile(filepaths=filepaths)
                logger.info(f"Loaded {len(rule_files)} YARA rule files for {category.value}")
            except yara.SyntaxError as e:
                logger.error(f"YARA syntax error in {category.value}: {e}")
            except Exception as e:
                logger.error(f"Failed to load YARA rules for {category.value}: {e}")
    
    def _extract_match_info(self, match: yara.Match, file_path: Optional[str] = None) -> YARAMatch:
        """Extract structured information from a YARA match"""
        meta = dict(match.meta) if match.meta else {}
        
        strings_matched = []
        for string_match in match.strings:
            try:
                # Handle different yara-python API versions
                if hasattr(string_match, 'instances'):
                    for instance in string_match.instances:
                        matched_data = getattr(instance, 'matched_data', b'')
                        strings_matched.append({
                            "identifier": string_match.identifier,
                            "offset": getattr(instance, 'offset', 0),
                            "length": len(matched_data),
                            "data": matched_data[:100].hex() if len(matched_data) > 100 else matched_data.hex()
                        })
                else:
                    # Older API: string_match is a tuple (offset, identifier, data)
                    strings_matched.append({
                        "identifier": str(string_match[1]) if len(string_match) > 1 else "unknown",
                        "offset": string_match[0] if len(string_match) > 0 else 0,
                        "length": len(string_match[2]) if len(string_match) > 2 else 0,
                        "data": string_match[2][:100].hex() if len(string_match) > 2 else ""
                    })
            except Exception as e:
                # Fallback for any API issues
                strings_matched.append({
                    "identifier": str(string_match),
                    "offset": 0,
                    "length": 0,
                    "data": ""
                })
        
        return YARAMatch(
            rule_name=match.rule,
            category=meta.get("category", "unknown"),
            severity=meta.get("severity", "MEDIUM"),
            description=meta.get("description", "No description"),
            confidence=int(meta.get("confidence", 50)),
            strings_matched=strings_matched,
            meta=meta,
            file_path=file_path
        )
    
    def scan_bytecode(self, bytecode: Union[str, bytes], 
                      contract_address: Optional[str] = None) -> ScanResult:
        """
        Scan EVM contract bytecode for malicious patterns.
        
        Args:
            bytecode: Contract bytecode (hex string or bytes)
            contract_address: Optional contract address for logging
            
        Returns:
            ScanResult with any matches found
        """
        import time
        start_time = time.time()
        
        # Normalize bytecode
        if isinstance(bytecode, str):
            if bytecode.startswith("0x"):
                bytecode = bytecode[2:]
            try:
                bytecode = bytes.fromhex(bytecode)
            except ValueError as e:
                return ScanResult(
                    target=contract_address or "unknown",
                    target_type="bytecode",
                    scan_time_ms=0,
                    matches=[],
                    errors=[f"Invalid bytecode hex: {e}"]
                )
        
        matches = []
        errors = []
        
        # Scan with web3 rules
        if ScanCategory.WEB3_CONTRACTS in self.compiled_rules:
            try:
                yara_matches = self.compiled_rules[ScanCategory.WEB3_CONTRACTS].match(data=bytecode)
                for m in yara_matches:
                    match_info = self._extract_match_info(m, contract_address)
                    matches.append(match_info)
            except Exception as e:
                errors.append(f"Web3 scan error: {e}")
        
        scan_time = (time.time() - start_time) * 1000
        
        return ScanResult(
            target=contract_address or f"bytecode_{hashlib.sha256(bytecode).hexdigest()[:16]}",
            target_type="bytecode",
            scan_time_ms=round(scan_time, 2),
            matches=matches,
            errors=errors
        )
    
    def scan_file(self, file_path: str, 
                  categories: Optional[List[ScanCategory]] = None) -> ScanResult:
        """
        Scan a single file with YARA rules.
        
        Args:
            file_path: Path to file to scan
            categories: Optional list of categories to scan with. Defaults to all.
            
        Returns:
            ScanResult with any matches found
        """
        import time
        start_time = time.time()
        
        file_path = Path(file_path)
        if not file_path.exists():
            return ScanResult(
                target=str(file_path),
                target_type="file",
                scan_time_ms=0,
                matches=[],
                errors=[f"File not found: {file_path}"]
            )
        
        if categories is None:
            categories = list(self.compiled_rules.keys())
        
        matches = []
        errors = []
        
        for category in categories:
            if category not in self.compiled_rules:
                continue
            
            try:
                yara_matches = self.compiled_rules[category].match(str(file_path))
                for m in yara_matches:
                    match_info = self._extract_match_info(m, str(file_path))
                    matches.append(match_info)
            except Exception as e:
                errors.append(f"{category.value} scan error: {e}")
        
        scan_time = (time.time() - start_time) * 1000
        
        return ScanResult(
            target=str(file_path),
            target_type="file",
            scan_time_ms=round(scan_time, 2),
            matches=matches,
            errors=errors
        )
    
    def scan_directory(self, dir_path: str, 
                       recursive: bool = True,
                       categories: Optional[List[ScanCategory]] = None,
                       file_extensions: Optional[List[str]] = None) -> List[ScanResult]:
        """
        Scan all files in a directory.
        
        Args:
            dir_path: Directory path to scan
            recursive: Whether to scan subdirectories
            categories: Optional list of categories to scan with
            file_extensions: Optional list of extensions to scan (e.g., ['.yaml', '.py'])
            
        Returns:
            List of ScanResults for files with matches
        """
        dir_path = Path(dir_path)
        if not dir_path.exists():
            return [ScanResult(
                target=str(dir_path),
                target_type="directory",
                scan_time_ms=0,
                matches=[],
                errors=[f"Directory not found: {dir_path}"]
            )]
        
        results = []
        pattern = "**/*" if recursive else "*"
        
        for file_path in dir_path.glob(pattern):
            if not file_path.is_file():
                continue
            
            if file_extensions and file_path.suffix not in file_extensions:
                continue
            
            # Skip very large files
            if file_path.stat().st_size > 50 * 1024 * 1024:  # 50MB
                logger.warning(f"Skipping large file: {file_path}")
                continue
            
            result = self.scan_file(str(file_path), categories)
            if result.has_matches or result.errors:
                results.append(result)
        
        return results
    
    def scan_config_files(self, config_dir: str = "/app/config") -> List[ScanResult]:
        """
        Scan configuration files for tampering.
        
        Args:
            config_dir: Path to configuration directory
            
        Returns:
            List of ScanResults for configs with suspicious modifications
        """
        return self.scan_directory(
            config_dir,
            recursive=True,
            categories=[ScanCategory.CONFIG_TAMPERING],
            file_extensions=[".yaml", ".yml", ".json", ".conf"]
        )
    
    def scan_memory(self, data: bytes) -> ScanResult:
        """
        Scan memory dump or process memory.
        
        Args:
            data: Memory data to scan
            
        Returns:
            ScanResult with any matches found
        """
        import time
        start_time = time.time()
        
        matches = []
        errors = []
        
        # Scan with all categories suitable for memory analysis
        scan_categories = [
            ScanCategory.CONTAINER_RUNTIME,
            ScanCategory.INCIDENT_RESPONSE,
            ScanCategory.MALWARE
        ]
        
        for category in scan_categories:
            if category not in self.compiled_rules:
                continue
            
            try:
                yara_matches = self.compiled_rules[category].match(data=data)
                for m in yara_matches:
                    match_info = self._extract_match_info(m)
                    matches.append(match_info)
            except Exception as e:
                errors.append(f"{category.value} scan error: {e}")
        
        scan_time = (time.time() - start_time) * 1000
        
        return ScanResult(
            target=f"memory_{hashlib.sha256(data).hexdigest()[:16]}",
            target_type="memory",
            scan_time_ms=round(scan_time, 2),
            matches=matches,
            errors=errors
        )
    
    def scan_transaction_calldata(self, calldata: str, 
                                   tx_hash: Optional[str] = None) -> ScanResult:
        """
        Scan transaction calldata for malicious function calls.
        
        Args:
            calldata: Transaction input data (hex string)
            tx_hash: Optional transaction hash for logging
            
        Returns:
            ScanResult with any matches found
        """
        return self.scan_bytecode(calldata, tx_hash or "calldata")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        stats = {
            "rules_loaded": {},
            "total_rules": 0
        }
        
        for category, rules in self.compiled_rules.items():
            # Count rules (this is an approximation)
            rule_count = len(list(rules))
            stats["rules_loaded"][category.value] = rule_count
            stats["total_rules"] += rule_count
        
        return stats


class ContractBytecodeScanner:
    """
    Specialized scanner for smart contract bytecode analysis.
    Integrates with Sentinel3's vulnerability scanner.
    """
    
    def __init__(self, yara_scanner: Optional[YARAScanner] = None):
        self.yara_scanner = yara_scanner or YARAScanner()
        
        # Common malicious function selectors
        self.dangerous_selectors = {
            "095ea7b3": ("approve", "unlimited_approval_risk"),
            "a9059cbb": ("transfer", "token_transfer"),
            "23b872dd": ("transferFrom", "token_transfer"),
            "3ccfd60b": ("withdraw", "fund_withdrawal"),
            "2e1a7d4d": ("withdraw", "fund_withdrawal"),
            "ff": ("SELFDESTRUCT", "contract_destruction"),
        }
    
    def analyze(self, bytecode: str, 
                contract_address: Optional[str] = None) -> Dict[str, Any]:
        """
        Full bytecode analysis combining YARA and heuristics.
        
        Args:
            bytecode: Contract bytecode
            contract_address: Contract address
            
        Returns:
            Complete analysis report
        """
        report = {
            "contract_address": contract_address,
            "bytecode_hash": hashlib.sha256(bytecode.encode()).hexdigest(),
            "bytecode_size": len(bytecode) // 2,
            "yara_scan": None,
            "dangerous_selectors": [],
            "risk_score": 0,
            "risk_factors": []
        }
        
        # YARA scan
        yara_result = self.yara_scanner.scan_bytecode(bytecode, contract_address)
        report["yara_scan"] = yara_result.to_dict()
        
        # Check for dangerous selectors
        bytecode_lower = bytecode.lower()
        for selector, (name, risk_type) in self.dangerous_selectors.items():
            if selector in bytecode_lower:
                report["dangerous_selectors"].append({
                    "selector": selector,
                    "function": name,
                    "risk_type": risk_type
                })
        
        # Calculate risk score
        risk_score = 0
        
        # YARA matches
        for match in yara_result.matches:
            if match.severity == "CRITICAL":
                risk_score += 40
                report["risk_factors"].append(f"CRITICAL: {match.rule_name}")
            elif match.severity == "HIGH":
                risk_score += 25
                report["risk_factors"].append(f"HIGH: {match.rule_name}")
            elif match.severity == "MEDIUM":
                risk_score += 10
                report["risk_factors"].append(f"MEDIUM: {match.rule_name}")
        
        # Dangerous selectors
        for ds in report["dangerous_selectors"]:
            if ds["risk_type"] == "contract_destruction":
                risk_score += 30
                report["risk_factors"].append("Contains SELFDESTRUCT")
            elif ds["risk_type"] == "fund_withdrawal":
                risk_score += 15
        
        report["risk_score"] = min(risk_score, 100)
        
        return report


# CLI interface
def main():
    """Command-line interface for YARA scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Sentinel3 YARA Scanner")
    parser.add_argument("target", help="File, directory, or bytecode to scan")
    parser.add_argument("-t", "--type", choices=["file", "dir", "bytecode", "calldata"],
                       default="file", help="Target type")
    parser.add_argument("-c", "--category", choices=[c.value for c in ScanCategory],
                       action="append", help="Categories to scan (can specify multiple)")
    parser.add_argument("-o", "--output", choices=["json", "text"], default="text",
                       help="Output format")
    parser.add_argument("-r", "--recursive", action="store_true", default=True,
                       help="Recursive directory scan")
    parser.add_argument("--rules-dir", help="Custom YARA rules directory")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = YARAScanner(rules_dir=args.rules_dir)
    
    # Determine categories
    categories = None
    if args.category:
        categories = [ScanCategory(c) for c in args.category]
    
    # Run scan based on type
    if args.type == "bytecode" or args.type == "calldata":
        result = scanner.scan_bytecode(args.target)
        results = [result]
    elif args.type == "dir":
        results = scanner.scan_directory(args.target, recursive=args.recursive, 
                                         categories=categories)
    else:
        result = scanner.scan_file(args.target, categories=categories)
        results = [result]
    
    # Output results
    if args.output == "json":
        output = {
            "scan_results": [r.to_dict() for r in results],
            "total_matches": sum(len(r.matches) for r in results),
            "critical_count": sum(1 for r in results for m in r.matches 
                                  if m.severity == "CRITICAL")
        }
        print(json.dumps(output, indent=2))
    else:
        total_matches = 0
        for result in results:
            if result.matches:
                print(f"\n{'='*60}")
                print(f"Target: {result.target}")
                print(f"Type: {result.target_type}")
                print(f"Scan time: {result.scan_time_ms}ms")
                print(f"Matches: {len(result.matches)}")
                print(f"{'='*60}")
                
                for match in result.matches:
                    total_matches += 1
                    print(f"\n  [{match.severity}] {match.rule_name}")
                    print(f"  Category: {match.category}")
                    print(f"  Confidence: {match.confidence}%")
                    print(f"  Description: {match.description}")
                    if match.strings_matched:
                        print(f"  Strings matched: {len(match.strings_matched)}")
            
            if result.errors:
                print(f"\n  Errors:")
                for error in result.errors:
                    print(f"    - {error}")
        
        print(f"\n{'='*60}")
        print(f"Total matches: {total_matches}")
        print(f"Critical: {sum(1 for r in results for m in r.matches if m.severity == 'CRITICAL')}")


if __name__ == "__main__":
    main()
