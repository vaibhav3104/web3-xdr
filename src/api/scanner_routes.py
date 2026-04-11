"""
API Routes for Vulnerability Scanner

Provides endpoints for:
- Bytecode scanning (all contracts)
- Source code scanning (verified contracts)
- Decompilation and analysis
- Batch scanning
- Specific vulnerability checks
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Body
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
import asyncio
import structlog

from ..scanner.vulnerability_scanner import (
    get_vulnerability_scanner
)
from ..scanner.taint_tracker import TaintTracker
from ..scanner.source_fetcher import get_source_fetcher
from ..scanner.source_analyzer import get_source_analyzer, SourceVulnerability

logger = structlog.get_logger()

router = APIRouter(prefix="/scanner", tags=["Vulnerability Scanner"])


# ============================================================================
# Request/Response Models
# ============================================================================

class ScanRequest(BaseModel):
    """Request to scan a contract"""
    address: str = Field(..., description="Contract address to scan")
    chain: str = Field(default="ethereum", description="Chain name")
    bytecode: Optional[str] = Field(None, description="Optional bytecode (fetched if not provided)")
    include_symbolic: bool = Field(default=False, description="Include symbolic execution (slower)")
    include_taint: bool = Field(default=True, description="Include taint analysis")


class BatchScanRequest(BaseModel):
    """Request to scan multiple contracts"""
    contracts: List[Dict[str, str]] = Field(..., description="List of {address, chain} dicts")
    include_symbolic: bool = Field(default=False)


class SourceScanRequest(BaseModel):
    """Request to scan Solidity source code"""
    source_code: str = Field(..., description="Solidity source code")
    contract_name: Optional[str] = Field(None, description="Contract name")
    filename: str = Field(default="main.sol", description="Source filename")


class FetchSourceRequest(BaseModel):
    """Request to fetch and analyze source code"""
    address: str = Field(..., description="Contract address")
    chain: str = Field(default="ethereum", description="Chain name")
    analyze: bool = Field(default=True, description="Analyze after fetching")


class CompareContractsRequest(BaseModel):
    """Request to compare two contracts"""
    address1: str = Field(..., description="First contract address")
    address2: str = Field(..., description="Second contract address")
    chain1: str = Field(default="ethereum", description="Chain for first contract")
    chain2: str = Field(default="ethereum", description="Chain for second contract")


class ScanResponse(BaseModel):
    """Response from a scan"""
    success: bool
    contract_address: str
    chain: str
    risk_score: float
    summary: Dict[str, int]
    vulnerabilities: List[Dict]
    scan_duration_ms: int
    scanned_at: str
    metadata: Dict[str, Any] = {}


class VulnerabilityDetail(BaseModel):
    """Detailed vulnerability information"""
    type: str
    severity: str
    title: str
    description: str
    location: str
    confidence: float
    recommendation: str
    references: List[str] = []
    exploit_scenario: str = ""


# ============================================================================
# Scan Endpoints
# ============================================================================

@router.post("/scan", response_model=ScanResponse)
async def scan_contract(request: ScanRequest):
    """
    Scan a single contract for vulnerabilities
    
    This performs:
    1. Static analysis (pattern matching)
    2. Taint analysis (data flow tracking)
    3. Optionally: Symbolic execution (path exploration)
    
    Returns vulnerabilities found with severity, description, and recommendations.
    """
    try:
        scanner = get_vulnerability_scanner()
        
        # Perform main scan
        result = await scanner.scan_contract(
            address=request.address,
            chain=request.chain,
            bytecode=request.bytecode
        )
        
        # Add taint analysis if requested
        if request.include_taint and (request.bytecode or result.bytecode_hash):
            try:
                taint_tracker = TaintTracker()
                bytecode = request.bytecode or await scanner._fetch_bytecode(
                    request.address, request.chain
                )
                if bytecode:
                    taint_violations = taint_tracker.analyze(bytecode)
                    
                    # Convert taint violations to vulnerabilities
                    for violation in taint_violations:
                        from ..scanner.vulnerability_scanner import Vulnerability, VulnerabilityType, Severity
                        
                        vuln = Vulnerability(
                            vuln_type=VulnerabilityType.ARBITRARY_EXTERNAL_CALL,
                            severity=Severity[violation.severity],
                            title=f"Taint Flow: {violation.sink.value}",
                            description=violation.description,
                            location=f"PC {violation.sink_pc}",
                            confidence=0.7,
                            detector_name="taint_tracker"
                        )
                        result.vulnerabilities.append(vuln)
                    
                    # Recalculate risk score
                    result.calculate_risk_score()
            except Exception as e:
                logger.warning("taint_analysis_failed", error=str(e))
        
        # Add symbolic execution if requested (more intensive)
        if request.include_symbolic:
            try:
                from ..scanner import SYMBOLIC_AVAILABLE
                
                if not SYMBOLIC_AVAILABLE:
                    logger.warning("z3_not_available", message="Symbolic execution requires z3-solver")
                else:
                    from ..scanner.symbolic_executor import SymbolicExecutor
                    
                    bytecode = request.bytecode or await scanner._fetch_bytecode(
                        request.address, request.chain
                    )
                    if bytecode:
                        executor = SymbolicExecutor()
                        executor.execute(bytecode)
                        symbolic_vulns = executor.get_vulnerabilities()
                        
                        # Add to result
                        for vuln in symbolic_vulns:
                            from ..scanner.vulnerability_scanner import Vulnerability, VulnerabilityType, Severity
                            
                            vuln_type_map = {
                                "integer_overflow": VulnerabilityType.INTEGER_OVERFLOW,
                                "integer_underflow": VulnerabilityType.INTEGER_UNDERFLOW,
                                "reentrancy": VulnerabilityType.REENTRANCY,
                            }
                            
                            v = Vulnerability(
                                vuln_type=vuln_type_map.get(vuln["type"], VulnerabilityType.LOGIC_ERROR),
                                severity=Severity[vuln.get("severity", "MEDIUM")],
                                title=f"Symbolic: {vuln['type']}",
                                description=f"Found via symbolic execution at PC {vuln.get('pc', 'unknown')}",
                                location=f"PC {vuln.get('pc', 'unknown')}",
                                confidence=0.8,
                                detector_name="symbolic_executor"
                            )
                            result.vulnerabilities.append(v)
                        
                        result.calculate_risk_score()
            except Exception as e:
                logger.warning("symbolic_execution_failed", error=str(e))
        
        return ScanResponse(
            success=True,
            contract_address=result.contract_address,
            chain=result.chain,
            risk_score=result.risk_score,
            summary={
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "total": len(result.vulnerabilities)
            },
            vulnerabilities=[v.to_dict() for v in result.vulnerabilities],
            scan_duration_ms=result.scan_duration_ms,
            scanned_at=result.scanned_at.isoformat(),
            metadata={
                "solidity_version": result.solidity_version,
                "is_proxy": result.is_proxy,
                "has_selfdestruct": result.has_selfdestruct,
                "uses_delegatecall": result.uses_delegatecall,
                "bytecode_size": result.bytecode_size
            }
        )
        
    except Exception as e:
        logger.error("scan_failed", address=request.address, error=str(e))
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan/batch")
async def scan_batch(request: BatchScanRequest, background_tasks: BackgroundTasks):
    """
    Scan multiple contracts in batch
    
    Returns immediately with a job ID. Results are processed in background.
    """
    job_id = f"batch_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    
    # Start background processing
    background_tasks.add_task(
        _process_batch_scan,
        job_id,
        request.contracts,
        request.include_symbolic
    )
    
    return {
        "job_id": job_id,
        "status": "processing",
        "total_contracts": len(request.contracts),
        "message": f"Scanning {len(request.contracts)} contracts in background"
    }


@router.post("/scan/source")
async def scan_source_code(request: SourceScanRequest):
    """
    Scan Solidity source code for vulnerabilities
    
    Provides precise line-number locations and code context.
    Useful for pre-deployment security checks.
    """
    try:
        analyzer = get_source_analyzer()
        vulnerabilities = analyzer.analyze(request.source_code, request.filename)
        summary = analyzer.get_summary()
        
        return {
            "success": True,
            "contract_name": request.contract_name,
            "filename": request.filename,
            "risk_score": _calculate_source_risk_score(vulnerabilities),
            "summary": summary["by_severity"],
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "total_vulnerabilities": len(vulnerabilities),
            "scan_type": "source_code"
        }
        
    except Exception as e:
        logger.error("source_scan_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Source scan failed: {str(e)}")


@router.post("/source/fetch")
async def fetch_source_code(request: FetchSourceRequest):
    """
    Fetch contract source code from Etherscan/Sourcify
    
    Returns:
    - Verified source code if available
    - Decompiled pseudo-Solidity if not verified
    - Optionally runs vulnerability analysis
    """
    try:
        fetcher = get_source_fetcher()
        source = await fetcher.fetch_source(request.address, request.chain)
        
        result = {
            "success": True,
            "address": request.address,
            "chain": request.chain,
            "is_verified": source.is_verified,
            "source_type": source.source_type.value,
            "contract_name": source.contract_name,
            "compiler_version": source.compiler_version,
            "is_proxy": source.is_proxy,
            "implementation_address": source.implementation_address,
            "file_count": len(source.source_files),
            "source_files": list(source.source_files.keys()),
            "source_code": source.source_code,
            "abi": source.abi[:10] if source.abi else [],  # Limit ABI size
        }
        
        # Optionally analyze the source
        if request.analyze and source.source_code:
            analyzer = get_source_analyzer()
            vulnerabilities = analyzer.analyze(source.source_code, source.contract_name or "main.sol")
            
            result["analysis"] = {
                "total_vulnerabilities": len(vulnerabilities),
                "risk_score": _calculate_source_risk_score(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v.severity.value == "critical"),
                "high": sum(1 for v in vulnerabilities if v.severity.value == "high"),
                "medium": sum(1 for v in vulnerabilities if v.severity.value == "medium"),
                "low": sum(1 for v in vulnerabilities if v.severity.value == "low"),
                "vulnerabilities": [v.to_dict() for v in vulnerabilities]
            }
        
        await fetcher.close()
        return result
        
    except Exception as e:
        logger.error("source_fetch_failed", address=request.address, error=str(e))
        raise HTTPException(status_code=500, detail=f"Source fetch failed: {str(e)}")


@router.get("/source/{address}")
async def get_source_code(
    address: str,
    chain: str = Query(default="ethereum"),
    analyze: bool = Query(default=False)
):
    """
    Get source code for a contract (GET version)
    
    Fetches from Etherscan/Sourcify or decompiles bytecode.
    """
    request = FetchSourceRequest(address=address, chain=chain, analyze=analyze)
    return await fetch_source_code(request)


@router.post("/source/analyze")
async def analyze_source_code(
    source_code: str = Body(..., embed=True, description="Solidity source code"),
    filename: str = Body(default="contract.sol", embed=True)
):
    """
    Analyze provided source code for vulnerabilities
    
    Returns detailed vulnerability report with:
    - Precise line numbers
    - Code snippets
    - Function/contract context
    - Recommendations
    """
    try:
        analyzer = get_source_analyzer()
        vulnerabilities = analyzer.analyze(source_code, filename)
        
        # Group by severity
        by_severity = {}
        for v in vulnerabilities:
            sev = v.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(v.to_dict())
        
        # Group by type
        by_type = {}
        for v in vulnerabilities:
            vtype = v.vuln_type.value
            if vtype not in by_type:
                by_type[vtype] = []
            by_type[vtype].append(v.to_dict())
        
        return {
            "success": True,
            "filename": filename,
            "total_vulnerabilities": len(vulnerabilities),
            "risk_score": _calculate_source_risk_score(vulnerabilities),
            "summary": {
                "critical": len(by_severity.get("critical", [])),
                "high": len(by_severity.get("high", [])),
                "medium": len(by_severity.get("medium", [])),
                "low": len(by_severity.get("low", [])),
            },
            "by_severity": by_severity,
            "by_type": by_type,
            "vulnerabilities": [v.to_dict() for v in vulnerabilities]
        }
        
    except Exception as e:
        logger.error("source_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/compare")
async def compare_contracts(request: CompareContractsRequest):
    """
    Compare two contracts for similarities and differences
    
    Useful for:
    - Detecting clones of vulnerable contracts
    - Comparing implementations
    - Identifying code reuse
    """
    try:
        scanner = get_vulnerability_scanner()
        
        # Scan both contracts
        result1 = await scanner.scan_contract(request.address1, request.chain1)
        result2 = await scanner.scan_contract(request.address2, request.chain2)
        
        # Compare vulnerabilities
        vulns1 = {v.vuln_type.value for v in result1.vulnerabilities}
        vulns2 = {v.vuln_type.value for v in result2.vulnerabilities}
        
        common_vulns = vulns1 & vulns2
        unique_to_1 = vulns1 - vulns2
        unique_to_2 = vulns2 - vulns1
        
        # Calculate similarity score
        all_vulns = vulns1 | vulns2
        similarity = len(common_vulns) / len(all_vulns) if all_vulns else 0
        
        return {
            "success": True,
            "contract1": {
                "address": request.address1,
                "chain": request.chain1,
                "risk_score": result1.risk_score,
                "vulnerability_count": len(result1.vulnerabilities),
                "bytecode_size": result1.bytecode_size
            },
            "contract2": {
                "address": request.address2,
                "chain": request.chain2,
                "risk_score": result2.risk_score,
                "vulnerability_count": len(result2.vulnerabilities),
                "bytecode_size": result2.bytecode_size
            },
            "comparison": {
                "similarity_score": round(similarity * 100, 2),
                "common_vulnerabilities": list(common_vulns),
                "unique_to_contract1": list(unique_to_1),
                "unique_to_contract2": list(unique_to_2),
                "risk_difference": abs(result1.risk_score - result2.risk_score)
            }
        }
        
    except Exception as e:
        logger.error("compare_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Comparison failed: {str(e)}")


@router.get("/scan/{address}")
async def get_scan_result(
    address: str,
    chain: str = Query(default="ethereum", description="Chain name")
):
    """
    Get scan result for a previously scanned contract
    
    If not previously scanned, performs a new scan.
    """
    # For now, just perform a new scan
    # In production, would check cache/database first
    scanner = get_vulnerability_scanner()
    result = await scanner.scan_contract(address=address, chain=chain)
    
    return {
        "contract_address": result.contract_address,
        "chain": result.chain,
        "risk_score": result.risk_score,
        "vulnerabilities": [v.to_dict() for v in result.vulnerabilities],
        "metadata": {
            "solidity_version": result.solidity_version,
            "is_proxy": result.is_proxy,
            "bytecode_size": result.bytecode_size
        }
    }


# ============================================================================
# Analysis Endpoints
# ============================================================================

@router.post("/analyze/bytecode")
async def analyze_bytecode(bytecode: str = Query(..., description="Contract bytecode")):
    """
    Analyze raw bytecode without fetching from chain
    
    Useful for analyzing contracts before deployment.
    """
    try:
        scanner = get_vulnerability_scanner()
        
        # Create a dummy result for bytecode analysis
        result = await scanner.scan_contract(
            address="0x0000000000000000000000000000000000000000",
            chain="unknown",
            bytecode=bytecode
        )
        
        return {
            "success": True,
            "risk_score": result.risk_score,
            "vulnerabilities": [v.to_dict() for v in result.vulnerabilities],
            "metadata": {
                "solidity_version": result.solidity_version,
                "bytecode_size": result.bytecode_size,
                "has_selfdestruct": result.has_selfdestruct,
                "uses_delegatecall": result.uses_delegatecall
            }
        }
        
    except Exception as e:
        logger.error("bytecode_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/analyze/truebit-style/{address}")
async def analyze_truebit_style(
    address: str,
    chain: str = Query(default="ethereum")
):
    """
    Specifically check for Truebit-style integer overflow vulnerabilities
    
    Checks:
    1. Solidity version < 0.8.0
    2. Missing SafeMath
    3. Arithmetic operations without overflow checks
    """
    try:
        scanner = get_vulnerability_scanner()
        result = await scanner.scan_contract(address=address, chain=chain)
        
        # Filter for integer overflow vulnerabilities
        overflow_vulns = [
            v for v in result.vulnerabilities
            if v.vuln_type.value in ["integer_overflow", "integer_underflow"]
        ]
        
        # Check Solidity version
        is_vulnerable_version = False
        if result.solidity_version:
            try:
                parts = result.solidity_version.split(".")
                major = int(parts[0])
                minor = int(parts[1]) if len(parts) > 1 else 0
                is_vulnerable_version = major == 0 and minor < 8
            except (ValueError, IndexError):
                pass
        
        return {
            "address": address,
            "chain": chain,
            "truebit_style_vulnerable": len(overflow_vulns) > 0 and is_vulnerable_version,
            "solidity_version": result.solidity_version,
            "is_pre_0_8": is_vulnerable_version,
            "overflow_vulnerabilities": [v.to_dict() for v in overflow_vulns],
            "risk_score": result.risk_score,
            "recommendation": (
                "CRITICAL: Contract uses pre-0.8.0 Solidity without apparent SafeMath. "
                "Vulnerable to Truebit-style integer overflow attacks. "
                "Upgrade to Solidity 0.8+ or implement SafeMath."
                if len(overflow_vulns) > 0 and is_vulnerable_version
                else "Contract appears to have overflow protection."
            )
        }
        
    except Exception as e:
        logger.error("truebit_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/analyze/reentrancy/{address}")
async def analyze_reentrancy(
    address: str,
    chain: str = Query(default="ethereum")
):
    """
    Specifically check for reentrancy vulnerabilities
    
    Checks:
    1. External calls before state updates
    2. Missing reentrancy guards
    3. Cross-function reentrancy
    """
    try:
        scanner = get_vulnerability_scanner()
        result = await scanner.scan_contract(address=address, chain=chain)
        
        # Filter for reentrancy vulnerabilities
        reentrancy_vulns = [
            v for v in result.vulnerabilities
            if "reentrancy" in v.vuln_type.value.lower()
        ]
        
        return {
            "address": address,
            "chain": chain,
            "has_reentrancy_risk": len(reentrancy_vulns) > 0,
            "vulnerabilities": [v.to_dict() for v in reentrancy_vulns],
            "uses_delegatecall": result.uses_delegatecall,
            "recommendation": (
                "WARNING: Potential reentrancy vulnerability detected. "
                "Implement checks-effects-interactions pattern and consider ReentrancyGuard."
                if len(reentrancy_vulns) > 0
                else "No obvious reentrancy vulnerabilities detected."
            )
        }
        
    except Exception as e:
        logger.error("reentrancy_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ============================================================================
# Utility Endpoints
# ============================================================================

@router.get("/supported-chains")
async def get_supported_chains():
    """Get list of supported chains for scanning"""
    scanner = get_vulnerability_scanner()
    return {
        "chains": list(scanner.EXPLORERS.keys()),
        "default": "ethereum"
    }


@router.get("/vulnerability-types")
async def get_vulnerability_types():
    """Get list of vulnerability types we detect"""
    from ..scanner.vulnerability_scanner import VulnerabilityType, Severity
    
    return {
        "vulnerability_types": [
            {
                "type": vt.value,
                "name": vt.name.replace("_", " ").title()
            }
            for vt in VulnerabilityType
        ],
        "severity_levels": [s.value for s in Severity]
    }


@router.get("/health")
async def scanner_health():
    """Check scanner health status"""
    try:
        scanner = get_vulnerability_scanner()
        
        return {
            "status": "healthy",
            "scanner_ready": True,
            "supported_chains": len(scanner.EXPLORERS),
            "detectors": [
                "integer_overflow",
                "reentrancy",
                "unchecked_call",
                "delegatecall",
                "selfdestruct",
                "timestamp_dependence",
                "tx_origin",
                "weak_randomness",
                "flash_loan",
                "oracle_manipulation",
                "taint_analysis",
                "symbolic_execution"
            ]
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


# ============================================================================
# Helper Functions
# ============================================================================

def _calculate_source_risk_score(vulnerabilities: List[SourceVulnerability]) -> float:
    """Calculate risk score from source code vulnerabilities"""
    if not vulnerabilities:
        return 0.0
    
    # Weight by severity
    weights = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 1
    }
    
    total_score = 0
    for v in vulnerabilities:
        severity = v.severity.value if hasattr(v.severity, 'value') else str(v.severity).lower()
        weight = weights.get(severity, 5)
        total_score += weight * v.confidence
    
    # Normalize to 0-100
    return min(100, total_score)


# ============================================================================
# Background Tasks
# ============================================================================

async def _process_batch_scan(
    job_id: str,
    contracts: List[Dict[str, str]],
    include_symbolic: bool
):
    """Process batch scan in background"""
    scanner = get_vulnerability_scanner()
    results = []
    
    for contract in contracts:
        try:
            result = await scanner.scan_contract(
                address=contract.get("address", ""),
                chain=contract.get("chain", "ethereum")
            )
            results.append({
                "address": result.contract_address,
                "chain": result.chain,
                "risk_score": result.risk_score,
                "vulnerability_count": len(result.vulnerabilities)
            })
        except Exception as e:
            results.append({
                "address": contract.get("address", ""),
                "chain": contract.get("chain", "ethereum"),
                "error": str(e)
            })
        
        # Small delay to avoid rate limiting
        await asyncio.sleep(0.5)
    
    # In production, would store results in database
    logger.info("batch_scan_complete", job_id=job_id, total=len(results))
