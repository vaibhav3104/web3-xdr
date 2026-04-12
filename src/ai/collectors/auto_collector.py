"""
Automatic Contract Deployment Collector
Monitors blockchain for new contract deployments and analyzes them in real-time

Features:
- Real-time monitoring of new blocks
- Automatic bytecode extraction
- ML-based threat analysis
- Alert generation for suspicious contracts
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
import aiohttp
import structlog

logger = structlog.get_logger(__name__)

@dataclass
class NewContract:
    """Represents a newly deployed contract"""
    address: str
    chain: str
    deployer: str
    tx_hash: str
    block_number: int
    timestamp: datetime
    bytecode: Optional[str] = None
    bytecode_length: int = 0
    gas_used: int = 0
    value_wei: int = 0
    
@dataclass
class ContractAnalysis:
    """
    Analysis result for a contract
    
    Combines results from:
    - ML Classifier (threat category prediction)
    - Vulnerability Scanner (specific CVE detection)
    - Source Scanner (if contract is verified)
    """
    contract: NewContract
    risk_score: float  # Combined risk score (0-1)
    threat_category: str  # ML-predicted threat category
    confidence: float  # Combined confidence score
    features: Dict = field(default_factory=dict)
    is_threat: bool = False
    alerts: List[str] = field(default_factory=list)
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    
    # Scanner-specific fields
    scanner_vulnerabilities: List[Dict] = field(default_factory=list)
    scanner_risk_score: float = 0.0
    source_verified: bool = False
    ml_risk_score: float = 0.0


class AutoContractCollector:
    """
    Automatically collects and analyzes new contract deployments
    """
    
    RPC_ENDPOINTS = {
        "ethereum": os.getenv("ETHEREUM_RPC_URL", os.getenv("ETH_RPC_URL", "https://ethereum-rpc.publicnode.com")),
        "arbitrum": os.getenv("ARBITRUM_RPC_URL", os.getenv("ARB_RPC_URL", "https://arb1.arbitrum.io/rpc")),
        "polygon": os.getenv("POLYGON_RPC_URL", "https://polygon-bor-rpc.publicnode.com"),
        "bsc": os.getenv("BSC_RPC_URL", "https://bsc-dataseed.binance.org"),
        "optimism": os.getenv("OP_RPC_URL", "https://mainnet.optimism.io"),
        "base": os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
        "avalanche": os.getenv("AVAX_RPC_URL", "https://api.avax.network/ext/bc/C/rpc"),
    }
    
    def __init__(
        self,
        chains: List[str] = None,
        analysis_callback: Optional[Callable[[ContractAnalysis], Any]] = None,
        threat_callback: Optional[Callable[[ContractAnalysis], Any]] = None,
        storage_path: str = "./data/collected_contracts"
    ):
        self.chains = chains or ["ethereum", "arbitrum", "polygon"]
        self.analysis_callback = analysis_callback
        self.threat_callback = threat_callback
        self.storage_path = storage_path
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.running = False
        self.last_blocks: Dict[str, int] = {}
        
        # Statistics
        self.stats = {
            "contracts_collected": 0,
            "contracts_analyzed": 0,
            "threats_detected": 0,
            "by_chain": {},
            "by_threat_type": {},
        }
        
        # Queue for analysis
        self.analysis_queue: asyncio.Queue = asyncio.Queue()
        
        # Feature extractor (lazy loaded)
        self._extractor = None
        self._classifier = None
        
        # Ensure storage directory exists
        os.makedirs(storage_path, exist_ok=True)
    
    @property
    def extractor(self):
        """Lazy load feature extractor"""
        if self._extractor is None:
            from ..data.bytecode_collector import RealBytecodeFeatureExtractor
            self._extractor = RealBytecodeFeatureExtractor()
        return self._extractor
    
    @property
    def classifier(self):
        """
        Lazy load classifier - uses Transformer model for highest accuracy by default.
        
        Model selection via ML_MODEL_TYPE env var:
        - "transformer" (default): Highest accuracy, uses attention mechanism
        - "ensemble": Combines MLP + CNN for robust predictions
        - "cnn": Fast pattern detection in opcode sequences
        - "mlp": Fastest, feature-based classification
        - "random_forest": Sklearn RandomForest (no GPU required)
        
        Device selection via ML_DEVICE env var:
        - "auto" (default): CUDA > MPS (Apple Silicon) > CPU
        - "cuda": Force NVIDIA GPU
        - "mps": Force Apple Silicon GPU
        - "cpu": Force CPU only
        """
        if self._classifier is None:
            # Get model type from environment (default: transformer for highest accuracy)
            model_type = os.getenv("ML_MODEL_TYPE", "transformer").lower()
            device = os.getenv("ML_DEVICE", "auto").lower()
            
            try:
                if model_type == "random_forest":
                    # Use sklearn RandomForest (no PyTorch required)
                    from ..models.contract_classifier import ContractThreatClassifier
                    self._classifier = ContractThreatClassifier()
                    logger.info("random_forest_classifier_loaded")
                else:
                    # Use PyTorch-based deep learning model
                    from ..models.deep_classifier import DeepContractClassifier, PYTORCH_AVAILABLE
                    
                    if PYTORCH_AVAILABLE:
                        # Model paths
                        model_paths = {
                            "transformer": "./data/models/deep_transformer.pt",
                            "ensemble": "./data/models/deep_ensemble.pt",
                            "cnn": "./data/models/deep_cnn.pt",
                            "mlp": "./data/models/deep_mlp.pt",
                        }
                        
                        model_path = model_paths.get(model_type, model_paths["transformer"])
                        
                        logger.info(
                            "loading_deep_classifier",
                            model_type=model_type,
                            model_path=model_path,
                            requested_device=device
                        )
                        
                        self._classifier = DeepContractClassifier(
                            model_type=model_type,
                            model_path=model_path,
                            device=device
                        )
                        
                        # Determine if GPU is being used
                        device_str = str(self._classifier.device)
                        gpu_type = "none"
                        if "cuda" in device_str:
                            gpu_type = "nvidia_cuda"
                        elif "mps" in device_str:
                            gpu_type = "apple_mps"
                        
                        logger.info(
                            "deep_classifier_loaded",
                            model_type=model_type,
                            device=device_str,
                            gpu_type=gpu_type,
                            gpu_accelerated=gpu_type != "none"
                        )
                    else:
                        # Fallback to RandomForest if PyTorch not available
                        logger.warning(
                            "pytorch_not_available",
                            requested_model=model_type,
                            fallback="random_forest"
                        )
                        from ..models.contract_classifier import ContractThreatClassifier
                        self._classifier = ContractThreatClassifier()
                        
            except Exception as e:
                logger.warning("deep_classifier_load_failed", error=str(e), model_type=model_type)
                # Final fallback to basic classifier
                try:
                    from ..models.contract_classifier import ContractThreatClassifier
                    self._classifier = ContractThreatClassifier()
                    logger.info("fallback_to_random_forest_classifier")
                except Exception as e2:
                    logger.error("all_classifiers_failed", error=str(e2))
                self._classifier = None
        return self._classifier
    
    async def start(self):
        """Start the auto-collector"""
        logger.info("auto_collector_starting", chains=self.chains)
        
        self.session = aiohttp.ClientSession()
        self.running = True
        
        # Start analysis worker
        analysis_task = asyncio.create_task(self._analysis_worker())
        
        # Start monitoring for each chain
        monitor_tasks = [
            asyncio.create_task(self._monitor_chain(chain))
            for chain in self.chains
        ]
        
        try:
            await asyncio.gather(analysis_task, *monitor_tasks)
        except asyncio.CancelledError:
            logger.info("auto_collector_cancelled")
        finally:
            await self.stop()
    
    async def stop(self):
        """Stop the auto-collector"""
        self.running = False
        if self.session:
            await self.session.close()
        logger.info("auto_collector_stopped", stats=self.stats)
    
    async def _monitor_chain(self, chain: str):
        """Monitor a single chain for new contract deployments"""
        rpc_url = self.RPC_ENDPOINTS.get(chain)
        if not rpc_url:
            logger.warning("no_rpc_endpoint", chain=chain)
            return
        
        logger.info("monitoring_chain", chain=chain)
        
        # Get current block number - ONLY monitor from current block onwards
        # This prevents scanning historical blocks which would flag old contracts as "new"
        current_block = await self._get_block_number(chain)
        
        # Safety check: ensure we're starting from a recent block (not genesis)
        # Arbitrum mainnet has ~300M+ blocks, Ethereum ~20M+, etc.
        MIN_SAFE_BLOCKS = {
            "ethereum": 19_000_000,   # ~Jan 2024
            "arbitrum": 200_000_000,  # Recent
            "polygon": 50_000_000,    # Recent  
            "optimism": 100_000_000,  # Recent
            "base": 10_000_000,       # Recent
            "bsc": 35_000_000,        # Recent
            "avalanche": 40_000_000,  # Recent
        }
        min_block = MIN_SAFE_BLOCKS.get(chain, 1_000_000)
        
        if current_block < min_block:
            logger.warning(
                "suspicious_low_block_number",
                chain=chain,
                current_block=current_block,
                min_expected=min_block,
                action="skipping_historical_scan"
            )
            # Use the minimum safe block to avoid scanning genesis
            self.last_blocks[chain] = min_block
        else:
            self.last_blocks[chain] = current_block
            
        logger.info(
            "monitoring_chain_from_block",
            chain=chain,
            starting_block=self.last_blocks[chain],
            current_block=current_block
        )
        
        while self.running:
            try:
                current_block = await self._get_block_number(chain)
                
                if current_block > self.last_blocks[chain]:
                    # Process new blocks
                    for block_num in range(self.last_blocks[chain] + 1, current_block + 1):
                        await self._process_block(chain, block_num)
                    
                    self.last_blocks[chain] = current_block
                
                # Wait before next poll (adjust based on chain block time)
                await asyncio.sleep(self._get_poll_interval(chain))
                
            except Exception as e:
                logger.error("chain_monitor_error", chain=chain, error=str(e))
                await asyncio.sleep(5)
    
    def _get_poll_interval(self, chain: str) -> float:
        """Get polling interval based on chain block time"""
        intervals = {
            "ethereum": 12,    # ~12 seconds
            "polygon": 2,      # ~2 seconds
            "bsc": 3,          # ~3 seconds
            "arbitrum": 0.25,  # ~250ms
            "optimism": 2,     # ~2 seconds
            "base": 2,         # ~2 seconds
            "avalanche": 2,    # ~2 seconds
        }
        return intervals.get(chain, 5)
    
    async def _get_block_number(self, chain: str) -> int:
        """Get current block number for a chain"""
        rpc_url = self.RPC_ENDPOINTS.get(chain)
        
        try:
            async with self.session.post(
                rpc_url,
                json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                data = await response.json()
                return int(data.get("result", "0x0"), 16)
        except Exception as e:
            logger.error("block_number_error", chain=chain, error=str(e))
            return self.last_blocks.get(chain, 0)
    
    async def _process_block(self, chain: str, block_number: int):
        """Process a block for contract deployments"""
        rpc_url = self.RPC_ENDPOINTS.get(chain)
        
        try:
            # Get block with transactions
            async with self.session.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getBlockByNumber",
                    "params": [hex(block_number), True],
                    "id": 1
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                data = await response.json()
                block = data.get("result")
                
                if not block:
                    return
                
                block_timestamp = datetime.fromtimestamp(int(block.get("timestamp", "0x0"), 16))
                
                # SAFETY CHECK: Skip blocks older than 7 days
                # This prevents false positives from historical contract deployments
                from datetime import timezone
                now = datetime.now(timezone.utc)
                block_age_days = (now - block_timestamp.replace(tzinfo=timezone.utc)).days
                
                if block_age_days > 7:
                    logger.warning(
                        "skipping_old_block",
                        chain=chain,
                        block=block_number,
                        block_timestamp=block_timestamp.isoformat(),
                        age_days=block_age_days,
                        reason="block_too_old"
                    )
                    return
                
                # Find contract deployments (transactions with to=null)
                for tx in block.get("transactions", []):
                    if tx.get("to") is None:
                        # This is a contract deployment!
                        await self._handle_deployment(chain, tx, block_number, block_timestamp)
                        
        except Exception as e:
            logger.error("block_process_error", chain=chain, block=block_number, error=str(e))
    
    async def _handle_deployment(
        self,
        chain: str,
        tx: Dict,
        block_number: int,
        timestamp: datetime
    ):
        """Handle a contract deployment transaction"""
        
        # Get transaction receipt to find contract address
        rpc_url = self.RPC_ENDPOINTS.get(chain)
        tx_hash = tx.get("hash")
        
        try:
            async with self.session.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getTransactionReceipt",
                    "params": [tx_hash],
                    "id": 1
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                data = await response.json()
                receipt = data.get("result")
                
                if not receipt:
                    return
                
                contract_address = receipt.get("contractAddress")
                if not contract_address:
                    return
                
                # Create contract object
                contract = NewContract(
                    address=contract_address.lower(),
                    chain=chain,
                    deployer=tx.get("from", "").lower(),
                    tx_hash=tx_hash,
                    block_number=block_number,
                    timestamp=timestamp,
                    gas_used=int(receipt.get("gasUsed", "0x0"), 16),
                    value_wei=int(tx.get("value", "0x0"), 16),
                )
                
                # Get bytecode
                contract.bytecode = await self._get_bytecode(chain, contract_address)
                contract.bytecode_length = len(contract.bytecode or "") // 2
                
                # Update stats
                self.stats["contracts_collected"] += 1
                self.stats["by_chain"][chain] = self.stats["by_chain"].get(chain, 0) + 1
                
                logger.info(
                    "contract_deployed",
                    address=contract_address[:16] + "...",
                    chain=chain,
                    deployer=contract.deployer[:16] + "...",
                    bytecode_size=contract.bytecode_length
                )
                
                # Queue for analysis
                await self.analysis_queue.put(contract)
                
        except Exception as e:
            logger.error("deployment_handle_error", tx_hash=tx_hash, error=str(e))
    
    async def _get_bytecode(self, chain: str, address: str) -> Optional[str]:
        """Get contract bytecode"""
        rpc_url = self.RPC_ENDPOINTS.get(chain)
        
        try:
            async with self.session.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getCode",
                    "params": [address, "latest"],
                    "id": 1
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                data = await response.json()
                bytecode = data.get("result", "0x")
                return bytecode if bytecode != "0x" else None
                
        except Exception as e:
            logger.error("bytecode_fetch_error", address=address, error=str(e))
            return None
    
    async def _analysis_worker(self):
        """Worker to analyze contracts from the queue"""
        while self.running:
            try:
                # Wait for contract with timeout
                try:
                    contract = await asyncio.wait_for(
                        self.analysis_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Analyze the contract
                analysis = await self._analyze_contract(contract)
                
                if analysis:
                    self.stats["contracts_analyzed"] += 1
                    
                    # Call analysis callback
                    if self.analysis_callback:
                        try:
                            await self.analysis_callback(analysis)
                        except Exception as e:
                            logger.error("analysis_callback_error", error=str(e))
                    
                    # If threat detected, call threat callback
                    if analysis.is_threat:
                        self.stats["threats_detected"] += 1
                        self.stats["by_threat_type"][analysis.threat_category] = \
                            self.stats["by_threat_type"].get(analysis.threat_category, 0) + 1
                        
                        if self.threat_callback:
                            try:
                                await self.threat_callback(analysis)
                            except Exception as e:
                                logger.error("threat_callback_error", error=str(e))
                        
                        logger.warning(
                            "threat_detected",
                            address=contract.address[:16] + "...",
                            chain=contract.chain,
                            category=analysis.threat_category,
                            risk_score=f"{analysis.risk_score:.2f}",
                            confidence=f"{analysis.confidence:.2f}"
                        )
                    
                    # Save analysis
                    await self._save_analysis(analysis)
                    
            except Exception as e:
                logger.error("analysis_worker_error", error=str(e))
    
    async def _analyze_contract(self, contract: NewContract) -> Optional[ContractAnalysis]:
        """
        Analyze a contract for threats using multiple detection methods:
        
        1. ML Classifier (Transformer/Ensemble) - Threat category prediction
        2. Vulnerability Scanner - Specific CVE detection (integer overflow, reentrancy, etc.)
        3. Optional Source Scanner - If contract is verified on Etherscan
        
        Results are combined for comprehensive risk scoring.
        """
        
        if not contract.bytecode:
            return None
        
        try:
            # Extract features
            features = self.extractor.extract_features(contract.bytecode)
            self.extractor.features_to_vector(features)
            
            # ================================================================
            # LAYER 1: ML Classifier (Threat Category)
            # ================================================================
            if self.classifier:
                result = self.classifier.classify(contract.bytecode)
                
                # Handle both old (threat_category) and new (category) attribute names
                if hasattr(result, 'threat_category'):
                    cat = result.threat_category
                elif hasattr(result, 'category'):
                    cat = result.category
                else:
                    cat = "unknown_threat"
                
                threat_category = cat.value if hasattr(cat, 'value') else str(cat)
                # Normalize to 0-1 scale (classifier returns 0-100)
                ml_risk_score = result.risk_score / 100.0 if result.risk_score > 1.0 else result.risk_score
                ml_confidence = result.confidence
            else:
                # Fallback to rule-based analysis
                ml_risk_score = features.get("risk_score", 0.0)
                
                if features.get("has_flash_loan_callback") and features.get("has_reentrancy_pattern"):
                    threat_category = "flash_loan_exploit"
                    ml_risk_score = max(ml_risk_score, 0.8)
                elif features.get("has_reentrancy_pattern"):
                    threat_category = "reentrancy_exploit"
                    ml_risk_score = max(ml_risk_score, 0.7)
                elif features.get("has_selfdestruct") and features.get("has_admin_functions"):
                    threat_category = "rug_pull"
                    ml_risk_score = max(ml_risk_score, 0.75)
                elif features.get("has_delegatecall_pattern") and features.get("delegatecall_count", 0) > 3:
                    threat_category = "unknown_threat"
                    ml_risk_score = max(ml_risk_score, 0.6)
                else:
                    threat_category = "safe"
                
                ml_confidence = 0.6  # Lower confidence for rule-based
            
            # ================================================================
            # LAYER 2: Vulnerability Scanner (Specific CVEs)
            # ================================================================
            scanner_risk_score = 0.0
            scanner_alerts = []
            scanner_vulnerabilities = []
            
            try:
                from src.scanner.vulnerability_scanner import get_vulnerability_scanner
                
                scanner = get_vulnerability_scanner()
                scan_result = await scanner.scan_contract(
                    address=contract.address,
                    chain=contract.chain,
                    bytecode=contract.bytecode
                )
                
                if scan_result:
                    # Normalize scanner risk score (0-100 to 0-1)
                    scanner_risk_score = scan_result.risk_score / 100.0
                    
                    # Add scanner findings to alerts
                    for vuln in scan_result.vulnerabilities:
                        severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                        scanner_alerts.append(f"[{severity.upper()}] {vuln.title}")
                        scanner_vulnerabilities.append({
                            "type": vuln.vuln_type.value if hasattr(vuln.vuln_type, 'value') else str(vuln.vuln_type),
                            "severity": severity,
                            "title": vuln.title,
                            "confidence": vuln.confidence,
                            "description": vuln.description[:200] if vuln.description else ""
                        })
                    
                    # Upgrade threat category if scanner finds critical issues
                    if scan_result.critical_count > 0:
                        # Map scanner findings to threat categories
                        for vuln in scan_result.vulnerabilities:
                            vuln_type = vuln.vuln_type.value if hasattr(vuln.vuln_type, 'value') else str(vuln.vuln_type)
                            if "overflow" in vuln_type or "underflow" in vuln_type:
                                if threat_category == "safe":
                                    threat_category = "integer_overflow_exploit"
                            elif "reentrancy" in vuln_type:
                                if threat_category == "safe":
                                    threat_category = "reentrancy_exploit"
                            elif "flash_loan" in vuln_type or "oracle" in vuln_type:
                                if threat_category == "safe":
                                    threat_category = "flash_loan_exploit"
                    
                    logger.info(
                        "vulnerability_scanner_completed",
                        address=contract.address[:16],
                        risk_score=f"{scanner_risk_score:.2f}",
                        critical=scan_result.critical_count,
                        high=scan_result.high_count,
                        total=len(scan_result.vulnerabilities)
                    )
                    
            except ImportError:
                logger.debug("vulnerability_scanner_not_available")
            except Exception as e:
                logger.warning("vulnerability_scanner_error", error=str(e))
            
            # ================================================================
            # LAYER 3: Source Code Scanner (If Verified - Optional)
            # ================================================================
            source_alerts = []
            source_available = False
            
            try:
                from src.scanner.source_fetcher import get_source_fetcher
                from src.scanner.source_analyzer import get_source_analyzer
                
                fetcher = get_source_fetcher()
                source = await fetcher.fetch_source(contract.address, contract.chain)
                
                if source and source.is_verified and source.source_code:
                    source_available = True
                    analyzer = get_source_analyzer()
                    source_vulns = analyzer.analyze(source.source_code, source.contract_name or "contract.sol")
                    
                    for vuln in source_vulns:
                        severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                        source_alerts.append(f"[SOURCE:{severity.upper()}] Line {vuln.line}: {vuln.title}")
                    
                    if source_vulns:
                        logger.info(
                            "source_scanner_completed",
                            address=contract.address[:16],
                            contract_name=source.contract_name,
                            vulnerabilities=len(source_vulns)
                        )
                        
                await fetcher.close()
                
            except ImportError:
                logger.debug("source_scanner_not_available")
            except Exception as e:
                logger.debug("source_scanner_skipped", reason=str(e)[:50])
            
            # ================================================================
            # COMBINE RESULTS
            # ================================================================

            # When no ML classifier is loaded, the "ML score" is just a
            # rule-based feature check (has_reentrancy_pattern, etc.) with
            # 0.6 confidence — not a trained model. Weight scanner lower
            # in that case to avoid heuristic-on-heuristic inflation.
            has_real_ml = self.classifier is not None
            if source_available:
                ml_w, sc_w = (0.45, 0.45) if has_real_ml else (0.50, 0.35)
                combined_risk_score = (ml_risk_score * ml_w) + (scanner_risk_score * sc_w) + (0.1 if source_alerts else 0)
            else:
                ml_w, sc_w = (0.55, 0.45) if has_real_ml else (0.60, 0.30)
                combined_risk_score = (ml_risk_score * ml_w) + (scanner_risk_score * sc_w)

            # Ensure risk score is capped at 1.0
            combined_risk_score = min(1.0, combined_risk_score)

            # Adjust confidence based on scanner agreement
            if scanner_risk_score > 0.5 and ml_risk_score > 0.5:
                combined_confidence = min(0.95, ml_confidence + 0.1)
            elif scanner_risk_score > 0.5 or ml_risk_score > 0.5:
                combined_confidence = ml_confidence
            else:
                combined_confidence = min(0.9, ml_confidence + 0.05)

            # Determine if threat — require higher bar when running without ML model
            threat_threshold = 0.45 if has_real_ml else 0.55
            is_threat = threat_category != "safe" and combined_risk_score > threat_threshold
            
            # ================================================================
            # GENERATE ALERTS
            # ================================================================
            alerts = []
            
            # ML-based alerts
            if features.get("has_flash_loan_callback"):
                alerts.append("Contains flash loan callback function")
            if features.get("has_reentrancy_pattern"):
                alerts.append("Potential reentrancy pattern detected")
            if features.get("has_selfdestruct"):
                alerts.append("Contains SELFDESTRUCT opcode")
            if features.get("delegatecall_count", 0) > 2:
                alerts.append(f"Multiple DELEGATECALL operations ({features['delegatecall_count']})")
            if features.get("has_mint_function"):
                alerts.append("Contains mint functionality")
            
            # Add scanner alerts
            alerts.extend(scanner_alerts)
            
            # Add source alerts (if any)
            alerts.extend(source_alerts)
            
            # Store scanner findings in features for training
            features["scanner_vulnerabilities"] = scanner_vulnerabilities
            features["scanner_risk_score"] = scanner_risk_score
            features["source_verified"] = source_available
            features["combined_risk_score"] = combined_risk_score
            
            return ContractAnalysis(
                contract=contract,
                risk_score=combined_risk_score,
                threat_category=threat_category,
                confidence=combined_confidence,
                features=features,
                is_threat=is_threat,
                alerts=alerts,
            )
            
        except Exception as e:
            logger.error("contract_analysis_error", address=contract.address, error=str(e))
            return None
    
    async def _save_analysis(self, analysis: ContractAnalysis):
        """Save analysis to storage"""
        filename = f"{analysis.contract.chain}_{analysis.contract.address[:16]}.json"
        filepath = os.path.join(self.storage_path, filename)
        
        data = {
            "contract": {
                "address": analysis.contract.address,
                "chain": analysis.contract.chain,
                "deployer": analysis.contract.deployer,
                "tx_hash": analysis.contract.tx_hash,
                "block_number": analysis.contract.block_number,
                "timestamp": analysis.contract.timestamp.isoformat(),
                "bytecode_length": analysis.contract.bytecode_length,
                "gas_used": analysis.contract.gas_used,
            },
            "analysis": {
                "risk_score": analysis.risk_score,
                "threat_category": analysis.threat_category,
                "confidence": analysis.confidence,
                "is_threat": analysis.is_threat,
                "alerts": analysis.alerts,
                "analyzed_at": analysis.analyzed_at.isoformat(),
            },
            "features": analysis.features,
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error("save_analysis_error", error=str(e))
    
    def get_stats(self) -> Dict:
        """Get collector statistics"""
        return {
            **self.stats,
            "running": self.running,
            "chains_monitoring": self.chains,
            "queue_size": self.analysis_queue.qsize(),
        }


# =============================================================================
# API INTEGRATION
# =============================================================================

# Global collector instance
_collector: Optional[AutoContractCollector] = None

def get_collector() -> Optional[AutoContractCollector]:
    """Get the global collector instance"""
    return _collector

async def start_auto_collection(
    chains: List[str] = None,
    analysis_callback: Optional[Callable] = None,
    threat_callback: Optional[Callable] = None,
):
    """Start automatic contract collection"""
    global _collector
    
    if _collector is not None and _collector.running:
        logger.warning("collector_already_running")
        return _collector
    
    _collector = AutoContractCollector(
        chains=chains,
        analysis_callback=analysis_callback,
        threat_callback=threat_callback,
    )
    
    # Start in background
    asyncio.create_task(_collector.start())
    
    return _collector

async def stop_auto_collection():
    """Stop automatic contract collection"""
    global _collector
    
    if _collector:
        await _collector.stop()
        _collector = None


if __name__ == "__main__":
    # Test the collector
    async def on_analysis(analysis: ContractAnalysis):
        print(f"Analyzed: {analysis.contract.address[:20]}... -> {analysis.threat_category}")
    
    async def on_threat(analysis: ContractAnalysis):
        print(f"⚠️ THREAT: {analysis.contract.address} ({analysis.threat_category})")
    
    async def main():
        collector = AutoContractCollector(
            chains=["ethereum"],
            analysis_callback=on_analysis,
            threat_callback=on_threat,
        )
        
        try:
            await collector.start()
        except KeyboardInterrupt:
            await collector.stop()
    
    asyncio.run(main())

