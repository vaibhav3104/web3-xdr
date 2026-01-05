"""
Contract Threat Monitor
Automatically detects new contract deployments and analyzes them for threats
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from decimal import Decimal
import structlog

from web3 import AsyncWeb3

logger = structlog.get_logger()

# Try to import ML components
try:
    from ..ai.models.contract_classifier import ContractThreatClassifier, ThreatCategory
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("ML modules not available for contract analysis")


@dataclass
class ContractThreatAlert:
    """Alert generated when a malicious contract is detected"""
    alert_id: str
    timestamp: datetime
    chain_id: str
    contract_address: str
    deployer_address: str
    tx_hash: str
    block_number: int
    
    # ML Analysis Results
    threat_category: str
    confidence: float
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    
    # Details
    detected_patterns: List[str]
    bytecode_size: int
    gas_used: int
    
    # Status
    status: str = "NEW"  # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    
    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "timestamp": self.timestamp.isoformat()
        }


class ContractThreatMonitor:
    """
    Monitors blockchain for new contract deployments and analyzes them for threats.
    
    Flow:
    1. Listen for contract creation transactions
    2. Extract deployed bytecode
    3. Run ML analysis
    4. Generate alert if threat detected
    5. Send notifications (Telegram, Slack, Dashboard)
    """
    
    def __init__(
        self,
        chain_id: str,
        w3: AsyncWeb3,
        alert_callback: Optional[Callable] = None,
        min_confidence: float = 0.7
    ):
        self.chain_id = chain_id
        self.w3 = w3
        self.alert_callback = alert_callback
        self.min_confidence = min_confidence
        
        # Initialize ML classifier
        self.classifier = None
        if ML_AVAILABLE:
            try:
                self.classifier = ContractThreatClassifier()
                logger.info("contract_threat_classifier_loaded", chain=chain_id)
            except Exception as e:
                logger.warning("classifier_load_failed", error=str(e))
        
        # Alert storage
        self.alerts: List[ContractThreatAlert] = []
        self.analyzed_contracts: Dict[str, dict] = {}
        
        # Statistics
        self.stats = {
            "contracts_analyzed": 0,
            "threats_detected": 0,
            "false_positives": 0
        }
    
    async def analyze_block_for_deployments(self, block_number: int) -> List[ContractThreatAlert]:
        """
        Analyze a block for new contract deployments.
        
        Contract creation transactions have:
        - to = None (or 0x0)
        - data = contract bytecode
        """
        alerts = []
        
        try:
            block = await self.w3.eth.get_block(block_number, full_transactions=True)
        except Exception as e:
            logger.error("block_fetch_failed", block=block_number, error=str(e))
            return alerts
        
        for tx in block.transactions:
            # Contract creation = no 'to' address
            if tx.get('to') is None or tx.get('to') == '0x' + '0' * 40:
                alert = await self._analyze_deployment(tx, block)
                if alert:
                    alerts.append(alert)
        
        return alerts
    
    async def _analyze_deployment(self, tx: dict, block: dict) -> Optional[ContractThreatAlert]:
        """
        Analyze a contract deployment transaction.
        """
        tx_hash = tx.hash.hex() if hasattr(tx.hash, 'hex') else tx.hash
        deployer = tx.get('from', '')
        
        logger.info(
            "analyzing_contract_deployment",
            chain=self.chain_id,
            tx_hash=tx_hash[:16] + "...",
            deployer=deployer[:16] + "..."
        )
        
        try:
            # Get transaction receipt for contract address
            receipt = await self.w3.eth.get_transaction_receipt(tx_hash)
            contract_address = receipt.get('contractAddress', '')
            
            if not contract_address:
                return None
            
            # Get deployed bytecode
            bytecode = await self.w3.eth.get_code(contract_address)
            bytecode_hex = bytecode.hex() if hasattr(bytecode, 'hex') else str(bytecode)
            
            self.stats["contracts_analyzed"] += 1
            
            # If no ML classifier, skip analysis
            if not self.classifier:
                logger.debug("no_classifier_available")
                return None
            
            # Run ML analysis
            result = self.classifier.classify(bytecode_hex)
            
            # Store analysis result
            self.analyzed_contracts[contract_address] = {
                "bytecode_hash": hash(bytecode_hex),
                "analysis": result.to_dict() if hasattr(result, 'to_dict') else str(result),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Check if threat detected
            if result.threat_category != ThreatCategory.SAFE and result.confidence >= self.min_confidence:
                
                # Determine risk level
                risk_level = self._calculate_risk_level(result)
                
                # Create alert
                alert = ContractThreatAlert(
                    alert_id=f"CTM-{self.chain_id}-{tx_hash[:8]}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    timestamp=datetime.utcnow(),
                    chain_id=self.chain_id,
                    contract_address=contract_address,
                    deployer_address=deployer,
                    tx_hash=tx_hash,
                    block_number=block.number,
                    threat_category=result.threat_category.value,
                    confidence=result.confidence,
                    risk_level=risk_level,
                    detected_patterns=result.detected_patterns if hasattr(result, 'detected_patterns') else [],
                    bytecode_size=len(bytecode_hex) // 2,
                    gas_used=receipt.get('gasUsed', 0)
                )
                
                self.alerts.append(alert)
                self.stats["threats_detected"] += 1
                
                # Log the threat
                logger.warning(
                    "🚨 MALICIOUS_CONTRACT_DETECTED",
                    chain=self.chain_id,
                    contract=contract_address,
                    threat=result.threat_category.value,
                    confidence=f"{result.confidence:.1%}",
                    risk=risk_level
                )
                
                # Call alert callback (for notifications)
                if self.alert_callback:
                    await self._send_alert(alert)
                
                return alert
            
            return None
            
        except Exception as e:
            logger.error("deployment_analysis_failed", tx_hash=tx_hash, error=str(e))
            return None
    
    def _calculate_risk_level(self, result) -> str:
        """Calculate risk level based on threat category and confidence."""
        high_risk_categories = [
            ThreatCategory.FLASH_LOAN_EXPLOIT,
            ThreatCategory.BRIDGE_EXPLOIT,
            ThreatCategory.REENTRANCY_EXPLOIT
        ]
        
        if result.threat_category in high_risk_categories:
            if result.confidence >= 0.9:
                return "CRITICAL"
            elif result.confidence >= 0.8:
                return "HIGH"
            else:
                return "MEDIUM"
        else:
            if result.confidence >= 0.9:
                return "HIGH"
            elif result.confidence >= 0.8:
                return "MEDIUM"
            else:
                return "LOW"
    
    async def _send_alert(self, alert: ContractThreatAlert):
        """Send alert through configured channels."""
        if self.alert_callback:
            try:
                await self.alert_callback(alert)
            except Exception as e:
                logger.error("alert_callback_failed", error=str(e))
        
        # Also store for API access
        # This will be picked up by the incidents system
    
    async def analyze_contract_address(self, contract_address: str) -> Optional[dict]:
        """
        Manually analyze a specific contract address.
        """
        if not self.classifier:
            return {"error": "ML classifier not available"}
        
        try:
            bytecode = await self.w3.eth.get_code(contract_address)
            bytecode_hex = bytecode.hex() if hasattr(bytecode, 'hex') else str(bytecode)
            
            if bytecode_hex == '0x' or not bytecode_hex:
                return {"error": "No bytecode at address (EOA or destroyed contract)"}
            
            result = self.classifier.classify(bytecode_hex)
            
            return {
                "contract_address": contract_address,
                "threat_category": result.threat_category.value,
                "confidence": result.confidence,
                "risk_level": self._calculate_risk_level(result),
                "is_threat": result.threat_category != ThreatCategory.SAFE,
                "detected_patterns": result.detected_patterns if hasattr(result, 'detected_patterns') else [],
                "bytecode_size": len(bytecode_hex) // 2
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def get_alerts(self, limit: int = 100) -> List[dict]:
        """Get recent alerts."""
        return [a.to_dict() for a in sorted(
            self.alerts, 
            key=lambda x: x.timestamp, 
            reverse=True
        )[:limit]]
    
    def get_stats(self) -> dict:
        """Get monitoring statistics."""
        return {
            **self.stats,
            "active_alerts": len([a for a in self.alerts if a.status == "NEW"]),
            "ml_available": self.classifier is not None
        }


# Global alert handlers
_alert_handlers: List[Callable] = []


def register_alert_handler(handler: Callable):
    """Register a handler to receive contract threat alerts."""
    _alert_handlers.append(handler)


async def broadcast_alert(alert: ContractThreatAlert):
    """Broadcast alert to all registered handlers."""
    for handler in _alert_handlers:
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(alert)
            else:
                handler(alert)
        except Exception as e:
            logger.error("alert_handler_failed", handler=str(handler), error=str(e))

