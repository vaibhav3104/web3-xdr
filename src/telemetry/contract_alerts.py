"""
Contract Threat Alerts - Storage and management of contract deployment alerts
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict
from enum import Enum
import structlog
import uuid

logger = structlog.get_logger()


class AlertStatus(Enum):
    """Alert status"""
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ThreatLevel(Enum):
    """Threat level"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ContractThreatAlert:
    """A detected contract threat alert"""
    
    # Identity
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Contract info
    chain_id: str = ""
    contract_address: str = ""
    deployer_address: str = ""
    tx_hash: str = ""
    block_number: int = 0
    
    # Analysis results
    threat_category: str = "unknown"
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    confidence: float = 0.0
    risk_score: float = 0.0
    
    # Details
    risk_factors: List[str] = field(default_factory=list)
    similar_exploits: List[str] = field(default_factory=list)
    recommendation: str = ""
    
    # Bytecode info
    bytecode_size: int = 0
    bytecode_hash: str = ""
    
    # Status
    status: AlertStatus = AlertStatus.ACTIVE
    notes: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "deployer_address": self.deployer_address,
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "threat_category": self.threat_category,
            "threat_level": self.threat_level.value,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
            "similar_exploits": self.similar_exploits,
            "recommendation": self.recommendation,
            "bytecode_size": self.bytecode_size,
            "bytecode_hash": self.bytecode_hash,
            "status": self.status.value,
            "notes": self.notes
        }


class ContractAlertStore:
    """In-memory store for contract threat alerts"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._alerts: Dict[str, ContractThreatAlert] = {}
        self._alerts_by_chain: Dict[str, List[str]] = {}
        self._alerts_by_contract: Dict[str, str] = {}
        
        # Stats
        self.total_contracts_analyzed = 0
        self.total_threats_detected = 0
        self.contracts_by_chain: Dict[str, int] = {}
        
        self._initialized = True
        logger.info("contract_alert_store_initialized")
    
    def add_alert(self, alert: ContractThreatAlert):
        """Add a new alert"""
        self._alerts[alert.alert_id] = alert
        
        # Index by chain
        if alert.chain_id not in self._alerts_by_chain:
            self._alerts_by_chain[alert.chain_id] = []
        self._alerts_by_chain[alert.chain_id].append(alert.alert_id)
        
        # Index by contract
        contract_key = f"{alert.chain_id}:{alert.contract_address.lower()}"
        self._alerts_by_contract[contract_key] = alert.alert_id
        
        self.total_threats_detected += 1
        
        logger.info(
            "contract_threat_alert_added",
            alert_id=alert.alert_id,
            chain=alert.chain_id,
            contract=alert.contract_address,
            threat=alert.threat_category,
            confidence=alert.confidence
        )
    
    def record_analysis(self, chain_id: str, is_threat: bool):
        """Record a contract analysis (for stats)"""
        self.total_contracts_analyzed += 1
        self.contracts_by_chain[chain_id] = self.contracts_by_chain.get(chain_id, 0) + 1
    
    def get_alert(self, alert_id: str) -> Optional[ContractThreatAlert]:
        """Get alert by ID"""
        return self._alerts.get(alert_id)
    
    def get_alert_by_contract(self, chain_id: str, contract_address: str) -> Optional[ContractThreatAlert]:
        """Get alert by contract address"""
        contract_key = f"{chain_id}:{contract_address.lower()}"
        alert_id = self._alerts_by_contract.get(contract_key)
        if alert_id:
            return self._alerts.get(alert_id)
        return None
    
    def get_all_alerts(
        self,
        chain_id: Optional[str] = None,
        status: Optional[AlertStatus] = None,
        threat_level: Optional[ThreatLevel] = None,
        limit: int = 100
    ) -> List[ContractThreatAlert]:
        """Get all alerts with optional filtering"""
        alerts = list(self._alerts.values())
        
        if chain_id:
            alerts = [a for a in alerts if a.chain_id == chain_id]
        
        if status:
            alerts = [a for a in alerts if a.status == status]
        
        if threat_level:
            alerts = [a for a in alerts if a.threat_level == threat_level]
        
        # Sort by timestamp descending
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        
        return alerts[:limit]
    
    def update_status(self, alert_id: str, status: AlertStatus, notes: str = "") -> bool:
        """Update alert status"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        
        alert.status = status
        if notes:
            alert.notes = notes
        
        logger.info(
            "contract_threat_alert_status_updated",
            alert_id=alert_id,
            status=status.value
        )
        return True
    
    def get_stats(self) -> dict:
        """Get statistics"""
        alerts = list(self._alerts.values())
        
        # Count by threat level
        by_threat_level = {}
        for level in ThreatLevel:
            by_threat_level[level.value] = len([a for a in alerts if a.threat_level == level])
        
        # Count by status
        by_status = {}
        for status in AlertStatus:
            by_status[status.value] = len([a for a in alerts if a.status == status])
        
        # Count by threat category
        by_category = {}
        for alert in alerts:
            by_category[alert.threat_category] = by_category.get(alert.threat_category, 0) + 1
        
        # Recent alerts (last 24h)
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(hours=24)
        recent = len([a for a in alerts if a.timestamp > cutoff])
        
        return {
            "total_contracts_analyzed": self.total_contracts_analyzed,
            "total_threats_detected": self.total_threats_detected,
            "contracts_by_chain": self.contracts_by_chain,
            "active_alerts": by_status.get("active", 0),
            "alerts_by_threat_level": by_threat_level,
            "alerts_by_status": by_status,
            "alerts_by_category": by_category,
            "alerts_last_24h": recent
        }


# Global singleton instance
contract_alert_store = ContractAlertStore()

