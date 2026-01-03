"""
Entity Model - Represents wallets, contracts, bridges, validators.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class EntityType(Enum):
    """Types of entities in the system."""
    WALLET = "wallet"
    CONTRACT = "contract"
    BRIDGE = "bridge"
    VALIDATOR = "validator"
    PROTOCOL = "protocol"
    EXCHANGE = "exchange"
    MULTISIG = "multisig"
    DAO = "dao"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk classification for entities."""
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    BLACKLISTED = 5


@dataclass
class Entity:
    """
    Represents an entity in the blockchain ecosystem.
    
    Entities are addresses that we track across chains.
    They can be wallets, contracts, bridges, validators, etc.
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    address: str = ""
    chain_id: str = ""
    entity_type: EntityType = EntityType.UNKNOWN
    
    # Identification
    name: Optional[str] = None
    labels: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_factors: List[str] = field(default_factory=list)
    
    # Cross-chain linkage
    linked_addresses: Dict[str, str] = field(default_factory=dict)  # chain -> address
    
    # Statistics
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tx_count: int = 0
    total_volume_usd: float = 0.0
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_display_name(self) -> str:
        """Get human-readable name for entity."""
        if self.name:
            return self.name
        # Truncate address for display
        if len(self.address) > 12:
            return f"{self.address[:6]}...{self.address[-4:]}"
        return self.address
    
    def is_bridge(self) -> bool:
        return self.entity_type == EntityType.BRIDGE
    
    def is_high_risk(self) -> bool:
        return self.risk_level.value >= RiskLevel.HIGH.value
    
    def add_risk_factor(self, factor: str):
        """Add a risk factor and update risk level."""
        if factor not in self.risk_factors:
            self.risk_factors.append(factor)
        # Update risk level based on factors
        self._recalculate_risk()
    
    def _recalculate_risk(self):
        """Recalculate risk level based on factors."""
        critical_factors = [
            "exploit_participation",
            "blacklisted_interaction",
            "stolen_funds_receiver"
        ]
        high_factors = [
            "mixer_usage",
            "flash_loan_usage",
            "abnormal_activity"
        ]
        
        if any(f in self.risk_factors for f in critical_factors):
            self.risk_level = RiskLevel.CRITICAL
        elif any(f in self.risk_factors for f in high_factors):
            self.risk_level = RiskLevel.HIGH
        elif len(self.risk_factors) > 3:
            self.risk_level = RiskLevel.MEDIUM
        elif self.risk_factors:
            self.risk_level = RiskLevel.LOW
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "address": self.address,
            "chain_id": self.chain_id,
            "entity_type": self.entity_type.value,
            "name": self.name,
            "labels": self.labels,
            "risk_level": self.risk_level.name,
            "risk_factors": self.risk_factors,
            "linked_addresses": self.linked_addresses,
            "tx_count": self.tx_count,
            "total_volume_usd": self.total_volume_usd,
        }


@dataclass
class EntityRelationship:
    """
    Represents a relationship between two entities.
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_entity_id: str = ""
    dest_entity_id: str = ""
    relationship_type: str = ""  # "transfer", "bridge", "governance", etc.
    
    # Statistics
    tx_count: int = 0
    total_volume_usd: float = 0.0
    first_interaction: Optional[datetime] = None
    last_interaction: Optional[datetime] = None
    
    # Evidence
    sample_tx_hashes: List[str] = field(default_factory=list)


@dataclass 
class EntityCluster:
    """
    A cluster of related entities (e.g., same owner across chains).
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: Optional[str] = None
    entity_ids: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    
    # Aggregated stats
    total_tx_count: int = 0
    total_volume_usd: float = 0.0
    chains: List[str] = field(default_factory=list)

