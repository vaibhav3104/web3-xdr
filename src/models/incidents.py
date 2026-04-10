"""
Incident Model - Represents security incidents.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from .events import Severity


class IncidentStatus(Enum):
    """Status of an incident."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AttackType(Enum):
    """Classification of attack types."""
    UNBACKED_MINT = "unbacked_mint"
    FORGED_MESSAGE = "forged_message"
    VALIDATOR_COMPROMISE = "validator_compromise"
    GOVERNANCE_ATTACK = "governance_attack"
    LIQUIDITY_DRAIN = "liquidity_drain"
    FLASH_LOAN_EXPLOIT = "flash_loan_exploit"
    CROSS_CHAIN_LAUNDERING = "cross_chain_laundering"
    INSIDER_ABUSE = "insider_abuse"
    REENTRANCY = "reentrancy"
    PRICE_MANIPULATION = "price_manipulation"
    UNKNOWN = "unknown"


@dataclass
class AttackGraphNode:
    """Node in the attack graph."""
    
    entity_id: str
    address: str
    chain_id: str
    role: str  # "attacker", "victim", "bridge", "intermediary"
    
    # Timing
    first_seen_in_attack: Optional[datetime] = None
    last_seen_in_attack: Optional[datetime] = None
    
    # Funds flow
    funds_received_usd: float = 0.0
    funds_sent_usd: float = 0.0


@dataclass
class AttackGraphEdge:
    """Edge in the attack graph."""
    
    source_id: str
    dest_id: str
    tx_hash: str
    chain_id: str
    amount_usd: float = 0.0
    timestamp: Optional[datetime] = None
    event_type: str = ""


@dataclass
class AttackGraph:
    """
    Graph representation of an attack.
    
    Nodes are entities, edges are transactions/events.
    """
    
    nodes: List[AttackGraphNode] = field(default_factory=list)
    edges: List[AttackGraphEdge] = field(default_factory=list)
    
    def get_attacker_nodes(self) -> List[AttackGraphNode]:
        """Get nodes identified as attackers."""
        return [n for n in self.nodes if n.role == "attacker"]
    
    def get_victim_nodes(self) -> List[AttackGraphNode]:
        """Get nodes identified as victims."""
        return [n for n in self.nodes if n.role == "victim"]
    
    def total_stolen(self) -> float:
        """Calculate total stolen amount."""
        attacker_nodes = self.get_attacker_nodes()
        return sum(n.funds_received_usd for n in attacker_nodes)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "nodes": [
                {
                    "entity_id": n.entity_id,
                    "address": n.address,
                    "chain_id": n.chain_id,
                    "role": n.role,
                    "funds_received_usd": n.funds_received_usd,
                    "funds_sent_usd": n.funds_sent_usd,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "source_id": e.source_id,
                    "dest_id": e.dest_id,
                    "tx_hash": e.tx_hash,
                    "chain_id": e.chain_id,
                    "amount_usd": e.amount_usd,
                    "event_type": e.event_type,
                }
                for e in self.edges
            ]
        }


@dataclass
class Incident:
    """
    A security incident combining multiple related violations.
    """
    
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Classification
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    attack_type: AttackType = AttackType.UNKNOWN
    confidence: float = 0.0  # 0.0 - 1.0
    
    # Scope
    affected_chains: List[str] = field(default_factory=list)
    affected_bridges: List[str] = field(default_factory=list)
    affected_protocols: List[str] = field(default_factory=list)
    
    # Violations
    violation_ids: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    
    # Impact
    total_loss_usd: float = 0.0
    estimated_loss_rate_per_block: float = 0.0
    tvl_at_risk_usd: float = 0.0
    
    # Attack details
    attack_graph: Optional[AttackGraph] = None
    attacker_addresses: List[str] = field(default_factory=list)
    victim_addresses: List[str] = field(default_factory=list)
    
    # Timing
    first_exploit_block: Optional[int] = None
    first_exploit_chain: Optional[str] = None
    first_exploit_tx: Optional[str] = None
    detection_block: Optional[int] = None
    detection_latency_blocks: int = 0
    
    # Response
    recommended_actions: List[str] = field(default_factory=list)
    response_runbook_id: Optional[str] = None
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    
    # Metadata
    title: str = ""
    summary: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_critical(self) -> bool:
        return self.severity == Severity.CRITICAL
    
    def is_active(self) -> bool:
        return self.status in [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONFIRMED]
    
    def add_event(self, event_id: str):
        """Add an event to this incident."""
        if event_id not in self.event_ids:
            self.event_ids.append(event_id)
            self.updated_at = datetime.now(timezone.utc)
    
    def add_violation(self, violation_id: str):
        """Add a violation to this incident."""
        if violation_id not in self.violation_ids:
            self.violation_ids.append(violation_id)
            self.updated_at = datetime.now(timezone.utc)
    
    def acknowledge(self, user: str):
        """Mark incident as acknowledged."""
        self.acknowledged_by = user
        self.acknowledged_at = datetime.now(timezone.utc)
        self.status = IncidentStatus.INVESTIGATING
        self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "severity": self.severity.name,
            "status": self.status.value,
            "attack_type": self.attack_type.value,
            "confidence": self.confidence,
            "affected_chains": self.affected_chains,
            "affected_bridges": self.affected_bridges,
            "violation_ids": self.violation_ids,
            "event_ids": self.event_ids,
            "total_loss_usd": self.total_loss_usd,
            "estimated_loss_rate_per_block": self.estimated_loss_rate_per_block,
            "tvl_at_risk_usd": self.tvl_at_risk_usd,
            "attacker_addresses": self.attacker_addresses,
            "detection_latency_blocks": self.detection_latency_blocks,
            "title": self.title,
            "summary": self.summary,
            "attack_graph": self.attack_graph.to_dict() if self.attack_graph else None,
        }


@dataclass
class IncidentTimeline:
    """Timeline of events in an incident."""
    
    incident_id: str
    entries: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_entry(
        self,
        timestamp: datetime,
        entry_type: str,
        description: str,
        chain_id: Optional[str] = None,
        tx_hash: Optional[str] = None,
        metadata: Optional[dict] = None
    ):
        """Add an entry to the timeline."""
        self.entries.append({
            "timestamp": timestamp.isoformat(),
            "type": entry_type,
            "description": description,
            "chain_id": chain_id,
            "tx_hash": tx_hash,
            "metadata": metadata or {}
        })
        # Keep sorted by timestamp
        self.entries.sort(key=lambda e: e["timestamp"])

