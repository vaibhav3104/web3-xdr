"""
Incident Builder Engine - Intelligent Clustering & Deduplication
================================================================

Phase 4: Groups related violations into cohesive incidents instead of
creating 100 separate alerts for a single attack.

Features:
- Stateful deduplication (upsert logic)
- Time-windowed clustering (1-hour buckets)
- Severity escalation
- Auto-resolution
- Event aggregation
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import structlog

from ..models.events import SecurityEvent, EventStatus, Severity
from ..models.invariants import InvariantResult

logger = structlog.get_logger(__name__)


class IncidentStatus(Enum):
    """Incident lifecycle status."""
    OPEN_PENDING = "OPEN_PENDING"  # New, not yet confirmed
    OPEN_CONFIRMED = "OPEN_CONFIRMED"  # Confirmed, actively being investigated
    RESOLVED = "RESOLVED"  # Resolved (no new events for 6h)
    STALE = "STALE"  # Unresolved but no new events for 6h
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Manually marked as false positive


@dataclass
class IncidentTimelineEntry:
    """Single entry in incident timeline."""
    timestamp: datetime
    chain: str
    tx_hash: str
    description: str
    event_id: str
    severity: str


@dataclass
class Incident:
    """
    A clustered incident containing multiple related violations.
    """
    # Identity
    incident_id: str
    cluster_key: str  # Deduplication key
    
    # Classification
    protocol_id: str
    violation_type: str  # e.g., "MINT_WITHOUT_LOCK", "AMOUNT_MISMATCH"
    attack_type: str  # e.g., "BRIDGE_EXPLOIT", "REENTRANCY"
    
    # Scope
    source_chain: str
    target_chain: Optional[str]
    affected_contracts: Set[str] = field(default_factory=set)
    affected_addresses: Set[str] = field(default_factory=set)
    
    # Lifecycle
    status: IncidentStatus = IncidentStatus.OPEN_PENDING
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    
    # Aggregated metrics
    event_count: int = 0
    total_value_at_risk_usd: Decimal = Decimal("0")
    first_event_time: Optional[datetime] = None
    last_event_time: Optional[datetime] = None
    
    # Related data
    event_ids: List[str] = field(default_factory=list)
    violation_results: List[InvariantResult] = field(default_factory=list)
    
    # Timeline
    timeline: List[IncidentTimelineEntry] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_violation(self, violation: InvariantResult, event: SecurityEvent):
        """Add a violation to this incident."""
        self.event_count += 1
        self.event_ids.append(event.event_id)
        self.violation_results.append(violation)
        
        # Update scope
        if event.contract_address:
            self.affected_contracts.add(event.contract_address)
        if event.source_address:
            self.affected_addresses.add(event.source_address)
        if event.dest_address:
            self.affected_addresses.add(event.dest_address)
        
        # Update value at risk
        if violation.violation_amount_usd > 0:
            self.total_value_at_risk_usd += Decimal(str(violation.violation_amount_usd))
        
        # Update timeline
        self.timeline.append(IncidentTimelineEntry(
            timestamp=event.block_timestamp,
            chain=event.chain_id,
            tx_hash=event.tx_hash,
            description=self._generate_timeline_description(violation, event),
            event_id=event.event_id,
            severity=violation.severity.name
        ))
        
        # Update timestamps
        if not self.first_event_time or event.block_timestamp < self.first_event_time:
            self.first_event_time = event.block_timestamp
        if not self.last_event_time or event.block_timestamp > self.last_event_time:
            self.last_event_time = event.block_timestamp
        
        # Escalate severity if needed
        if violation.severity.value > self.severity.value:
            self.severity = violation.severity
            logger.info(
                "incident_severity_escalated",
                incident_id=self.incident_id,
                old_severity=self.severity.name,
                new_severity=violation.severity.name
            )
        
        # Update confidence (weighted average)
        self.confidence = (self.confidence * (self.event_count - 1) + violation.confidence) / self.event_count
        
        self.updated_at = datetime.now(timezone.utc)
    
    def _generate_timeline_description(self, violation: InvariantResult, event: SecurityEvent) -> str:
        """Generate human-readable timeline description."""
        if violation.invariant_name.startswith("MINT_BURN_PARITY"):
            return f"Mint without lock detected: {event.amount} {event.asset_type or 'tokens'} on {event.chain_id}"
        elif violation.invariant_name.startswith("LIQUIDITY_PARITY"):
            return f"Fill without deposit: {event.amount} {event.asset_type or 'tokens'}"
        elif violation.invariant_name.startswith("AMOUNT_MISMATCH"):
            return f"Amount mismatch: Expected {violation.evidence.get('expected', 'N/A')}, got {event.amount}"
        else:
            return f"{violation.invariant_name} violation on {event.chain_id}"
    
    def should_auto_resolve(self, max_idle_hours: int = 6) -> bool:
        """Check if incident should be auto-resolved."""
        if self.status in [IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE]:
            return False
        
        if not self.last_event_time:
            return False
        
        idle_time = datetime.now(timezone.utc) - self.last_event_time
        return idle_time.total_seconds() >= max_idle_hours * 3600
    
    def to_dict(self) -> dict:
        """Convert to dictionary for storage/API."""
        return {
            "incident_id": self.incident_id,
            "cluster_key": self.cluster_key,
            "protocol_id": self.protocol_id,
            "violation_type": self.violation_type,
            "attack_type": self.attack_type,
            "source_chain": self.source_chain,
            "target_chain": self.target_chain,
            "affected_contracts": list(self.affected_contracts),
            "affected_addresses": list(self.affected_addresses),
            "status": self.status.value,
            "severity": self.severity.name,
            "confidence": self.confidence,
            "event_count": self.event_count,
            "total_value_at_risk_usd": str(self.total_value_at_risk_usd),
            "first_event_time": self.first_event_time.isoformat() if self.first_event_time else None,
            "last_event_time": self.last_event_time.isoformat() if self.last_event_time else None,
            "event_ids": self.event_ids,
            "timeline": [
                {
                    "timestamp": entry.timestamp.isoformat(),
                    "chain": entry.chain,
                    "tx_hash": entry.tx_hash,
                    "description": entry.description,
                    "event_id": entry.event_id,
                    "severity": entry.severity
                }
                for entry in self.timeline
            ],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }


class IncidentBuilder:
    """
    Builds and manages incidents from violations.
    
    Implements intelligent clustering to group related violations
    into cohesive incidents.
    """
    
    def __init__(self, time_window_hours: int = 1):
        """
        Initialize incident builder.
        
        Args:
            time_window_hours: Time window for clustering (default: 1 hour)
        """
        self.time_window_hours = time_window_hours
        self.incidents: Dict[str, Incident] = {}  # cluster_key -> Incident
        self.event_to_incident: Dict[str, str] = {}  # event_id -> cluster_key (for idempotency)
        
        logger.info(
            "incident_builder_initialized",
            time_window_hours=time_window_hours
        )
    
    def _generate_cluster_key(
        self,
        protocol_id: str,
        violation_type: str,
        source_chain: str,
        target_chain: Optional[str],
        event_time: datetime
    ) -> str:
        """
        Generate deduplication cluster key.
        
        Format: (protocol_id, violation_type, source_chain, target_chain, time_window_bucket_1h)
        """
        # Round down to nearest hour
        time_bucket = event_time.replace(minute=0, second=0, microsecond=0)
        time_bucket_str = time_bucket.isoformat()
        
        key_parts = [
            protocol_id,
            violation_type,
            source_chain,
            target_chain or "unknown",
            time_bucket_str
        ]
        
        key_string = ":".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]
    
    def _extract_violation_type(self, violation: InvariantResult) -> str:
        """Extract violation type from invariant result."""
        # Check evidence for violation type
        if "violations" in violation.evidence:
            violations = violation.evidence["violations"]
            if violations:
                return violations[0].get("type", violation.invariant_name)
        
        # Fallback to invariant name
        return violation.invariant_name
    
    def upsert_incident(
        self,
        violation: InvariantResult,
        event: SecurityEvent
    ) -> Incident:
        """
        Upsert (update or insert) an incident.
        
        If a matching incident exists (same cluster key), append the violation.
        Otherwise, create a new incident.
        
        Returns:
            Incident (new or updated)
        """
        # Check idempotency: if event already processed, return existing incident
        if event.event_id in self.event_to_incident:
            cluster_key = self.event_to_incident[event.event_id]
            incident = self.incidents.get(cluster_key)
            if incident:
                logger.debug(
                    "duplicate_event_skipped",
                    event_id=event.event_id,
                    incident_id=incident.incident_id
                )
                return incident
        
        # Extract violation type
        violation_type = self._extract_violation_type(violation)
        
        # Determine protocol
        protocol_id = violation.bridge_id or "unknown"
        
        # Determine chains
        source_chain = violation.chain_id or event.chain_id
        target_chain = None
        if "dest_chain" in violation.evidence:
            target_chain = violation.evidence["dest_chain"]
        
        # Generate cluster key
        cluster_key = self._generate_cluster_key(
            protocol_id=protocol_id,
            violation_type=violation_type,
            source_chain=source_chain,
            target_chain=target_chain,
            event_time=event.block_timestamp
        )
        
        # Get or create incident
        if cluster_key in self.incidents:
            incident = self.incidents[cluster_key]
            incident.add_violation(violation, event)
            logger.info(
                "incident_updated",
                incident_id=incident.incident_id,
                event_count=incident.event_count,
                cluster_key=cluster_key[:16]
            )
        else:
            # Create new incident
            incident_id = f"inc_{cluster_key[:16]}_{int(event.block_timestamp.timestamp())}"
            
            incident = Incident(
                incident_id=incident_id,
                cluster_key=cluster_key,
                protocol_id=protocol_id,
                violation_type=violation_type,
                attack_type=self._classify_attack_type(violation_type),
                source_chain=source_chain,
                target_chain=target_chain,
                severity=violation.severity,
                confidence=violation.confidence
            )
            
            incident.add_violation(violation, event)
            self.incidents[cluster_key] = incident
            
            logger.info(
                "incident_created",
                incident_id=incident_id,
                protocol_id=protocol_id,
                violation_type=violation_type,
                cluster_key=cluster_key[:16]
            )
        
        # Track event -> incident mapping for idempotency
        self.event_to_incident[event.event_id] = cluster_key
        
        return incident
    
    def _classify_attack_type(self, violation_type: str) -> str:
        """Classify attack type from violation type."""
        if "MINT_WITHOUT_LOCK" in violation_type:
            return "BRIDGE_EXPLOIT"
        elif "AMOUNT_MISMATCH" in violation_type:
            return "BRIDGE_EXPLOIT"
        elif "FILL_WITHOUT_DEPOSIT" in violation_type:
            return "LIQUIDITY_EXPLOIT"
        elif "SEQUENCE" in violation_type:
            return "MESSAGE_REPLAY"
        elif "REENTRANCY" in violation_type:
            return "REENTRANCY_ATTACK"
        else:
            return "UNKNOWN_EXPLOIT"
    
    def auto_resolve_stale_incidents(self, max_idle_hours: int = 6) -> List[Incident]:
        """
        Auto-resolve incidents that haven't received new events.
        
        Returns:
            List of resolved incidents
        """
        resolved = []
        
        for cluster_key, incident in list(self.incidents.items()):
            if incident.should_auto_resolve(max_idle_hours):
                if incident.status == IncidentStatus.OPEN_CONFIRMED:
                    # Mark as STALE if unresolved
                    incident.status = IncidentStatus.STALE
                    logger.info(
                        "incident_marked_stale",
                        incident_id=incident.incident_id,
                        idle_hours=max_idle_hours
                    )
                else:
                    # Mark as RESOLVED
                    incident.status = IncidentStatus.RESOLVED
                    logger.info(
                        "incident_auto_resolved",
                        incident_id=incident.incident_id,
                        idle_hours=max_idle_hours
                    )
                
                resolved.append(incident)
        
        return resolved
    
    def get_incident(self, cluster_key: str) -> Optional[Incident]:
        """Get incident by cluster key."""
        return self.incidents.get(cluster_key)
    
    def get_open_incidents(self) -> List[Incident]:
        """Get all open incidents."""
        return [
            incident for incident in self.incidents.values()
            if incident.status in [IncidentStatus.OPEN_PENDING, IncidentStatus.OPEN_CONFIRMED]
        ]
    
    def get_incidents_by_protocol(self, protocol_id: str) -> List[Incident]:
        """Get incidents for a specific protocol."""
        return [
            incident for incident in self.incidents.values()
            if incident.protocol_id == protocol_id
        ]
    
    def mark_incident_resolved(self, cluster_key: str, false_positive: bool = False):
        """Manually mark an incident as resolved."""
        incident = self.incidents.get(cluster_key)
        if incident:
            if false_positive:
                incident.status = IncidentStatus.FALSE_POSITIVE
            else:
                incident.status = IncidentStatus.RESOLVED
            incident.updated_at = datetime.now(timezone.utc)
            logger.info(
                "incident_manually_resolved",
                incident_id=incident.incident_id,
                false_positive=false_positive
            )
