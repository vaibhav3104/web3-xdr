"""
Incident Builder - Constructs incidents from violations and patterns.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import structlog

from ..models.events import SecurityEvent, Severity
from ..models.incidents import (
    Incident, 
    IncidentStatus, 
    AttackType, 
    AttackGraph,
    IncidentTimeline
)
from ..models.invariants import InvariantResult
from .pattern_matcher import PatternMatch
from .entity_graph import EntityGraph

logger = structlog.get_logger()


@dataclass
class IncidentCandidate:
    """Intermediate structure for building incidents."""
    violations: List[InvariantResult]
    pattern_matches: List[PatternMatch]
    events: List[SecurityEvent]
    chains: Set[str]
    bridges: Set[str]
    start_time: datetime
    end_time: datetime


class IncidentBuilder:
    """
    Builds unified incidents from violations, patterns, and events.
    
    Features:
    - Aggregates related violations
    - Merges overlapping incidents
    - Calculates severity and confidence
    - Builds attack timeline
    """
    
    def __init__(self, entity_graph: Optional[EntityGraph] = None):
        self.entity_graph = entity_graph
        
        # Severity mapping for attack types
        self._attack_severity = {
            AttackType.UNBACKED_MINT: Severity.CRITICAL,
            AttackType.FORGED_MESSAGE: Severity.CRITICAL,
            AttackType.VALIDATOR_COMPROMISE: Severity.CRITICAL,
            AttackType.GOVERNANCE_ATTACK: Severity.CRITICAL,
            AttackType.LIQUIDITY_DRAIN: Severity.HIGH,
            AttackType.FLASH_LOAN_EXPLOIT: Severity.HIGH,
            AttackType.CROSS_CHAIN_LAUNDERING: Severity.MEDIUM,
            AttackType.INSIDER_ABUSE: Severity.HIGH,
            AttackType.UNKNOWN: Severity.MEDIUM,
        }
    
    def build_incident(
        self,
        violations: List[InvariantResult],
        pattern_matches: Optional[List[PatternMatch]] = None,
        events: Optional[List[SecurityEvent]] = None
    ) -> Incident:
        """
        Build an incident from violations and pattern matches.
        """
        pattern_matches = pattern_matches or []
        events = events or []
        
        # Determine attack type
        attack_type = self._determine_attack_type(violations, pattern_matches)
        
        # Calculate severity
        severity = self._calculate_severity(violations, pattern_matches, attack_type)
        
        # Calculate confidence
        confidence = self._calculate_confidence(violations, pattern_matches)
        
        # Gather scope
        chains = self._gather_chains(violations, events)
        bridges = self._gather_bridges(violations, events)
        
        # Calculate loss
        total_loss = self._calculate_total_loss(violations, pattern_matches)
        
        # Get timing info
        first_event_time = self._get_first_event_time(violations, events)
        
        # Build title and summary
        title = self._generate_title(attack_type, total_loss)
        summary = self._generate_summary(violations, pattern_matches, attack_type)
        
        # Build attack graph if we have entity graph
        attack_graph = None
        if self.entity_graph and events:
            attack_graph = self.entity_graph.build_attack_graph(events)
        
        # Get attacker addresses from attack graph
        attacker_addresses = []
        if attack_graph:
            for node in attack_graph.get_attacker_nodes():
                attacker_addresses.append(node.address)
        
        # Build incident
        incident = Incident(
            created_at=datetime.utcnow(),
            severity=severity,
            status=IncidentStatus.OPEN,
            attack_type=attack_type,
            confidence=confidence,
            affected_chains=list(chains),
            affected_bridges=list(bridges),
            violation_ids=[v.id for v in violations],
            event_ids=[e.event_id for e in events],
            total_loss_usd=total_loss,
            attack_graph=attack_graph,
            attacker_addresses=attacker_addresses,
            title=title,
            summary=summary,
            recommended_actions=self._get_recommended_actions(attack_type, severity),
        )
        
        # Calculate detection latency
        if first_event_time:
            incident.detection_latency_blocks = self._estimate_block_latency(
                first_event_time, incident.created_at
            )
        
        logger.info(
            "incident_built",
            incident_id=incident.id,
            attack_type=attack_type.value,
            severity=severity.name,
            total_loss=total_loss
        )
        
        return incident
    
    def _determine_attack_type(
        self,
        violations: List[InvariantResult],
        pattern_matches: List[PatternMatch]
    ) -> AttackType:
        """Determine the attack type from violations and patterns."""
        
        # Pattern matches have explicit attack types
        if pattern_matches:
            # Return most severe attack type
            types = [m.attack_type for m in pattern_matches]
            for attack_type in [
                AttackType.UNBACKED_MINT,
                AttackType.VALIDATOR_COMPROMISE,
                AttackType.GOVERNANCE_ATTACK,
                AttackType.FLASH_LOAN_EXPLOIT,
                AttackType.LIQUIDITY_DRAIN,
            ]:
                if attack_type in types:
                    return attack_type
        
        # Infer from violation names
        violation_names = [v.invariant_name for v in violations]
        
        if "MINT_LOCK_PARITY" in violation_names or "UNBACKED_MINT" in violation_names:
            return AttackType.UNBACKED_MINT
        if "SIGNATURE_THRESHOLD" in violation_names:
            return AttackType.VALIDATOR_COMPROMISE
        if "TIMELOCK_RESPECTED" in violation_names:
            return AttackType.GOVERNANCE_ATTACK
        if "TVL_VELOCITY" in violation_names:
            return AttackType.LIQUIDITY_DRAIN
        if "SINGLE_BLOCK_CONCENTRATION" in violation_names:
            return AttackType.FLASH_LOAN_EXPLOIT
        
        return AttackType.UNKNOWN
    
    def _calculate_severity(
        self,
        violations: List[InvariantResult],
        pattern_matches: List[PatternMatch],
        attack_type: AttackType
    ) -> Severity:
        """Calculate overall incident severity."""
        
        # Start with attack type severity
        severity = self._attack_severity.get(attack_type, Severity.MEDIUM)
        
        # Escalate based on violation severities
        for violation in violations:
            if violation.severity.value > severity.value:
                severity = violation.severity
        
        # Escalate based on loss amount
        total_loss = self._calculate_total_loss(violations, pattern_matches)
        if total_loss > 10_000_000:
            severity = Severity.CRITICAL
        elif total_loss > 1_000_000:
            severity = max(severity, Severity.HIGH)
        
        return severity
    
    def _calculate_confidence(
        self,
        violations: List[InvariantResult],
        pattern_matches: List[PatternMatch]
    ) -> float:
        """Calculate overall incident confidence."""
        confidences = []
        
        # Add violation confidences
        for violation in violations:
            confidences.append(violation.confidence)
        
        # Add pattern match confidences
        for match in pattern_matches:
            confidences.append(match.confidence)
        
        if not confidences:
            return 0.5
        
        # Weight higher confidences more
        weighted_sum = sum(c * c for c in confidences)
        weight_total = sum(c for c in confidences)
        
        return weighted_sum / weight_total if weight_total > 0 else 0.5
    
    def _calculate_total_loss(
        self,
        violations: List[InvariantResult],
        pattern_matches: List[PatternMatch]
    ) -> float:
        """Calculate total estimated loss."""
        loss = 0.0
        
        # From violations
        for violation in violations:
            loss = max(loss, violation.violation_amount_usd)
        
        # From pattern matches
        for match in pattern_matches:
            loss = max(loss, match.get_total_volume())
        
        return loss
    
    def _gather_chains(
        self,
        violations: List[InvariantResult],
        events: List[SecurityEvent]
    ) -> Set[str]:
        """Gather all affected chains."""
        chains = set()
        
        for violation in violations:
            if violation.chain_id:
                chains.add(violation.chain_id)
        
        for event in events:
            chains.add(event.chain_id)
        
        return chains
    
    def _gather_bridges(
        self,
        violations: List[InvariantResult],
        events: List[SecurityEvent]
    ) -> Set[str]:
        """Gather all affected bridges."""
        bridges = set()
        
        for violation in violations:
            if violation.bridge_id:
                bridges.add(violation.bridge_id)
        
        for event in events:
            if event.bridge_id:
                bridges.add(event.bridge_id)
        
        return bridges
    
    def _get_first_event_time(
        self,
        violations: List[InvariantResult],
        events: List[SecurityEvent]
    ) -> Optional[datetime]:
        """Get the timestamp of the first event."""
        times = []
        
        for violation in violations:
            times.append(violation.timestamp)
        
        for event in events:
            times.append(event.block_timestamp)
        
        return min(times) if times else None
    
    def _estimate_block_latency(
        self,
        first_event_time: datetime,
        detection_time: datetime
    ) -> int:
        """Estimate latency in blocks (assumes ~12s blocks)."""
        delta = detection_time - first_event_time
        return max(0, int(delta.total_seconds() / 12))
    
    def _generate_title(self, attack_type: AttackType, total_loss: float) -> str:
        """Generate incident title."""
        type_names = {
            AttackType.UNBACKED_MINT: "Unbacked Cross-Chain Mint",
            AttackType.FORGED_MESSAGE: "Forged Bridge Message",
            AttackType.VALIDATOR_COMPROMISE: "Validator Key Compromise",
            AttackType.GOVERNANCE_ATTACK: "Governance Attack",
            AttackType.LIQUIDITY_DRAIN: "Liquidity Drain",
            AttackType.FLASH_LOAN_EXPLOIT: "Flash Loan Exploit",
            AttackType.CROSS_CHAIN_LAUNDERING: "Cross-Chain Fund Movement",
            AttackType.INSIDER_ABUSE: "Insider Abuse",
            AttackType.UNKNOWN: "Suspicious Activity",
        }
        
        type_name = type_names.get(attack_type, "Security Incident")
        
        if total_loss >= 1_000_000:
            return f"{type_name} (${total_loss/1_000_000:.1f}M at risk)"
        elif total_loss >= 1_000:
            return f"{type_name} (${total_loss/1_000:.0f}K at risk)"
        else:
            return type_name
    
    def _generate_summary(
        self,
        violations: List[InvariantResult],
        pattern_matches: List[PatternMatch],
        attack_type: AttackType
    ) -> str:
        """Generate incident summary."""
        parts = []
        
        # Describe violations
        if violations:
            violation_types = list(set(v.invariant_name for v in violations))
            parts.append(f"Detected {len(violations)} invariant violations: {', '.join(violation_types)}")
        
        # Describe patterns
        if pattern_matches:
            pattern_names = list(set(m.pattern_name for m in pattern_matches))
            parts.append(f"Matched attack patterns: {', '.join(pattern_names)}")
        
        return ". ".join(parts) if parts else "Security incident detected"
    
    def _get_recommended_actions(
        self,
        attack_type: AttackType,
        severity: Severity
    ) -> List[str]:
        """Get recommended response actions."""
        actions = []
        
        # Universal critical actions
        if severity == Severity.CRITICAL:
            actions.append("⚠️ CONSIDER EMERGENCY PAUSE - Contact bridge operators immediately")
        
        # Attack-type specific actions
        if attack_type == AttackType.UNBACKED_MINT:
            actions.extend([
                "Verify all recent mints against source chain locks",
                "Check guardian/validator signing keys for compromise",
                "Prepare incident communication for users",
                "Consider pausing mint functionality"
            ])
        elif attack_type == AttackType.VALIDATOR_COMPROMISE:
            actions.extend([
                "Identify compromised validator keys",
                "Initiate validator key rotation procedure",
                "Review all recent bridge operations signed by affected keys",
                "Increase signature threshold temporarily"
            ])
        elif attack_type == AttackType.GOVERNANCE_ATTACK:
            actions.extend([
                "Review executed governance actions",
                "Check timelock configuration",
                "Verify proposal legitimacy",
                "Consider reverting unauthorized changes"
            ])
        elif attack_type == AttackType.LIQUIDITY_DRAIN:
            actions.extend([
                "Monitor ongoing withdrawal activity",
                "Identify large withdrawers",
                "Check for correlated activity across chains",
                "Consider temporary withdrawal limits"
            ])
        elif attack_type == AttackType.FLASH_LOAN_EXPLOIT:
            actions.extend([
                "Analyze exploit transaction in detail",
                "Identify vulnerable contract logic",
                "Prepare hotfix if applicable",
                "Assess impact on protocol reserves"
            ])
        else:
            actions.extend([
                "Investigate flagged activity in detail",
                "Review recent transactions for anomalies",
                "Monitor for continued suspicious activity"
            ])
        
        return actions
    
    def build_timeline(self, incident: Incident, events: List[SecurityEvent]) -> IncidentTimeline:
        """Build a timeline for an incident."""
        timeline = IncidentTimeline(incident_id=incident.id)
        
        # Add events
        for event in sorted(events, key=lambda e: e.block_timestamp):
            timeline.add_entry(
                timestamp=event.block_timestamp,
                entry_type=event.event_type.value,
                description=f"{event.event_type.value.upper()} of {event.amount} on {event.chain_id}",
                chain_id=event.chain_id,
                tx_hash=event.tx_hash
            )
        
        # Add detection
        timeline.add_entry(
            timestamp=incident.created_at,
            entry_type="detection",
            description="Incident detected by XDR system"
        )
        
        return timeline

