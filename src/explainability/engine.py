"""
Explainability Engine 2.0 - Structured Explanations
===================================================

Phase 4: Provides human-readable, evidence-based explanations for incidents.
"""

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Any
import structlog

from ..models.events import SecurityEvent
from ..models.invariants import InvariantResult
from ..correlation.incident_builder import Incident
from .templates import ExplanationTemplate

logger = structlog.get_logger(__name__)


class RecommendedAction(Enum):
    """Recommended actions for incidents."""
    PAUSE = "PAUSE"  # Pause the contract/bridge immediately
    INVESTIGATE = "INVESTIGATE"  # Investigate further before action
    CONTACT_TEAM = "CONTACT_TEAM"  # Contact protocol team
    MONITOR = "MONITOR"  # Continue monitoring
    IGNORE = "IGNORE"  # Likely false positive


@dataclass
class TimelineEntry:
    """Timeline entry for explanation."""
    timestamp: datetime
    chain: str
    tx_hash: str
    description: str
    event_id: Optional[str] = None


@dataclass
class TechnicalContext:
    """Technical context for explanation."""
    function_name: Optional[str] = None
    protocol_version: Optional[str] = None
    detected_pattern: Optional[str] = None
    contract_address: Optional[str] = None
    bridge_id: Optional[str] = None


@dataclass
class Evidence:
    """Evidence for correlation."""
    correlation_key: Optional[str] = None
    source_msg_id: Optional[str] = None
    dest_msg_id: Optional[str] = None
    source_amount: Optional[Decimal] = None
    dest_amount: Optional[Decimal] = None
    matched: bool = False
    confidence: float = 0.0


@dataclass
class Explanation:
    """
    Structured explanation for an incident.
    
    Contains all information needed to understand and respond to an incident.
    """
    # Summary
    summary: str  # One-sentence natural language description
    
    # Timeline
    timeline: List[TimelineEntry] = field(default_factory=list)
    
    # Technical context
    technical_context: TechnicalContext = field(default_factory=TechnicalContext)
    
    # Evidence
    evidence: List[Evidence] = field(default_factory=list)
    
    # Recommended action
    recommended_action: RecommendedAction = RecommendedAction.INVESTIGATE
    
    # Additional context
    confidence: float = 0.5
    severity: str = "MEDIUM"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for storage/API."""
        return {
            "summary": self.summary,
            "timeline": [
                {
                    "timestamp": entry.timestamp.isoformat(),
                    "chain": entry.chain,
                    "tx_hash": entry.tx_hash,
                    "description": entry.description,
                    "event_id": entry.event_id
                }
                for entry in self.timeline
            ],
            "technical_context": {
                "function_name": self.technical_context.function_name,
                "protocol_version": self.technical_context.protocol_version,
                "detected_pattern": self.technical_context.detected_pattern,
                "contract_address": self.technical_context.contract_address,
                "bridge_id": self.technical_context.bridge_id
            },
            "evidence": [
                {
                    "correlation_key": ev.correlation_key,
                    "source_msg_id": ev.source_msg_id,
                    "dest_msg_id": ev.dest_msg_id,
                    "source_amount": str(ev.source_amount) if ev.source_amount else None,
                    "dest_amount": str(ev.dest_amount) if ev.dest_amount else None,
                    "matched": ev.matched,
                    "confidence": ev.confidence
                }
                for ev in self.evidence
            ],
            "recommended_action": self.recommended_action.value,
            "confidence": self.confidence,
            "severity": self.severity
        }

    def to_markdown(self) -> str:
        """Render explanation as a Markdown report."""
        lines = [
            f"# {self.severity} Security Incident",
            "",
            f"**Summary:** {self.summary}",
            f"**Confidence:** {self.confidence:.0%}",
            f"**Recommended Action:** {self.recommended_action.value}",
            "",
        ]

        if self.technical_context.bridge_id:
            lines.append(f"**Bridge:** {self.technical_context.bridge_id}")
        if self.technical_context.detected_pattern:
            lines.append(f"**Pattern:** {self.technical_context.detected_pattern}")
        if self.technical_context.contract_address:
            lines.append(f"**Contract:** `{self.technical_context.contract_address}`")
        lines.append("")

        if self.timeline:
            lines.append("## Timeline")
            lines.append("")
            for entry in self.timeline:
                ts = entry.timestamp.strftime("%H:%M:%S UTC")
                lines.append(f"- **{ts}** [{entry.chain}] {entry.description}")
                lines.append(f"  tx: `{entry.tx_hash}`")
            lines.append("")

        if self.evidence:
            lines.append("## Evidence")
            lines.append("")
            for i, ev in enumerate(self.evidence, 1):
                lines.append(f"### Evidence #{i} (confidence: {ev.confidence:.0%})")
                if ev.source_amount is not None:
                    lines.append(f"- Source amount: {ev.source_amount}")
                if ev.dest_amount is not None:
                    lines.append(f"- Dest amount: {ev.dest_amount}")
                if ev.source_msg_id:
                    lines.append(f"- Source msg: `{ev.source_msg_id}`")
                if ev.dest_msg_id:
                    lines.append(f"- Dest msg: `{ev.dest_msg_id}`")
                lines.append(f"- Cross-chain matched: {'YES' if ev.matched else 'NO'}")
            lines.append("")

        return "\n".join(lines)

    def to_telegram(self) -> str:
        """Render explanation as a compact Telegram alert."""
        action_emoji = {
            RecommendedAction.PAUSE: "🛑",
            RecommendedAction.INVESTIGATE: "🔍",
            RecommendedAction.CONTACT_TEAM: "📞",
            RecommendedAction.MONITOR: "👁",
            RecommendedAction.IGNORE: "✅",
        }
        emoji = action_emoji.get(self.recommended_action, "⚠️")

        lines = [
            f"🚨 <b>{self.severity} ALERT</b>",
            "",
            self.summary,
            "",
            f"Confidence: {self.confidence:.0%}",
        ]

        if self.technical_context.bridge_id:
            lines.append(f"Bridge: {self.technical_context.bridge_id}")
        if self.technical_context.detected_pattern:
            lines.append(f"Pattern: {self.technical_context.detected_pattern}")

        lines.append("")
        lines.append(f"{emoji} <b>Action: {self.recommended_action.value}</b>")

        return "\n".join(lines)


class ExplainabilityEngine:
    """
    Generates structured explanations for incidents.
    
    Uses templates and evidence to create human-readable narratives.
    """
    
    def __init__(self):
        self.template = ExplanationTemplate()
        logger.info("explainability_engine_initialized")
    
    def explain_incident(
        self,
        incident: Incident,
        violations: List[InvariantResult],
        events: List[SecurityEvent]
    ) -> Explanation:
        """
        Generate explanation for an incident.
        
        Args:
            incident: The clustered incident
            violations: List of violations that created this incident
            events: List of events related to this incident
        
        Returns:
            Structured Explanation object
        """
        # Build timeline from incident timeline
        timeline = [
            TimelineEntry(
                timestamp=entry.timestamp,
                chain=entry.chain,
                tx_hash=entry.tx_hash,
                description=entry.description,
                event_id=entry.event_id
            )
            for entry in incident.timeline
        ]
        
        # Extract technical context
        technical_context = self._extract_technical_context(incident, violations, events)
        
        # Extract evidence
        evidence = self._extract_evidence(incident, violations, events)
        
        # Generate summary using template
        summary = self.template.generate_summary(
            violation_type=incident.violation_type,
            protocol_id=incident.protocol_id,
            source_chain=incident.source_chain,
            target_chain=incident.target_chain,
            event_count=incident.event_count,
            total_value=incident.total_value_at_risk_usd,
            evidence=evidence
        )
        
        # Determine recommended action
        recommended_action = self._determine_recommended_action(
            incident=incident,
            violations=violations,
            evidence=evidence
        )
        
        return Explanation(
            summary=summary,
            timeline=timeline,
            technical_context=technical_context,
            evidence=evidence,
            recommended_action=recommended_action,
            confidence=incident.confidence,
            severity=incident.severity.name
        )
    
    def _extract_technical_context(
        self,
        incident: Incident,
        violations: List[InvariantResult],
        events: List[SecurityEvent]
    ) -> TechnicalContext:
        """Extract technical context from incident data."""
        # Get first event for context
        first_event = events[0] if events else None
        
        # Extract pattern from violations
        detected_pattern = None
        if violations:
            violation = violations[0]
            if "violations" in violation.evidence:
                violations_list = violation.evidence.get("violations", [])
                if violations_list:
                    detected_pattern = violations_list[0].get("type", violation.invariant_name)
            else:
                detected_pattern = violation.invariant_name
        
        return TechnicalContext(
            function_name=None,  # Would need to decode calldata
            protocol_version=None,  # Would need to query contract
            detected_pattern=detected_pattern,
            contract_address=first_event.contract_address if first_event else None,
            bridge_id=incident.protocol_id
        )
    
    def _extract_evidence(
        self,
        incident: Incident,
        violations: List[InvariantResult],
        events: List[SecurityEvent]
    ) -> List[Evidence]:
        """Extract evidence from violations and events."""
        evidence_list = []
        
        for violation in violations:
            # Extract correlation keys from violation evidence
            corr_key = None
            source_msg_id = None
            dest_msg_id = None
            
            if "correlation_key" in violation.evidence:
                corr_key = violation.evidence["correlation_key"]
            
            if "source_msg_id" in violation.evidence:
                source_msg_id = violation.evidence["source_msg_id"]
            
            if "dest_msg_id" in violation.evidence:
                dest_msg_id = violation.evidence["dest_msg_id"]
            
            # Extract amounts
            source_amount = None
            dest_amount = None
            
            if "source_amount" in violation.evidence:
                source_amount = Decimal(str(violation.evidence["source_amount"]))
            
            if "dest_amount" in violation.evidence:
                dest_amount = Decimal(str(violation.evidence["dest_amount"]))
            
            # Check if matched
            matched = bool(source_msg_id and dest_msg_id and source_msg_id == dest_msg_id)
            
            evidence_list.append(Evidence(
                correlation_key=corr_key,
                source_msg_id=source_msg_id,
                dest_msg_id=dest_msg_id,
                source_amount=source_amount,
                dest_amount=dest_amount,
                matched=matched,
                confidence=violation.confidence
            ))
        
        return evidence_list
    
    def _determine_recommended_action(
        self,
        incident: Incident,
        violations: List[InvariantResult],
        evidence: List[Evidence]
    ) -> RecommendedAction:
        """
        Determine recommended action based on incident characteristics.
        """
        # High severity + high confidence = PAUSE
        if incident.severity.value >= 3 and incident.confidence >= 0.8:
            return RecommendedAction.PAUSE
        
        # High value at risk = PAUSE
        if incident.total_value_at_risk_usd >= Decimal("1000000"):  # $1M+
            return RecommendedAction.PAUSE
        
        # Multiple events = INVESTIGATE
        if incident.event_count > 10:
            return RecommendedAction.INVESTIGATE
        
        # Low confidence = MONITOR
        if incident.confidence < 0.5:
            return RecommendedAction.MONITOR
        
        # Default: INVESTIGATE
        return RecommendedAction.INVESTIGATE
