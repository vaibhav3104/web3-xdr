"""
Explainability Engine - Generates deterministic explanations.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import structlog

from ..models.events import SecurityEvent, Severity
from ..models.incidents import Incident, AttackType
from ..models.invariants import InvariantResult
from .explanation import Explanation, EvidenceItem, RecommendedAction
from .templates import ExplanationTemplates

logger = structlog.get_logger()


class ExplainabilityEngine:
    """
    Generates deterministic, human-readable explanations.
    
    Key principles:
    - NO AI hallucination - purely template-based
    - All claims backed by evidence
    - Actionable, not just informational
    - Consistent output for same input
    """
    
    def __init__(self):
        self.templates = ExplanationTemplates
    
    def explain(
        self,
        incident: Incident,
        violations: Optional[List[InvariantResult]] = None,
        events: Optional[List[SecurityEvent]] = None
    ) -> Explanation:
        """
        Generate an explanation for an incident.
        """
        violations = violations or []
        events = events or []
        
        # Extract variables for templates
        variables = self._extract_variables(incident, violations, events)
        
        # Render sections
        attack_type = incident.attack_type
        
        title = self.templates.render(attack_type, "title", variables)
        what_happened = self.templates.render(attack_type, "what_happened", variables)
        why_dangerous = self.templates.render(attack_type, "why_dangerous", variables)
        blast_radius = self.templates.render(attack_type, "blast_radius", variables)
        what_to_do = self.templates.render(attack_type, "what_to_do", variables)
        
        # Build evidence items
        evidence_items = self._build_evidence(violations, events, variables)
        
        # Build recommended actions
        recommended_actions = self._build_actions(incident, attack_type)
        
        # Calculate confidence
        confidence = self._calculate_confidence(incident, violations)
        
        explanation = Explanation(
            incident_id=incident.id,
            title=title,
            severity=incident.severity,
            confidence=confidence,
            what_happened=what_happened.strip(),
            why_dangerous=why_dangerous.strip(),
            blast_radius=blast_radius.strip(),
            what_to_do=what_to_do.strip(),
            evidence_items=evidence_items,
            recommended_actions=recommended_actions,
            template_used=attack_type.value,
            attack_type=attack_type.value,
        )
        
        # Build full text
        explanation.full_text = explanation.to_markdown()
        
        logger.info(
            "explanation_generated",
            incident_id=incident.id,
            attack_type=attack_type.value,
            confidence=confidence
        )
        
        return explanation
    
    def _extract_variables(
        self,
        incident: Incident,
        violations: List[InvariantResult],
        events: List[SecurityEvent]
    ) -> Dict[str, Any]:
        """
        Extract template variables from incident data.
        """
        variables = {}
        
        # Basic incident info
        variables["incident_id"] = incident.id
        variables["severity"] = incident.severity.name
        variables["attack_type"] = incident.attack_type.value
        
        # Chains and bridges
        variables["source_chain"] = incident.affected_chains[0] if incident.affected_chains else "Unknown"
        variables["dest_chain"] = incident.affected_chains[1] if len(incident.affected_chains) > 1 else incident.affected_chains[0] if incident.affected_chains else "Unknown"
        variables["chains_list"] = ", ".join(incident.affected_chains) if incident.affected_chains else "Unknown"
        variables["chain_count"] = len(incident.affected_chains)
        
        # Loss amounts
        variables["total_loss_usd"] = self.templates.format_usd(incident.total_loss_usd)
        variables["gap_usd"] = self.templates.format_usd(incident.total_loss_usd)
        variables["drain_usd"] = self.templates.format_usd(incident.total_loss_usd)
        variables["estimated_exposure"] = self.templates.format_usd(incident.tvl_at_risk_usd)
        
        # TVL info
        variables["bridge_tvl"] = self.templates.format_usd(incident.tvl_at_risk_usd)
        variables["tvl_now"] = self.templates.format_usd(incident.tvl_at_risk_usd)
        variables["tvl_before"] = self.templates.format_usd(incident.tvl_at_risk_usd + incident.total_loss_usd)
        
        # Drain rate
        drain_rate = incident.estimated_loss_rate_per_block
        variables["drain_rate_per_block"] = self.templates.format_usd(drain_rate)
        if drain_rate > 0 and incident.tvl_at_risk_usd > 0:
            blocks_to_drain = incident.tvl_at_risk_usd / drain_rate
            variables["time_to_drain"] = f"~{int(blocks_to_drain)} blocks (~{int(blocks_to_drain * 12 / 60)} minutes)"
        else:
            variables["time_to_drain"] = "Unknown"
        
        # Extract from violations
        if violations:
            primary = violations[0]
            evidence = primary.evidence or {}
            
            # Mint/lock specific
            variables["minted_amount"] = evidence.get("total_minted", "Unknown")
            variables["locked_amount"] = evidence.get("total_locked", "Unknown")
            variables["gap_amount"] = evidence.get("delta", "Unknown")
            variables["mint_count"] = len(evidence.get("mints", []))
            variables["lock_count"] = len(evidence.get("locks", []))
            
            # Asset info
            variables["asset"] = evidence.get("asset", "tokens")
            
            # Signature info
            variables["signature_count"] = evidence.get("signatures_provided", "Unknown")
            variables["threshold"] = evidence.get("threshold_required", "Unknown")
            variables["shortfall"] = evidence.get("shortfall", "Unknown")
            
            # Drain info
            variables["drain_percent"] = f"{evidence.get('drain_rate_percent', 0):.1f}"
            variables["multiplier"] = f"{evidence.get('spike_multiplier', 1):.1f}"
            
            # Violation count
            variables["violation_count"] = len(violations)
            variables["confidence"] = f"{primary.confidence * 100:.0f}"
        
        # Build transaction list
        if events:
            tx_lines = []
            for event in events[:5]:  # First 5
                tx_lines.append(f"- `{event.tx_hash[:16]}...` ({event.event_type.value}, {event.amount} on {event.chain_id})")
            variables["transaction_list"] = "\n".join(tx_lines) if tx_lines else "No transactions recorded"
        else:
            variables["transaction_list"] = "No transactions recorded"
        
        # Time info
        if events:
            times = [e.block_timestamp for e in events]
            span = max(times) - min(times)
            variables["time_span"] = self.templates.format_duration(span.total_seconds())
            variables["time_window"] = self.templates.format_duration(span.total_seconds())
        else:
            variables["time_span"] = "Unknown"
            variables["time_window"] = "1 hour"
        
        # Hop/transfer count
        transfer_events = [e for e in events if e.event_type.value == "transfer"]
        variables["hop_count"] = len(transfer_events)
        
        # Flash loan specific
        flash_events = [e for e in events if "flash" in e.event_type.value.lower()]
        if flash_events:
            variables["flash_loan_amount"] = str(flash_events[0].amount)
            variables["flash_asset"] = flash_events[0].asset_type
        else:
            variables["flash_loan_amount"] = "Unknown"
            variables["flash_asset"] = "Unknown"
        
        variables["operation_count"] = len(events)
        variables["total_volume"] = self.templates.format_usd(sum(float(e.amount_usd) for e in events))
        
        if events:
            variables["tx_hash"] = events[0].tx_hash
        else:
            variables["tx_hash"] = "Unknown"
        
        # Address info
        variables["address_count"] = len(set(
            e.source_address for e in events if e.source_address
        ) | set(
            e.dest_address for e in events if e.dest_address
        ))
        variables["origin_chain"] = events[0].chain_id if events else "Unknown"
        variables["current_chain"] = events[-1].chain_id if events else "Unknown"
        
        # Evidence summary for unknown attacks
        if violations:
            evidence_lines = []
            for v in violations[:3]:
                evidence_lines.append(f"- {v.invariant_name}: {v.description}")
            variables["evidence_summary"] = "\n".join(evidence_lines)
        else:
            variables["evidence_summary"] = "Insufficient data"
        
        # Governance specific
        variables["action_type"] = "Unknown governance action"
        variables["elapsed_time"] = "Unknown"
        variables["required_delay"] = "24 hours"
        variables["delay_shortfall"] = "Unknown"
        variables["affected_contracts"] = ", ".join(incident.affected_bridges) if incident.affected_bridges else "Unknown"
        variables["protocol_tvl"] = variables["bridge_tvl"]
        
        # Exploit linking
        variables["known_exploit_link"] = "None identified"
        variables["estimated_profit"] = variables["total_loss_usd"]
        variables["reserves_at_risk"] = variables["bridge_tvl"]
        
        return variables
    
    def _build_evidence(
        self,
        violations: List[InvariantResult],
        events: List[SecurityEvent],
        variables: Dict[str, Any]
    ) -> List[EvidenceItem]:
        """
        Build evidence items from violations and events.
        """
        items = []
        
        # Evidence from violations
        for violation in violations[:5]:
            items.append(EvidenceItem(
                type="violation",
                title=f"Invariant Violation: {violation.invariant_name}",
                description=violation.description or f"Detected violation of {violation.invariant_name}",
                data=violation.evidence,
                chain_id=violation.chain_id,
            ))
        
        # Evidence from key events
        for event in events[:5]:
            items.append(EvidenceItem(
                type="transaction",
                title=f"{event.event_type.value.upper()} Event",
                description=f"{event.amount} {event.asset_type} on {event.chain_id}",
                tx_hash=event.tx_hash,
                chain_id=event.chain_id,
                block_number=event.block_number,
            ))
        
        # Metrics evidence
        if "drain_percent" in variables:
            items.append(EvidenceItem(
                type="metric",
                title="TVL Drain Rate",
                description=f"TVL decreased by {variables['drain_percent']}%",
                metric_name="tvl_drain_rate",
                metric_value=float(variables.get("drain_percent", 0).replace("%", "")),
                threshold=10.0,  # 10% threshold
            ))
        
        return items
    
    def _build_actions(
        self,
        incident: Incident,
        attack_type: AttackType
    ) -> List[RecommendedAction]:
        """
        Build recommended actions based on attack type and severity.
        """
        actions = []
        
        # Critical = pause
        if incident.severity == Severity.CRITICAL:
            actions.append(RecommendedAction(
                priority=1,
                action="EMERGENCY PAUSE - Halt bridge operations immediately",
                reason="Every block of delay increases attacker profit",
                is_urgent=True,
                requires_human=True,
            ))
        
        # Attack-specific actions
        if attack_type == AttackType.UNBACKED_MINT:
            actions.extend([
                RecommendedAction(
                    priority=2,
                    action="Verify recent mints against source chain locks",
                    reason="Confirm scope of unbacked minting",
                    is_urgent=True,
                ),
                RecommendedAction(
                    priority=3,
                    action="Check guardian/validator key status",
                    reason="Determine if keys are compromised",
                    is_urgent=True,
                ),
                RecommendedAction(
                    priority=4,
                    action="Prepare user communication",
                    reason="Inform users of situation and safety measures",
                    is_urgent=False,
                ),
            ])
        
        elif attack_type == AttackType.VALIDATOR_COMPROMISE:
            actions.extend([
                RecommendedAction(
                    priority=2,
                    action="Identify compromised validator keys",
                    reason="Contain the breach scope",
                    is_urgent=True,
                ),
                RecommendedAction(
                    priority=3,
                    action="Initiate key rotation procedure",
                    reason="Prevent further unauthorized operations",
                    is_urgent=True,
                ),
            ])
        
        elif attack_type == AttackType.LIQUIDITY_DRAIN:
            actions.extend([
                RecommendedAction(
                    priority=2,
                    action="Investigate largest withdrawals",
                    reason="Identify if exploit or legitimate activity",
                    is_urgent=True,
                ),
                RecommendedAction(
                    priority=3,
                    action="Consider temporary withdrawal limits",
                    reason="Slow down potential drain",
                    is_urgent=False,
                ),
            ])
        
        else:
            actions.extend([
                RecommendedAction(
                    priority=2,
                    action="Investigate flagged activity",
                    reason="Determine if attack or false positive",
                    is_urgent=False,
                ),
                RecommendedAction(
                    priority=3,
                    action="Monitor for continued anomalies",
                    reason="Detect escalation",
                    is_urgent=False,
                ),
            ])
        
        return actions
    
    def _calculate_confidence(
        self,
        incident: Incident,
        violations: List[InvariantResult]
    ) -> float:
        """
        Calculate explanation confidence.
        """
        base_confidence = incident.confidence
        
        # Boost for multiple violations
        if len(violations) >= 3:
            base_confidence += 0.1
        
        # Boost for known attack type
        if incident.attack_type != AttackType.UNKNOWN:
            base_confidence += 0.1
        
        # Boost for economic evidence
        if incident.total_loss_usd > 100000:
            base_confidence += 0.1
        
        return min(0.99, base_confidence)
    
    def explain_violation(self, violation: InvariantResult) -> str:
        """
        Generate a simple explanation for a single violation.
        """
        templates = {
            "MINT_LOCK_PARITY": "Tokens were minted without corresponding lock on source chain",
            "UNBACKED_MINT": "Mint operation occurred without verified backing",
            "TVL_VELOCITY": "Bridge TVL is draining faster than normal",
            "SIGNATURE_THRESHOLD": "Bridge operation executed with insufficient signatures",
            "TIMELOCK_RESPECTED": "Governance action bypassed required delay",
            "SEQUENCE": "Bridge operations occurred out of order",
        }
        
        base = templates.get(violation.invariant_name, f"Violation of {violation.invariant_name}")
        
        if violation.violation_amount_usd > 0:
            base += f" (${violation.violation_amount_usd:,.0f} at risk)"
        
        return base

