"""
Explanation data structures.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models.events import Severity


@dataclass
class EvidenceItem:
    """A piece of evidence supporting the explanation."""
    
    type: str  # "transaction", "event", "metric", "comparison"
    title: str
    description: str
    data: Dict[str, Any] = field(default_factory=dict)
    
    # For transaction evidence
    tx_hash: Optional[str] = None
    chain_id: Optional[str] = None
    block_number: Optional[int] = None
    
    # For metric evidence
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None


@dataclass
class RecommendedAction:
    """A recommended response action."""
    
    priority: int  # 1 = highest
    action: str
    reason: str
    is_urgent: bool = False
    requires_human: bool = True
    
    # For automated actions
    automation_available: bool = False
    automation_id: Optional[str] = None


@dataclass
class Explanation:
    """
    Complete explanation of an incident.
    
    Designed to be:
    - Deterministic (no AI hallucination)
    - Decision-grade (actionable)
    - Evidence-backed
    """
    
    # Identity
    incident_id: str
    generated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Core content
    title: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.0
    
    # Structured sections
    what_happened: str = ""
    why_dangerous: str = ""
    blast_radius: str = ""
    what_to_do: str = ""
    
    # Full text (for simple rendering)
    full_text: str = ""
    
    # Evidence
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    
    # Actions
    recommended_actions: List[RecommendedAction] = field(default_factory=list)
    
    # Metadata
    template_used: Optional[str] = None
    attack_type: Optional[str] = None
    affected_assets: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "incident_id": self.incident_id,
            "generated_at": self.generated_at.isoformat(),
            "title": self.title,
            "severity": self.severity.name,
            "confidence": self.confidence,
            "what_happened": self.what_happened,
            "why_dangerous": self.why_dangerous,
            "blast_radius": self.blast_radius,
            "what_to_do": self.what_to_do,
            "evidence_items": [
                {
                    "type": e.type,
                    "title": e.title,
                    "description": e.description,
                    "tx_hash": e.tx_hash,
                    "chain_id": e.chain_id,
                }
                for e in self.evidence_items
            ],
            "recommended_actions": [
                {
                    "priority": a.priority,
                    "action": a.action,
                    "is_urgent": a.is_urgent,
                }
                for a in self.recommended_actions
            ],
        }
    
    def to_markdown(self) -> str:
        """Render as Markdown."""
        lines = []
        
        # Header
        severity_emoji = {
            Severity.CRITICAL: "🚨🚨🚨",
            Severity.HIGH: "🚨",
            Severity.MEDIUM: "⚠️",
            Severity.LOW: "ℹ️",
            Severity.INFO: "📋",
        }
        emoji = severity_emoji.get(self.severity, "📋")
        lines.append(f"# {emoji} {self.title}")
        lines.append("")
        
        # Metadata
        lines.append(f"**Severity:** {self.severity.name}")
        lines.append(f"**Confidence:** {self.confidence:.0%}")
        lines.append(f"**Detected:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        
        # What happened
        if self.what_happened:
            lines.append("## What Happened")
            lines.append(self.what_happened)
            lines.append("")
        
        # Why dangerous
        if self.why_dangerous:
            lines.append("## Why This Is Dangerous")
            lines.append(self.why_dangerous)
            lines.append("")
        
        # Blast radius
        if self.blast_radius:
            lines.append("## Blast Radius")
            lines.append(self.blast_radius)
            lines.append("")
        
        # Evidence
        if self.evidence_items:
            lines.append("## Evidence")
            for item in self.evidence_items:
                lines.append(f"### {item.title}")
                lines.append(item.description)
                if item.tx_hash:
                    lines.append(f"- Transaction: `{item.tx_hash}`")
                if item.chain_id:
                    lines.append(f"- Chain: {item.chain_id}")
                lines.append("")
        
        # What to do
        if self.what_to_do:
            lines.append("## Recommended Actions")
            lines.append(self.what_to_do)
            lines.append("")
        
        if self.recommended_actions:
            lines.append("### Action Checklist")
            for action in sorted(self.recommended_actions, key=lambda a: a.priority):
                urgent = "🔴 " if action.is_urgent else ""
                lines.append(f"- [ ] {urgent}{action.action}")
            lines.append("")
        
        return "\n".join(lines)
    
    def to_slack_blocks(self) -> List[dict]:
        """Render as Slack Block Kit blocks."""
        blocks = []
        
        # Header
        severity_emoji = {
            Severity.CRITICAL: ":rotating_light::rotating_light::rotating_light:",
            Severity.HIGH: ":rotating_light:",
            Severity.MEDIUM: ":warning:",
            Severity.LOW: ":information_source:",
            Severity.INFO: ":memo:",
        }
        emoji = severity_emoji.get(self.severity, ":memo:")
        
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {self.title}",
                "emoji": True
            }
        })
        
        # Context
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:* {self.severity.name} | *Confidence:* {self.confidence:.0%}"
                }
            ]
        })
        
        blocks.append({"type": "divider"})
        
        # What happened
        if self.what_happened:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*What Happened*\n{self.what_happened[:500]}"
                }
            })
        
        # Blast radius
        if self.blast_radius:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Blast Radius*\n{self.blast_radius[:500]}"
                }
            })
        
        # Actions
        if self.recommended_actions:
            urgent = [a for a in self.recommended_actions if a.is_urgent]
            if urgent:
                action_text = "\n".join([f"• {a.action}" for a in urgent[:3]])
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*:fire: Immediate Actions*\n{action_text}"
                    }
                })
        
        return blocks
    
    def to_telegram(self) -> str:
        """Render as Telegram message (HTML format)."""
        severity_emoji = {
            Severity.CRITICAL: "🚨🚨🚨",
            Severity.HIGH: "🚨",
            Severity.MEDIUM: "⚠️",
            Severity.LOW: "ℹ️",
            Severity.INFO: "📋",
        }
        emoji = severity_emoji.get(self.severity, "📋")
        
        lines = []
        lines.append(f"<b>{emoji} {self.title}</b>")
        lines.append("")
        lines.append(f"<b>Severity:</b> {self.severity.name}")
        lines.append(f"<b>Confidence:</b> {self.confidence:.0%}")
        lines.append("")
        
        if self.what_happened:
            lines.append("<b>What Happened</b>")
            lines.append(self.what_happened[:500])
            lines.append("")
        
        if self.blast_radius:
            lines.append("<b>Blast Radius</b>")
            lines.append(self.blast_radius[:300])
            lines.append("")
        
        if self.recommended_actions:
            urgent = [a for a in self.recommended_actions if a.is_urgent][:3]
            if urgent:
                lines.append("<b>⚡ Immediate Actions</b>")
                for action in urgent:
                    lines.append(f"• {action.action}")
        
        return "\n".join(lines)

