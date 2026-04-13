"""
LLM Incident Triage
====================

Analyzes each AlertMatch via Claude API to determine TP vs FP.
Feeds verdicts back into the feedback loop for auto-suppression.

Usage:
    triage = IncidentTriage()
    verdict = await triage.analyze(alert_match)
    # verdict.is_tp, verdict.reasoning, verdict.confidence
"""

import json
from dataclasses import dataclass
from typing import Dict, Any, Optional, List
import structlog

from .client import get_client, get_async_client, MODEL, MAX_TOKENS

logger = structlog.get_logger(__name__)

# Import feedback loop for auto-feeding verdicts
try:
    from src.rules.feedback_loop import get_feedback_loop

    FEEDBACK_AVAILABLE = True
except ImportError:
    FEEDBACK_AVAILABLE = False

# Import entity registry for context enrichment
try:
    from src.enrichment.entity_registry import get_entity_registry

    ENTITY_AVAILABLE = True
except ImportError:
    ENTITY_AVAILABLE = False


@dataclass
class TriageVerdict:
    """Result of LLM triage analysis."""

    rule_id: str
    is_tp: bool
    confidence: float  # 0.0 - 1.0 how confident the LLM is
    verdict: str  # "true_positive", "false_positive", "needs_review"
    reasoning: str  # LLM's explanation
    suggested_action: str  # "escalate", "dismiss", "investigate", "auto_resolve"
    risk_factors: List[str]
    mitigating_factors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "is_tp": self.is_tp,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "reasoning": self.reasoning,
            "suggested_action": self.suggested_action,
            "risk_factors": self.risk_factors,
            "mitigating_factors": self.mitigating_factors,
        }


TRIAGE_SYSTEM_PROMPT = """You are a Web3 security analyst performing first-pass triage on blockchain security alerts.

Your job is to determine if an alert is a TRUE POSITIVE (real threat) or FALSE POSITIVE (benign activity) based on the evidence provided.

Key principles:
- Transfers between known exchanges (CEX), DEX routers, bridges, and DeFi protocols are almost always routine
- Whale transfers that are just large CEX-to-CEX or protocol-to-protocol movements are FP
- Hacker/sanctioned address activity is almost always TP regardless of amount
- Flash loans are suspicious but common in legitimate arbitrage — look at the full context
- Admin/ownership changes from known deployer factories are routine, from unknown addresses are suspicious
- Consider the entity reputation tiers: TRUSTED (CEX/DEX/bridge/protocol), KNOWN (VCs/smart money), NEUTRAL (unknown), SUSPICIOUS (mixers), MALICIOUS (hackers/sanctioned)

Respond with ONLY valid JSON matching this schema:
{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "confidence": 0.0-1.0,
  "reasoning": "1-3 sentence explanation",
  "suggested_action": "escalate" | "dismiss" | "investigate" | "auto_resolve",
  "risk_factors": ["list of suspicious indicators"],
  "mitigating_factors": ["list of benign indicators"]
}"""


class IncidentTriage:
    """
    LLM-powered incident triage that auto-classifies alerts as TP/FP.

    Integrates with:
    - EntityRegistry: enriches alert context with address classifications
    - FeedbackLoop: auto-feeds verdicts for rule suppression
    - ConfidenceCalculator: provides evidence bundle for LLM context
    """

    def __init__(self, auto_feed_feedback: bool = True):
        self._auto_feed = auto_feed_feedback
        self._registry = get_entity_registry() if ENTITY_AVAILABLE else None
        self._feedback = get_feedback_loop() if FEEDBACK_AVAILABLE else None

    def _build_context(self, alert_match_dict: Dict[str, Any]) -> str:
        """Build rich context string for the LLM from an alert match."""
        event = alert_match_dict.get("event", {})
        details = alert_match_dict.get("details", {})
        evidence = alert_match_dict.get("evidence", {})

        parts = []
        parts.append(f"ALERT: {alert_match_dict.get('rule_name', 'Unknown Rule')}")
        parts.append(f"Rule ID: {alert_match_dict.get('rule_id', 'unknown')}")
        parts.append(f"Severity: {alert_match_dict.get('severity', 'unknown')}")
        parts.append(
            f"Base Confidence: {alert_match_dict.get('base_confidence', 'N/A')}"
        )
        parts.append(
            f"Dynamic Confidence: {alert_match_dict.get('confidence', 'N/A')}"
        )

        # Event details
        parts.append("\n--- EVENT ---")
        parts.append(f"Type: {event.get('event_type', 'unknown')}")
        parts.append(f"Chain: {event.get('chain', event.get('chain_id', 'unknown'))}")

        amount_usd = event.get("amount_usd")
        if amount_usd:
            parts.append(f"Amount USD: ${float(amount_usd):,.2f}")

        amount = event.get("amount")
        if amount:
            parts.append(f"Token Amount: {amount}")

        # Addresses with entity enrichment
        from_addr = event.get("from_address") or event.get("source_address", "")
        to_addr = event.get("to_address") or event.get("dest_address", "")

        if from_addr:
            parts.append(f"\nFrom: {from_addr}")
            if self._registry:
                entity = self._registry.classify(from_addr)
                if entity.name:
                    parts.append(f"  Entity: {entity.name} ({entity.entity_type.value})")
                    parts.append(f"  Risk Score: {entity.risk_score}")
                tier = self._registry.get_reputation_tier(from_addr)
                parts.append(f"  Reputation: {tier.value}")

        if to_addr:
            parts.append(f"\nTo: {to_addr}")
            if self._registry:
                entity = self._registry.classify(to_addr)
                if entity.name:
                    parts.append(f"  Entity: {entity.name} ({entity.entity_type.value})")
                    parts.append(f"  Risk Score: {entity.risk_score}")
                tier = self._registry.get_reputation_tier(to_addr)
                parts.append(f"  Reputation: {tier.value}")

        # Evidence bundle
        if evidence:
            parts.append("\n--- EVIDENCE ---")
            parts.append(f"Source Tier: {evidence.get('source_tier', 'unknown')}")
            parts.append(f"Dest Tier: {evidence.get('dest_tier', 'unknown')}")
            if evidence.get("amount_multiple"):
                parts.append(
                    f"Amount Multiple (vs threshold): {evidence['amount_multiple']}x"
                )
            if evidence.get("rule_fp_rate"):
                parts.append(
                    f"Rule Historical FP Rate: {evidence['rule_fp_rate']:.1%}"
                )
            parts.append(f"Off-hours: {evidence.get('is_off_hours', False)}")
            parts.append(
                f"Corroborating Rules: {evidence.get('corroborating_rules', 0)}"
            )

        # Match details
        if details:
            parts.append("\n--- MATCH DETAILS ---")
            for k, v in details.items():
                parts.append(f"{k}: {v}")

        return "\n".join(parts)

    def analyze(self, alert_match_dict: Dict[str, Any]) -> Optional[TriageVerdict]:
        """
        Analyze an alert match and return a triage verdict.

        Args:
            alert_match_dict: Output of AlertMatch.to_dict()

        Returns:
            TriageVerdict or None if LLM is unavailable
        """
        client = get_client()
        if not client:
            return None

        context = self._build_context(alert_match_dict)
        rule_id = alert_match_dict.get("rule_id", "unknown")

        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=TRIAGE_SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": f"Triage this alert:\n\n{context}",
                    }
                ],
            )

            raw = response.content[0].text.strip()
            # Extract JSON from response (handle markdown code blocks)
            if "```" in raw:
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            result = json.loads(raw)

            verdict = TriageVerdict(
                rule_id=rule_id,
                is_tp=result["verdict"] == "true_positive",
                confidence=float(result.get("confidence", 0.5)),
                verdict=result["verdict"],
                reasoning=result.get("reasoning", ""),
                suggested_action=result.get("suggested_action", "investigate"),
                risk_factors=result.get("risk_factors", []),
                mitigating_factors=result.get("mitigating_factors", []),
            )

            # Auto-feed into feedback loop
            if self._auto_feed and self._feedback and verdict.confidence >= 0.8:
                self._feedback.record_feedback(rule_id, verdict.is_tp)
                logger.info(
                    "triage_verdict_fed_to_feedback",
                    rule_id=rule_id,
                    verdict=verdict.verdict,
                    confidence=verdict.confidence,
                )

            logger.info(
                "incident_triaged",
                rule_id=rule_id,
                verdict=verdict.verdict,
                confidence=verdict.confidence,
                action=verdict.suggested_action,
            )

            return verdict

        except Exception as e:
            logger.error("triage_failed", rule_id=rule_id, error=str(e))
            return None

    async def analyze_async(self, alert_match_dict: Dict[str, Any]) -> Optional[TriageVerdict]:
        """Async version of analyze() — uses AsyncAnthropic for non-blocking calls."""
        client = get_async_client()
        if not client:
            return None

        context = self._build_context(alert_match_dict)
        rule_id = alert_match_dict.get("rule_id", "unknown")

        try:
            response = await client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=TRIAGE_SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": f"Triage this alert:\n\n{context}",
                    }
                ],
            )

            raw = response.content[0].text.strip()
            if "```" in raw:
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            result = json.loads(raw)

            verdict = TriageVerdict(
                rule_id=rule_id,
                is_tp=result["verdict"] == "true_positive",
                confidence=float(result.get("confidence", 0.5)),
                verdict=result["verdict"],
                reasoning=result.get("reasoning", ""),
                suggested_action=result.get("suggested_action", "investigate"),
                risk_factors=result.get("risk_factors", []),
                mitigating_factors=result.get("mitigating_factors", []),
            )

            if self._auto_feed and self._feedback and verdict.confidence >= 0.8:
                self._feedback.record_feedback(rule_id, verdict.is_tp)
                logger.info(
                    "triage_verdict_fed_to_feedback",
                    rule_id=rule_id,
                    verdict=verdict.verdict,
                    confidence=verdict.confidence,
                )

            logger.info(
                "incident_triaged_async",
                rule_id=rule_id,
                verdict=verdict.verdict,
                confidence=verdict.confidence,
                action=verdict.suggested_action,
            )
            return verdict

        except Exception as e:
            logger.error("triage_async_failed", rule_id=rule_id, error=str(e))
            return None

    def analyze_batch(
        self, alert_matches: List[Dict[str, Any]]
    ) -> List[TriageVerdict]:
        """Analyze multiple alerts and return verdicts."""
        verdicts = []
        for match in alert_matches:
            verdict = self.analyze(match)
            if verdict:
                verdicts.append(verdict)
        return verdicts
