"""
PagerDuty Alerter - Sends critical alerts to PagerDuty.
"""

import os
from typing import Optional

import structlog

from ..models.incidents import Incident
from ..explainability.explanation import Explanation

logger = structlog.get_logger()


class PagerDutyAlerter:
    """
    Sends alerts to PagerDuty via Events API v2.

    Only pages for incidents at or above the configured minimum severity
    (default: HIGH). Supports dedup and resolution.
    """

    SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    PD_SEVERITY_MAP = {
        "critical": "critical",
        "high": "error",
        "medium": "warning",
        "low": "info",
        "info": "info",
    }

    def __init__(
        self,
        routing_key: Optional[str] = None,
        min_severity: str = "high",
        dashboard_url: str = "https://xdr.example.com",
    ):
        self.routing_key = routing_key or os.getenv("PAGERDUTY_ROUTING_KEY", "")
        self.min_severity = min_severity
        self.dashboard_url = dashboard_url

    # ── Public interface (matches Slack/Telegram pattern) ──────────

    async def send_critical(self, incident: Incident, explanation: Explanation):
        """Send critical alert to PagerDuty."""
        await self._send_event(incident, explanation)

    async def send_high(self, incident: Incident, explanation: Explanation):
        """Send high-severity alert to PagerDuty (if min_severity allows)."""
        await self._send_event(incident, explanation)

    async def send_info(self, incident: Incident, explanation: Explanation):
        """Send info-level alert to PagerDuty (usually filtered by min_severity)."""
        await self._send_event(incident, explanation)

    async def resolve(self, incident_id: str):
        """Resolve a PagerDuty incident when the Sentinel3 incident is resolved."""
        if not self.routing_key:
            return

        try:
            import httpx
        except ImportError:
            logger.warning("httpx_not_installed")
            return

        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json={
                        "routing_key": self.routing_key,
                        "event_action": "resolve",
                        "dedup_key": f"sentinel3-{incident_id}",
                    },
                    timeout=10,
                )
                logger.info("pagerduty_alert_resolved", incident_id=incident_id)
        except Exception as e:
            logger.error("pagerduty_resolve_failed", error=str(e))

    # ── Internal ───────────────────────────────────────────────────

    async def _send_event(self, incident: Incident, explanation: Explanation):
        """Trigger a PagerDuty event if severity meets threshold."""
        if not self.routing_key:
            logger.info(
                "pagerduty_would_send",
                incident_id=incident.id,
                reason="no routing key configured",
            )
            return

        sev_str = incident.severity.name.lower()
        if self.SEVERITY_ORDER.get(sev_str, 0) < self.SEVERITY_ORDER.get(self.min_severity.lower(), 3):
            logger.debug(
                "pagerduty_below_threshold",
                incident_id=incident.id,
                severity=sev_str,
                min_severity=self.min_severity,
            )
            return

        pd_severity = self.PD_SEVERITY_MAP.get(sev_str, "warning")
        chains = ", ".join(incident.affected_chains) if incident.affected_chains else "unknown"

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": f"sentinel3-{incident.id}",
            "payload": {
                "summary": (
                    f"[{incident.severity.name}] {explanation.title} "
                    f"— Loss: ${incident.total_loss_usd:,.0f} on {chains}"
                ),
                "source": "sentinel3-xdr",
                "severity": pd_severity,
                "component": "detection-engine",
                "group": "web3-security",
                "class": incident.attack_type.value,
                "custom_details": {
                    "incident_id": incident.id,
                    "attack_type": incident.attack_type.value,
                    "confidence": incident.confidence,
                    "total_loss_usd": incident.total_loss_usd,
                    "tvl_at_risk_usd": incident.tvl_at_risk_usd,
                    "affected_chains": incident.affected_chains,
                    "what_happened": explanation.what_happened[:500],
                    "dashboard_link": f"{self.dashboard_url}/incidents/{incident.id}",
                },
            },
        }

        try:
            import httpx
        except ImportError:
            logger.warning("httpx_not_installed")
            return

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=payload,
                    timeout=10,
                )
                if resp.status_code in (200, 202):
                    logger.info(
                        "pagerduty_alert_sent",
                        incident_id=incident.id,
                        severity=incident.severity.name,
                    )
                else:
                    logger.error(
                        "pagerduty_alert_failed",
                        status=resp.status_code,
                        body=resp.text[:200],
                    )
        except Exception as e:
            logger.error("pagerduty_alert_failed", error=str(e))
