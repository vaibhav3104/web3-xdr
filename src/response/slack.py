"""
Slack Alerter - Sends alerts to Slack channels.
"""

from typing import List, Optional
import structlog

from ..models.events import Severity
from ..models.incidents import Incident
from ..explainability.explanation import Explanation

logger = structlog.get_logger()


class SlackAlerter:
    """
    Sends formatted alerts to Slack.
    
    Uses Slack Block Kit for rich formatting.
    """
    
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        critical_channel: Optional[str] = None,
        general_channel: Optional[str] = None,
        dashboard_url: str = "https://xdr.example.com"
    ):
        self.webhook_url = webhook_url
        self.critical_channel = critical_channel
        self.general_channel = general_channel
        self.dashboard_url = dashboard_url
        
        self._client = None
    
    async def _get_client(self):
        """Get or create HTTP client."""
        if self._client is None:
            try:
                import httpx
                self._client = httpx.AsyncClient()
            except ImportError:
                logger.warning("httpx_not_installed")
                return None
        return self._client
    
    async def send_critical(self, incident: Incident, explanation: Explanation):
        """
        Send critical alert to Slack.
        """
        blocks = self._format_critical_blocks(incident, explanation)
        await self._send(blocks, self.critical_channel or self.general_channel)
        
        logger.info(
            "slack_critical_sent",
            incident_id=incident.id
        )
    
    async def send_high(self, incident: Incident, explanation: Explanation):
        """
        Send high severity alert.
        """
        blocks = self._format_high_blocks(incident, explanation)
        await self._send(blocks, self.general_channel)
        
        logger.info(
            "slack_high_sent",
            incident_id=incident.id
        )
    
    async def send_info(self, incident: Incident, explanation: Explanation):
        """
        Send info alert.
        """
        blocks = self._format_info_blocks(incident, explanation)
        await self._send(blocks, self.general_channel)
    
    async def _send(self, blocks: List[dict], channel: Optional[str]):
        """Send blocks to Slack webhook."""
        client = await self._get_client()
        
        if client and self.webhook_url:
            try:
                payload = {
                    "blocks": blocks,
                    "unfurl_links": False,
                    "unfurl_media": False
                }
                if channel:
                    payload["channel"] = channel
                
                await client.post(
                    self.webhook_url,
                    json=payload
                )
            except Exception as e:
                logger.error("slack_send_failed", error=str(e))
        else:
            logger.info(
                "slack_would_send",
                block_count=len(blocks)
            )
    
    def _format_critical_blocks(
        self,
        incident: Incident,
        explanation: Explanation
    ) -> List[dict]:
        """Format critical alert as Slack blocks."""
        blocks = []
        
        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨🚨🚨 CRITICAL: {explanation.title}",
                "emoji": True
            }
        })
        
        # Context
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:* {incident.severity.name} | *Confidence:* {explanation.confidence:.0%} | *Chains:* {', '.join(incident.affected_chains)}"
                }
            ]
        })
        
        blocks.append({"type": "divider"})
        
        # What happened
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*What Happened*\n{explanation.what_happened[:500]}"
            }
        })
        
        # Metrics
        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Estimated Loss*\n${incident.total_loss_usd:,.0f}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*TVL at Risk*\n${incident.tvl_at_risk_usd:,.0f}"
                }
            ]
        })
        
        blocks.append({"type": "divider"})
        
        # Urgent actions
        urgent_actions = [a for a in explanation.recommended_actions if a.is_urgent]
        if urgent_actions:
            action_text = "\n".join([f"• {a.action}" for a in urgent_actions[:3]])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*:fire: IMMEDIATE ACTIONS REQUIRED*\n{action_text}"
                }
            })
        
        # Action buttons
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Incident",
                        "emoji": True
                    },
                    "url": f"{self.dashboard_url}/incidents/{incident.id}",
                    "style": "danger"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Acknowledge",
                        "emoji": True
                    },
                    "action_id": f"ack_{incident.id}"
                }
            ]
        })
        
        return blocks
    
    def _format_high_blocks(
        self,
        incident: Incident,
        explanation: Explanation
    ) -> List[dict]:
        """Format high severity alert."""
        blocks = []
        
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 HIGH: {explanation.title}",
                "emoji": True
            }
        })
        
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:* {incident.severity.name} | *Confidence:* {explanation.confidence:.0%}"
                }
            ]
        })
        
        blocks.append({"type": "divider"})
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Summary*\n{explanation.what_happened[:400]}"
            }
        })
        
        # Loss estimate
        if incident.total_loss_usd > 0:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Estimated Exposure:* ${incident.total_loss_usd:,.0f}"
                }
            })
        
        # Actions
        actions = explanation.recommended_actions[:3]
        if actions:
            action_text = "\n".join([f"• {a.action}" for a in actions])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Actions*\n{action_text}"
                }
            })
        
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Details",
                        "emoji": True
                    },
                    "url": f"{self.dashboard_url}/incidents/{incident.id}"
                }
            ]
        })
        
        return blocks
    
    def _format_info_blocks(
        self,
        incident: Incident,
        explanation: Explanation
    ) -> List[dict]:
        """Format info alert."""
        blocks = []
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"ℹ️ *{explanation.title}*\n\n{explanation.what_happened[:300]}"
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "View",
                    "emoji": True
                },
                "url": f"{self.dashboard_url}/incidents/{incident.id}"
            }
        })
        
        return blocks

