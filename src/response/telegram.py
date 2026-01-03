"""
Telegram Alerter - Sends alerts to Telegram channels.
"""

from typing import Optional
import structlog

from ..models.events import Severity
from ..models.incidents import Incident
from ..explainability.explanation import Explanation

logger = structlog.get_logger()


class TelegramAlerter:
    """
    Sends formatted alerts to Telegram.
    
    Uses Telegram Bot API with HTML formatting.
    """
    
    def __init__(
        self,
        bot_token: Optional[str] = None,
        critical_channel: Optional[str] = None,
        general_channel: Optional[str] = None,
        dashboard_url: str = "https://xdr.example.com"
    ):
        self.bot_token = bot_token
        self.critical_channel = critical_channel
        self.general_channel = general_channel
        self.dashboard_url = dashboard_url
        
        self._bot = None
    
    async def _get_bot(self):
        """Get or create Telegram bot instance."""
        if self._bot is None and self.bot_token:
            try:
                from telegram import Bot
                self._bot = Bot(token=self.bot_token)
            except ImportError:
                logger.warning("telegram_library_not_installed")
                return None
        return self._bot
    
    async def send_critical(self, incident: Incident, explanation: Explanation):
        """
        Send critical alert to Telegram.
        """
        bot = await self._get_bot()
        
        message = self._format_critical_message(incident, explanation)
        
        if bot and self.critical_channel:
            try:
                await bot.send_message(
                    chat_id=self.critical_channel,
                    text=message,
                    parse_mode="HTML"
                )
                logger.info(
                    "telegram_critical_sent",
                    incident_id=incident.id,
                    channel=self.critical_channel
                )
            except Exception as e:
                logger.error("telegram_send_failed", error=str(e))
        else:
            # Log what would be sent
            logger.info(
                "telegram_critical_would_send",
                incident_id=incident.id,
                message_preview=message[:200]
            )
    
    async def send_high(self, incident: Incident, explanation: Explanation):
        """
        Send high severity alert.
        """
        bot = await self._get_bot()
        
        message = self._format_high_message(incident, explanation)
        channel = self.general_channel or self.critical_channel
        
        if bot and channel:
            try:
                await bot.send_message(
                    chat_id=channel,
                    text=message,
                    parse_mode="HTML"
                )
                logger.info(
                    "telegram_high_sent",
                    incident_id=incident.id
                )
            except Exception as e:
                logger.error("telegram_send_failed", error=str(e))
        else:
            logger.info(
                "telegram_high_would_send",
                incident_id=incident.id
            )
    
    async def send_info(self, incident: Incident, explanation: Explanation):
        """
        Send info alert.
        """
        bot = await self._get_bot()
        
        message = self._format_info_message(incident, explanation)
        channel = self.general_channel
        
        if bot and channel:
            try:
                await bot.send_message(
                    chat_id=channel,
                    text=message,
                    parse_mode="HTML"
                )
            except Exception as e:
                logger.error("telegram_send_failed", error=str(e))
    
    def _format_critical_message(
        self,
        incident: Incident,
        explanation: Explanation
    ) -> str:
        """Format critical alert message."""
        return f"""
🚨🚨🚨 <b>CRITICAL SECURITY ALERT</b> 🚨🚨🚨

<b>{explanation.title}</b>

<b>Severity:</b> {incident.severity.name}
<b>Confidence:</b> {explanation.confidence:.0%}
<b>Chains:</b> {', '.join(incident.affected_chains)}

<b>What Happened:</b>
{explanation.what_happened[:300]}...

<b>Estimated Loss:</b> ${incident.total_loss_usd:,.0f}
<b>TVL at Risk:</b> ${incident.tvl_at_risk_usd:,.0f}

<b>⚡ IMMEDIATE ACTIONS REQUIRED:</b>
{self._format_urgent_actions(explanation)}

🔗 <a href="{self.dashboard_url}/incidents/{incident.id}">View Full Incident</a>
"""
    
    def _format_high_message(
        self,
        incident: Incident,
        explanation: Explanation
    ) -> str:
        """Format high severity message."""
        return f"""
🚨 <b>HIGH SEVERITY ALERT</b>

<b>{explanation.title}</b>

<b>Severity:</b> {incident.severity.name}
<b>Confidence:</b> {explanation.confidence:.0%}

<b>Summary:</b>
{explanation.what_happened[:200]}...

<b>Estimated Exposure:</b> ${incident.total_loss_usd:,.0f}

<b>Recommended Actions:</b>
{self._format_actions(explanation)}

🔗 <a href="{self.dashboard_url}/incidents/{incident.id}">View Details</a>
"""
    
    def _format_info_message(
        self,
        incident: Incident,
        explanation: Explanation
    ) -> str:
        """Format info message."""
        return f"""
ℹ️ <b>Security Alert</b>

{explanation.title}

<b>Severity:</b> {incident.severity.name}
<b>Confidence:</b> {explanation.confidence:.0%}

{explanation.what_happened[:150]}...

🔗 <a href="{self.dashboard_url}/incidents/{incident.id}">View Details</a>
"""
    
    def _format_urgent_actions(self, explanation: Explanation) -> str:
        """Format urgent actions for critical alerts."""
        urgent = [a for a in explanation.recommended_actions if a.is_urgent][:3]
        if not urgent:
            return "• Review incident immediately\n• Consider emergency pause"
        
        lines = []
        for action in urgent:
            lines.append(f"• {action.action}")
        return "\n".join(lines)
    
    def _format_actions(self, explanation: Explanation) -> str:
        """Format action list."""
        actions = explanation.recommended_actions[:5]
        if not actions:
            return "• Review incident details"
        
        lines = []
        for action in actions:
            lines.append(f"• {action.action}")
        return "\n".join(lines)

