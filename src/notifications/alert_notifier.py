"""
Alert Notification Service
Sends alerts to Telegram, Slack, Email, and Dashboard
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
import structlog
import aiohttp

logger = structlog.get_logger()


@dataclass
class NotificationConfig:
    """Configuration for notification channels"""
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    email_smtp_server: Optional[str] = None
    email_from: Optional[str] = None
    email_to: Optional[List[str]] = None


class AlertNotifier:
    """
    Multi-channel alert notification service.
    
    Supports:
    - Telegram
    - Slack
    - Email (future)
    - Webhook (custom integrations)
    """
    
    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or NotificationConfig(
            telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN"),
            telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID"),
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL")
        )
        
        # Track sent notifications to avoid duplicates
        self.sent_alerts: Dict[str, datetime] = {}
        
        # Statistics
        self.stats = {
            "telegram_sent": 0,
            "slack_sent": 0,
            "email_sent": 0,
            "webhook_sent": 0,
            "failed": 0
        }
    
    async def send_contract_threat_alert(self, alert: dict):
        """
        Send a contract threat alert to all configured channels.
        
        Args:
            alert: ContractThreatAlert as dict
        """
        alert_id = alert.get("alert_id", "unknown")
        
        # Check for duplicate
        if alert_id in self.sent_alerts:
            logger.debug("duplicate_alert_skipped", alert_id=alert_id)
            return
        
        self.sent_alerts[alert_id] = datetime.utcnow()
        
        # Build message
        message = self._format_contract_threat_message(alert)
        
        # Send to all channels
        tasks = []
        
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            tasks.append(self._send_telegram(message, alert))
        
        if self.config.slack_webhook_url:
            tasks.append(self._send_slack(message, alert))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(
            "alert_notifications_sent",
            alert_id=alert_id,
            channels=len(tasks)
        )
    
    def _format_contract_threat_message(self, alert: dict) -> str:
        """Format alert as human-readable message."""
        risk_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }
        
        risk = alert.get("risk_level", "UNKNOWN")
        emoji = risk_emoji.get(risk, "⚪")
        
        threat_category = alert.get("threat_category", "unknown").replace("_", " ").title()
        confidence = alert.get("confidence", 0)
        
        message = f"""
{emoji} **MALICIOUS CONTRACT DETECTED** {emoji}

🔗 **Chain:** {alert.get("chain_id", "unknown")}
📍 **Contract:** `{alert.get("contract_address", "unknown")}`
👤 **Deployer:** `{alert.get("deployer_address", "unknown")[:20]}...`

⚠️ **Threat:** {threat_category}
📊 **Confidence:** {confidence:.1%}
🎯 **Risk Level:** {risk}

📦 **Bytecode Size:** {alert.get("bytecode_size", 0):,} bytes
⛽ **Gas Used:** {alert.get("gas_used", 0):,}

🔍 **TX Hash:** `{alert.get("tx_hash", "unknown")[:20]}...`
📦 **Block:** #{alert.get("block_number", 0):,}

⏰ **Detected:** {alert.get("timestamp", "unknown")}
🆔 **Alert ID:** {alert.get("alert_id", "unknown")}
        """.strip()
        
        return message
    
    async def _send_telegram(self, message: str, alert: dict):
        """Send alert to Telegram."""
        try:
            url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
            
            # Convert markdown to Telegram format
            telegram_message = message.replace("**", "*")
            
            payload = {
                "chat_id": self.config.telegram_chat_id,
                "text": telegram_message,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        self.stats["telegram_sent"] += 1
                        logger.info("telegram_alert_sent", alert_id=alert.get("alert_id"))
                    else:
                        error = await resp.text()
                        logger.error("telegram_send_failed", status=resp.status, error=error)
                        self.stats["failed"] += 1
                        
        except Exception as e:
            logger.error("telegram_error", error=str(e))
            self.stats["failed"] += 1
    
    async def _send_slack(self, message: str, alert: dict):
        """Send alert to Slack."""
        try:
            risk_colors = {
                "CRITICAL": "#ff0000",
                "HIGH": "#ff8800",
                "MEDIUM": "#ffcc00",
                "LOW": "#00cc00"
            }
            
            risk = alert.get("risk_level", "UNKNOWN")
            color = risk_colors.get(risk, "#808080")
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"🚨 Malicious Contract Detected - {alert.get('threat_category', 'Unknown').replace('_', ' ').title()}",
                    "fields": [
                        {
                            "title": "Chain",
                            "value": alert.get("chain_id", "unknown"),
                            "short": True
                        },
                        {
                            "title": "Risk Level",
                            "value": risk,
                            "short": True
                        },
                        {
                            "title": "Contract Address",
                            "value": f"`{alert.get('contract_address', 'unknown')}`",
                            "short": False
                        },
                        {
                            "title": "Deployer",
                            "value": f"`{alert.get('deployer_address', 'unknown')}`",
                            "short": False
                        },
                        {
                            "title": "Confidence",
                            "value": f"{alert.get('confidence', 0):.1%}",
                            "short": True
                        },
                        {
                            "title": "Bytecode Size",
                            "value": f"{alert.get('bytecode_size', 0):,} bytes",
                            "short": True
                        }
                    ],
                    "footer": f"Alert ID: {alert.get('alert_id', 'unknown')}",
                    "ts": int(datetime.utcnow().timestamp())
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.config.slack_webhook_url, json=payload) as resp:
                    if resp.status == 200:
                        self.stats["slack_sent"] += 1
                        logger.info("slack_alert_sent", alert_id=alert.get("alert_id"))
                    else:
                        error = await resp.text()
                        logger.error("slack_send_failed", status=resp.status, error=error)
                        self.stats["failed"] += 1
                        
        except Exception as e:
            logger.error("slack_error", error=str(e))
            self.stats["failed"] += 1
    
    async def send_incident_alert(self, incident: dict):
        """Send general incident alert."""
        message = self._format_incident_message(incident)
        
        tasks = []
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            tasks.append(self._send_telegram(message, incident))
        if self.config.slack_webhook_url:
            tasks.append(self._send_slack(message, incident))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def _format_incident_message(self, incident: dict) -> str:
        """Format incident as message."""
        return f"""
🚨 **SECURITY INCIDENT**

**Title:** {incident.get('title', 'Unknown')}
**Severity:** {incident.get('severity', 'UNKNOWN')}
**Chain:** {incident.get('chain', 'unknown')}

**Description:** {incident.get('description', 'No description')}

**Time:** {incident.get('timestamp', 'unknown')}
        """.strip()
    
    def get_stats(self) -> dict:
        """Get notification statistics."""
        return {
            **self.stats,
            "channels_configured": {
                "telegram": bool(self.config.telegram_bot_token),
                "slack": bool(self.config.slack_webhook_url)
            }
        }


# Global notifier instance
_notifier: Optional[AlertNotifier] = None


def get_notifier() -> AlertNotifier:
    """Get or create global notifier instance."""
    global _notifier
    if _notifier is None:
        _notifier = AlertNotifier()
    return _notifier


async def send_alert(alert: dict):
    """Convenience function to send alert."""
    notifier = get_notifier()
    await notifier.send_contract_threat_alert(alert)

