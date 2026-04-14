"""
Alert Router - Routes alerts based on severity and configuration.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set
import asyncio
import structlog

from ..models.events import Severity
from ..models.incidents import Incident
from ..explainability.explanation import Explanation

logger = structlog.get_logger()


@dataclass
class AlertConfig:
    """Configuration for alerting."""

    # Telegram config
    telegram_enabled: bool = False
    telegram_bot_token: Optional[str] = None
    telegram_critical_channel: Optional[str] = None
    telegram_general_channel: Optional[str] = None

    # Slack config
    slack_enabled: bool = False
    slack_webhook_url: Optional[str] = None
    slack_critical_channel: Optional[str] = None
    slack_general_channel: Optional[str] = None

    # Email config
    email_enabled: bool = False
    email_provider: str = "smtp"  # "smtp" or "sendgrid"
    email_smtp_host: Optional[str] = None
    email_smtp_port: int = 587
    email_smtp_user: Optional[str] = None
    email_smtp_password: Optional[str] = None
    email_smtp_use_tls: bool = True
    email_sendgrid_api_key: Optional[str] = None
    email_from: Optional[str] = None
    email_to: Optional[List[str]] = None

    # PagerDuty config
    pagerduty_enabled: bool = False
    pagerduty_routing_key: Optional[str] = None
    pagerduty_min_severity: str = "high"

    # Rate limiting
    min_alert_interval_seconds: int = 60
    max_alerts_per_hour: int = 50

    # Dedup
    dedup_window_minutes: int = 30


class AlertRouter:
    """
    Routes alerts to appropriate channels based on severity.
    
    Features:
    - Severity-based routing
    - Rate limiting
    - Deduplication
    - Multiple channel support
    """
    
    def __init__(self, config: AlertConfig):
        self.config = config
        
        # Initialize alerters
        self.telegram = None
        self.slack = None
        self.email = None
        self.pagerduty = None
        
        # Rate limiting
        self._alert_history: List[datetime] = []
        self._sent_alerts: Dict[str, datetime] = {}  # incident_id -> last alert time
        
        # Dedup
        self._alert_hashes: Set[str] = set()
    
    async def initialize(self):
        """Initialize alerting channels."""
        if self.config.telegram_enabled:
            from .telegram import TelegramAlerter
            self.telegram = TelegramAlerter(
                bot_token=self.config.telegram_bot_token,
                critical_channel=self.config.telegram_critical_channel,
                general_channel=self.config.telegram_general_channel,
            )
            logger.info("telegram_alerter_initialized")

        if self.config.slack_enabled:
            from .slack import SlackAlerter
            self.slack = SlackAlerter(
                webhook_url=self.config.slack_webhook_url,
                critical_channel=self.config.slack_critical_channel,
                general_channel=self.config.slack_general_channel,
            )
            logger.info("slack_alerter_initialized")

        if self.config.email_enabled:
            from .email_alerter import EmailAlerter
            self.email = EmailAlerter(
                provider=self.config.email_provider,
                smtp_host=self.config.email_smtp_host,
                smtp_port=self.config.email_smtp_port,
                smtp_user=self.config.email_smtp_user,
                smtp_password=self.config.email_smtp_password,
                smtp_use_tls=self.config.email_smtp_use_tls,
                sendgrid_api_key=self.config.email_sendgrid_api_key,
                from_email=self.config.email_from,
                to_emails=self.config.email_to,
            )
            logger.info("email_alerter_initialized")

        if self.config.pagerduty_enabled:
            from .pagerduty import PagerDutyAlerter
            self.pagerduty = PagerDutyAlerter(
                routing_key=self.config.pagerduty_routing_key,
                min_severity=self.config.pagerduty_min_severity,
            )
            logger.info("pagerduty_alerter_initialized")
    
    async def route(self, incident: Incident, explanation: Explanation):
        """
        Route an alert based on severity.
        """
        # Check rate limiting
        if not self._check_rate_limit():
            logger.warning("rate_limit_exceeded", incident_id=incident.id)
            return
        
        # Check dedup
        if not self._check_dedup(incident, explanation):
            logger.debug("alert_deduplicated", incident_id=incident.id)
            return
        
        # Record alert
        self._record_alert(incident)
        
        severity = incident.severity
        
        try:
            if severity == Severity.CRITICAL:
                await self._route_critical(incident, explanation)
            elif severity == Severity.HIGH:
                await self._route_high(incident, explanation)
            else:
                await self._route_normal(incident, explanation)
        
        except Exception as e:
            logger.error(
                "alert_routing_failed",
                incident_id=incident.id,
                error=str(e)
            )

        # Fire-and-forget WebSocket broadcast for the alert
        try:
            from ..api.ws_broadcast import broadcast_alert
            asyncio.create_task(broadcast_alert({
                "incident_id": incident.id,
                "severity": severity.name,
                "attack_type": str(incident.attack_type.value) if hasattr(incident.attack_type, 'value') else str(incident.attack_type),
                "title": explanation.title if explanation else "",
                "confidence": getattr(incident, 'confidence', 0.0),
            }))
        except Exception:
            pass  # WS unavailable; non-critical

    async def _route_critical(self, incident: Incident, explanation: Explanation):
        """
        Route critical alerts - all channels + pager.
        """
        logger.warning(
            "routing_critical_alert",
            incident_id=incident.id,
            title=explanation.title
        )

        tasks = []

        # PagerDuty
        if self.pagerduty:
            tasks.append(self.pagerduty.send_critical(incident, explanation))

        # Telegram
        if self.telegram:
            tasks.append(self.telegram.send_critical(incident, explanation))

        # Slack
        if self.slack:
            tasks.append(self.slack.send_critical(incident, explanation))

        # Email
        if self.email:
            tasks.append(self.email.send_critical(incident, explanation))

        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _route_high(self, incident: Incident, explanation: Explanation):
        """
        Route high severity alerts - Telegram + Slack + Email + PagerDuty.
        """
        logger.info(
            "routing_high_alert",
            incident_id=incident.id,
            title=explanation.title
        )

        tasks = []

        # PagerDuty (respects its own min_severity filter)
        if self.pagerduty:
            tasks.append(self.pagerduty.send_high(incident, explanation))

        if self.telegram:
            tasks.append(self.telegram.send_high(incident, explanation))

        if self.slack:
            tasks.append(self.slack.send_high(incident, explanation))

        if self.email:
            tasks.append(self.email.send_high(incident, explanation))

        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _route_normal(self, incident: Incident, explanation: Explanation):
        """
        Route normal alerts - Slack + Email.
        """
        logger.info(
            "routing_normal_alert",
            incident_id=incident.id,
            title=explanation.title
        )

        tasks = []

        if self.slack:
            tasks.append(self.slack.send_info(incident, explanation))

        if self.email:
            tasks.append(self.email.send_info(incident, explanation))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        
        # Prune old history
        self._alert_history = [
            t for t in self._alert_history if t > hour_ago
        ]
        
        return len(self._alert_history) < self.config.max_alerts_per_hour
    
    def _check_dedup(self, incident: Incident, explanation: Explanation) -> bool:
        """
        Check if this alert is a duplicate.
        """
        # Create hash of alert content
        alert_hash = f"{incident.id}:{incident.attack_type.value}:{incident.severity.name}"
        
        if alert_hash in self._alert_hashes:
            # Check if outside dedup window
            last_sent = self._sent_alerts.get(incident.id)
            if last_sent:
                elapsed = (datetime.now(timezone.utc) - last_sent).total_seconds() / 60
                if elapsed < self.config.dedup_window_minutes:
                    return False
        
        self._alert_hashes.add(alert_hash)
        return True
    
    def _record_alert(self, incident: Incident):
        """Record that an alert was sent."""
        now = datetime.now(timezone.utc)
        self._alert_history.append(now)
        self._sent_alerts[incident.id] = now
        
        # Limit dedup cache size
        if len(self._alert_hashes) > 1000:
            self._alert_hashes = set(list(self._alert_hashes)[-500:])
    
    def get_stats(self) -> dict:
        """Get alerting statistics."""
        return {
            "alerts_last_hour": len(self._alert_history),
            "max_per_hour": self.config.max_alerts_per_hour,
            "telegram_enabled": self.config.telegram_enabled,
            "slack_enabled": self.config.slack_enabled,
            "email_enabled": self.config.email_enabled,
            "pagerduty_enabled": self.config.pagerduty_enabled,
        }

