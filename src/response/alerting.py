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
    
    # PagerDuty config
    pagerduty_enabled: bool = False
    pagerduty_api_key: Optional[str] = None
    pagerduty_service_id: Optional[str] = None
    
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
            tasks.append(self._send_pagerduty(incident, explanation))
        
        # Telegram
        if self.telegram:
            tasks.append(self.telegram.send_critical(incident, explanation))
        
        # Slack
        if self.slack:
            tasks.append(self.slack.send_critical(incident, explanation))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _route_high(self, incident: Incident, explanation: Explanation):
        """
        Route high severity alerts - Telegram + Slack.
        """
        logger.info(
            "routing_high_alert",
            incident_id=incident.id,
            title=explanation.title
        )
        
        tasks = []
        
        if self.telegram:
            tasks.append(self.telegram.send_high(incident, explanation))
        
        if self.slack:
            tasks.append(self.slack.send_high(incident, explanation))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _route_normal(self, incident: Incident, explanation: Explanation):
        """
        Route normal alerts - Slack only.
        """
        logger.info(
            "routing_normal_alert",
            incident_id=incident.id,
            title=explanation.title
        )
        
        if self.slack:
            await self.slack.send_info(incident, explanation)
    
    async def _send_pagerduty(self, incident: Incident, explanation: Explanation):
        """Send PagerDuty alert via the centralized alert_notifier."""
        try:
            from ..notifications.alert_notifier import get_notifier
            notifier = get_notifier()
            if not notifier.config.pagerduty_routing_key:
                logger.debug("pagerduty_not_configured")
                return
            await notifier._send_pagerduty({
                "alert_id": incident.id,
                "risk_level": incident.severity.name,
                "chain_id": ",".join(incident.affected_chains) if hasattr(incident, 'affected_chains') else "unknown",
                "threat_category": incident.attack_type.value if hasattr(incident.attack_type, 'value') else str(incident.attack_type),
                "confidence": incident.confidence if hasattr(incident, 'confidence') else 0.0,
                "contract_address": "",
                "tx_hash": "",
            })
        except Exception as e:
            logger.error("pagerduty_alert_failed", incident_id=incident.id, error=str(e))
    
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
            "pagerduty_enabled": self.config.pagerduty_enabled,
        }

