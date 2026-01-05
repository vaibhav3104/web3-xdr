"""
Response Layer.

Handles alerting and automated response:
- Telegram / Slack / PagerDuty alerts
- Guardian system for auto-pause
- Runbook execution
- Safe response templates
- Human-in-the-loop verification
"""

from .alerting import AlertRouter, AlertConfig
from .telegram import TelegramAlerter
from .slack import SlackAlerter
from .guardian import (
    GuardianSystem,
    ProtocolConfig,
    ResponseAction,
    ResponseStatus,
    ResponseRecord,
    guardian,
    auto_respond_to_incident
)

__all__ = [
    "AlertRouter",
    "AlertConfig",
    "TelegramAlerter",
    "SlackAlerter",
    "GuardianSystem",
    "ProtocolConfig",
    "ResponseAction",
    "ResponseStatus",
    "ResponseRecord",
    "guardian",
    "auto_respond_to_incident",
]

