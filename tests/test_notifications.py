"""
Alert Notifier Unit Tests
==========================

Tests the AlertNotifier multi-channel notification service.
Covers Telegram, Slack, Email, PagerDuty channels, deduplication, and stats.
All HTTP calls are mocked via aiohttp session patching; SMTP is mocked via smtplib.
"""

# ---------------------------------------------------------------------------
# Block torch import so ML-heavy modules don't drag in GPU dependencies
# ---------------------------------------------------------------------------
import builtins

_real_import = builtins.__import__


def _patched_import(name, *args, **kwargs):
    if name == "torch" or name.startswith("torch."):
        raise ImportError(f"No module named '{name}' (mocked for test)")
    return _real_import(name, *args, **kwargs)


builtins.__import__ = _patched_import

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
import os
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock, call

import pytest
import aiohttp

from src.notifications.alert_notifier import (
    AlertNotifier,
    NotificationConfig,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ALERT = {
    "alert_id": "alert-001",
    "chain_id": "ethereum",
    "contract_address": "0xDeadBeef00000000000000000000000000000001",
    "deployer_address": "0xAttacker0000000000000000000000000000000A",
    "threat_category": "reentrancy_attack",
    "confidence": 0.92,
    "risk_level": "CRITICAL",
    "bytecode_size": 4096,
    "gas_used": 210000,
    "tx_hash": "0xaaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666",
    "block_number": 18_500_000,
    "timestamp": "2025-01-15T12:00:00Z",
}


def _make_config(**overrides) -> NotificationConfig:
    """Build a NotificationConfig with sensible test defaults."""
    defaults = {
        "telegram_bot_token": "test-bot-token",
        "telegram_chat_id": "-100123456789",
        "slack_webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
        "email_smtp_server": "smtp.example.com",
        "email_smtp_port": 587,
        "email_smtp_user": "alerts@example.com",
        "email_smtp_password": "s3cret",
        "email_from": "sentinel3@example.com",
        "email_to": ["ops@example.com"],
        "pagerduty_routing_key": "pd-routing-key-123",
    }
    defaults.update(overrides)
    return NotificationConfig(**defaults)


def _mock_response(status: int = 200, text: str = "ok"):
    """Build a mock aiohttp response object."""
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=text)
    return resp


@pytest.fixture
def notifier():
    """AlertNotifier with all channels configured."""
    return AlertNotifier(config=_make_config())


@pytest.fixture
def alert():
    """Copy of the sample alert dict."""
    return dict(SAMPLE_ALERT)


# ---------------------------------------------------------------------------
# 1. TestNotificationConfig
# ---------------------------------------------------------------------------


class TestNotificationConfig:
    """Test config creation including env-var defaults."""

    def test_explicit_config(self):
        cfg = _make_config()
        assert cfg.telegram_bot_token == "test-bot-token"
        assert cfg.slack_webhook_url.startswith("https://hooks.slack.com")
        assert cfg.email_smtp_port == 587
        assert cfg.pagerduty_routing_key == "pd-routing-key-123"

    def test_default_config_from_env(self):
        env = {
            "TELEGRAM_BOT_TOKEN": "env-bot-token",
            "TELEGRAM_CHAT_ID": "-999",
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/env",
            "SMTP_SERVER": "smtp.env.com",
            "SMTP_PORT": "465",
            "SMTP_USER": "user@env.com",
            "SMTP_PASSWORD": "pw",
            "ALERT_EMAIL_FROM": "from@env.com",
            "ALERT_EMAIL_TO": "a@b.com, c@d.com",
            "PAGERDUTY_ROUTING_KEY": "env-pd-key",
        }
        with patch.dict(os.environ, env, clear=False):
            notifier = AlertNotifier(config=None)

        assert notifier.config.telegram_bot_token == "env-bot-token"
        assert notifier.config.telegram_chat_id == "-999"
        assert notifier.config.email_smtp_port == 465
        assert notifier.config.email_to == ["a@b.com", "c@d.com"]
        assert notifier.config.pagerduty_routing_key == "env-pd-key"


# ---------------------------------------------------------------------------
# 2. TestMessageFormatting
# ---------------------------------------------------------------------------


class TestMessageFormatting:
    """Test _format_contract_threat_message output."""

    def test_format_contains_key_fields(self, notifier, alert):
        msg = notifier._format_contract_threat_message(alert)
        assert "MALICIOUS CONTRACT DETECTED" in msg
        assert alert["contract_address"] in msg
        assert "Reentrancy Attack" in msg  # title-cased, underscores replaced
        assert "92.0%" in msg  # confidence formatted as percent
        assert "CRITICAL" in msg
        assert "4,096" in msg  # bytecode_size with comma
        assert "18,500,000" in msg  # block_number
        assert alert["alert_id"] in msg

    def test_format_unknown_risk_level(self, notifier):
        alert = {"risk_level": "UNKNOWN_LEVEL"}
        msg = notifier._format_contract_threat_message(alert)
        # Should not crash; uses default emoji
        assert "MALICIOUS CONTRACT DETECTED" in msg


# ---------------------------------------------------------------------------
# 3. TestTelegramChannel
# ---------------------------------------------------------------------------


class TestTelegramChannel:
    """Test _send_telegram success and failure paths."""

    @pytest.mark.asyncio
    async def test_telegram_success(self, notifier, alert):
        mock_resp = _mock_response(200)
        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            await notifier._send_telegram("test message", alert)

        assert notifier.stats["telegram_sent"] == 1
        assert notifier.stats["failed"] == 0

        # Verify URL contains bot token
        posted_url = mock_session.post.call_args[0][0]
        assert "test-bot-token" in posted_url
        assert "/sendMessage" in posted_url

        # Verify payload
        payload = mock_session.post.call_args[1]["json"]
        assert payload["chat_id"] == "-100123456789"
        assert payload["parse_mode"] == "Markdown"

    @pytest.mark.asyncio
    async def test_telegram_failure_increments_failed(self, notifier, alert):
        mock_resp = _mock_response(status=403, text="Forbidden")
        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            await notifier._send_telegram("test message", alert)

        assert notifier.stats["telegram_sent"] == 0
        assert notifier.stats["failed"] == 1


# ---------------------------------------------------------------------------
# 4. TestSlackChannel
# ---------------------------------------------------------------------------


class TestSlackChannel:
    """Test _send_slack success and failure paths."""

    @pytest.mark.asyncio
    async def test_slack_success(self, notifier, alert):
        mock_resp = _mock_response(200)
        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            await notifier._send_slack("test message", alert)

        assert notifier.stats["slack_sent"] == 1

        # Verify webhook URL used
        posted_url = mock_session.post.call_args[0][0]
        assert posted_url == notifier.config.slack_webhook_url

        # Verify payload structure
        payload = mock_session.post.call_args[1]["json"]
        assert "attachments" in payload
        attachment = payload["attachments"][0]
        assert attachment["color"] == "#ff0000"  # CRITICAL -> red
        assert any(f["value"] == "CRITICAL" for f in attachment["fields"])

    @pytest.mark.asyncio
    async def test_slack_failure_increments_failed(self, notifier, alert):
        mock_resp = _mock_response(status=500, text="Internal Server Error")
        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            await notifier._send_slack("test message", alert)

        assert notifier.stats["slack_sent"] == 0
        assert notifier.stats["failed"] == 1


# ---------------------------------------------------------------------------
# 5. TestEmailChannel
# ---------------------------------------------------------------------------


class TestEmailChannel:
    """Test _send_email with mocked smtplib."""

    @pytest.mark.asyncio
    async def test_email_success(self, notifier, alert):
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch("smtplib.SMTP", return_value=mock_smtp_instance):
            await notifier._send_email("test message", alert)

        assert notifier.stats["email_sent"] == 1
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once_with(
            "alerts@example.com", "s3cret"
        )
        mock_smtp_instance.send_message.assert_called_once()

        # Verify message subject contains risk level and chain
        sent_msg = mock_smtp_instance.send_message.call_args[0][0]
        assert "CRITICAL" in sent_msg["Subject"]
        assert "ethereum" in sent_msg["Subject"]
        assert sent_msg["From"] == "sentinel3@example.com"
        assert "ops@example.com" in sent_msg["To"]

    @pytest.mark.asyncio
    async def test_email_failure_increments_failed(self, notifier, alert):
        with patch("smtplib.SMTP", side_effect=ConnectionRefusedError("refused")):
            await notifier._send_email("test message", alert)

        assert notifier.stats["email_sent"] == 0
        assert notifier.stats["failed"] == 1


# ---------------------------------------------------------------------------
# 6. TestPagerDutyChannel
# ---------------------------------------------------------------------------


class TestPagerDutyChannel:
    """Test _send_pagerduty triggers only for CRITICAL/HIGH."""

    @pytest.mark.asyncio
    async def test_pagerduty_critical_alert(self, notifier, alert):
        """CRITICAL alert should be sent and accepted (202)."""
        mock_resp = _mock_response(status=202, text='{"status":"success"}')
        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            await notifier._send_pagerduty(alert)

        assert notifier.stats["webhook_sent"] == 1

        # Verify PagerDuty URL
        posted_url = mock_session.post.call_args[0][0]
        assert "events.pagerduty.com/v2/enqueue" in posted_url

        # Verify payload structure
        payload = mock_session.post.call_args[1]["json"]
        assert payload["routing_key"] == "pd-routing-key-123"
        assert payload["event_action"] == "trigger"
        assert payload["dedup_key"] == "alert-001"
        assert payload["payload"]["severity"] == "critical"
        assert payload["payload"]["source"] == "sentinel3"

    @pytest.mark.asyncio
    async def test_pagerduty_not_triggered_for_low(self, notifier):
        """send_contract_threat_alert should NOT dispatch PagerDuty for LOW risk."""
        low_alert = dict(SAMPLE_ALERT, alert_id="alert-low", risk_level="LOW")
        mock_resp = _mock_response(200)

        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            await notifier.send_contract_threat_alert(low_alert)

        # PagerDuty uses webhook_sent counter; it must stay 0 for LOW
        assert notifier.stats["webhook_sent"] == 0


# ---------------------------------------------------------------------------
# 7. TestAlertDeduplication
# ---------------------------------------------------------------------------


class TestAlertDeduplication:
    """Test that duplicate alert_id is skipped."""

    @pytest.mark.asyncio
    async def test_duplicate_alert_id_skipped(self, notifier, alert):
        mock_resp = _mock_response(200)
        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            await notifier.send_contract_threat_alert(alert)
            first_telegram = notifier.stats["telegram_sent"]

            # Send the exact same alert again
            await notifier.send_contract_threat_alert(alert)
            second_telegram = notifier.stats["telegram_sent"]

        # Counts should be unchanged on the second call
        assert first_telegram == second_telegram
        assert alert["alert_id"] in notifier.sent_alerts


# ---------------------------------------------------------------------------
# 8. TestMultiChannelDispatch
# ---------------------------------------------------------------------------


class TestMultiChannelDispatch:
    """Test send_contract_threat_alert dispatches to all configured channels."""

    @pytest.mark.asyncio
    async def test_all_channels_dispatched(self):
        """CRITICAL alert should hit Telegram, Slack, Email, and PagerDuty."""
        config = _make_config()
        n = AlertNotifier(config=config)

        mock_resp = _mock_response(200)
        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)

        alert = dict(SAMPLE_ALERT)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("smtplib.SMTP", return_value=mock_smtp):
            await n.send_contract_threat_alert(alert)

        # All four channels should have fired
        assert n.stats["telegram_sent"] == 1
        assert n.stats["slack_sent"] == 1
        assert n.stats["email_sent"] == 1
        assert n.stats["webhook_sent"] == 1  # PagerDuty for CRITICAL

    @pytest.mark.asyncio
    async def test_no_channels_configured(self):
        """No channels configured means no tasks dispatched, no errors."""
        config = NotificationConfig()  # all None
        n = AlertNotifier(config=config)

        alert = dict(SAMPLE_ALERT, alert_id="alert-empty")
        await n.send_contract_threat_alert(alert)

        assert n.stats["telegram_sent"] == 0
        assert n.stats["slack_sent"] == 0
        assert n.stats["email_sent"] == 0
        assert n.stats["webhook_sent"] == 0
        assert n.stats["failed"] == 0


# ---------------------------------------------------------------------------
# 9. TestStats
# ---------------------------------------------------------------------------


class TestStats:
    """Test get_stats reflects send counts and configured channels."""

    def test_initial_stats(self, notifier):
        stats = notifier.get_stats()
        assert stats["telegram_sent"] == 0
        assert stats["slack_sent"] == 0
        assert stats["email_sent"] == 0
        assert stats["webhook_sent"] == 0
        assert stats["failed"] == 0
        assert stats["channels_configured"]["telegram"] is True
        assert stats["channels_configured"]["slack"] is True

    @pytest.mark.asyncio
    async def test_stats_after_sends(self):
        config = _make_config()
        n = AlertNotifier(config=config)

        mock_resp = _mock_response(200)
        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("smtplib.SMTP", return_value=mock_smtp):
            await n.send_contract_threat_alert(dict(SAMPLE_ALERT))

        stats = n.get_stats()
        total_sent = (
            stats["telegram_sent"]
            + stats["slack_sent"]
            + stats["email_sent"]
            + stats["webhook_sent"]
        )
        assert total_sent == 4  # All channels fired for CRITICAL
        assert stats["failed"] == 0

    def test_stats_unconfigured_channels(self):
        config = NotificationConfig()  # all None
        n = AlertNotifier(config=config)
        stats = n.get_stats()
        assert stats["channels_configured"]["telegram"] is False
        assert stats["channels_configured"]["slack"] is False
