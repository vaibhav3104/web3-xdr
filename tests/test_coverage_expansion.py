"""
Coverage Expansion Tests for Sentinel3 XDR
==========================================

Unit tests for previously untested modules:
  - src/response/alerting.py      (AlertRouter)
  - src/response/email_alerter.py (EmailAlerter)
  - src/response/pagerduty.py     (PagerDutyAlerter)
  - src/ml/anomaly_detector.py    (Statistical, IsolationForest, Temporal, Engine)
  - src/api/export_routes.py      (CSV/PDF export)
  - src/api/threat_intel_routes.py (Threat intel feed)
  - src/rules/feedback_loop.py    (TP/FP feedback recording)
  - src/invariants/dsl.py         (DSL parsing and evaluation)
  - src/api/anomaly_routes.py     (Anomaly API endpoints)
  - src/logging_config.py         (Structured logging setup)

All external services (SMTP, HTTP, DB) are mocked.
"""

import io
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.models.events import EventType, SecurityEvent, Severity
from src.models.incidents import AttackType, Incident, IncidentStatus
from src.explainability.explanation import Explanation, RecommendedAction


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_incident(
    severity=Severity.CRITICAL,
    attack_type=AttackType.UNBACKED_MINT,
    loss=100_000,
    chains=None,
    incident_id=None,
):
    return Incident(
        id=incident_id or str(uuid.uuid4()),
        severity=severity,
        attack_type=attack_type,
        total_loss_usd=loss,
        tvl_at_risk_usd=loss * 5,
        affected_chains=chains or ["ethereum"],
        confidence=0.92,
    )


def _make_explanation(incident_id="inc-1", title="Unbacked Mint Detected"):
    return Explanation(
        incident_id=incident_id,
        title=title,
        severity=Severity.CRITICAL,
        confidence=0.92,
        what_happened="Tokens minted without lock.",
        why_dangerous="Drains bridge reserves.",
        blast_radius="$500K at risk.",
        recommended_actions=[
            RecommendedAction(priority=1, action="Pause bridge", reason="Stop loss", is_urgent=True),
            RecommendedAction(priority=2, action="Notify team", reason="Awareness", is_urgent=False),
        ],
    )


def _make_event(chain_id="ethereum", amount_usd=1000, event_type=EventType.TRANSFER):
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        chain_id=chain_id,
        block_number=100,
        block_timestamp=datetime.now(timezone.utc),
        tx_hash="0xdeadbeef",
        event_type=event_type,
        source_address="0xaaa",
        dest_address="0xbbb",
        amount=Decimal(str(amount_usd)),
        amount_usd=Decimal(str(amount_usd)),
    )


# ---------------------------------------------------------------------------
# App / client fixture for API tests — mirrors test_api_routes.py
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def app():
    import builtins
    _real_import = builtins.__import__

    def _patched_import(name, *args, **kwargs):
        if name == "torch" or name.startswith("torch."):
            raise ImportError(f"No module named '{name}' (mocked for test)")
        return _real_import(name, *args, **kwargs)

    with patch("src.database.connection.DatabaseManager.initialize", new_callable=AsyncMock), \
         patch("src.database.connection.DatabaseManager.ensure_indexes", new_callable=AsyncMock), \
         patch("builtins.__import__", side_effect=_patched_import):
        from src.api.server import create_app
        _app = create_app()
    return _app


@pytest.fixture(scope="module")
def client(app):
    return TestClient(app, raise_server_exceptions=False)


# ===========================================================================
# 1. AlertRouter Tests
# ===========================================================================

class TestAlertRouter:
    """Tests for src.response.alerting.AlertRouter."""

    def _make_router(self, **overrides):
        from src.response.alerting import AlertConfig, AlertRouter
        config = AlertConfig(**overrides)
        return AlertRouter(config)

    @pytest.mark.asyncio
    async def test_route_critical_invokes_all_channels(self):
        """Critical incidents route to PagerDuty, Telegram, Slack, Email."""
        router = self._make_router()
        router.pagerduty = AsyncMock()
        router.telegram = AsyncMock()
        router.slack = AsyncMock()
        router.email = AsyncMock()

        incident = _make_incident(severity=Severity.CRITICAL)
        explanation = _make_explanation(incident.id)

        with patch("src.response.alerting.asyncio.create_task"):
            await router.route(incident, explanation)

        router.pagerduty.send_critical.assert_awaited_once()
        router.telegram.send_critical.assert_awaited_once()
        router.slack.send_critical.assert_awaited_once()
        router.email.send_critical.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_route_high_invokes_channels(self):
        """HIGH incidents route to PagerDuty, Telegram, Slack, Email."""
        router = self._make_router()
        router.pagerduty = AsyncMock()
        router.telegram = AsyncMock()
        router.slack = AsyncMock()
        router.email = AsyncMock()

        incident = _make_incident(severity=Severity.HIGH)
        explanation = _make_explanation(incident.id)

        with patch("src.response.alerting.asyncio.create_task"):
            await router.route(incident, explanation)

        router.pagerduty.send_high.assert_awaited_once()
        router.telegram.send_high.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_route_normal_goes_to_slack_email_only(self):
        """MEDIUM/LOW/INFO incidents only route to Slack and Email."""
        router = self._make_router()
        router.pagerduty = AsyncMock()
        router.telegram = AsyncMock()
        router.slack = AsyncMock()
        router.email = AsyncMock()

        incident = _make_incident(severity=Severity.MEDIUM)
        explanation = _make_explanation(incident.id)

        with patch("src.response.alerting.asyncio.create_task"):
            await router.route(incident, explanation)

        router.pagerduty.send_critical.assert_not_awaited()
        router.telegram.send_critical.assert_not_awaited()
        router.slack.send_info.assert_awaited_once()
        router.email.send_info.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rate_limiting_blocks_excess_alerts(self):
        """Alerts beyond max_alerts_per_hour are suppressed."""
        router = self._make_router(max_alerts_per_hour=2)
        router.slack = AsyncMock()

        for i in range(5):
            incident = _make_incident(severity=Severity.LOW, incident_id=f"inc-rl-{i}")
            explanation = _make_explanation(incident.id)
            with patch("src.response.alerting.asyncio.create_task"):
                await router.route(incident, explanation)

        # Only 2 should have gone through
        assert router.slack.send_info.await_count == 2

    @pytest.mark.asyncio
    async def test_dedup_blocks_duplicate_alerts(self):
        """Same incident+attack_type+severity within dedup window is suppressed."""
        router = self._make_router(dedup_window_minutes=60)
        router.slack = AsyncMock()

        incident = _make_incident(severity=Severity.MEDIUM, incident_id="dedup-test")
        explanation = _make_explanation(incident.id)

        with patch("src.response.alerting.asyncio.create_task"):
            await router.route(incident, explanation)
            await router.route(incident, explanation)

        # Second call should be deduplicated
        assert router.slack.send_info.await_count == 1

    def test_get_stats(self):
        """get_stats returns expected keys."""
        router = self._make_router(telegram_enabled=True, email_enabled=True)
        stats = router.get_stats()
        assert stats["telegram_enabled"] is True
        assert stats["email_enabled"] is True
        assert "alerts_last_hour" in stats

    @pytest.mark.asyncio
    async def test_route_records_alert_history(self):
        """Each routed alert is added to _alert_history."""
        router = self._make_router()
        router.slack = AsyncMock()

        incident = _make_incident(severity=Severity.LOW)
        explanation = _make_explanation(incident.id)
        with patch("src.response.alerting.asyncio.create_task"):
            await router.route(incident, explanation)

        assert len(router._alert_history) == 1
        assert incident.id in router._sent_alerts


# ===========================================================================
# 2. EmailAlerter Tests
# ===========================================================================

class TestEmailAlerter:
    """Tests for src.response.email_alerter.EmailAlerter."""

    def _make_alerter(self, **kwargs):
        from src.response.email_alerter import EmailAlerter
        defaults = dict(
            provider="smtp",
            smtp_host="smtp.test.local",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass",
            from_email="test@alert.local",
            to_emails=["ops@example.com"],
        )
        defaults.update(kwargs)
        return EmailAlerter(**defaults)

    def test_build_html_contains_severity_and_title(self):
        """_build_html produces HTML with severity badge and explanation title."""
        alerter = self._make_alerter()
        incident = _make_incident()
        explanation = _make_explanation(incident.id)
        html = alerter._build_html(incident, explanation, "CRITICAL")
        assert "CRITICAL" in html
        assert explanation.title in html
        assert incident.id in html

    def test_build_html_includes_urgent_actions(self):
        """Urgent recommended actions appear in the email body."""
        alerter = self._make_alerter()
        incident = _make_incident()
        explanation = _make_explanation(incident.id)
        html = alerter._build_html(incident, explanation, "HIGH")
        assert "Pause bridge" in html

    @pytest.mark.asyncio
    async def test_send_smtp(self):
        """_send_smtp calls aiosmtplib.send with correct parameters."""
        alerter = self._make_alerter()
        with patch("src.response.email_alerter.aiosmtplib", create=True) as mock_smtp_mod:
            mock_smtp_mod.send = AsyncMock()
            # Patch the import inside the method
            import sys
            sys.modules["aiosmtplib"] = mock_smtp_mod
            try:
                await alerter._send_smtp("Test Subject", "<html>body</html>")
                mock_smtp_mod.send.assert_awaited_once()
                call_kwargs = mock_smtp_mod.send.call_args
                assert call_kwargs.kwargs["hostname"] == "smtp.test.local"
            finally:
                del sys.modules["aiosmtplib"]

    @pytest.mark.asyncio
    async def test_send_skips_when_no_recipients(self):
        """_send does nothing when to_emails is empty."""
        alerter = self._make_alerter(to_emails=[])
        # Should not raise
        await alerter._send("Subject", "<html></html>")

    @pytest.mark.asyncio
    async def test_send_critical(self):
        """send_critical builds subject with CRITICAL prefix and sends."""
        alerter = self._make_alerter()
        alerter._send = AsyncMock()
        incident = _make_incident()
        explanation = _make_explanation(incident.id)
        await alerter.send_critical(incident, explanation)
        alerter._send.assert_awaited_once()
        subject = alerter._send.call_args[0][0]
        assert "[Sentinel3 CRITICAL]" in subject

    @pytest.mark.asyncio
    async def test_send_high(self):
        """send_high builds subject with HIGH prefix."""
        alerter = self._make_alerter()
        alerter._send = AsyncMock()
        incident = _make_incident(severity=Severity.HIGH)
        explanation = _make_explanation(incident.id)
        await alerter.send_high(incident, explanation)
        subject = alerter._send.call_args[0][0]
        assert "[Sentinel3 HIGH]" in subject


# ===========================================================================
# 3. PagerDutyAlerter Tests
# ===========================================================================

class TestPagerDutyAlerter:
    """Tests for src.response.pagerduty.PagerDutyAlerter."""

    def _make_alerter(self, routing_key="test-key", min_severity="high"):
        from src.response.pagerduty import PagerDutyAlerter
        return PagerDutyAlerter(routing_key=routing_key, min_severity=min_severity)

    @pytest.mark.asyncio
    async def test_send_event_triggers_for_critical(self):
        """Critical incidents trigger a PagerDuty event."""
        alerter = self._make_alerter()
        incident = _make_incident(severity=Severity.CRITICAL)
        explanation = _make_explanation(incident.id)

        mock_resp = MagicMock(status_code=202, text="ok")
        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post = AsyncMock(return_value=mock_resp)
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = instance

            await alerter.send_critical(incident, explanation)
            instance.post.assert_awaited_once()
            payload = instance.post.call_args.kwargs["json"]
            assert payload["event_action"] == "trigger"
            assert "sentinel3" in payload["dedup_key"]

    @pytest.mark.asyncio
    async def test_send_event_skipped_below_threshold(self):
        """LOW severity incident is skipped when min_severity=high."""
        alerter = self._make_alerter(min_severity="high")
        incident = _make_incident(severity=Severity.LOW)
        explanation = _make_explanation(incident.id)

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = instance

            await alerter.send_info(incident, explanation)
            instance.post.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_event_skipped_no_routing_key(self):
        """No routing key configured means no HTTP call."""
        alerter = self._make_alerter(routing_key="")
        incident = _make_incident(severity=Severity.CRITICAL)
        explanation = _make_explanation(incident.id)

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = instance

            await alerter.send_critical(incident, explanation)
            instance.post.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_resolve_sends_resolve_event(self):
        """resolve() sends event_action=resolve to PagerDuty."""
        alerter = self._make_alerter()
        mock_resp = MagicMock(status_code=202)
        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post = AsyncMock(return_value=mock_resp)
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = instance

            await alerter.resolve("inc-123")
            payload = instance.post.call_args.kwargs["json"]
            assert payload["event_action"] == "resolve"
            assert payload["dedup_key"] == "sentinel3-inc-123"

    def test_severity_order_mapping(self):
        """SEVERITY_ORDER has correct ordinal values."""
        from src.response.pagerduty import PagerDutyAlerter
        assert PagerDutyAlerter.SEVERITY_ORDER["critical"] > PagerDutyAlerter.SEVERITY_ORDER["high"]
        assert PagerDutyAlerter.SEVERITY_ORDER["high"] > PagerDutyAlerter.SEVERITY_ORDER["medium"]


# ===========================================================================
# 4. Anomaly Detector Tests
# ===========================================================================

class TestStatisticalAnomalyDetector:
    """Tests for StatisticalAnomalyDetector."""

    def test_normal_data_not_anomalous(self):
        from src.ml.anomaly_detector import StatisticalAnomalyDetector
        detector = StatisticalAnomalyDetector(window_size=100, z_threshold=3.0)
        # Feed 50 normal samples with tight range
        for i in range(50):
            is_anom, score, exp = detector.detect({"amount": 100.0 + i * 0.1}, "eth")
        # Last value should be normal (np.bool_ is truthy/falsy but not 'is')
        assert not is_anom

    def test_extreme_value_detected(self):
        from src.ml.anomaly_detector import StatisticalAnomalyDetector
        detector = StatisticalAnomalyDetector(window_size=100, z_threshold=3.0)
        # Feed varied baseline so std > 0 (identical values yield std=0, skipped)
        import random
        random.seed(42)
        for _ in range(30):
            detector.detect({"amount": 100.0 + random.gauss(0, 5)}, "eth")
        # Inject extreme outlier
        is_anom, score, exp = detector.detect({"amount": 100000.0}, "eth")
        assert is_anom  # np.bool_ — use truthiness, not 'is True'
        assert score > 3.0
        assert "Statistical anomaly" in exp

    def test_insufficient_data_not_anomalous(self):
        from src.ml.anomaly_detector import StatisticalAnomalyDetector
        detector = StatisticalAnomalyDetector(window_size=100, z_threshold=3.0)
        # Less than 10 samples
        for _ in range(5):
            is_anom, score, exp = detector.detect({"amount": 100.0}, "eth")
        assert is_anom is False


class TestIsolationForestDetector:
    """Tests for IsolationForestDetector."""

    def test_untrained_returns_not_anomalous(self):
        from src.ml.anomaly_detector import IsolationForestDetector
        detector = IsolationForestDetector()
        is_anom, score, exp = detector.detect({"amount": 100.0})
        assert is_anom is False
        assert "not yet trained" in exp.lower()

    def test_add_sample_fills_buffer(self):
        from src.ml.anomaly_detector import IsolationForestDetector
        detector = IsolationForestDetector()
        detector.min_training_samples = 1000  # high threshold so no auto-train
        for i in range(10):
            detector.add_sample({"amount": float(i)})
        assert len(detector._training_buffer) == 10

    def test_train_with_insufficient_samples(self):
        from src.ml.anomaly_detector import IsolationForestDetector
        detector = IsolationForestDetector()
        detector.min_training_samples = 500
        for i in range(10):
            detector.add_sample({"amount": float(i)})
        detector.train()
        assert detector.is_trained is False


class TestTemporalAnomalyDetector:
    """Tests for TemporalAnomalyDetector."""

    def test_insufficient_history(self):
        from src.ml.anomaly_detector import TemporalAnomalyDetector
        detector = TemporalAnomalyDetector()
        ts = datetime.now(timezone.utc)
        is_anom, score, exp = detector.detect("ethereum", "transfer", ts)
        assert is_anom is False
        assert "Insufficient" in exp

    def test_normal_temporal_pattern(self):
        from src.ml.anomaly_detector import TemporalAnomalyDetector
        detector = TemporalAnomalyDetector()
        ts = datetime.now(timezone.utc)
        # Feed 30 history entries to exceed minimum of 24
        for i in range(30):
            detector.detect("ethereum", "transfer", ts)
        is_anom, score, exp = detector.detect("ethereum", "transfer", ts)
        assert not is_anom  # np.bool_ — check truthiness, not isinstance(bool)


class TestAnomalyDetectionEngine:
    """Tests for AnomalyDetectionEngine orchestrator."""

    @pytest.mark.asyncio
    async def test_analyze_normal_event_returns_none(self):
        from src.ml.anomaly_detector import AnomalyDetectionEngine
        engine = AnomalyDetectionEngine({"enabled": True})
        event_data = {
            "event_id": "evt-1",
            "chain_id": "ethereum",
            "event_type": "TRANSFER",
            "amount_usd": 100,
            "block_number": 100,
            "block_timestamp": datetime.now(timezone.utc),
        }
        result = await engine.analyze_event(event_data)
        # With sparse data, no anomaly expected
        assert result is None

    @pytest.mark.asyncio
    async def test_analyze_event_disabled_returns_none(self):
        from src.ml.anomaly_detector import AnomalyDetectionEngine
        engine = AnomalyDetectionEngine({"enabled": False})
        result = await engine.analyze_event({"event_id": "x"})
        assert result is None

    def test_extract_features_includes_expected_keys(self):
        from src.ml.anomaly_detector import AnomalyDetectionEngine
        engine = AnomalyDetectionEngine()
        features = engine.extract_features({
            "amount_usd": 5000,
            "block_number": 18000000,
            "event_type": "TRANSFER",
            "severity": "HIGH",
            "source_address": "0xaaa",
            "dest_address": "0xbbb",
        })
        assert "amount_usd" in features
        assert "log_amount" in features
        assert "event_type_code" in features
        assert features["event_type_code"] == 1.0
        assert features["severity_code"] == 3.0
        assert features["has_from"] == 1.0
        assert features["same_sender_receiver"] == 0.0

    def test_extract_features_same_sender_receiver(self):
        from src.ml.anomaly_detector import AnomalyDetectionEngine
        engine = AnomalyDetectionEngine()
        features = engine.extract_features({
            "source_address": "0xaaa",
            "dest_address": "0xaaa",
        })
        assert features["same_sender_receiver"] == 1.0

    def test_get_stats(self):
        from src.ml.anomaly_detector import AnomalyDetectionEngine
        engine = AnomalyDetectionEngine()
        stats = engine.get_stats()
        assert "total_anomalies" in stats
        assert "isolation_forest_trained" in stats
        assert "enabled" in stats

    def test_get_recent_anomalies_empty(self):
        from src.ml.anomaly_detector import AnomalyDetectionEngine
        engine = AnomalyDetectionEngine()
        anomalies = engine.get_recent_anomalies()
        assert anomalies == []


# ===========================================================================
# 5. Export Routes Tests
# ===========================================================================

class TestExportRoutes:
    """Tests for src.api.export_routes."""

    @patch("src.api.export_routes._get_incidents", new_callable=AsyncMock, return_value=[])
    def test_csv_export_empty(self, mock_get, client):
        """CSV export with no incidents returns header-only CSV."""
        resp = client.get("/api/export/incidents/csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")
        content = resp.text
        assert "Incident ID" in content

    @patch("src.api.export_routes._get_incidents", new_callable=AsyncMock)
    def test_csv_export_with_data(self, mock_get, client):
        """CSV export with data includes incident rows."""
        mock_get.return_value = [
            {
                "incident_id": "inc-001",
                "title": "Test Incident",
                "severity": "HIGH",
                "status": "open",
                "attack_type": "unbacked_mint",
                "confidence": 0.9,
                "total_loss_usd": 50000,
                "affected_chains": ["ethereum"],
                "event_count": 3,
            }
        ]
        resp = client.get("/api/export/incidents/csv")
        assert resp.status_code == 200
        assert "inc-001" in resp.text
        assert "Test Incident" in resp.text

    @patch("src.api.export_routes._get_incidents", new_callable=AsyncMock, return_value=[])
    def test_pdf_export_returns_pdf(self, mock_get, client):
        """PDF export returns application/pdf content."""
        resp = client.get("/api/export/incidents/pdf")
        assert resp.status_code == 200
        assert "application/pdf" in resp.headers.get("content-type", "")
        # PDF starts with %PDF
        assert resp.content[:5] == b"%PDF-"


# ===========================================================================
# 6. Threat Intel Routes Tests
# ===========================================================================

class TestThreatIntelRoutes:
    """Tests for src.api.threat_intel_routes."""

    def test_get_feed(self, client):
        """GET /api/threat-intel/feed returns seeded data."""
        resp = client.get("/api/threat-intel/feed")
        assert resp.status_code == 200
        data = resp.json()
        assert "feed_version" in data
        assert data["total_items"] > 0
        assert "items" in data

    def test_get_feed_severity_filter(self, client):
        """Severity filter narrows results."""
        resp = client.get("/api/threat-intel/feed?severity=critical")
        assert resp.status_code == 200
        data = resp.json()
        for item in data["items"]:
            assert item.get("severity") == "critical"

    def test_get_feed_chain_filter(self, client):
        """Chain filter returns only matching items."""
        resp = client.get("/api/threat-intel/feed?chain=ethereum")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_items"] > 0

    def test_get_malicious_addresses(self, client):
        """GET /api/threat-intel/addresses returns known bad addresses."""
        resp = client.get("/api/threat-intel/addresses")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] > 0
        assert any("Ronin" in a.get("label", "") for a in data["addresses"])

    def test_get_attack_signatures(self, client):
        """GET /api/threat-intel/signatures returns seeded signatures."""
        resp = client.get("/api/threat-intel/signatures")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] > 0

    def test_get_signatures_by_type(self, client):
        """Filter signatures by attack_type."""
        resp = client.get("/api/threat-intel/signatures?attack_type=UNBACKED_MINT")
        assert resp.status_code == 200
        data = resp.json()
        for sig in data["signatures"]:
            assert sig["attack_type"] == "UNBACKED_MINT"

    def test_check_known_address(self, client):
        """Check a known malicious address returns found=True."""
        resp = client.get("/api/threat-intel/check/0x098B716B8Aaf21512996dC57EB0615e2383E2f96")
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is True
        assert "Ronin" in data["threat"]["label"]

    def test_check_unknown_address(self, client):
        """Check an unknown address returns found=False."""
        with patch("src.database.service.DatabaseService.query_events_by_address",
                   new_callable=AsyncMock, return_value=[]):
            resp = client.get("/api/threat-intel/check/0x0000000000000000000000000000000000000000")
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is False

    def test_report_threat(self, client):
        """POST /api/threat-intel/report accepts a new IOC."""
        payload = {
            "type": "address",
            "value": "0xbadbeefbadbeefbadbeefbadbeefbadbeef",
            "chain_id": "ethereum",
            "severity": "high",
            "description": "Test malicious address",
            "confidence": 0.95,
        }
        resp = client.post("/api/threat-intel/report", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "accepted"
        assert "ioc_id" in data


# ===========================================================================
# 7. Feedback Loop Tests
# ===========================================================================

class TestFeedbackLoop:
    """Tests for src.rules.feedback_loop.FeedbackLoop."""

    def _make_loop(self):
        from src.rules.feedback_loop import FeedbackLoop
        return FeedbackLoop()

    def test_record_tp(self):
        """Recording a TP increments tp_count."""
        loop = self._make_loop()
        loop.record_feedback("rule-1", is_tp=True)
        stats = loop.get_rule_stats("rule-1")
        assert stats["tp_count"] == 1
        assert stats["fp_count"] == 0

    def test_record_fp(self):
        """Recording an FP increments fp_count."""
        loop = self._make_loop()
        loop.record_feedback("rule-1", is_tp=False)
        stats = loop.get_rule_stats("rule-1")
        assert stats["fp_count"] == 1
        assert stats["tp_count"] == 0

    def test_fp_rate_calculation(self):
        """FP rate is correctly computed."""
        loop = self._make_loop()
        for _ in range(8):
            loop.record_feedback("rule-1", is_tp=False)
        for _ in range(2):
            loop.record_feedback("rule-1", is_tp=True)
        stats = loop.get_rule_stats("rule-1")
        assert abs(stats["fp_rate"] - 0.8) < 0.01

    def test_evaluate_rules_suppresses_high_fp(self):
        """Rule with FP rate above threshold gets suppressed."""
        loop = self._make_loop()
        loop._fp_threshold = 0.7
        loop._min_samples = 5
        for _ in range(9):
            loop.record_feedback("noisy-rule", is_tp=False)
        loop.record_feedback("noisy-rule", is_tp=True)

        actions = loop.evaluate_rules()
        action_map = {a[0]: a[1] for a in actions}
        assert action_map.get("noisy-rule") in ("suppressed", "auto_disabled")

    def test_is_suppressed_returns_true_after_suppression(self):
        """A suppressed rule is reported as suppressed."""
        loop = self._make_loop()
        loop._fp_threshold = 0.5
        loop._min_samples = 2
        loop.record_feedback("rule-x", is_tp=False)
        loop.record_feedback("rule-x", is_tp=False)
        loop.record_feedback("rule-x", is_tp=True)
        loop.evaluate_rules()
        assert loop.is_suppressed("rule-x") is True

    def test_is_suppressed_returns_false_for_unknown_rule(self):
        """Unknown rule is not suppressed."""
        loop = self._make_loop()
        assert loop.is_suppressed("nonexistent-rule") is False

    def test_record_bulk_feedback(self):
        """record_bulk_feedback processes multiple entries."""
        loop = self._make_loop()
        loop.record_bulk_feedback([
            ("rule-a", True),
            ("rule-a", False),
            ("rule-b", True),
        ])
        assert loop.get_rule_stats("rule-a")["total"] == 2
        assert loop.get_rule_stats("rule-b")["total"] == 1

    def test_get_all_stats_sorted_by_fp_rate(self):
        """get_all_stats returns rules sorted by FP rate descending."""
        loop = self._make_loop()
        # rule-bad: 100% FP
        for _ in range(5):
            loop.record_feedback("rule-bad", is_tp=False)
        # rule-good: 0% FP
        for _ in range(5):
            loop.record_feedback("rule-good", is_tp=True)

        all_stats = loop.get_all_stats()
        assert len(all_stats) == 2
        assert all_stats[0]["rule_id"] == "rule-bad"
        assert all_stats[0]["fp_rate"] == 1.0

    def test_auto_disable_extreme_fp(self):
        """Rule with extreme FP rate (>=0.95) is auto-disabled."""
        loop = self._make_loop()
        loop._auto_disable_fp = 0.95
        loop._min_samples = 5
        # 19 FP, 1 TP = 95% FP
        for _ in range(19):
            loop.record_feedback("very-noisy", is_tp=False)
        loop.record_feedback("very-noisy", is_tp=True)

        actions = loop.evaluate_rules()
        action_map = {a[0]: a[1] for a in actions}
        assert action_map.get("very-noisy") == "auto_disabled"


# ===========================================================================
# 8. DSL (Extended) Tests
# ===========================================================================

class TestDSLExtended:
    """Additional tests for src.invariants.dsl."""

    def test_operator_symbols(self):
        """Operator symbols (>, <, ==, etc.) are supported."""
        from src.invariants.dsl import DSLCondition
        from src.invariants.base import InvariantContext

        event = _make_event(amount_usd=500)
        ctx = InvariantContext()

        assert DSLCondition(field="event.amount_usd", operator=">", value=100).evaluate(event, ctx, {}) is True
        assert DSLCondition(field="event.amount_usd", operator="<", value=100).evaluate(event, ctx, {}) is False
        assert DSLCondition(field="event.amount_usd", operator=">=", value=500).evaluate(event, ctx, {}) is True
        assert DSLCondition(field="event.amount_usd", operator="==", value=500).evaluate(event, ctx, {}) is True
        assert DSLCondition(field="event.amount_usd", operator="!=", value=500).evaluate(event, ctx, {}) is False

    def test_invalid_operator_returns_false(self):
        """Invalid operator returns False."""
        from src.invariants.dsl import DSLCondition
        from src.invariants.base import InvariantContext

        event = _make_event(amount_usd=500)
        ctx = InvariantContext()
        result = DSLCondition(field="event.amount_usd", operator="INVALID", value=100).evaluate(event, ctx, {})
        assert result is False

    def test_none_field_returns_false(self):
        """Condition on a missing/None field returns False."""
        from src.invariants.dsl import DSLCondition
        from src.invariants.base import InvariantContext

        event = _make_event()
        ctx = InvariantContext()
        result = DSLCondition(field="event.nonexistent_field", operator="gt", value=0).evaluate(event, ctx, {})
        assert result is False

    def test_load_string_multiple_invariants(self):
        """Load multiple invariants from a single YAML string."""
        from src.invariants.dsl import DSLLoader
        yaml_str = """
invariants:
  - name: inv_a
    description: "First"
    type: threshold
    severity: high
    conditions:
      - field: event.amount_usd
        operator: gt
        value: 100
  - name: inv_b
    description: "Second"
    type: economic
    severity: critical
    conditions:
      - field: event.amount_usd
        operator: gt
        value: 5000
"""
        defs = DSLLoader.load_string(yaml_str)
        assert len(defs) == 2
        assert defs[0].name == "inv_a"
        assert defs[1].name == "inv_b"
        assert defs[1].invariant_type == "economic"

    def test_create_invariants_skips_disabled(self):
        """create_invariants skips definitions with enabled=False."""
        from src.invariants.dsl import DSLLoader
        yaml_str = """
invariants:
  - name: active
    description: "Enabled"
    type: threshold
    severity: medium
    enabled: true
    conditions:
      - field: event.amount_usd
        operator: gt
        value: 100
  - name: disabled
    description: "Disabled"
    type: threshold
    severity: medium
    enabled: false
    conditions:
      - field: event.amount_usd
        operator: gt
        value: 100
"""
        defs = DSLLoader.load_string(yaml_str)
        invariants = DSLLoader.create_invariants(defs)
        assert len(invariants) == 1
        assert invariants[0].name == "active"

    @pytest.mark.asyncio
    async def test_dsl_invariant_match_mode_any(self):
        """match_mode='any' triggers when at least one condition matches."""
        from src.invariants.dsl import DSLInvariant, DSLInvariantDef, DSLCondition
        from src.invariants.base import InvariantContext

        definition = DSLInvariantDef(
            name="any_mode_test",
            description="Any mode",
            invariant_type="threshold",
            severity="high",
            match_mode="any",
            conditions=[
                DSLCondition(field="event.amount_usd", operator="gt", value=999999),
                DSLCondition(field="event.amount_usd", operator="lt", value=500),
            ],
            cooldown_seconds=0,
        )
        invariant = DSLInvariant(definition)
        ctx = InvariantContext()
        event = _make_event(amount_usd=100)
        ctx.add_event(event)

        result = await invariant.evaluate(ctx)
        assert result.violated is True

    def test_load_string_empty_returns_empty(self):
        """Empty YAML string returns empty list."""
        from src.invariants.dsl import DSLLoader
        assert DSLLoader.load_string("") == []
        assert DSLLoader.load_string("---") == []


# ===========================================================================
# 9. Anomaly Routes API Tests
# ===========================================================================

class TestAnomalyRoutesAPI:
    """Tests for src.api.anomaly_routes endpoints."""

    def test_get_recent_anomalies(self, client):
        """GET /api/anomaly/recent returns a list."""
        resp = client.get("/api/anomaly/recent")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_stats(self, client):
        """GET /api/anomaly/stats returns engine stats."""
        resp = client.get("/api/anomaly/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_anomalies" in data
        assert "enabled" in data

    def test_train_empty_buffer_returns_400(self, client):
        """POST /api/anomaly/train with empty buffer returns 400."""
        # Reset the engine to ensure empty buffer
        import src.api.anomaly_routes as ar
        old_engine = ar._engine
        ar._engine = None
        try:
            resp = client.post("/api/anomaly/train")
            assert resp.status_code == 400
            assert "empty" in resp.json()["detail"].lower()
        finally:
            ar._engine = old_engine

    def test_analyze_event_normal(self, client):
        """POST /api/anomaly/analyze with a normal event."""
        payload = {
            "event": {
                "event_id": "evt-test-1",
                "chain_id": "ethereum",
                "event_type": "TRANSFER",
                "amount_usd": 100,
                "block_number": 100,
            }
        }
        resp = client.post("/api/anomaly/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        # With sparse data, likely no anomaly
        assert "is_anomalous" in data


# ===========================================================================
# 10. Logging Config Tests
# ===========================================================================

class TestLoggingConfig:
    """Tests for src.logging_config."""

    def test_structured_formatter_json_output(self):
        """StructuredFormatter produces valid JSON."""
        from src.logging_config import StructuredFormatter

        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.WARNING,
            pathname="test.py",
            lineno=42,
            msg="Test warning message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["severity"] == "WARNING"
        assert parsed["message"] == "Test warning message"
        assert parsed["logger"] == "test.logger"
        assert parsed["line"] == 42

    def test_structured_formatter_with_trace_id(self):
        """Trace ID from contextvar appears in JSON output."""
        from src.logging_config import StructuredFormatter, request_trace_id

        token = request_trace_id.set("trace-abc-123")
        try:
            formatter = StructuredFormatter()
            record = logging.LogRecord(
                name="test", level=logging.INFO, pathname="t.py",
                lineno=1, msg="hi", args=(), exc_info=None,
            )
            output = formatter.format(record)
            parsed = json.loads(output)
            assert parsed["trace_id"] == "trace-abc-123"
            assert "traces/trace-abc-123" in parsed.get("logging.googleapis.com/trace", "")
        finally:
            request_trace_id.reset(token)

    def test_structured_formatter_with_exception(self):
        """Exception info is included in JSON output."""
        from src.logging_config import StructuredFormatter

        formatter = StructuredFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="t.py",
            lineno=1, msg="error occurred", args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert parsed["exception"]["type"] == "ValueError"
        assert "test error" in parsed["exception"]["message"]

    def test_setup_logging_dev(self):
        """setup_logging in dev mode does not use StructuredFormatter."""
        from src.logging_config import setup_logging

        with patch.dict(os.environ, {"ENVIRONMENT": "development", "LOG_LEVEL": "DEBUG"}):
            setup_logging()
            root = logging.getLogger()
            assert root.level == logging.DEBUG
            # Dev mode should NOT use StructuredFormatter
            for h in root.handlers:
                from src.logging_config import StructuredFormatter
                assert not isinstance(h.formatter, StructuredFormatter)

    def test_setup_logging_production(self):
        """setup_logging in production mode uses StructuredFormatter."""
        from src.logging_config import setup_logging, StructuredFormatter

        with patch.dict(os.environ, {"ENVIRONMENT": "production", "LOG_LEVEL": "WARNING"}):
            setup_logging()
            root = logging.getLogger()
            assert root.level == logging.WARNING
            has_structured = any(isinstance(h.formatter, StructuredFormatter) for h in root.handlers)
            assert has_structured

    def test_context_vars_default_empty(self):
        """Context vars default to empty string."""
        from src.logging_config import request_trace_id, request_correlation_id, request_tenant_id
        # In a fresh context, defaults should be empty
        assert request_trace_id.get('') == ''
        assert request_correlation_id.get('') == ''
        assert request_tenant_id.get('') == ''
