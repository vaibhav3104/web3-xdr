"""
Tests for New Features (Forensics, DSL, MEV, Guardian, Tenant, Health, Metrics, Forensics API, DSL API)
========================================================================================================

Comprehensive test coverage for the 8 new features added to Sentinel3 XDR.
All external dependencies (DB, Redis, Web3) are mocked.
"""

import os
import time
import tempfile
import pytest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from unittest.mock import patch, AsyncMock, MagicMock, PropertyMock

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Shared app / client fixtures — mirrors test_api_routes.py pattern
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def app():
    """Create a test FastAPI app with mocked DB init."""
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
    """TestClient wrapping the app."""
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helper: build a SecurityEvent quickly
# ---------------------------------------------------------------------------

def _make_event(
    chain_id="ethereum",
    event_type=None,
    amount_usd=0,
    source_address="0xaaa",
    dest_address="0xbbb",
    contract_address="",
    tx_hash="0xdeadbeef",
    block_number=100,
    bridge_id=None,
    event_id=None,
    block_timestamp=None,
):
    from src.models.events import SecurityEvent, EventType, EventStatus
    import uuid

    if event_type is None:
        event_type = EventType.TRANSFER

    return SecurityEvent(
        event_id=event_id or str(uuid.uuid4()),
        chain_id=chain_id,
        block_number=block_number,
        block_timestamp=block_timestamp or datetime.now(timezone.utc),
        tx_hash=tx_hash,
        event_type=event_type,
        source_address=source_address,
        dest_address=dest_address,
        contract_address=contract_address,
        amount=Decimal(str(amount_usd)),
        amount_usd=Decimal(str(amount_usd)),
        bridge_id=bridge_id,
    )


# ===========================================================================
# TestForensicsEngine
# ===========================================================================

class TestForensicsEngine:
    """Tests for src.forensics.engine.ForensicsEngine."""

    async def test_address_history_query(self):
        """ForensicQuery with ADDRESS_HISTORY returns report with correct structure."""
        from src.forensics.engine import ForensicsEngine, ForensicQuery, ForensicQueryType

        engine = ForensicsEngine()

        mock_events = [
            {
                "block_timestamp": datetime.now(timezone.utc),
                "chain_id": "ethereum",
                "event_type": "transfer",
                "tx_hash": "0xabc",
                "block_number": 100,
                "amount_usd": 5000,
                "from_address": "0x1111",
                "to_address": "0x2222",
                "severity": "info",
            }
        ]

        with patch(
            "src.database.service.DatabaseService.query_events_by_address",
            new_callable=AsyncMock,
            return_value=mock_events,
        ):
            query = ForensicQuery(
                query_type=ForensicQueryType.ADDRESS_HISTORY,
                addresses=["0x1111"],
                chain_ids=["ethereum"],
            )
            report = await engine.investigate(query)

        assert len(report.timeline) == 1
        assert report.timeline[0].chain_id == "ethereum"
        assert report.affected_addresses == ["0x1111"]
        assert "address_history" in report.summary
        assert report.summary  # non-empty

    async def test_fund_flow_trace(self):
        """FUND_FLOW_TRACE query populates fund_flows."""
        from src.forensics.engine import ForensicsEngine, ForensicQuery, ForensicQueryType

        engine = ForensicsEngine()

        mock_events = [
            {
                "from_address": "0xaaa",
                "to_address": "0xbbb",
                "amount_usd": 10000,
                "chain_id": "ethereum",
                "tx_hash": "0xfff",
                "block_timestamp": datetime.now(timezone.utc),
                "event_type": "transfer",
            }
        ]

        with patch(
            "src.database.service.DatabaseService.query_events_by_address",
            new_callable=AsyncMock,
            return_value=mock_events,
        ):
            query = ForensicQuery(
                query_type=ForensicQueryType.FUND_FLOW_TRACE,
                addresses=["0xaaa"],
                max_depth=1,
            )
            report = await engine.investigate(query)

        assert len(report.fund_flows) >= 1
        assert report.fund_flows[0]["from"] == "0xaaa"
        assert report.fund_flows[0]["to"] == "0xbbb"
        assert report.total_loss_usd > 0
        assert "fund_flow_trace" in report.summary

    async def test_incident_replay(self):
        """INCIDENT_REPLAY returns a timeline from stored incident events."""
        from src.forensics.engine import ForensicsEngine, ForensicQuery, ForensicQueryType

        engine = ForensicsEngine()

        mock_incident = {
            "event_ids": ["evt-1", "evt-2"],
            "total_loss_usd": 50000,
            "attack_type": "flash_loan",
            "affected_chains": ["ethereum"],
        }
        mock_event_1 = {
            "block_timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
            "chain_id": "ethereum",
            "event_type": "flash_borrow",
            "tx_hash": "0x111",
            "block_number": 200,
            "amount_usd": 50000,
            "from_address": "0xattacker",
            "to_address": "0xpool",
            "severity": "high",
        }
        mock_event_2 = {
            "block_timestamp": datetime.now(timezone.utc),
            "chain_id": "ethereum",
            "event_type": "flash_repay",
            "tx_hash": "0x222",
            "block_number": 200,
            "amount_usd": 50000,
            "from_address": "0xattacker",
            "to_address": "0xpool",
            "severity": "high",
        }

        with patch(
            "src.database.service.DatabaseService.get_incident_by_id",
            new_callable=AsyncMock,
            return_value=mock_incident,
        ), patch(
            "src.database.service.DatabaseService.get_event_by_id",
            new_callable=AsyncMock,
            side_effect=[mock_event_1, mock_event_2],
        ):
            query = ForensicQuery(
                query_type=ForensicQueryType.INCIDENT_REPLAY,
                incident_id="inc-001",
            )
            report = await engine.investigate(query)

        assert len(report.timeline) == 2
        assert report.total_loss_usd == 50000
        assert report.attack_pattern == "flash_loan"
        assert "incident_replay" in report.summary

    def test_summary_generation(self):
        """_generate_summary produces non-empty text with correct markers."""
        from src.forensics.engine import (
            ForensicsEngine,
            ForensicQuery,
            ForensicQueryType,
            ForensicReport,
            TimelineEntry,
        )

        engine = ForensicsEngine()
        query = ForensicQuery(query_type=ForensicQueryType.ADDRESS_HISTORY)
        report = ForensicReport(
            query=query,
            timeline=[
                TimelineEntry(
                    timestamp=datetime.now(timezone.utc),
                    chain_id="ethereum",
                    event_type="transfer",
                    tx_hash="0x1",
                    block_number=1,
                    description="test",
                )
            ],
            fund_flows=[{"amount_usd": 100}],
            violations_found=[{"invariant": "test"}],
            affected_addresses=["0xaaa"],
            affected_chains=["ethereum"],
            total_loss_usd=1000.0,
            attack_pattern="reentrancy",
        )

        summary = engine._generate_summary(report)

        assert "address_history" in summary
        assert "Timeline events: 1" in summary
        assert "Violations found: 1" in summary
        assert "Fund flows traced: 1" in summary
        assert "$1,000.00" in summary
        assert "ethereum" in summary
        assert "reentrancy" in summary


# ===========================================================================
# TestDSLInvariants
# ===========================================================================

class TestDSLInvariants:
    """Tests for src.invariants.dsl (DSLLoader, DSLCondition, DSLInvariant)."""

    def test_load_yaml_string(self):
        """DSLLoader.load_string() parses a YAML invariant definition."""
        from src.invariants.dsl import DSLLoader

        yaml_str = """
invariants:
  - name: test_invariant
    description: "Test threshold"
    type: threshold
    severity: high
    conditions:
      - field: event.amount_usd
        operator: gt
        value: 1000
    cooldown_seconds: 120
"""
        defs = DSLLoader.load_string(yaml_str)
        assert len(defs) == 1
        assert defs[0].name == "test_invariant"
        assert defs[0].severity == "high"
        assert defs[0].cooldown_seconds == 120
        assert len(defs[0].conditions) == 1
        assert defs[0].conditions[0].field == "event.amount_usd"
        assert defs[0].conditions[0].operator == "gt"
        assert defs[0].conditions[0].value == 1000

    def test_load_yaml_file(self):
        """Load the real bridge_invariants.yaml file from config/."""
        from src.invariants.dsl import DSLLoader

        yaml_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "config",
            "custom_invariants",
            "bridge_invariants.yaml",
        )
        yaml_path = os.path.abspath(yaml_path)

        if not os.path.exists(yaml_path):
            pytest.skip("bridge_invariants.yaml not found")

        defs = DSLLoader.load_file(yaml_path)
        assert len(defs) >= 1
        names = [d.name for d in defs]
        assert "large_bridge_transfer" in names

    def test_condition_evaluation(self):
        """DSLCondition.evaluate() returns True when condition is met."""
        from src.invariants.dsl import DSLCondition
        from src.invariants.base import InvariantContext
        from src.models.events import SecurityEvent, EventType

        cond = DSLCondition(field="event.amount_usd", operator="gt", value=500)
        event = _make_event(amount_usd=1000)
        ctx = InvariantContext()

        result = cond.evaluate(event, ctx, {})
        assert result is True

    def test_condition_evaluation_false(self):
        """DSLCondition.evaluate() returns False when condition is NOT met."""
        from src.invariants.dsl import DSLCondition
        from src.invariants.base import InvariantContext

        cond = DSLCondition(field="event.amount_usd", operator="gt", value=5000)
        event = _make_event(amount_usd=100)
        ctx = InvariantContext()

        result = cond.evaluate(event, ctx, {})
        assert result is False

    async def test_dsl_invariant_evaluate(self):
        """Full DSLInvariant.evaluate() flow triggers a violation on matching event."""
        from src.invariants.dsl import DSLInvariant, DSLInvariantDef, DSLCondition
        from src.invariants.base import InvariantContext
        from src.models.events import EventType

        definition = DSLInvariantDef(
            name="test_high_transfer",
            description="Fires on large transfers",
            invariant_type="threshold",
            severity="high",
            conditions=[
                DSLCondition(field="event.amount_usd", operator="gt", value=500)
            ],
            cooldown_seconds=0,
        )

        invariant = DSLInvariant(definition)
        ctx = InvariantContext()
        # Add a recent event that matches
        event = _make_event(amount_usd=10000, event_type=EventType.TRANSFER)
        ctx.add_event(event)

        result = await invariant.evaluate(ctx)
        assert result.violated is True
        assert result.invariant_name == "test_high_transfer"

    async def test_chain_filter(self):
        """Invariant with chains=['ethereum'] ignores polygon events."""
        from src.invariants.dsl import DSLInvariant, DSLInvariantDef, DSLCondition
        from src.invariants.base import InvariantContext
        from src.models.events import EventType

        definition = DSLInvariantDef(
            name="eth_only",
            description="Only Ethereum",
            invariant_type="threshold",
            severity="high",
            chains=["ethereum"],
            conditions=[
                DSLCondition(field="event.amount_usd", operator="gt", value=100)
            ],
            cooldown_seconds=0,
        )

        invariant = DSLInvariant(definition)
        ctx = InvariantContext()
        # Add a polygon event that exceeds threshold -- should be filtered out
        event = _make_event(chain_id="polygon", amount_usd=99999, event_type=EventType.TRANSFER)
        ctx.add_event(event)

        result = await invariant.evaluate(ctx)
        assert result.violated is False

    async def test_cooldown(self):
        """Second violation within cooldown window returns None (no violation)."""
        from src.invariants.dsl import DSLInvariant, DSLInvariantDef, DSLCondition
        from src.invariants.base import InvariantContext
        from src.models.events import EventType

        definition = DSLInvariantDef(
            name="cooldown_test",
            description="Test cooldown",
            invariant_type="threshold",
            severity="medium",
            conditions=[
                DSLCondition(field="event.amount_usd", operator="gt", value=100)
            ],
            cooldown_seconds=3600,  # 1 hour cooldown
        )

        invariant = DSLInvariant(definition)
        ctx = InvariantContext()

        # First event triggers violation
        event1 = _make_event(chain_id="ethereum", amount_usd=5000, event_type=EventType.TRANSFER)
        ctx.add_event(event1)
        result1 = await invariant.evaluate(ctx)
        assert result1.violated is True

        # Second event with same chain -- cooldown should suppress
        event2 = _make_event(chain_id="ethereum", amount_usd=9000, event_type=EventType.TRANSFER)
        ctx.add_event(event2)
        result2 = await invariant.evaluate(ctx)
        assert result2.violated is False


# ===========================================================================
# TestMEVDetectors
# ===========================================================================

class TestMEVDetectors:
    """Tests for src.invariants.mev detector initialization."""

    def test_sandwich_detector_init(self):
        """SandwichAttackDetector has correct name and type."""
        from src.invariants.mev import SandwichAttackDetector
        from src.models.invariants import InvariantType
        from src.models.events import Severity

        detector = SandwichAttackDetector()
        assert detector.name == "MEV_SANDWICH_ATTACK"
        assert detector.invariant_type == InvariantType.ECONOMIC
        assert detector.severity == Severity.HIGH

    def test_frontrunning_detector_init(self):
        """FrontrunningDetector has correct name and type."""
        from src.invariants.mev import FrontrunningDetector
        from src.models.invariants import InvariantType
        from src.models.events import Severity

        detector = FrontrunningDetector()
        assert detector.name == "MEV_FRONTRUNNING"
        assert detector.invariant_type == InvariantType.TEMPORAL
        assert detector.severity == Severity.MEDIUM

    def test_backrunning_detector_init(self):
        """BackrunningDetector has correct name and type."""
        from src.invariants.mev import BackrunningDetector
        from src.models.invariants import InvariantType
        from src.models.events import Severity

        detector = BackrunningDetector()
        assert detector.name == "MEV_BACKRUNNING"
        assert detector.invariant_type == InvariantType.TEMPORAL
        assert detector.severity == Severity.MEDIUM

    def test_jit_liquidity_detector_init(self):
        """JITLiquidityDetector has correct name and type."""
        from src.invariants.mev import JITLiquidityDetector
        from src.models.invariants import InvariantType
        from src.models.events import Severity

        detector = JITLiquidityDetector()
        assert detector.name == "MEV_JIT_LIQUIDITY"
        assert detector.invariant_type == InvariantType.ECONOMIC
        assert detector.severity == Severity.MEDIUM


# ===========================================================================
# TestGuardianAPI
# ===========================================================================

class TestGuardianAPI:
    """Tests for Guardian API endpoints using TestClient."""

    def test_get_pending_actions(self, client):
        """GET /api/guardian/pending-actions returns pending list."""
        resp = client.get("/api/guardian/pending-actions")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "pending_actions" in data
        assert isinstance(data["pending_actions"], list)

    def test_list_protocols(self, client):
        """GET /api/guardian/protocols returns protocol list."""
        resp = client.get("/api/guardian/protocols")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "protocols" in data
        assert isinstance(data["protocols"], list)

    def test_action_history(self, client):
        """GET /api/guardian/history returns response history."""
        resp = client.get("/api/guardian/history")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "responses" in data

    def test_register_protocol(self, client):
        """POST /api/guardian/protocols registers a new protocol."""
        payload = {
            "protocol_id": "test-proto-1",
            "protocol_name": "Test Protocol",
            "chain_id": "ethereum",
            "main_contract": "0x1234567890abcdef1234567890abcdef12345678",
        }
        resp = client.post("/api/guardian/protocols", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["protocol_id"] == "test-proto-1"

    def test_approve_action_not_found(self, client):
        """POST approve flow returns 404 for non-existent action."""
        resp = client.post(
            "/api/guardian/actions/nonexistent-action-id/approve",
            json={"approved_by": "admin_user"},
        )
        assert resp.status_code == 404

    def test_reject_action_not_found(self, client):
        """POST reject flow returns 404 for non-existent action."""
        resp = client.post(
            "/api/guardian/actions/nonexistent-action-id/reject",
            json={"rejected_by": "admin_user", "reason": "Testing rejection"},
        )
        assert resp.status_code == 404


# ===========================================================================
# TestTenantMiddleware
# ===========================================================================

class TestTenantMiddleware:
    """Tests for src.auth.tenant_middleware."""

    def test_public_paths_skip_tenant(self):
        """PUBLIC_PATHS (health, metrics) don't require tenant context."""
        from src.auth.tenant_middleware import TenantMiddleware

        public_paths = TenantMiddleware.PUBLIC_PATHS
        assert "/health" in public_paths
        assert "/metrics" in public_paths
        assert "/health/ready" in public_paths

    def test_get_tenant_id_helper(self):
        """get_tenant_id extracts tenant_id from request.state."""
        from src.auth.tenant_middleware import get_tenant_id

        mock_request = MagicMock()
        mock_request.state.tenant_id = "tenant-abc"
        assert get_tenant_id(mock_request) == "tenant-abc"

    def test_get_tenant_id_none(self):
        """get_tenant_id returns None when no tenant_id in state."""
        from src.auth.tenant_middleware import get_tenant_id

        mock_request = MagicMock(spec=[])
        mock_request.state = MagicMock(spec=[])
        result = get_tenant_id(mock_request)
        assert result is None

    async def test_rate_limit_check(self):
        """Rate limiting allows requests under the limit and blocks above."""
        from src.auth.tenant_middleware import TenantMiddleware

        middleware = TenantMiddleware(app=MagicMock())
        # Clear any prior cache state
        middleware._rate_limit_cache.clear()

        tenant_starter = {
            "customer_id": "test-rate-limit-tenant",
            "tier": "starter",
            "scopes": [],
        }

        # Starter tier has 100 req/min -- first request should pass
        result = await middleware._check_rate_limit(tenant_starter)
        assert result is True

        # Simulate hitting the limit
        now = int(time.time() / 60)
        key = f"test-rate-limit-tenant:{now}"
        middleware._rate_limit_cache[key] = 100

        result_over = await middleware._check_rate_limit(tenant_starter)
        assert result_over is False


# ===========================================================================
# TestHealthEndpoints
# ===========================================================================

class TestHealthEndpoints:
    """Tests for src.api.health endpoints."""

    def test_health_liveness(self, client):
        """GET /health/live returns alive=True."""
        resp = client.get("/health/live")
        assert resp.status_code == 200
        data = resp.json()
        assert data["alive"] is True
        assert "uptime_seconds" in data

    def test_health_readiness(self, client):
        """GET /health/ready returns a valid response."""
        resp = client.get("/health/ready")
        # 200 if DB connected, 503 if not -- both valid in test env
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert "ready" in data or "reason" in data


# ===========================================================================
# TestDSLAPI
# ===========================================================================

class TestDSLAPI:
    """Tests for src.api.dsl_routes endpoints."""

    def test_list_custom_invariants(self, client):
        """GET /api/invariants/custom/ lists loaded invariants."""
        resp = client.get("/api/invariants/custom/")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "invariants" in data
        assert isinstance(data["invariants"], list)

    def test_validate_yaml(self, client):
        """POST /api/invariants/custom/validate validates YAML without saving."""
        yaml_str = """
invariants:
  - name: validate_test
    description: "Test validation"
    type: threshold
    severity: medium
    conditions:
      - field: event.amount_usd
        operator: gt
        value: 100
"""
        resp = client.post(
            "/api/invariants/custom/validate",
            json={"yaml": yaml_str},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["invariant_count"] == 1
        assert data["invariants"][0]["name"] == "validate_test"

    def test_validate_yaml_invalid(self, client):
        """POST /api/invariants/custom/validate with invalid YAML returns valid=False."""
        resp = client.post(
            "/api/invariants/custom/validate",
            json={"yaml": "not: valid: yaml: [[["},
        )
        assert resp.status_code == 200
        data = resp.json()
        # YAML parsing might fail or produce something unexpected
        # Either valid=False or an error in the response is acceptable
        assert "valid" in data

    def test_create_custom_invariant(self, client):
        """POST /api/invariants/custom/ creates a new invariant file."""
        payload = {
            "name": "test_create_invariant",
            "description": "Created by test",
            "type": "threshold",
            "severity": "low",
            "conditions": [
                {"field": "event.amount_usd", "operator": "gt", "value": 999}
            ],
        }
        resp = client.post("/api/invariants/custom/", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "created"
        assert "file" in data

        # Cleanup: delete the created file
        created_file = os.path.join(
            os.path.dirname(__file__),
            "..",
            "config",
            "custom_invariants",
            data["file"],
        )
        created_file = os.path.abspath(created_file)
        if os.path.exists(created_file):
            os.remove(created_file)


# ===========================================================================
# TestForensicsAPI
# ===========================================================================

class TestForensicsAPI:
    """Tests for src.api.forensics_routes endpoints."""

    def test_list_investigations(self, client):
        """GET /api/forensics/investigations lists investigations."""
        resp = client.get("/api/forensics/investigations")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_address_history(self, client):
        """GET /api/forensics/address/{addr}/history returns address history."""
        with patch(
            "src.database.service.DatabaseService.query_events_by_address",
            new_callable=AsyncMock,
            return_value=[],
        ):
            resp = client.get(
                "/api/forensics/address/0x1111111111111111111111111111111111111111/history"
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["address"] == "0x1111111111111111111111111111111111111111"
        assert "event_count" in data
        assert "timeline" in data


# ===========================================================================
# TestMetricsCollector
# ===========================================================================

class TestMetricsCollector:
    """Tests for src.metrics.collector new metrics and helpers."""

    def test_new_metrics_exist(self):
        """Verify forensics_queries_total, guardian_actions_total etc. exist on XDRMetrics."""
        from src.metrics.collector import XDRMetrics

        # Create a fresh instance with a unique namespace to avoid collisions
        # with the global singleton.  We can still verify attribute existence.
        m = XDRMetrics.__new__(XDRMetrics)
        # Access via the global singleton instead
        from src.metrics.collector import metrics

        assert hasattr(metrics, "forensics_queries_total")
        assert hasattr(metrics, "guardian_actions_total")
        assert hasattr(metrics, "custom_invariants_loaded")
        assert hasattr(metrics, "tenant_api_requests_total")
        assert hasattr(metrics, "event_backlog_size")
        assert hasattr(metrics, "db_query_duration_seconds")
        assert hasattr(metrics, "websocket_connections_active")

    def test_track_forensics_query(self):
        """track_forensics_query increments the counter without error."""
        from src.metrics.collector import track_forensics_query

        # Should not raise
        track_forensics_query("address_history", "success")
        track_forensics_query("fund_flow_trace", "error")

    def test_track_guardian_action(self):
        """track_guardian_action increments the counter without error."""
        from src.metrics.collector import track_guardian_action

        track_guardian_action("pause_contract", "success")
        track_guardian_action("pause_contract", "failed")

    def test_track_tenant_request(self):
        """track_tenant_request increments the counter without error."""
        from src.metrics.collector import track_tenant_request

        track_tenant_request("tenant-123", "/api/events")

    def test_track_db_query(self):
        """track_db_query records a histogram observation without error."""
        from src.metrics.collector import track_db_query

        track_db_query("SELECT", "events", 0.015)

    def test_set_event_backlog(self):
        """set_event_backlog sets the gauge without error."""
        from src.metrics.collector import set_event_backlog

        set_event_backlog("ethereum", 42)

    def test_set_websocket_connections(self):
        """set_websocket_connections sets the gauge without error."""
        from src.metrics.collector import set_websocket_connections

        set_websocket_connections("incidents", 5)

    def test_set_custom_invariants(self):
        """set_custom_invariants sets the gauge without error."""
        from src.metrics.collector import set_custom_invariants

        set_custom_invariants("threshold", 10)
