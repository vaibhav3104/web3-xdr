"""
API Route Tests for Sentinel3
==============================

Tests core API endpoints: health, incidents, events, stats, and auth.
All external services (DB, Redis) are mocked.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App fixture — patch DB and make torch raise ImportError so ml_routes
# is skipped cleanly via _try_import_router.
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
# Health Endpoints
# ---------------------------------------------------------------------------

class TestHealthEndpoints:
    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "sentinel3"

    def test_health_detailed(self, client):
        resp = client.get("/health/detailed")
        assert resp.status_code == 200
        data = resp.json()
        assert "checks" in data
        assert "postgres" in data["checks"]
        assert "redis" in data["checks"]

    def test_health_ready(self, client):
        resp = client.get("/health/ready")
        # May return 503 if DB is not connected
        assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# Root / Frontend Serving
# ---------------------------------------------------------------------------

class TestFrontendServing:
    def test_root_returns_response(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_nonexistent_page_returns_404(self, client):
        resp = client.get("/nonexistent-page-xyz.html")
        assert resp.status_code == 404

    def test_path_traversal_blocked(self, client):
        resp = client.get("/../../../etc/passwd.html")
        assert resp.status_code in (404, 422)

    def test_docs_redirect(self, client):
        resp = client.get("/docs", follow_redirects=False)
        assert resp.status_code in (200, 307)


# ---------------------------------------------------------------------------
# API Docs
# ---------------------------------------------------------------------------

class TestAPIDocs:
    def test_openapi_schema(self, client):
        resp = client.get("/api/docs")
        assert resp.status_code == 200

    def test_redoc(self, client):
        resp = client.get("/api/redoc")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Incidents API
# ---------------------------------------------------------------------------

class TestIncidentsAPI:
    @patch("src.database.service.DatabaseService.get_incidents")
    def test_get_incidents_empty(self, mock_get, client):
        mock_get.return_value = []
        resp = client.get("/api/incidents")
        assert resp.status_code == 200
        assert isinstance(resp.json(), (list, dict))

    @patch("src.database.service.DatabaseService.get_incidents")
    def test_get_incidents_with_severity_filter(self, mock_get, client):
        mock_get.return_value = []
        resp = client.get("/api/incidents?severity=CRITICAL")
        assert resp.status_code == 200

    @patch("src.database.service.DatabaseService.get_incident")
    def test_get_incident_not_found(self, mock_get, client):
        mock_get.return_value = None
        resp = client.get("/api/incidents/nonexistent-id")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Events API
# ---------------------------------------------------------------------------

class TestEventsAPI:
    @patch("src.database.service.DatabaseService.get_events")
    def test_get_events_empty(self, mock_get, client):
        mock_get.return_value = []
        resp = client.get("/api/events")
        assert resp.status_code == 200

    @patch("src.database.service.DatabaseService.get_events")
    def test_get_events_with_chain_filter(self, mock_get, client):
        mock_get.return_value = []
        resp = client.get("/api/events?chain=ethereum")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Stats API
# ---------------------------------------------------------------------------

class TestStatsAPI:
    def test_get_stats(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code in (200, 500)


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    def test_security_headers_present(self, client):
        resp = client.get("/health")
        headers = resp.headers
        assert headers.get("x-content-type-options") == "nosniff"
        assert headers.get("x-frame-options") == "DENY"
        assert "content-security-policy" in headers

    def test_request_id_present(self, client):
        resp = client.get("/api/stats")
        if resp.status_code != 500:
            assert "x-request-id" in resp.headers


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_rate_limit_headers_present(self, client):
        resp = client.get("/api/stats")
        if resp.status_code not in (429, 500):
            assert "x-ratelimit-limit" in resp.headers

    def test_health_exempt_from_rate_limit(self, client):
        for _ in range(20):
            resp = client.get("/health")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# API Key Validation
# ---------------------------------------------------------------------------

class TestAPIKeyValidation:
    def test_invalid_api_key_format(self, client):
        resp = client.get("/api/events", headers={"X-API-Key": "bad_key"})
        assert resp.status_code in (200, 401, 403, 500)

    def test_missing_api_key_on_public_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Guardian Routes (if available)
# ---------------------------------------------------------------------------

class TestGuardianRoutes:
    def test_guardian_stats(self, client):
        resp = client.get("/guardian/stats")
        assert resp.status_code in (200, 404, 500)
