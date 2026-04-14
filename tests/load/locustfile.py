"""
Sentinel3 XDR API - Locust Load Tests
======================================

Usage:
    locust -f tests/load/locustfile.py --host=http://localhost:8080
    locust -f tests/load/locustfile.py --host=http://localhost:8080 --headless -u 100 -r 10 -t 5m

User profiles:
    ReadOnlyUser  — browses dashboards, views stats and events
    AnalystUser   — investigates incidents, runs forensics, views details
    AdminUser     — manages tenants, creates rules, views system health
"""

import json
import random
import uuid
from datetime import datetime, timezone

from locust import HttpUser, task, between, tag, events


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

CHAINS = ["ethereum", "polygon", "arbitrum", "optimism", "bsc", "avalanche"]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
TIME_RANGES = ["1h", "6h", "24h", "7d", "30d"]


def _random_tx_hash() -> str:
    return "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:24]


def _random_address() -> str:
    return "0x" + uuid.uuid4().hex[:40]


# ---------------------------------------------------------------------------
# ReadOnlyUser — dashboard browsing
# ---------------------------------------------------------------------------

class ReadOnlyUser(HttpUser):
    """
    Simulates a dashboard viewer who repeatedly polls health, stats,
    recent events, and chart endpoints.
    """
    weight = 5  # Most common user type
    wait_time = between(1, 3)

    @tag("health")
    @task(10)
    def health(self):
        with self.client.get("/health", name="/health", catch_response=True) as resp:
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") != "healthy":
                    resp.failure(f"Unhealthy status: {data.get('status')}")
            else:
                resp.failure(f"Status {resp.status_code}")

    @tag("health")
    @task(3)
    def health_detailed(self):
        self.client.get("/health/detailed", name="/health/detailed")

    @tag("stats")
    @task(8)
    def stats(self):
        self.client.get("/api/stats", name="/api/stats")

    @tag("events")
    @task(5)
    def events_list(self):
        limit = random.choice([10, 20, 50])
        self.client.get(f"/api/events?limit={limit}", name="/api/events")

    @tag("events")
    @task(3)
    def events_filtered(self):
        chain = random.choice(CHAINS)
        self.client.get(
            f"/api/events?limit=20&chain={chain}",
            name="/api/events?chain=[chain]",
        )

    @tag("incidents")
    @task(5)
    def incidents_list(self):
        self.client.get("/api/incidents?limit=20", name="/api/incidents")

    @tag("incidents")
    @task(2)
    def incidents_filtered(self):
        severity = random.choice(SEVERITIES)
        time_range = random.choice(TIME_RANGES)
        self.client.get(
            f"/api/incidents?severity={severity}&time_range={time_range}&limit=20",
            name="/api/incidents?severity=[sev]&time_range=[tr]",
        )

    @tag("analytics")
    @task(3)
    def analytics_historical(self):
        days = random.choice([7, 14, 30])
        self.client.get(
            f"/api/analytics/historical?days={days}",
            name="/api/analytics/historical",
        )

    @tag("analytics")
    @task(2)
    def analytics_chart_incidents(self):
        self.client.get(
            "/api/analytics/charts/incidents-over-time?days=7&granularity=hour",
            name="/api/analytics/charts/incidents-over-time",
        )

    @tag("analytics")
    @task(2)
    def analytics_chart_by_chain(self):
        self.client.get(
            "/api/analytics/charts/by-chain?days=30",
            name="/api/analytics/charts/by-chain",
        )

    @tag("metrics")
    @task(1)
    def prometheus_metrics(self):
        self.client.get("/metrics", name="/metrics")

    @tag("chains")
    @task(2)
    def chains_status(self):
        self.client.get("/api/chains/status", name="/api/chains/status")


# ---------------------------------------------------------------------------
# AnalystUser — investigates incidents, runs forensics
# ---------------------------------------------------------------------------

class AnalystUser(HttpUser):
    """
    Simulates a security analyst who looks at incident details,
    runs forensic investigations, and queries events with filters.
    """
    weight = 3
    wait_time = between(2, 5)

    def on_start(self):
        """Fetch some incident IDs to use in later requests."""
        self._incident_ids = []
        resp = self.client.get("/api/incidents?limit=10", name="/api/incidents [analyst-init]")
        if resp.status_code == 200:
            try:
                incidents = resp.json()
                if isinstance(incidents, list):
                    self._incident_ids = [inc["id"] for inc in incidents if "id" in inc]
            except (json.JSONDecodeError, KeyError):
                pass

    @tag("incidents")
    @task(5)
    def incidents_list(self):
        self.client.get("/api/incidents?limit=50", name="/api/incidents")

    @tag("incidents")
    @task(4)
    def incident_detail(self):
        if self._incident_ids:
            iid = random.choice(self._incident_ids)
            self.client.get(
                f"/api/incidents/{iid}",
                name="/api/incidents/[id]",
            )

    @tag("incidents")
    @task(2)
    def incident_timeline(self):
        if self._incident_ids:
            iid = random.choice(self._incident_ids)
            self.client.get(
                f"/api/incidents/{iid}/timeline",
                name="/api/incidents/[id]/timeline",
            )

    @tag("events")
    @task(4)
    def events_filtered(self):
        chain = random.choice(CHAINS)
        severity = random.choice(SEVERITIES)
        self.client.get(
            f"/api/events?chain={chain}&severity={severity}&limit=50",
            name="/api/events?chain&severity",
        )

    @tag("forensics")
    @task(2)
    def forensics_analyze_incident(self):
        """Submit a forensic analysis request for an incident."""
        if self._incident_ids:
            iid = random.choice(self._incident_ids)
            self.client.get(
                f"/api/ai/analyze/{iid}",
                name="/api/ai/analyze/[id]",
            )

    @tag("stats")
    @task(3)
    def stats(self):
        self.client.get("/api/stats", name="/api/stats")

    @tag("analytics")
    @task(2)
    def analytics_historical(self):
        self.client.get(
            "/api/analytics/historical?days=7",
            name="/api/analytics/historical",
        )

    @tag("health")
    @task(1)
    def health_ready(self):
        self.client.get("/health/ready", name="/health/ready")


# ---------------------------------------------------------------------------
# AdminUser — manages tenants, rules, system-level ops
# ---------------------------------------------------------------------------

class AdminUser(HttpUser):
    """
    Simulates an admin user who checks system health, manages tenants
    and guardian settings, and monitors the full platform.
    """
    weight = 1
    wait_time = between(3, 8)

    @tag("health")
    @task(5)
    def health_detailed(self):
        self.client.get("/health/detailed", name="/health/detailed")

    @tag("health")
    @task(3)
    def health_ready(self):
        self.client.get("/health/ready", name="/health/ready")

    @tag("metrics")
    @task(3)
    def prometheus_metrics(self):
        self.client.get("/metrics", name="/metrics")

    @tag("metrics")
    @task(2)
    def metrics_health(self):
        self.client.get("/metrics/health", name="/metrics/health")

    @tag("guardian")
    @task(3)
    def guardian_status(self):
        self.client.get("/api/guardian/status", name="/api/guardian/status")

    @tag("guardian")
    @task(2)
    def guardian_protocols(self):
        self.client.get("/api/guardian/protocols", name="/api/guardian/protocols")

    @tag("guardian")
    @task(2)
    def guardian_actions(self):
        self.client.get(
            "/api/guardian/actions?limit=20",
            name="/api/guardian/actions",
        )

    @tag("tenants")
    @task(2)
    def tenant_list(self):
        self.client.get("/api/tenants", name="/api/tenants")

    @tag("stats")
    @task(3)
    def stats(self):
        self.client.get("/api/stats", name="/api/stats")

    @tag("chains")
    @task(3)
    def chains_status(self):
        self.client.get("/api/chains/status", name="/api/chains/status")

    @tag("websocket")
    @task(1)
    def websocket_status(self):
        self.client.get("/ws/status", name="/ws/status")

    @tag("incidents")
    @task(2)
    def incidents_list(self):
        self.client.get(
            "/api/incidents?limit=100",
            name="/api/incidents",
        )
