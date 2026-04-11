/**
 * Sentinel3 API - k6 Load Test
 *
 * Install k6:  brew install k6  (macOS) | https://k6.io/docs/get-started/installation/
 * Run:         k6 run tests/load/loadtest.js
 * With env:    k6 run -e BASE_URL=http://localhost:8080 tests/load/loadtest.js
 *
 * Stages: ramp-up → sustained → spike → cool-down
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Rate, Trend } from "k6/metrics";

// ── Custom metrics ──────────────────────────────────────────────────
const errorRate = new Rate("errors");
const healthLatency = new Trend("health_latency", true);
const apiLatency = new Trend("api_latency", true);

// ── Options ─────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: "30s", target: 10 },   // ramp up
    { duration: "1m",  target: 50 },   // sustained load
    { duration: "15s", target: 100 },  // spike
    { duration: "15s", target: 50 },   // recover
    { duration: "30s", target: 0 },    // cool down
  ],
  thresholds: {
    http_req_duration: ["p(95)<2000", "p(99)<5000"],
    errors: ["rate<0.05"],
    health_latency: ["p(95)<200"],
    api_latency: ["p(95)<3000"],
  },
};

const BASE = __ENV.BASE_URL || "http://localhost:8080";

// ── Helpers ─────────────────────────────────────────────────────────
function get(path, tag) {
  const res = http.get(`${BASE}${path}`, { tags: { name: tag } });
  errorRate.add(res.status >= 400);
  return res;
}

// ── Scenarios ───────────────────────────────────────────────────────
export default function () {
  // Health checks (lightweight, should always be fast)
  group("health", () => {
    const res = get("/health", "health");
    healthLatency.add(res.timings.duration);
    check(res, {
      "health 200": (r) => r.status === 200,
      "status healthy": (r) => r.json("status") === "healthy",
    });
  });

  // Dashboard stats (most-polled endpoint)
  group("stats", () => {
    const res = get("/api/stats", "stats");
    apiLatency.add(res.timings.duration);
    check(res, { "stats 200": (r) => r.status === 200 });
  });

  // Incidents list
  group("incidents", () => {
    const res = get("/api/incidents?limit=20", "incidents");
    apiLatency.add(res.timings.duration);
    check(res, { "incidents 200": (r) => r.status === 200 });
  });

  // Events list
  group("events", () => {
    const res = get("/api/events?limit=20", "events");
    apiLatency.add(res.timings.duration);
    check(res, { "events 200": (r) => r.status === 200 });
  });

  // Analytics (cached, heavier queries)
  group("analytics", () => {
    const res = get("/api/analytics/historical?days=30", "analytics_hist");
    apiLatency.add(res.timings.duration);
    check(res, { "historical 200": (r) => r.status === 200 });

    const charts = get("/api/analytics/charts/incidents-over-time?days=7&granularity=hour", "chart_incidents");
    apiLatency.add(charts.timings.duration);
    check(charts, { "chart 200": (r) => r.status === 200 });
  });

  // Chain distribution chart
  group("charts", () => {
    const res = get("/api/analytics/charts/by-chain?days=30", "chart_chain");
    apiLatency.add(res.timings.duration);
    check(res, { "by-chain 200": (r) => r.status === 200 });
  });

  // Detailed health (DB + Redis connectivity)
  group("health_detailed", () => {
    const res = get("/health/detailed", "health_detailed");
    apiLatency.add(res.timings.duration);
    check(res, {
      "detailed 200": (r) => r.status === 200,
      "has checks": (r) => r.json("checks") !== undefined,
    });
  });

  sleep(0.5 + Math.random() * 1.5); // 0.5-2s think time
}
