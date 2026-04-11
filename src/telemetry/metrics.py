"""
Prometheus Metrics for Sentinel3 Worker & RPC
=============================================

Phase 2: Metrics for ingestion, RPC, finality, and event bus.
"""

from prometheus_client import Counter, Histogram, Gauge
import structlog

logger = structlog.get_logger(__name__)

# Event ingestion metrics
events_ingested_total = Counter(
    "sentinel3_events_ingested_total",
    "Total number of events ingested from chains",
    ["chain", "status"]  # status: pending, confirmed, dropped
)

# RPC metrics
rpc_latency_seconds = Histogram(
    "sentinel3_rpc_latency_seconds",
    "RPC request latency in seconds",
    ["chain", "endpoint", "method"],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
)

rpc_errors_total = Counter(
    "sentinel3_rpc_errors_total",
    "Total RPC errors",
    ["chain", "endpoint", "error_type"]
)

rpc_requests_total = Counter(
    "sentinel3_rpc_requests_total",
    "Total RPC requests",
    ["chain", "endpoint", "method", "status"]  # status: success, error
)

# Head lag metrics
head_lag_blocks = Gauge(
    "sentinel3_head_lag_blocks",
    "Number of blocks behind chain head",
    ["chain"]
)

chain_head_height = Gauge(
    "sentinel3_chain_head_height",
    "Current chain head block height",
    ["chain"]
)

worker_processed_height = Gauge(
    "sentinel3_worker_processed_height",
    "Last processed block height by worker",
    ["chain"]
)

# Event bus metrics
bus_queue_depth = Gauge(
    "sentinel3_bus_queue_depth",
    "Current event bus queue depth",
    ["bus_type"]  # bus_type: redis, memory
)

bus_events_published_total = Counter(
    "sentinel3_bus_events_published_total",
    "Total events published to bus",
    ["bus_type"]
)

bus_events_consumed_total = Counter(
    "sentinel3_bus_events_consumed_total",
    "Total events consumed from bus",
    ["bus_type"]
)

bus_publish_errors_total = Counter(
    "sentinel3_bus_publish_errors_total",
    "Total bus publish errors",
    ["bus_type", "error_type"]
)

# Finality metrics
finality_confirmed_blocks = Gauge(
    "sentinel3_finality_confirmed_blocks",
    "Last confirmed block number (beyond finality threshold)",
    ["chain"]
)

finality_reorgs_total = Counter(
    "sentinel3_finality_reorgs_total",
    "Total reorgs detected",
    ["chain"]
)

# Worker metrics
worker_uptime_seconds = Gauge(
    "sentinel3_worker_uptime_seconds",
    "Worker uptime in seconds"
)

worker_events_processed_total = Counter(
    "sentinel3_worker_events_processed_total",
    "Total events processed by worker",
    ["chain", "status"]
)

worker_processing_duration_seconds = Histogram(
    "sentinel3_worker_processing_duration_seconds",
    "Event processing duration",
    ["chain", "event_type"],
    buckets=[0.001, 0.01, 0.1, 0.5, 1.0, 5.0]
)

# Runtime Security Plane metrics
runtime_simulations_total = Counter(
    "sentinel3_runtime_simulations_total",
    "Total number of simulations run",
    ["chain", "mode", "result"]  # mode: FAST/FULL/BUNDLE, result: SUCCESS/FAILED/TIMEOUT
)

runtime_simulation_duration_ms = Histogram(
    "sentinel3_runtime_simulation_duration_ms",
    "Simulation duration in milliseconds",
    ["chain", "mode"],
    buckets=[10, 50, 100, 500, 1000, 5000, 10000]
)

runtime_risk_router_decisions_total = Counter(
    "sentinel3_runtime_risk_router_decisions_total",
    "Total risk router decisions",
    ["chain", "decision"]  # decision: IGNORE/HOT_ONLY/SIM_FAST/SIM_FULL/TRACE
)

runtime_budget_drops_total = Counter(
    "sentinel3_runtime_budget_drops_total",
    "Total simulations dropped due to budget limits",
    ["chain", "reason"]  # reason: chain_budget_exceeded/protocol_budget_exceeded
)

predicted_incidents_total = Counter(
    "sentinel3_predicted_incidents_total",
    "Total predicted incidents created",
    ["severity", "status"]  # severity: LOW/MEDIUM/HIGH/CRITICAL, status: OPEN/DISMISSED/CONFIRMED_MATCH/CONFIRMED_MISMATCH
)

predicted_to_confirmed_match_rate = Gauge(
    "sentinel3_predicted_to_confirmed_match_rate",
    "Rate of predicted incidents that matched confirmed incidents",
    ["chain"]
)

# =============================================================
# Incident & Detection Metrics
# =============================================================

incidents_created_total = Counter(
    "sentinel3_incidents_created_total",
    "Total incidents created",
    ["severity", "source"]  # source: rule, ml, invariant
)

incidents_active = Gauge(
    "sentinel3_incidents_active",
    "Currently active (unresolved) incidents",
    ["severity"]
)

rule_evaluations_total = Counter(
    "sentinel3_rule_evaluations_total",
    "Total rule evaluations",
    ["rule_id", "result"]  # result: match, no_match
)

invariant_violations_total = Counter(
    "sentinel3_invariant_violations_total",
    "Total invariant violations detected",
    ["invariant_type", "bridge_id"]
)

invariant_checks_total = Counter(
    "sentinel3_invariant_checks_total",
    "Total invariant checks run",
    ["invariant_type"]
)

# =============================================================
# Circuit Breaker Metrics
# =============================================================

circuit_breaker_state = Gauge(
    "sentinel3_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=open, 2=half_open)",
    ["chain"]
)

circuit_breaker_trips_total = Counter(
    "sentinel3_circuit_breaker_trips_total",
    "Total circuit breaker trips (closed -> open)",
    ["chain"]
)

# =============================================================
# Alert Delivery Metrics
# =============================================================

alerts_sent_total = Counter(
    "sentinel3_alerts_sent_total",
    "Total alert notifications sent",
    ["channel", "severity"]  # channel: slack, telegram
)

alerts_failed_total = Counter(
    "sentinel3_alerts_failed_total",
    "Total alert delivery failures",
    ["channel", "error_type"]
)

# =============================================================
# DB & Pool Metrics
# =============================================================

db_operations_total = Counter(
    "sentinel3_db_operations_total",
    "Total database operations",
    ["operation"]  # operation: save_event, save_incident, query_incidents
)

db_operation_duration_seconds = Histogram(
    "sentinel3_db_operation_duration_seconds",
    "Database operation duration",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
)

db_errors_total = Counter(
    "sentinel3_db_errors_total",
    "Total database errors",
    ["operation", "error_type"]
)

