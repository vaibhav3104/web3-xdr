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

