"""
Prometheus Metrics Collector for Sentinel3.

Provides comprehensive metrics for monitoring:
- Event processing
- Incident detection
- Rule triggers
- Chain connectivity
- API performance
"""

import time
from typing import Optional, Callable
from functools import wraps

from prometheus_client import (
    Counter, Gauge, Histogram, Summary, Info,
    REGISTRY, generate_latest, CONTENT_TYPE_LATEST
)
import structlog

logger = structlog.get_logger()


class XDRMetrics:
    """
    Centralized metrics collector for Sentinel3.
    """
    
    def __init__(self, namespace: str = "web3_xdr"):
        self.namespace = namespace
        
        # ============================================================
        # EVENT METRICS
        # ============================================================
        
        self.events_total = Counter(
            f"{namespace}_events_total",
            "Total number of blockchain events processed",
            ["chain", "event_type"]
        )
        
        self.events_per_second = Gauge(
            f"{namespace}_events_per_second",
            "Current events per second",
            ["chain"]
        )
        
        self.event_processing_time = Histogram(
            f"{namespace}_event_processing_seconds",
            "Time to process an event",
            ["chain"],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)
        )
        
        # ============================================================
        # INCIDENT METRICS
        # ============================================================
        
        self.incidents_total = Counter(
            f"{namespace}_incidents_total",
            "Total number of security incidents detected",
            ["severity", "chain", "rule_id"]
        )
        
        self.active_incidents = Gauge(
            f"{namespace}_active_incidents",
            "Number of currently active incidents",
            ["severity"]
        )
        
        self.incident_detection_time = Histogram(
            f"{namespace}_incident_detection_seconds",
            "Time from event to incident detection",
            ["severity"],
            buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)
        )
        
        # ============================================================
        # RULE METRICS
        # ============================================================
        
        self.rules_loaded = Gauge(
            f"{namespace}_rules_loaded",
            "Number of detection rules loaded",
            ["severity"]
        )
        
        self.rule_triggers_total = Counter(
            f"{namespace}_rule_triggers_total",
            "Total number of rule triggers",
            ["rule_id", "severity", "chain"]
        )
        
        self.rule_evaluation_time = Histogram(
            f"{namespace}_rule_evaluation_seconds",
            "Time to evaluate a rule",
            ["rule_id"],
            buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1)
        )
        
        self.false_positives = Counter(
            f"{namespace}_false_positives_total",
            "Number of false positives (manually marked)",
            ["rule_id"]
        )
        
        # ============================================================
        # CHAIN METRICS
        # ============================================================
        
        self.chain_connected = Gauge(
            f"{namespace}_chain_connected",
            "Whether chain is connected (1) or not (0)",
            ["chain"]
        )
        
        self.chain_block_height = Gauge(
            f"{namespace}_chain_block_height",
            "Current block height being monitored",
            ["chain"]
        )
        
        self.chain_latency = Histogram(
            f"{namespace}_chain_latency_seconds",
            "RPC call latency",
            ["chain"],
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
        )
        
        self.chain_errors = Counter(
            f"{namespace}_chain_errors_total",
            "Total RPC errors by chain",
            ["chain", "error_type"]
        )
        
        # ============================================================
        # API METRICS
        # ============================================================
        
        self.api_requests_total = Counter(
            f"{namespace}_api_requests_total",
            "Total API requests",
            ["method", "endpoint", "status"]
        )
        
        self.api_request_duration = Histogram(
            f"{namespace}_api_request_duration_seconds",
            "API request duration",
            ["method", "endpoint"],
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
        )
        
        self.api_active_connections = Gauge(
            f"{namespace}_api_active_connections",
            "Number of active API connections"
        )
        
        # ============================================================
        # SYSTEM METRICS
        # ============================================================
        
        self.uptime_seconds = Gauge(
            f"{namespace}_uptime_seconds",
            "System uptime in seconds"
        )
        
        self.memory_usage_bytes = Gauge(
            f"{namespace}_memory_usage_bytes",
            "Current memory usage"
        )
        
        self.queue_size = Gauge(
            f"{namespace}_queue_size",
            "Number of events in processing queue",
            ["queue_name"]
        )
        
        # ============================================================
        # ALERTING METRICS
        # ============================================================
        
        self.alerts_sent_total = Counter(
            f"{namespace}_alerts_sent_total",
            "Total alerts sent",
            ["channel", "severity"]
        )
        
        self.alert_failures = Counter(
            f"{namespace}_alert_failures_total",
            "Failed alert deliveries",
            ["channel", "error_type"]
        )
        
        # ============================================================
        # INFO METRIC
        # ============================================================
        
        self.info = Info(
            f"{namespace}_build",
            "Build information"
        )
        self.info.info({
            "version": "1.0.0",
            "component": "web3-xdr"
        })
        
        # Track start time for uptime
        self._start_time = time.time()
        
        logger.info("prometheus_metrics_initialized", namespace=namespace)
    
    def update_uptime(self):
        """Update the uptime gauge."""
        self.uptime_seconds.set(time.time() - self._start_time)
    
    def get_metrics(self) -> bytes:
        """Get all metrics in Prometheus format."""
        self.update_uptime()
        return generate_latest(REGISTRY)
    
    def get_content_type(self) -> str:
        """Get Prometheus content type."""
        return CONTENT_TYPE_LATEST


# Global metrics instance
metrics = XDRMetrics()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def track_event(chain: str, event_type: str, processing_time: Optional[float] = None):
    """Track a processed event."""
    metrics.events_total.labels(chain=chain, event_type=event_type).inc()
    if processing_time is not None:
        metrics.event_processing_time.labels(chain=chain).observe(processing_time)


def track_incident(
    severity: str,
    chain: str,
    rule_id: str,
    detection_time: Optional[float] = None
):
    """Track a detected incident."""
    metrics.incidents_total.labels(
        severity=severity,
        chain=chain,
        rule_id=rule_id
    ).inc()
    
    if detection_time is not None:
        metrics.incident_detection_time.labels(severity=severity).observe(detection_time)


def track_rule_trigger(rule_id: str, severity: str, chain: str):
    """Track a rule trigger."""
    metrics.rule_triggers_total.labels(
        rule_id=rule_id,
        severity=severity,
        chain=chain
    ).inc()


def track_chain_status(
    chain: str,
    connected: bool,
    block_height: Optional[int] = None,
    latency: Optional[float] = None
):
    """Track chain connection status."""
    metrics.chain_connected.labels(chain=chain).set(1 if connected else 0)
    
    if block_height is not None:
        metrics.chain_block_height.labels(chain=chain).set(block_height)
    
    if latency is not None:
        metrics.chain_latency.labels(chain=chain).observe(latency)


def track_api_request(method: str, endpoint: str, status: int, duration: float):
    """Track an API request."""
    metrics.api_requests_total.labels(
        method=method,
        endpoint=endpoint,
        status=str(status)
    ).inc()
    
    metrics.api_request_duration.labels(
        method=method,
        endpoint=endpoint
    ).observe(duration)


# ============================================================
# DECORATORS
# ============================================================

def measure_time(metric_name: str = "operation"):
    """Decorator to measure execution time."""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                return func(*args, **kwargs)
            finally:
                duration = time.time() - start
                logger.debug(
                    f"{metric_name}_duration",
                    duration=duration,
                    function=func.__name__
                )
        return wrapper
    return decorator


def async_measure_time(metric_name: str = "operation"):
    """Async decorator to measure execution time."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start = time.time()
            try:
                return await func(*args, **kwargs)
            finally:
                duration = time.time() - start
                logger.debug(
                    f"{metric_name}_duration",
                    duration=duration,
                    function=func.__name__
                )
        return wrapper
    return decorator

