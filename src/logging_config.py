"""
Structured logging configuration for Cloud Logging integration.

Outputs JSON in production for log aggregation (Google Cloud Logging, ELK, etc).
Human-readable console output in development.
"""

import logging
import json
import os
import sys
from datetime import datetime, timezone
from contextvars import ContextVar

import structlog

# Context variables for request tracing
request_trace_id: ContextVar[str] = ContextVar('request_trace_id', default='')
request_correlation_id: ContextVar[str] = ContextVar('request_correlation_id', default='')
request_tenant_id: ContextVar[str] = ContextVar('request_tenant_id', default='')


class StructuredFormatter(logging.Formatter):
    """JSON formatter compatible with Google Cloud Logging."""

    # Map Python levels to Cloud Logging severity
    SEVERITY_MAP = {
        'DEBUG': 'DEBUG',
        'INFO': 'INFO',
        'WARNING': 'WARNING',
        'ERROR': 'ERROR',
        'CRITICAL': 'CRITICAL',
    }

    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": self.SEVERITY_MAP.get(record.levelname, 'DEFAULT'),
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add trace context from contextvars
        trace_id = request_trace_id.get('')
        if trace_id:
            project = os.getenv('GCP_PROJECT', 'web3-xdr')
            log_entry["logging.googleapis.com/trace"] = f"projects/{project}/traces/{trace_id}"
            log_entry["trace_id"] = trace_id

        correlation_id = request_correlation_id.get('')
        if correlation_id:
            log_entry["correlation_id"] = correlation_id

        tenant_id = request_tenant_id.get('')
        if tenant_id:
            log_entry["tenant_id"] = tenant_id

        # Add extra fields from structlog-style kwargs
        if hasattr(record, '_extra'):
            log_entry.update(record._extra)

        # Add exception info
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }

        return json.dumps(log_entry, default=str)


def setup_logging(level: str = None):
    """Configure stdlib logging with structured JSON (prod) or readable (dev) output."""
    env = os.getenv("ENVIRONMENT", "development")
    level = level or os.getenv("LOG_LEVEL", "INFO")

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)

    if env == "production":
        handler.setFormatter(StructuredFormatter())
    else:
        # Dev: readable format with trace ID
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s:%(funcName)s:%(lineno)d — %(message)s'
        ))

    root.addHandler(handler)

    # Quiet noisy libraries
    for lib in ('uvicorn.access', 'httpcore', 'httpx', 'asyncio'):
        logging.getLogger(lib).setLevel(logging.WARNING)


def configure_logging():
    """Configure structlog and stdlib logging based on environment."""
    is_prod = os.getenv("ENVIRONMENT") == "production"

    # Set up stdlib logging first
    setup_logging()

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if is_prod:
        # JSON output for log aggregation
        shared_processors.append(structlog.processors.JSONRenderer())
    else:
        # Human-readable for development
        shared_processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=shared_processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
