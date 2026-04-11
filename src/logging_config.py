"""
Sentinel3 Structured Logging Configuration.

Outputs JSON in production for log aggregation (ELK, CloudWatch, etc).
Human-readable console output in development.
"""

import os
import structlog


def configure_logging():
    """Configure structlog based on environment."""
    is_prod = os.getenv("ENVIRONMENT") == "production"

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
