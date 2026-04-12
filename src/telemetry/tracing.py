"""
OpenTelemetry Distributed Tracing for Sentinel3
================================================

Initializes OTLP tracing with FastAPI and async instrumentation.
Exports to any OTLP-compatible collector (Jaeger, Tempo, etc.).

Usage:
    from src.telemetry.tracing import init_tracing
    init_tracing(app)  # Call once during FastAPI startup
"""

import os
import structlog

logger = structlog.get_logger(__name__)


def init_tracing(app=None, service_name: str = "sentinel3"):
    """
    Initialize OpenTelemetry tracing.

    Reads configuration from environment variables:
      - OTEL_EXPORTER_OTLP_ENDPOINT: Collector endpoint (default: none / noop)
      - OTEL_SERVICE_NAME: Override service name
      - ENVIRONMENT: Added as resource attribute
      - OTEL_TRACES_SAMPLER_ARG: Sampling ratio (default: 1.0 in dev, 0.1 in prod)
    """
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    env = os.getenv("ENVIRONMENT", "development")
    service = os.getenv("OTEL_SERVICE_NAME", service_name)

    if not endpoint:
        logger.info("otel_tracing_disabled", reason="OTEL_EXPORTER_OTLP_ENDPOINT not set")
        return None

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

        # Sampling: lower in production to control volume
        default_ratio = 0.1 if env == "production" else 1.0
        sample_ratio = float(os.getenv("OTEL_TRACES_SAMPLER_ARG", str(default_ratio)))
        sampler = TraceIdRatioBased(sample_ratio)

        resource = Resource.create({
            SERVICE_NAME: service,
            "deployment.environment": env,
            "service.version": os.getenv("APP_VERSION", "2.0.0"),
        })

        provider = TracerProvider(resource=resource, sampler=sampler)
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=endpoint.startswith("http://"))
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        # Instrument FastAPI if app is provided
        if app:
            try:
                from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
                FastAPIInstrumentor.instrument_app(app)
                logger.info("otel_fastapi_instrumented")
            except ImportError:
                logger.debug("opentelemetry-instrumentation-fastapi not installed, skipping")

        # Instrument aiohttp client (used by alert_notifier)
        try:
            from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
            AioHttpClientInstrumentor().instrument()
        except ImportError:
            pass

        # Instrument SQLAlchemy (used for DB queries)
        try:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
            SQLAlchemyInstrumentor().instrument()
        except ImportError:
            pass

        logger.info(
            "otel_tracing_initialized",
            endpoint=endpoint,
            service=service,
            sample_ratio=sample_ratio,
        )
        return provider

    except ImportError as e:
        logger.warning("otel_tracing_init_failed", error=str(e), hint="pip install opentelemetry-exporter-otlp-proto-grpc")
        return None
    except Exception as e:
        logger.error("otel_tracing_init_error", error=str(e))
        return None


def get_tracer(name: str = "sentinel3"):
    """Get a tracer instance for manual span creation."""
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        return None
