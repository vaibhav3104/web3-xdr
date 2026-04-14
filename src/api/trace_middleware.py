"""
Request trace ID middleware for Cloud Logging correlation.

Extracts trace IDs from incoming headers (GCP Cloud Trace, generic X-Request-ID)
or generates new ones. Sets context variables so all log entries within a request
automatically include trace and correlation IDs.
"""

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

from ..logging_config import request_trace_id, request_correlation_id, request_tenant_id


class TraceMiddleware(BaseHTTPMiddleware):
    """Middleware that propagates trace/correlation IDs through request context."""

    async def dispatch(self, request: Request, call_next):
        # Extract or generate trace ID
        # GCP Cloud Trace header format: TRACE_ID/SPAN_ID;o=TRACE_TRUE
        cloud_trace = request.headers.get("X-Cloud-Trace-Context", "")
        trace_id = (
            cloud_trace.split("/")[0]
            or request.headers.get("X-Request-ID", "")
            or uuid.uuid4().hex
        )

        correlation_id = (
            request.headers.get("X-Correlation-ID", "")
            or uuid.uuid4().hex[:12]
        )

        tenant_id = getattr(request.state, "tenant_id", None) or ""

        # Set context vars so all downstream loggers include these fields
        trace_token = request_trace_id.set(trace_id)
        corr_token = request_correlation_id.set(correlation_id)
        tenant_token = request_tenant_id.set(str(tenant_id))

        try:
            response = await call_next(request)
            response.headers["X-Trace-ID"] = trace_id
            response.headers["X-Correlation-ID"] = correlation_id
            return response
        finally:
            request_trace_id.reset(trace_token)
            request_correlation_id.reset(corr_token)
            request_tenant_id.reset(tenant_token)
