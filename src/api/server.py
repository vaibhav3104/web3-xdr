"""
FastAPI Server for Sentinel3 XDR Dashboard API.
"""

import os
import importlib
from typing import Optional

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from ..logging_config import configure_logging
configure_logging()

logger = structlog.get_logger()

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")


def _try_import_router(module_path: str, attr: str = "router"):
    """Import a router from a module, returning None on ImportError."""
    try:
        mod = importlib.import_module(module_path, package="src.api")
        return getattr(mod, attr, None)
    except ImportError:
        return None


# ── Route registry ──────────────────────────────────────────────────
# (module_path, attribute, prefix, description)
# Prefix=None means the router defines its own prefix.
_CORE_ROUTES = [
    (".routes",           "router", "/api",  "core"),
    (".admin_routes",     "router", "/api",  "admin"),
    (".auth_routes",      "router", "/api",  "auth"),
    (".metrics_routes",   "router", None,    "metrics"),
    (".ai_routes",        "router", "/api",  "ai"),
    (".tenant_routes",    "router", "/api",  "tenants"),
    (".simulator_routes", "router", "/api",  "simulator"),
    (".guardian_routes",  "router", None,    "guardian"),
    (".parser_routes",    "router", None,    "parsers"),
    (".alert_routes",     "router", None,    "alerts"),
    (".contract_routes",  "router", "/api",  "contracts"),
    (".scorecard_routes", "router", None,    "scorecard"),
    (".analytics_routes", "router", "/api",  "analytics"),
]

_OPTIONAL_ROUTES = [
    (".protocol_routes",     "router", "/api",  "protocols"),
    (".public_api",          "router", "/api",  "public-api"),
    (".websocket_routes",    "router", None,    "websocket"),
    (".runtime_routes",      "router", None,    "runtime"),
    (".customer_routes",     "router", "/api",  "customers"),
    (".cross_chain_routes",  "router", "/api",  "cross-chain"),
    (".ml_routes",           "router", None,    "ml"),
    (".graph_routes",        "router", None,    "security-graph"),
    (".ml_threat_routes",    "router", None,    "ml-threat"),
    (".scanner_routes",      "router", "/api",  "scanner"),
    (".verification_routes", "router", None,    "verification"),
]


def create_app(
    title: str = "Sentinel3 API",
    version: str = "2.0.0",
    cors_origins: Optional[list] = None
) -> FastAPI:
    """Create and configure FastAPI application."""

    app = FastAPI(
        title=title,
        description=(
            "# Sentinel3 - Web3 Extended Detection & Response\n\n"
            "Real-time security monitoring for bridges, DeFi protocols, and EVM chains.\n\n"
            "## Authentication\n"
            "All `/v1/*` endpoints require an API key via `X-API-Key` header.\n\n"
            "## Rate Limits\n"
            "- **Free:** 100 req/min  |  **Pro:** 1,000 req/min  |  **Enterprise:** Custom\n\n"
            "Check `GET /api/v1/usage` for current usage.\n"
        ),
        version=version,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_tags=[
            {"name": "public-api", "description": "Partner API - wallet risk, contract threats"},
            {"name": "Incidents", "description": "Incident management and triage"},
            {"name": "Metrics", "description": "Prometheus metrics"},
        ],
    )

    # ── Startup ─────────────────────────────────────────────────────
    @app.on_event("startup")
    async def startup_event():
        try:
            from ..database.connection import DatabaseManager
            await DatabaseManager.initialize()
            await DatabaseManager.ensure_indexes()
            logger.info("database_initialized")
        except (ConnectionError, OSError, ImportError) as e:
            logger.error("database_init_failed", error=str(e))

        try:
            from ..shared_state import monitor_state
            monitor_state.set_start_time()
        except (ImportError, AttributeError):
            pass

        # Load API keys from database
        try:
            from .api_keys import api_key_manager
            loaded = await api_key_manager.load_from_db()
            logger.info("api_keys_loaded", count=loaded)
        except (ImportError, ConnectionError, OSError) as e:
            logger.warning("api_keys_load_failed", error=str(e))

        # Bootstrap TP/FP feedback loop from historical incident data
        try:
            import psycopg2
            from ..rules.feedback_loop import get_feedback_loop
            fl = get_feedback_loop()
            pg_password = os.getenv("POSTGRES_PASSWORD")
            if not pg_password:
                raise ValueError("POSTGRES_PASSWORD not set")
            pg_conn = psycopg2.connect(
                host=os.getenv("POSTGRES_HOST", "postgres"),
                port=os.getenv("POSTGRES_PORT", "5432"),
                dbname=os.getenv("POSTGRES_DB", "sentinel"),
                user=os.getenv("POSTGRES_USER", "sentinel"),
                password=pg_password,
            )
            loaded = fl.load_from_db(pg_conn.cursor())
            pg_conn.close()
            logger.info("feedback_loop_bootstrapped", feedbacks_loaded=loaded)
        except (ImportError, ConnectionError, OSError, ValueError) as e:
            logger.warning("feedback_loop_bootstrap_failed", error=str(e))

    # ── CORS ────────────────────────────────────────────────────────
    # All origins come from env; localhost defaults only in non-production
    env_cors = os.getenv("CORS_ALLOWED_ORIGINS", "")
    if env_cors:
        default_origins = [o.strip() for o in env_cors.split(",") if o.strip()]
    elif os.getenv("ENVIRONMENT", "").lower() == "production":
        # Production MUST set CORS_ALLOWED_ORIGINS explicitly
        default_origins = []
        logger.warning("cors_origins_not_configured", hint="Set CORS_ALLOWED_ORIGINS env var")
    else:
        # Development defaults only
        default_origins = [
            "http://localhost:3000", "http://localhost:8000", "http://localhost:8080",
            "http://127.0.0.1:3000", "http://127.0.0.1:8000", "http://127.0.0.1:8080",
        ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins or default_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
    )

    # ── Security middleware ──────────────────────────────────────────
    try:
        from .middleware.security import (
            RateLimitMiddleware, SecurityHeadersMiddleware,
            RequestLoggingMiddleware, ErrorSanitizationMiddleware
        )
        app.add_middleware(ErrorSanitizationMiddleware)
        app.add_middleware(SecurityHeadersMiddleware)
        if os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true":
            app.add_middleware(RateLimitMiddleware)
        if os.getenv("ENABLE_REQUEST_LOGGING", "true").lower() == "true":
            app.add_middleware(RequestLoggingMiddleware)
    except ImportError as e:
        logger.warning("security_middleware_unavailable", error=str(e))

    # ── Register routes ─────────────────────────────────────────────
    registered = []

    for module, attr, prefix, name in _CORE_ROUTES:
        r = _try_import_router(module, attr)
        if r:
            app.include_router(r, **({} if prefix is None else {"prefix": prefix}))
            registered.append(name)

    for module, attr, prefix, name in _OPTIONAL_ROUTES:
        r = _try_import_router(module, attr)
        if r:
            app.include_router(r, **({} if prefix is None else {"prefix": prefix}))
            registered.append(name)

    logger.info("routes_registered", count=len(registered), modules=registered)

    # ── OpenTelemetry tracing ──────────────────────────────────────────
    try:
        from ..telemetry.tracing import init_tracing
        init_tracing(app)
    except ImportError as e:
        logger.debug("otel_init_skipped", error=str(e))

    # ── Static routes ───────────────────────────────────────────────
    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "service": "sentinel3",
            "environment": os.getenv("ENVIRONMENT", "development"),
        }

    @app.get("/health/detailed")
    async def health_detailed():
        """Detailed health check for monitoring dashboards."""
        checks = {"postgres": "unknown", "redis": "unknown"}

        # Check Postgres
        try:
            from ..database.connection import DatabaseManager
            async with DatabaseManager.get_session() as session:
                from sqlalchemy import text
                await session.execute(text("SELECT 1"))
            checks["postgres"] = "connected"
        except (ConnectionError, OSError, ImportError, RuntimeError) as e:
            checks["postgres"] = f"error: {str(e)[:80]}"

        # Check Redis
        try:
            import redis.asyncio as aioredis
            url = os.getenv("REDIS_URL", "redis://localhost:6379")
            r = aioredis.from_url(url)
            await r.ping()
            await r.aclose()
            checks["redis"] = "connected"
        except (ConnectionError, OSError, ImportError, RuntimeError) as e:
            checks["redis"] = f"error: {str(e)[:80]}"

        all_ok = all(v == "connected" for v in checks.values())
        return {
            "status": "healthy" if all_ok else "degraded",
            "service": "sentinel3",
            "environment": os.getenv("ENVIRONMENT", "development"),
            "checks": checks,
        }

    @app.get("/health/ready")
    async def readiness_check():
        """K8s readiness probe — returns 503 if DB is unreachable."""
        try:
            from ..database.connection import DatabaseManager
            async with DatabaseManager.get_session() as session:
                from sqlalchemy import text
                await session.execute(text("SELECT 1"))
            return {"ready": True}
        except Exception:
            from starlette.responses import JSONResponse
            return JSONResponse({"ready": False}, status_code=503)

    @app.get("/docs", include_in_schema=False)
    async def docs_redirect():
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/api/docs")

    @app.get("/")
    async def serve_index():
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"status": "healthy", "service": "sentinel3", "dashboard": "frontend not found"}

    @app.get("/{page}.html")
    async def serve_frontend_page(page: str):
        if not all(c.isalnum() or c == '-' for c in page):
            raise HTTPException(status_code=404)
        file_path = os.path.join(FRONTEND_DIR, f"{page}.html")
        if os.path.exists(file_path):
            return FileResponse(file_path)
        raise HTTPException(status_code=404, detail=f"Page not found: {page}.html")

    if os.path.exists(FRONTEND_DIR):
        app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")

    return app


async def run_server(app: FastAPI, host: str = "0.0.0.0", port: int = 8080):
    """Run the API server."""
    workers = int(os.getenv("UVICORN_WORKERS", "1"))
    config = uvicorn.Config(
        app, host=host, port=port,
        log_level="info",
        workers=workers if workers > 1 else None,
        access_log=os.getenv("ENVIRONMENT") != "production",
    )
    server = uvicorn.Server(config)
    logger.info("starting_api_server", host=host, port=port, workers=workers)
    await server.serve()


def main():
    """Main entry point."""
    import asyncio
    app = create_app()
    asyncio.run(run_server(app))


if __name__ == "__main__":
    main()
