"""
FastAPI Server for Sentinel3 XDR Dashboard API.
"""

import os
from typing import Optional
import asyncio
import structlog
from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from .routes import router
from .admin_routes import router as admin_router
from .auth_routes import router as auth_router
from .metrics_routes import router as metrics_router
from .ai_routes import router as ai_router
from .tenant_routes import router as tenant_router
from .simulator_routes import router as simulator_router
from .guardian_routes import router as guardian_router
from .parser_routes import router as parser_router
from .alert_routes import router as alert_router
from .contract_routes import router as contract_router
from .scorecard_routes import router as scorecard_router
from .analytics_routes import router as analytics_router

# Protocol monitoring routes
try:
    from .protocol_routes import router as protocol_router
    PROTOCOL_ROUTES_AVAILABLE = True
except ImportError:
    PROTOCOL_ROUTES_AVAILABLE = False
    protocol_router = None

# Public API routes
try:
    from .public_api import router as public_api_router
    PUBLIC_API_AVAILABLE = True
except ImportError:
    PUBLIC_API_AVAILABLE = False
    public_api_router = None

# WebSocket real-time feed
try:
    from .websocket_routes import router as websocket_router, get_ws_manager
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False
    websocket_router = None

# Runtime Security Plane routes
try:
    from .runtime_routes import router as runtime_router
    RUNTIME_ROUTES_AVAILABLE = True
except ImportError:
    RUNTIME_ROUTES_AVAILABLE = False
    runtime_router = None

# Customer management and API keys
try:
    from .customer_routes import router as customer_router
    CUSTOMER_ROUTES_AVAILABLE = True
except ImportError:
    CUSTOMER_ROUTES_AVAILABLE = False
    customer_router = None

# Cross-chain correlation routes
try:
    from .cross_chain_routes import router as cross_chain_router
    CROSS_CHAIN_ROUTES_AVAILABLE = True
except ImportError:
    CROSS_CHAIN_ROUTES_AVAILABLE = False
    cross_chain_router = None

# ML/AI contract analysis routes
try:
    from .ml_routes import router as ml_router
    ML_ROUTES_AVAILABLE = True
except ImportError:
    ML_ROUTES_AVAILABLE = False
    ml_router = None

# Security Graph routes (Wiz-for-Web3)
try:
    from .graph_routes import router as graph_router, initialize_graph
    GRAPH_ROUTES_AVAILABLE = True
except ImportError:
    GRAPH_ROUTES_AVAILABLE = False
    graph_router = None
    initialize_graph = None

# ML Threat Detection routes
try:
    from .ml_threat_routes import router as ml_threat_router, initialize_ml_components
    ML_THREAT_ROUTES_AVAILABLE = True
except ImportError:
    ML_THREAT_ROUTES_AVAILABLE = False
    ml_threat_router = None

# Vulnerability Scanner routes
try:
    from .scanner_routes import router as scanner_router
    SCANNER_ROUTES_AVAILABLE = True
except ImportError:
    SCANNER_ROUTES_AVAILABLE = False
    scanner_router = None
    initialize_ml_components = None

# Verification routes (exploit tracking)
try:
    from .verification_routes import router as verification_router
    VERIFICATION_ROUTES_AVAILABLE = True
except ImportError:
    VERIFICATION_ROUTES_AVAILABLE = False
    verification_router = None

logger = structlog.get_logger()

# Get frontend directory path
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")


def create_app(
    title: str = "Sentinel3 API",
    version: str = "2.0.0",
    cors_origins: Optional[list] = None
) -> FastAPI:
    """
    Create and configure FastAPI application.
    """
    app = FastAPI(
        title=title,
        description="Sentinel3 - Web3 Extended Detection & Response for Bridges and DeFi",
        version=version,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )
    
    # Initialize database on startup
    @app.on_event("startup")
    async def startup_event():
        try:
            from ..database.connection import DatabaseManager
            await DatabaseManager.initialize()
            # Ensure indexes exist (safe to call multiple times)
            await DatabaseManager.ensure_indexes()
            logger.info("database_initialized_on_startup")
            
            # Set start time in shared state for uptime tracking
            from ..shared_state import monitor_state
            monitor_state.set_start_time()
            logger.info("api_start_time_set")
        except Exception as e:
            logger.error("database_initialization_failed", error=str(e))
    
    # CORS middleware - Restricted to allowed origins only
    # Security: Only allow requests from our own frontend and local development
    default_cors_origins = [
        # Production frontend (Cloud Run)
        "https://web3-xdr-production-api-1003459948096.us-central1.run.app",
        # GPU service
        "https://sentinel3-gpu-1003459948096.us-central1.run.app",
        # Local development
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8080",
    ]
    
    # Allow override via environment variable (comma-separated)
    env_cors = os.getenv("CORS_ALLOWED_ORIGINS", "")
    if env_cors:
        default_cors_origins.extend([origin.strip() for origin in env_cors.split(",") if origin.strip()])
    
    allowed_origins = cors_origins or default_cors_origins
    logger.info("cors_configured", allowed_origins=allowed_origins)
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
    )
    
    # Security middleware (rate limiting, headers, logging)
    try:
        from .middleware.security import (
            RateLimitMiddleware,
            SecurityHeadersMiddleware,
            RequestLoggingMiddleware
        )
        
        # Add security headers to all responses
        app.add_middleware(SecurityHeadersMiddleware)
        
        # Rate limiting (can be disabled via env var)
        if os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true":
            app.add_middleware(RateLimitMiddleware)
            logger.info("rate_limiting_enabled")
        
        # Request logging for audit trail
        if os.getenv("ENABLE_REQUEST_LOGGING", "true").lower() == "true":
            app.add_middleware(RequestLoggingMiddleware)
            logger.info("request_logging_enabled")
            
    except ImportError as e:
        logger.warning("security_middleware_not_loaded", error=str(e))
    
    # Include main API routes
    app.include_router(router, prefix="/api")
    
    # Include admin API routes
    app.include_router(admin_router, prefix="/api")
    
    # Include auth routes
    app.include_router(auth_router, prefix="/api")
    
    # Include metrics routes (no prefix - /metrics is standard)
    app.include_router(metrics_router)
    
    # Include AI analysis routes
    app.include_router(ai_router, prefix="/api")
    
    # Include multi-tenancy routes
    app.include_router(tenant_router, prefix="/api")
    
    # Include attack simulator routes
    app.include_router(simulator_router, prefix="/api")
    
    # Include guardian/auto-response routes
    app.include_router(guardian_router)
    
    # Include parser management routes
    app.include_router(parser_router)
    
    # Include ML/AI contract analysis routes
    if ML_ROUTES_AVAILABLE and ml_router:
        app.include_router(ml_router)
    
    # Include contract threat alert routes
    app.include_router(alert_router)
    
    # Include contract deployment detection routes
    app.include_router(contract_router, prefix="/api")
    
    # Include customer management and API key routes
    if CUSTOMER_ROUTES_AVAILABLE and customer_router:
        app.include_router(customer_router, prefix="/api")
    
    # Include cross-chain correlation routes
    if CROSS_CHAIN_ROUTES_AVAILABLE and cross_chain_router:
        app.include_router(cross_chain_router, prefix="/api")
    
    # Include Security Graph routes (Wiz-for-Web3)
    if GRAPH_ROUTES_AVAILABLE and graph_router:
        app.include_router(graph_router)
        logger.info("security_graph_routes_enabled")
    
    # Include ML Threat Detection routes
    if ML_THREAT_ROUTES_AVAILABLE and ml_threat_router:
        app.include_router(ml_threat_router)
        logger.info("ml_threat_detection_routes_enabled")
    
    # Include Runtime Security Plane routes
    if RUNTIME_ROUTES_AVAILABLE and runtime_router:
        app.include_router(runtime_router)
    
    # Include Scorecard/ROI routes
    app.include_router(scorecard_router)
    
    # Include Protocol monitoring routes
    if PROTOCOL_ROUTES_AVAILABLE and protocol_router:
        app.include_router(protocol_router, prefix="/api")
        logger.info("protocol_routes_registered")
    
    # Include Public API routes
    if PUBLIC_API_AVAILABLE and public_api_router:
        app.include_router(public_api_router, prefix="/api")
        logger.info("public_api_routes_registered")
    
    # Include Analytics routes
    app.include_router(analytics_router, prefix="/api")
    
    # Include WebSocket real-time feed
    if WEBSOCKET_AVAILABLE and websocket_router:
        app.include_router(websocket_router)
        logger.info("websocket_routes_registered")
    
    # Include Verification routes (exploit tracking)
    if VERIFICATION_ROUTES_AVAILABLE and verification_router:
        app.include_router(verification_router)
        logger.info("verification_routes_registered")
    
    # Include Vulnerability Scanner routes
    if SCANNER_ROUTES_AVAILABLE and scanner_router:
        app.include_router(scanner_router, prefix="/api")
        logger.info("vulnerability_scanner_routes_registered")
    
    # Health check
    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": "sentinel3"}
    
    # Serve frontend dashboard at root
    @app.get("/")
    async def serve_index():
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"status": "healthy", "service": "sentinel3", "dashboard": "frontend not found"}

    # Serve any .html file from frontend directory at root level
    @app.get("/{page}.html")
    async def serve_frontend_page(page: str):
        # Sanitize: only allow alphanumeric and hyphens
        if not all(c.isalnum() or c == '-' for c in page):
            raise HTTPException(status_code=404)
        file_path = os.path.join(FRONTEND_DIR, f"{page}.html")
        if os.path.exists(file_path):
            return FileResponse(file_path)
        raise HTTPException(status_code=404, detail=f"Page not found: {page}.html")

    # Mount frontend directory for static assets (JS, CSS, images)
    if os.path.exists(FRONTEND_DIR):
        app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")
    
    return app


async def run_server(
    app: FastAPI,
    host: str = "0.0.0.0",
    port: int = 8080
):
    """
    Run the API server.
    """
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    
    logger.info(
        "starting_api_server",
        host=host,
        port=port
    )
    
    await server.serve()


def main():
    """Main entry point for API server."""
    import asyncio
    
    app = create_app()
    asyncio.run(run_server(app))


if __name__ == "__main__":
    main()

