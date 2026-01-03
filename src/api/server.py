"""
FastAPI Server for Web3 XDR Dashboard API.
"""

import os
from typing import Optional
import asyncio
import structlog
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from .routes import router
from .admin_routes import router as admin_router
from .auth_routes import router as auth_router
from .metrics_routes import router as metrics_router
from .ai_routes import router as ai_router

logger = structlog.get_logger()

# Get frontend directory path
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")


def create_app(
    title: str = "Web3 XDR API",
    version: str = "1.0.0",
    cors_origins: Optional[list] = None
) -> FastAPI:
    """
    Create and configure FastAPI application.
    """
    app = FastAPI(
        title=title,
        description="Explainable Web3 XDR - Cross-Chain Bridge Security",
        version=version,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
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
    
    # Health check
    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": "web3-xdr"}
    
    # Serve analytics dashboard
    @app.get("/frontend/dashboard.html")
    async def serve_dashboard():
        return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))
    
    # Mount static files (for CSS, JS, etc.)
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

