"""
REST API for Web3 XDR Dashboard.
"""

from .server import create_app, run_server
from .routes import router

__all__ = ["create_app", "run_server", "router"]

# CI/CD trigger - Tue Jan  6 00:11:18 IST 2026
