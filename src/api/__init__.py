"""
REST API for Web3 XDR Dashboard.
"""

from .server import create_app, run_server
from .routes import router

__all__ = ["create_app", "run_server", "router"]

