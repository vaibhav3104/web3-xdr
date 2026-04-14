"""Tenant isolation middleware for multi-tenant SaaS."""
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Optional
import hashlib
import time

import structlog

logger = structlog.get_logger()


class TenantMiddleware(BaseHTTPMiddleware):
    """Extracts tenant context from API key or JWT and injects into request state."""

    # Paths that don't require tenant context
    PUBLIC_PATHS = {"/health", "/health/detailed", "/health/ready", "/metrics", "/login", "/api/auth"}

    async def dispatch(self, request: Request, call_next):
        # Skip tenant check for public paths and frontend
        path = request.url.path
        if any(path.startswith(p) for p in self.PUBLIC_PATHS) or not path.startswith("/api"):
            request.state.tenant_id = None
            request.state.tenant_tier = "enterprise"  # default for non-API
            request.state.tenant_scopes = []
            return await call_next(request)

        # Try to extract tenant from API key header
        api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
        if api_key:
            tenant = await self._resolve_from_api_key(api_key)
            if tenant:
                request.state.tenant_id = tenant["customer_id"]
                request.state.tenant_tier = tenant["tier"]
                request.state.tenant_scopes = tenant["scopes"]
                # Rate limiting per tier
                if not await self._check_rate_limit(tenant):
                    raise HTTPException(status_code=429, detail="Rate limit exceeded for your tier")
                return await call_next(request)

        # Try JWT token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            tenant = await self._resolve_from_jwt(token)
            if tenant:
                request.state.tenant_id = tenant.get("customer_id")
                request.state.tenant_tier = tenant.get("tier", "starter")
                request.state.tenant_scopes = tenant.get("scopes", [])
                return await call_next(request)

        # No tenant context -- allow but mark as unauthenticated
        request.state.tenant_id = None
        request.state.tenant_tier = "starter"
        request.state.tenant_scopes = []
        return await call_next(request)

    async def _resolve_from_api_key(self, api_key: str) -> Optional[dict]:
        """Look up tenant from API key."""
        try:
            from src.database.service import DatabaseService
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            return await DatabaseService.get_tenant_by_api_key(key_hash)
        except Exception as exc:
            logger.debug("tenant_resolve_api_key_failed", error=str(exc))
            return None

    async def _resolve_from_jwt(self, token: str) -> Optional[dict]:
        """Extract tenant info from JWT."""
        try:
            from src.auth.jwt_handler import jwt_handler
            token_data = jwt_handler.decode_token(token)
            if token_data is None:
                return None
            return {
                "customer_id": getattr(token_data, "customer_id", None),
                "tier": getattr(token_data, "tier", "starter"),
                "scopes": getattr(token_data, "scopes", []),
            }
        except Exception as exc:
            logger.debug("tenant_resolve_jwt_failed", error=str(exc))
            return None

    _rate_limit_cache: dict = {}

    async def _check_rate_limit(self, tenant: dict) -> bool:
        """Simple in-memory rate limiting per tenant tier."""
        tier_limits = {
            "starter": 100,      # requests per minute
            "pro": 500,
            "enterprise": 2000,
        }
        tenant_id = tenant["customer_id"]
        limit = tier_limits.get(tenant.get("tier", "starter"), 100)

        now = int(time.time() / 60)  # minute bucket
        key = f"{tenant_id}:{now}"

        count = self._rate_limit_cache.get(key, 0) + 1
        self._rate_limit_cache[key] = count

        # Clean old entries
        old_keys = [k for k in self._rate_limit_cache if not k.endswith(f":{now}")]
        for k in old_keys:
            self._rate_limit_cache.pop(k, None)

        return count <= limit


def get_tenant_id(request: Request) -> Optional[str]:
    """Helper to extract tenant_id from request state."""
    return getattr(request.state, "tenant_id", None)


def get_tenant_tier(request: Request) -> str:
    """Helper to extract tenant tier from request state."""
    return getattr(request.state, "tenant_tier", "starter")


def require_scope(request: Request, scope: str):
    """Check if tenant has required scope. Raises 403 if not."""
    scopes = getattr(request.state, "tenant_scopes", [])
    if scopes and scope not in scopes:
        raise HTTPException(status_code=403, detail=f"Missing scope: {scope}")
