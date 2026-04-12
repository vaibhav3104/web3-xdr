"""
Security Middleware for Sentinel3 API
Implements rate limiting, API key validation, and security headers
"""

import os
import time
import hashlib
import uuid
from typing import Dict, Optional, Callable
from collections import defaultdict
from datetime import datetime, timezone
import asyncio
import structlog

from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = structlog.get_logger(__name__)

# ============================================================================
# Rate Limiting
# ============================================================================

class RateLimiter:
    """
    Redis-backed sliding window rate limiter with in-memory fallback.
    Uses sorted sets in Redis for distributed, replica-safe rate limiting.
    Falls back to in-memory when Redis is unavailable.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        burst_limit: int = 10
    ):
        self.rpm = requests_per_minute
        self.rph = requests_per_hour
        self.burst = burst_limit

        # In-memory fallback
        self._mem_minute: Dict[str, list] = defaultdict(list)
        self._mem_hour: Dict[str, list] = defaultdict(list)
        self._lock = asyncio.Lock()

        # Redis (lazy init)
        self._redis = None
        self._redis_failed = False

    async def _get_redis(self):
        if self._redis_failed:
            return None
        if self._redis is not None:
            return self._redis
        try:
            import redis.asyncio as aioredis
            url = os.getenv("REDIS_URL", "redis://localhost:6379")
            self._redis = aioredis.from_url(url, decode_responses=True)
            await self._redis.ping()
            logger.info("rate_limiter_redis_connected")
            return self._redis
        except Exception as e:
            logger.warning("rate_limiter_redis_fallback", error=str(e))
            self._redis_failed = True
            return None

    async def _check_redis(self, client_ip: str, now: float) -> tuple[bool, dict]:
        """Check rate limits using Redis sorted sets."""
        r = await self._get_redis()
        if not r:
            return await self._check_memory(client_ip, now)

        try:
            minute_key = f"rl:m:{client_ip}"
            hour_key = f"rl:h:{client_ip}"
            pipe = r.pipeline()

            # Remove expired entries and count
            pipe.zremrangebyscore(minute_key, 0, now - 60)
            pipe.zremrangebyscore(hour_key, 0, now - 3600)
            pipe.zcard(minute_key)
            pipe.zcard(hour_key)
            results = await pipe.execute()
            minute_count = results[2]
            hour_count = results[3]

            if minute_count >= self.rpm:
                return False, {"error": "rate_limit_exceeded", "limit": "per_minute", "retry_after": 60}
            if hour_count >= self.rph:
                return False, {"error": "rate_limit_exceeded", "limit": "per_hour", "retry_after": 3600}

            # Record this request
            pipe2 = r.pipeline()
            pipe2.zadd(minute_key, {str(now): now})
            pipe2.expire(minute_key, 120)
            pipe2.zadd(hour_key, {str(now): now})
            pipe2.expire(hour_key, 7200)
            await pipe2.execute()

            return True, {
                "remaining_minute": self.rpm - minute_count - 1,
                "remaining_hour": self.rph - hour_count - 1
            }
        except Exception:
            # Redis error — fall back to memory
            return await self._check_memory(client_ip, now)

    async def _check_memory(self, client_ip: str, now: float) -> tuple[bool, dict]:
        """Fallback in-memory rate limiting."""
        async with self._lock:
            self._mem_minute[client_ip] = [t for t in self._mem_minute[client_ip] if t > now - 60]
            self._mem_hour[client_ip] = [t for t in self._mem_hour[client_ip] if t > now - 3600]

            mc = len(self._mem_minute[client_ip])
            hc = len(self._mem_hour[client_ip])

            if mc >= self.rpm:
                return False, {"error": "rate_limit_exceeded", "limit": "per_minute", "retry_after": 60}
            if hc >= self.rph:
                return False, {"error": "rate_limit_exceeded", "limit": "per_hour", "retry_after": 3600}

            self._mem_minute[client_ip].append(now)
            self._mem_hour[client_ip].append(now)
            return True, {"remaining_minute": self.rpm - mc - 1, "remaining_hour": self.rph - hc - 1}

    async def is_allowed(self, client_ip: str) -> tuple[bool, dict]:
        return await self._check_redis(client_ip, time.time())


# Global rate limiter instance
rate_limiter = RateLimiter(
    requests_per_minute=int(os.getenv("RATE_LIMIT_RPM", "300")),
    requests_per_hour=int(os.getenv("RATE_LIMIT_RPH", "10000")),
    burst_limit=int(os.getenv("RATE_LIMIT_BURST", "20"))
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce rate limits
    """
    
    # Paths exempt from rate limiting
    EXEMPT_PATHS = {
        "/health",
        "/metrics",
        "/ws",
        "/ws/events",
        "/ws/incidents",
        "/ws/alerts",
    }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Check forwarded headers (for load balancers)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

        # --- Per-key rate limiting ---
        # If the request carries an API key, apply per-key limits from APIKeyManager
        api_key_raw = request.headers.get("X-API-Key") or ""
        if not api_key_raw:
            auth = request.headers.get("Authorization") or ""
            if auth.startswith("Bearer "):
                api_key_raw = auth[7:]

        if api_key_raw and api_key_raw.startswith("s3_"):
            try:
                from src.api.api_keys import api_key_manager
                is_valid, api_key_obj, err = api_key_manager.validate_key(api_key_raw, client_ip=client_ip)
                if not is_valid:
                    return Response(
                        content='{"error": "' + err + '"}',
                        status_code=401 if "Invalid" in err else 429 if "Rate limit" in err else 403,
                        headers={"Content-Type": "application/json"}
                    )
                # Per-key validation passed (includes built-in rate limit check)
                response = await call_next(request)
                response.headers["X-RateLimit-Limit"] = str(api_key_obj.rate_limit_requests)
                remaining = max(0, api_key_obj.rate_limit_requests - api_key_obj.requests_this_window)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                return response
            except Exception:
                pass  # Fall through to IP-based limiting

        # --- IP-based rate limiting (no API key) ---
        allowed, info = await rate_limiter.is_allowed(client_ip)

        if not allowed:
            logger.warning(
                "rate_limit_exceeded",
                client_ip=client_ip,
                path=request.url.path,
                **info
            )
            return Response(
                content='{"error": "Rate limit exceeded", "retry_after": ' + str(int(info.get("retry_after", 60))) + '}',
                status_code=429,
                headers={
                    "Content-Type": "application/json",
                    "Retry-After": str(int(info.get("retry_after", 60))),
                    "X-RateLimit-Limit": str(rate_limiter.rpm),
                    "X-RateLimit-Remaining": "0"
                }
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(rate_limiter.rpm)
        response.headers["X-RateLimit-Remaining"] = str(info.get("remaining_minute", 0))

        return response


# ============================================================================
# Security Headers
# ============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses
    """

    # CSP allows our CDN scripts (Tailwind, Alpine, Chart.js, D3, DOMPurify, Google Fonts)
    CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com "
        "https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://d3js.org; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none';"
    )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = self.CSP

        # Prevent caching of HTML/JS so browser always gets latest
        path = request.url.path
        if path.endswith(('.html', '.js')) or path == '/':
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        # HSTS (only in production)
        if os.getenv("ENVIRONMENT") == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


# ============================================================================
# API Key Authentication
# ============================================================================

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_token = HTTPBearer(auto_error=False)

# In-memory API key store (in production, use database)
API_KEYS: Dict[str, dict] = {
    # Format: "api_key_hash": {"name": "client_name", "scopes": ["read", "write"], "rate_limit": 1000}
}

def hash_api_key(key: str) -> str:
    """Hash an API key for storage"""
    return hashlib.sha256(key.encode()).hexdigest()


def register_api_key(key: str, name: str, scopes: list = None, rate_limit: int = 1000):
    """Register a new API key"""
    key_hash = hash_api_key(key)
    API_KEYS[key_hash] = {
        "name": name,
        "scopes": scopes or ["read"],
        "rate_limit": rate_limit,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    logger.info("api_key_registered", name=name, scopes=scopes)


async def validate_api_key(
    api_key: Optional[str] = Depends(api_key_header),
    bearer: Optional[str] = Depends(bearer_token)
) -> Optional[dict]:
    """
    Validate API key from header or bearer token
    Returns client info if valid, None if no key provided
    Raises HTTPException if invalid key
    """
    key = api_key
    if not key and bearer:
        key = bearer.credentials
    
    if not key:
        return None  # No key provided (might be public endpoint)
    
    key_hash = hash_api_key(key)
    
    if key_hash not in API_KEYS:
        logger.warning("invalid_api_key_attempt", key_prefix=key[:8] if len(key) > 8 else "***")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    return API_KEYS[key_hash]


def require_api_key(scopes: list = None):
    """
    Dependency that requires a valid API key with specific scopes
    
    Usage:
        @app.get("/protected")
        async def protected_endpoint(client: dict = Depends(require_api_key(["admin"]))):
            ...
    """
    async def dependency(client: Optional[dict] = Depends(validate_api_key)):
        if client is None:
            raise HTTPException(
                status_code=401,
                detail="API key required"
            )
        
        if scopes:
            client_scopes = set(client.get("scopes", []))
            required_scopes = set(scopes)
            
            if not required_scopes.issubset(client_scopes):
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions. Required scopes: {scopes}"
                )
        
        return client
    
    return dependency


# ============================================================================
# Error Sanitization
# ============================================================================

class ErrorSanitizationMiddleware(BaseHTTPMiddleware):
    """
    Catches unhandled exceptions and returns sanitized JSON errors.
    In production, stack traces are never exposed.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:
            import traceback
            import json
            import uuid

            error_id = uuid.uuid4().hex[:12]
            is_prod = os.getenv("ENVIRONMENT") == "production"

            logger.error(
                "unhandled_exception",
                error_id=error_id,
                path=request.url.path,
                method=request.method,
                error=str(exc),
                traceback=traceback.format_exc() if not is_prod else None
            )

            body = {
                "error": "internal_server_error",
                "message": "An unexpected error occurred." if is_prod else str(exc),
                "error_id": error_id,
            }

            return Response(
                content=json.dumps(body),
                status_code=500,
                media_type="application/json"
            )


# ============================================================================
# Request Logging
# ============================================================================

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log all requests for audit trail
    """
    
    # Paths to exclude from logging
    EXCLUDE_PATHS = {"/health", "/metrics", "/favicon.ico"}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in self.EXCLUDE_PATHS:
            return await call_next(request)

        start_time = time.time()

        # Assign request ID for correlation
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:12])
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        # Get client info
        client_ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

        # Process request
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        
        # Track Prometheus metrics
        try:
            from src.metrics import track_api_request
            # Normalize path to avoid high-cardinality labels
            path = request.url.path
            # Collapse IDs: /api/incidents/abc123 → /api/incidents/{id}
            parts = path.strip("/").split("/")
            normalized = []
            for i, part in enumerate(parts):
                if i > 0 and len(part) > 20:
                    normalized.append("{id}")
                elif part.startswith("0x") and len(part) > 10:
                    normalized.append("{address}")
                else:
                    normalized.append(part)
            norm_path = "/" + "/".join(normalized)
            track_api_request(request.method, norm_path, response.status_code, duration_ms / 1000.0)
        except Exception:
            pass

        # Log request
        logger.info(
            "api_request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round(duration_ms, 2),
            client_ip=client_ip,
            user_agent=request.headers.get("User-Agent", "")[:100]
        )

        return response


# ============================================================================
# Initialize default API keys
# ============================================================================

def init_default_api_keys():
    """Initialize default API keys from environment"""
    
    # Admin key from environment
    admin_key = os.getenv("ADMIN_API_KEY")
    if admin_key:
        register_api_key(admin_key, "admin", ["read", "write", "admin"], rate_limit=10000)
    
    # Read-only key from environment  
    readonly_key = os.getenv("READONLY_API_KEY")
    if readonly_key:
        register_api_key(readonly_key, "readonly", ["read"], rate_limit=5000)


# Initialize on module load
init_default_api_keys()
