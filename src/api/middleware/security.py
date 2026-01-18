"""
Security Middleware for Sentinel3 API
Implements rate limiting, API key validation, and security headers
"""

import os
import time
import hashlib
from typing import Dict, Optional, Callable
from collections import defaultdict
from datetime import datetime, timedelta
import asyncio

from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import structlog

logger = structlog.get_logger(__name__)

# ============================================================================
# Rate Limiting
# ============================================================================

class RateLimiter:
    """
    Token bucket rate limiter with sliding window
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
        
        # Track requests per IP
        self.minute_requests: Dict[str, list] = defaultdict(list)
        self.hour_requests: Dict[str, list] = defaultdict(list)
        
        self._lock = asyncio.Lock()
    
    async def is_allowed(self, client_ip: str) -> tuple[bool, dict]:
        """
        Check if request is allowed under rate limits
        Returns (allowed, info_dict)
        """
        now = time.time()
        minute_ago = now - 60
        hour_ago = now - 3600
        
        async with self._lock:
            # Clean old entries
            self.minute_requests[client_ip] = [
                t for t in self.minute_requests[client_ip] if t > minute_ago
            ]
            self.hour_requests[client_ip] = [
                t for t in self.hour_requests[client_ip] if t > hour_ago
            ]
            
            minute_count = len(self.minute_requests[client_ip])
            hour_count = len(self.hour_requests[client_ip])
            
            # Check limits
            if minute_count >= self.rpm:
                return False, {
                    "error": "rate_limit_exceeded",
                    "limit": "per_minute",
                    "retry_after": 60 - (now - self.minute_requests[client_ip][0])
                }
            
            if hour_count >= self.rph:
                return False, {
                    "error": "rate_limit_exceeded", 
                    "limit": "per_hour",
                    "retry_after": 3600 - (now - self.hour_requests[client_ip][0])
                }
            
            # Allow and record
            self.minute_requests[client_ip].append(now)
            self.hour_requests[client_ip].append(now)
            
            return True, {
                "remaining_minute": self.rpm - minute_count - 1,
                "remaining_hour": self.rph - hour_count - 1
            }


# Global rate limiter instance
rate_limiter = RateLimiter(
    requests_per_minute=int(os.getenv("RATE_LIMIT_RPM", "120")),
    requests_per_hour=int(os.getenv("RATE_LIMIT_RPH", "3000")),
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
        
        # Check rate limit
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
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
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
        "created_at": datetime.utcnow().isoformat()
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
        
        # Get client info
        client_ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        
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
