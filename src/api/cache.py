"""
Redis Cache for Sentinel3 API hot paths.

Provides get/set with TTL for caching expensive computations:
- Wallet risk scores (60s TTL)
- Incident counts/stats (30s TTL)
- Graph stats (120s TTL)

Falls back to in-memory dict if Redis is unavailable.
"""

import json
import os
import hashlib
from typing import Optional, Any
import structlog

logger = structlog.get_logger(__name__)

_redis = None
_fallback_cache: dict = {}  # in-memory fallback


async def _get_redis():
    """Lazy Redis connection."""
    global _redis
    if _redis is not None:
        return _redis

    redis_url = os.getenv("REDIS_URL", "")
    if not redis_url:
        return None

    try:
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(redis_url, decode_responses=True, socket_timeout=2)
        await _redis.ping()
        logger.info("redis_cache_connected", url=redis_url[:30])
        return _redis
    except Exception as e:
        logger.warning("redis_cache_unavailable", error=str(e)[:100])
        _redis = None
        return None


def _cache_key(prefix: str, *parts) -> str:
    """Build a cache key."""
    raw = ":".join(str(p) for p in parts)
    h = hashlib.md5(raw.encode()).hexdigest()[:12]
    return f"s3:{prefix}:{h}"


async def cache_get(prefix: str, *key_parts) -> Optional[Any]:
    """Get a value from cache. Returns None on miss."""
    key = _cache_key(prefix, *key_parts)

    r = await _get_redis()
    if r:
        try:
            val = await r.get(key)
            if val:
                return json.loads(val)
        except Exception:
            pass

    # Fallback: in-memory
    import time
    entry = _fallback_cache.get(key)
    if entry and entry["exp"] > time.time():
        return entry["val"]
    return None


async def cache_set(prefix: str, *key_parts, value: Any, ttl: int = 60):
    """Set a value in cache with TTL in seconds."""
    key = _cache_key(prefix, *key_parts)
    serialized = json.dumps(value)

    r = await _get_redis()
    if r:
        try:
            await r.setex(key, ttl, serialized)
            return
        except Exception:
            pass

    # Fallback: in-memory
    import time
    _fallback_cache[key] = {"val": value, "exp": time.time() + ttl}

    # Evict old entries if cache grows too large
    if len(_fallback_cache) > 1000:
        now = time.time()
        expired = [k for k, v in _fallback_cache.items() if v["exp"] < now]
        for k in expired:
            del _fallback_cache[k]
