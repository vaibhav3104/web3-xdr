"""
Redis State Manager for Distributed Cross-Chain Correlation
============================================================

This module provides a Redis-backed state manager that enables:
1. Distributed state sharing across multiple instances
2. Atomic operations for Lock/Mint parity checking (Lua scripts)
3. TTL-based event expiration (24 hours default)
4. High-performance indexing by bridge_id, chain, amount

CRITICAL: This replaces in-memory dictionaries for production scaling.
"""

import os
import json
import hashlib
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import structlog

# Redis async client
try:
    import redis.asyncio as aioredis
    from redis.asyncio import Redis
    from redis.exceptions import ConnectionError, TimeoutError as RedisTimeoutError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None
    Redis = None

logger = structlog.get_logger(__name__)

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_MAX_CONNECTIONS = int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))
EVENT_TTL_HOURS = int(os.getenv("EVENT_TTL_HOURS", "24"))
DEFAULT_CORRELATION_WINDOW_MINUTES = int(os.getenv("CORRELATION_WINDOW_MINUTES", "30"))

# Redis key prefixes (namespace isolation)
class RedisKeys:
    """Redis key patterns for different data types."""
    # Events
    EVENT = "sentinel3:event:{event_id}"                    # Hash: event data
    EVENTS_BY_CHAIN = "sentinel3:events:chain:{chain_id}"   # Sorted Set: score=timestamp
    EVENTS_BY_BRIDGE = "sentinel3:events:bridge:{bridge_id}" # Sorted Set: score=timestamp
    EVENTS_BY_TYPE = "sentinel3:events:type:{event_type}"    # Sorted Set
    
    # Cross-chain correlation
    PENDING_LOCKS = "sentinel3:correlation:locks:{key}"      # Sorted Set: score=timestamp
    PENDING_MINTS = "sentinel3:correlation:mints:{key}"      # Sorted Set: score=timestamp
    LOCK_DATA = "sentinel3:correlation:lock_data:{event_id}" # Hash: event details
    MINT_DATA = "sentinel3:correlation:mint_data:{event_id}" # Hash: event details
    CORRELATIONS = "sentinel3:correlations:{correlation_id}" # Hash: correlation pair
    PROCESSED_MESSAGES = "sentinel3:processed_messages"      # Set: message IDs
    MESSAGE_SEQUENCES = "sentinel3:sequences:{bridge_id}"    # String: last sequence
    
    # Violations
    VIOLATIONS = "sentinel3:violations"                      # Sorted Set: score=timestamp
    VIOLATION_DATA = "sentinel3:violation:{violation_id}"    # Hash: violation details
    
    # Incidents
    INCIDENT = "sentinel3:incident:{incident_id}"            # Hash: incident data
    INCIDENTS_ACTIVE = "sentinel3:incidents:active"          # Set: active incident IDs
    INCIDENTS_BY_SEVERITY = "sentinel3:incidents:severity:{severity}" # Set
    
    # Stats
    STATS = "sentinel3:stats"                                # Hash: counters
    CHAIN_STATUS = "sentinel3:chain_status:{chain_id}"       # Hash: status info
    
    # Locks for atomic operations
    CORRELATION_LOCK = "sentinel3:lock:correlation:{key}"    # String: distributed lock


# Lua Scripts for Atomic Operations
# =============================================================================

# Atomic: Check if a matching lock exists and return it, or store as orphan mint
LUA_CHECK_LOCK_OR_STORE_MINT = """
-- KEYS[1] = pending_locks sorted set key
-- KEYS[2] = pending_mints sorted set key  
-- KEYS[3] = processed_messages set key
-- ARGV[1] = mint event ID
-- ARGV[2] = mint event JSON
-- ARGV[3] = mint timestamp (score)
-- ARGV[4] = amount_tolerance (float, e.g., 0.001)
-- ARGV[5] = correlation_window_seconds
-- ARGV[6] = mint amount
-- ARGV[7] = message_id (optional)

local pending_locks_key = KEYS[1]
local pending_mints_key = KEYS[2]
local processed_key = KEYS[3]
local mint_id = ARGV[1]
local mint_json = ARGV[2]
local mint_timestamp = tonumber(ARGV[3])
local tolerance = tonumber(ARGV[4])
local window_seconds = tonumber(ARGV[5])
local mint_amount = tonumber(ARGV[6])
local message_id = ARGV[7]

-- Check for replay attack
if message_id and message_id ~= "" then
    if redis.call('SISMEMBER', processed_key, message_id) == 1 then
        return {'REPLAY', '', ''}
    end
    redis.call('SADD', processed_key, message_id)
    -- TTL: expire processed messages after 7 days to prevent unbounded growth
    redis.call('EXPIRE', processed_key, 604800)
end

-- Calculate time window
local min_time = mint_timestamp - window_seconds
local max_time = mint_timestamp

-- Get all pending locks in the time window
local locks = redis.call('ZRANGEBYSCORE', pending_locks_key, min_time, max_time, 'WITHSCORES')

-- Find matching lock by amount
local matching_lock_id = nil
local matching_lock_json = nil

for i = 1, #locks, 2 do
    local lock_id = locks[i]
    local lock_key = 'sentinel3:correlation:lock_data:' .. lock_id
    local lock_data = redis.call('HGETALL', lock_key)
    
    if #lock_data > 0 then
        -- Convert to table
        local lock = {}
        for j = 1, #lock_data, 2 do
            lock[lock_data[j]] = lock_data[j+1]
        end
        
        local lock_amount = tonumber(lock['amount'] or 0)
        if lock_amount > 0 and mint_amount > 0 then
            local diff = math.abs(mint_amount - lock_amount) / lock_amount
            -- Tolerance covers base config + bridge fee allowance
            if diff <= tolerance then
                matching_lock_id = lock_id
                matching_lock_json = cjson.encode(lock)
                break
            end
        end
    end
end

if matching_lock_id then
    -- Remove lock from pending
    redis.call('ZREM', pending_locks_key, matching_lock_id)
    redis.call('DEL', 'sentinel3:correlation:lock_data:' .. matching_lock_id)
    return {'MATCHED', matching_lock_id, matching_lock_json}
else
    -- Store as pending mint
    redis.call('ZADD', pending_mints_key, mint_timestamp, mint_id)
    redis.call('HMSET', 'sentinel3:correlation:mint_data:' .. mint_id, 
               'event_id', mint_id, 
               'timestamp', mint_timestamp,
               'amount', mint_amount,
               'data', mint_json)
    redis.call('EXPIRE', 'sentinel3:correlation:mint_data:' .. mint_id, window_seconds * 2)
    return {'ORPHAN', '', ''}
end
"""

# Atomic: Store lock and check for pending orphan mints
LUA_STORE_LOCK_CHECK_MINTS = """
-- KEYS[1] = pending_locks sorted set key
-- KEYS[2] = pending_mints sorted set key
-- ARGV[1] = lock event ID
-- ARGV[2] = lock event JSON  
-- ARGV[3] = lock timestamp (score)
-- ARGV[4] = amount_tolerance
-- ARGV[5] = correlation_window_seconds
-- ARGV[6] = lock amount

local pending_locks_key = KEYS[1]
local pending_mints_key = KEYS[2]
local lock_id = ARGV[1]
local lock_json = ARGV[2]
local lock_timestamp = tonumber(ARGV[3])
local tolerance = tonumber(ARGV[4])
local window_seconds = tonumber(ARGV[5])
local lock_amount = tonumber(ARGV[6])

-- Check for matching pending mint first
local min_time = lock_timestamp
local max_time = lock_timestamp + window_seconds

local mints = redis.call('ZRANGEBYSCORE', pending_mints_key, min_time, max_time, 'WITHSCORES')

local matching_mint_id = nil
local matching_mint_json = nil

for i = 1, #mints, 2 do
    local mint_id = mints[i]
    local mint_key = 'sentinel3:correlation:mint_data:' .. mint_id
    local mint_data = redis.call('HGETALL', mint_key)
    
    if #mint_data > 0 then
        local mint = {}
        for j = 1, #mint_data, 2 do
            mint[mint_data[j]] = mint_data[j+1]
        end
        
        local mint_amount = tonumber(mint['amount'] or 0)
        if mint_amount > 0 and lock_amount > 0 then
            local diff = math.abs(mint_amount - lock_amount) / lock_amount
            if diff <= tolerance then
                matching_mint_id = mint_id
                matching_mint_json = mint['data'] or cjson.encode(mint)
                break
            end
        end
    end
end

if matching_mint_id then
    -- Remove mint from pending
    redis.call('ZREM', pending_mints_key, matching_mint_id)
    redis.call('DEL', 'sentinel3:correlation:mint_data:' .. matching_mint_id)
    return {'MATCHED', matching_mint_id, matching_mint_json}
else
    -- Store as pending lock
    redis.call('ZADD', pending_locks_key, lock_timestamp, lock_id)
    redis.call('HMSET', 'sentinel3:correlation:lock_data:' .. lock_id,
               'event_id', lock_id,
               'timestamp', lock_timestamp,
               'amount', lock_amount,
               'data', lock_json)
    redis.call('EXPIRE', 'sentinel3:correlation:lock_data:' .. lock_id, window_seconds * 2)
    return {'PENDING', '', ''}
end
"""

# Atomic: Increment stats counters
LUA_INCREMENT_STATS = """
-- KEYS[1] = stats hash key
-- ARGV = pairs of field, increment value

local key = KEYS[1]
for i = 1, #ARGV, 2 do
    redis.call('HINCRBY', key, ARGV[i], ARGV[i+1])
end
return redis.call('HGETALL', key)
"""


@dataclass
class RedisConnectionConfig:
    """Configuration for Redis connection."""
    url: str = REDIS_URL
    max_connections: int = REDIS_MAX_CONNECTIONS
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 5.0
    retry_on_timeout: bool = True
    health_check_interval: int = 30
    decode_responses: bool = True


class RedisStateManager:
    """
    Redis-backed state manager for distributed Sentinel3 instances.
    
    Features:
    - Async Redis operations
    - Atomic Lock/Mint correlation with Lua scripts
    - TTL-based expiration (24 hours)
    - Connection pooling
    - Graceful degradation on Redis unavailability
    """
    
    _instance: Optional["RedisStateManager"] = None
    _lock = asyncio.Lock()
    
    def __init__(self, config: Optional[RedisConnectionConfig] = None):
        self.config = config or RedisConnectionConfig()
        self._client: Optional[Redis] = None
        self._connected = False
        self._lua_scripts: Dict[str, Any] = {}
        self._event_ttl = timedelta(hours=EVENT_TTL_HOURS)
        self._correlation_window = timedelta(minutes=DEFAULT_CORRELATION_WINDOW_MINUTES)
        
        # Local fallback cache (when Redis unavailable)
        self._fallback_mode = False
        self._local_cache: Dict[str, Any] = {}

        # Reconnection state
        self._reconnect_attempts = 0
        self._last_reconnect_attempt: Optional[datetime] = None
        self._max_reconnect_backoff = 300  # 5 minutes max between attempts
        self._base_reconnect_interval = 10  # start with 10 seconds
        
    @classmethod
    async def get_instance(cls) -> "RedisStateManager":
        """Get singleton instance (async-safe)."""
        if cls._instance is None:
            async with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
                    await cls._instance.connect()
        return cls._instance
    
    async def connect(self) -> bool:
        """Establish connection to Redis."""
        if not REDIS_AVAILABLE:
            logger.warning("redis_not_available", reason="redis-py not installed")
            self._fallback_mode = True
            return False
        
        try:
            self._client = await aioredis.from_url(
                self.config.url,
                max_connections=self.config.max_connections,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.socket_connect_timeout,
                retry_on_timeout=self.config.retry_on_timeout,
                health_check_interval=self.config.health_check_interval,
                decode_responses=self.config.decode_responses,
            )
            
            # Test connection
            await self._client.ping()
            
            # Register Lua scripts
            await self._register_lua_scripts()
            
            self._connected = True
            self._fallback_mode = False
            
            logger.info(
                "redis_connected",
                url=self.config.url.split("@")[-1],  # Hide credentials
                max_connections=self.config.max_connections
            )
            return True
            
        except (ConnectionError, RedisTimeoutError, Exception) as e:
            logger.error("redis_connection_failed", error=str(e))
            self._fallback_mode = True
            return False
    
    async def _register_lua_scripts(self):
        """Register Lua scripts for atomic operations."""
        if not self._client:
            return
            
        self._lua_scripts["check_lock_or_store_mint"] = self._client.register_script(
            LUA_CHECK_LOCK_OR_STORE_MINT
        )
        self._lua_scripts["store_lock_check_mints"] = self._client.register_script(
            LUA_STORE_LOCK_CHECK_MINTS
        )
        self._lua_scripts["increment_stats"] = self._client.register_script(
            LUA_INCREMENT_STATS
        )
        
        logger.debug("lua_scripts_registered", count=len(self._lua_scripts))
    
    async def disconnect(self):
        """Close Redis connection."""
        if self._client:
            await self._client.close()
            self._connected = False
            logger.info("redis_disconnected")

    async def try_reconnect(self) -> bool:
        """
        Attempt to reconnect to Redis with exponential backoff.

        Call this periodically (e.g., from a health check loop) when in fallback mode.
        Returns True if reconnection succeeded.
        """
        if not self._fallback_mode:
            return True  # Already connected

        now = datetime.now(timezone.utc)

        # Exponential backoff: 10s, 20s, 40s, 80s, 160s, 300s (capped)
        backoff = min(
            self._base_reconnect_interval * (2 ** self._reconnect_attempts),
            self._max_reconnect_backoff,
        )

        if self._last_reconnect_attempt:
            elapsed = (now - self._last_reconnect_attempt).total_seconds()
            if elapsed < backoff:
                return False  # Too early to retry

        self._last_reconnect_attempt = now
        self._reconnect_attempts += 1

        logger.info(
            "redis_reconnect_attempt",
            attempt=self._reconnect_attempts,
            backoff_seconds=backoff,
        )

        try:
            if self._client:
                await self._client.close()

            self._client = await aioredis.from_url(
                self.config.url,
                max_connections=self.config.max_connections,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.socket_connect_timeout,
                retry_on_timeout=self.config.retry_on_timeout,
                health_check_interval=self.config.health_check_interval,
                decode_responses=self.config.decode_responses,
            )

            await self._client.ping()
            await self._register_lua_scripts()

            self._connected = True
            self._fallback_mode = False
            self._reconnect_attempts = 0

            logger.info(
                "redis_reconnected",
                after_attempts=self._reconnect_attempts,
                url=self.config.url.split("@")[-1],
            )
            return True

        except Exception as e:
            logger.warning(
                "redis_reconnect_failed",
                attempt=self._reconnect_attempts,
                next_backoff=min(backoff * 2, self._max_reconnect_backoff),
                error=str(e),
            )
            return False

    @property
    def is_connected(self) -> bool:
        """Check if connected to Redis."""
        return self._connected and not self._fallback_mode
    
    # =========================================================================
    # Event Storage
    # =========================================================================
    
    async def add_event(
        self,
        event_id: str,
        event_data: Dict[str, Any],
        chain_id: str,
        event_type: str,
        bridge_id: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> bool:
        """
        Store an event with multiple indexes.
        
        Args:
            event_id: Unique event identifier
            event_data: Event data dictionary
            chain_id: Chain where event occurred
            event_type: Type of event
            bridge_id: Optional bridge identifier
            timestamp: Event timestamp (defaults to now)
            
        Returns:
            True if stored successfully
        """
        if self._fallback_mode:
            # Attempt reconnection before falling back
            await self.try_reconnect()
            if self._fallback_mode:
                return self._fallback_add_event(event_id, event_data)

        try:
            timestamp = timestamp or datetime.now(timezone.utc)
            ts_score = timestamp.timestamp()
            ttl_seconds = int(self._event_ttl.total_seconds())
            
            pipe = self._client.pipeline()
            
            # Store event data
            event_key = RedisKeys.EVENT.format(event_id=event_id)
            pipe.hset(event_key, mapping={
                "event_id": event_id,
                "chain_id": chain_id,
                "event_type": event_type,
                "bridge_id": bridge_id or "",
                "timestamp": timestamp.isoformat(),
                "data": json.dumps(event_data)
            })
            pipe.expire(event_key, ttl_seconds)
            
            # Index by chain
            chain_key = RedisKeys.EVENTS_BY_CHAIN.format(chain_id=chain_id)
            pipe.zadd(chain_key, {event_id: ts_score})
            
            # Index by type
            type_key = RedisKeys.EVENTS_BY_TYPE.format(event_type=event_type)
            pipe.zadd(type_key, {event_id: ts_score})
            
            # Index by bridge
            if bridge_id:
                bridge_key = RedisKeys.EVENTS_BY_BRIDGE.format(bridge_id=bridge_id)
                pipe.zadd(bridge_key, {event_id: ts_score})
            
            # Increment stats
            pipe.hincrby(RedisKeys.STATS, "total_events", 1)
            pipe.hincrby(RedisKeys.STATS, f"events_{chain_id}", 1)
            
            await pipe.execute()
            return True
            
        except Exception as e:
            logger.error("redis_add_event_failed", event_id=event_id, error=str(e))
            return self._fallback_add_event(event_id, event_data)
    
    async def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Get event by ID."""
        if self._fallback_mode:
            return self._local_cache.get(f"event:{event_id}")
        
        try:
            event_key = RedisKeys.EVENT.format(event_id=event_id)
            data = await self._client.hgetall(event_key)
            
            if not data:
                return None
            
            result = dict(data)
            if "data" in result:
                result["data"] = json.loads(result["data"])
            return result
            
        except Exception as e:
            logger.error("redis_get_event_failed", event_id=event_id, error=str(e))
            return None
    
    async def get_events_by_chain(
        self,
        chain_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get events for a specific chain within time range."""
        if self._fallback_mode:
            return []
        
        try:
            chain_key = RedisKeys.EVENTS_BY_CHAIN.format(chain_id=chain_id)
            
            min_score = start_time.timestamp() if start_time else "-inf"
            max_score = end_time.timestamp() if end_time else "+inf"
            
            event_ids = await self._client.zrangebyscore(
                chain_key, min_score, max_score, start=0, num=limit
            )
            
            events = []
            for event_id in event_ids:
                event = await self.get_event(event_id)
                if event:
                    events.append(event)
            
            return events
            
        except Exception as e:
            logger.error("redis_get_events_by_chain_failed", chain_id=chain_id, error=str(e))
            return []
    
    # =========================================================================
    # Cross-Chain Correlation (Atomic Operations)
    # =========================================================================
    
    async def process_lock_event(
        self,
        event_id: str,
        event_data: Dict[str, Any],
        correlation_key: str,
        amount: float,
        timestamp: datetime,
        tolerance: float = 0.001
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Process a Lock event atomically.

        Returns:
            Tuple of (status, matched_mint_data)
            status: 'MATCHED' | 'PENDING'
        """
        if self._fallback_mode:
            await self.try_reconnect()
            if self._fallback_mode:
                return self._fallback_process_lock(event_id, event_data, correlation_key, amount)
        
        try:
            pending_locks_key = RedisKeys.PENDING_LOCKS.format(key=correlation_key)
            pending_mints_key = RedisKeys.PENDING_MINTS.format(key=correlation_key)
            
            window_seconds = int(self._correlation_window.total_seconds())
            
            result = await self._lua_scripts["store_lock_check_mints"](
                keys=[pending_locks_key, pending_mints_key],
                args=[
                    event_id,
                    json.dumps(event_data),
                    str(timestamp.timestamp()),
                    str(tolerance),
                    str(window_seconds),
                    str(amount)
                ]
            )
            
            status = result[0]
            matched_id = result[1] if len(result) > 1 else None
            matched_data = json.loads(result[2]) if len(result) > 2 and result[2] else None
            
            # Update stats
            await self._client.hincrby(RedisKeys.STATS, "locks_received", 1)
            if status == "MATCHED":
                await self._client.hincrby(RedisKeys.STATS, "correlations_matched", 1)
            
            return (status, matched_data)
            
        except Exception as e:
            logger.error("redis_process_lock_failed", event_id=event_id, error=str(e))
            self._fallback_mode = True
            self._connected = False
            return self._fallback_process_lock(event_id, event_data, correlation_key, amount)
    
    async def process_mint_event(
        self,
        event_id: str,
        event_data: Dict[str, Any],
        correlation_key: str,
        amount: float,
        timestamp: datetime,
        message_id: Optional[str] = None,
        tolerance: float = 0.001
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Process a Mint event atomically.
        
        Returns:
            Tuple of (status, matched_lock_data)
            status: 'MATCHED' | 'ORPHAN' | 'REPLAY'
        """
        if self._fallback_mode:
            await self.try_reconnect()
            if self._fallback_mode:
                return self._fallback_process_mint(event_id, event_data, correlation_key, amount)

        try:
            pending_locks_key = RedisKeys.PENDING_LOCKS.format(key=correlation_key)
            pending_mints_key = RedisKeys.PENDING_MINTS.format(key=correlation_key)
            processed_key = RedisKeys.PROCESSED_MESSAGES
            
            window_seconds = int(self._correlation_window.total_seconds())
            
            result = await self._lua_scripts["check_lock_or_store_mint"](
                keys=[pending_locks_key, pending_mints_key, processed_key],
                args=[
                    event_id,
                    json.dumps(event_data),
                    str(timestamp.timestamp()),
                    str(tolerance),
                    str(window_seconds),
                    str(amount),
                    message_id or ""
                ]
            )
            
            status = result[0]
            matched_id = result[1] if len(result) > 1 else None
            matched_data = json.loads(result[2]) if len(result) > 2 and result[2] else None
            
            # Update stats
            await self._client.hincrby(RedisKeys.STATS, "mints_received", 1)
            if status == "MATCHED":
                await self._client.hincrby(RedisKeys.STATS, "correlations_matched", 1)
            elif status == "ORPHAN":
                await self._client.hincrby(RedisKeys.STATS, "orphan_mints", 1)
            elif status == "REPLAY":
                await self._client.hincrby(RedisKeys.STATS, "replay_attempts", 1)
            
            return (status, matched_data)
            
        except Exception as e:
            logger.error("redis_process_mint_failed", event_id=event_id, error=str(e))
            self._fallback_mode = True
            self._connected = False
            return self._fallback_process_mint(event_id, event_data, correlation_key, amount)
    
    async def find_correlated_event(
        self,
        bridge_id: str,
        amount: float,
        tolerance: float = 0.01,
        event_type: str = "lock"
    ) -> Optional[Dict[str, Any]]:
        """
        Find a correlated event by bridge and amount.
        
        This is a non-atomic lookup for manual correlation checks.
        """
        if self._fallback_mode:
            return None
        
        try:
            # Get all pending events for this bridge
            bridge_key = RedisKeys.EVENTS_BY_BRIDGE.format(bridge_id=bridge_id)
            event_ids = await self._client.zrange(bridge_key, 0, -1)
            
            for event_id in event_ids:
                event = await self.get_event(event_id)
                if not event:
                    continue
                
                event_amount = float(event.get("data", {}).get("amount", 0))
                if event_amount <= 0:
                    continue
                
                diff = abs(amount - event_amount) / event_amount
                if diff <= tolerance:
                    return event
            
            return None
            
        except Exception as e:
            logger.error("redis_find_correlated_failed", bridge_id=bridge_id, error=str(e))
            return None
    
    async def check_orphan_events(
        self,
        max_age_seconds: Optional[int] = None
    ) -> Tuple[List[str], List[str]]:
        """
        Check for orphan locks and mints that exceeded correlation window.
        
        Returns:
            Tuple of (orphan_lock_ids, orphan_mint_ids)
        """
        if self._fallback_mode:
            await self.try_reconnect()
            if self._fallback_mode:
                return ([], [])

        try:
            max_age = max_age_seconds or int(self._correlation_window.total_seconds())
            cutoff_time = (datetime.now(timezone.utc) - timedelta(seconds=max_age)).timestamp()
            
            orphan_locks = []
            orphan_mints = []
            
            # Find all pending lock/mint keys
            lock_keys = await self._client.keys(RedisKeys.PENDING_LOCKS.format(key="*"))
            mint_keys = await self._client.keys(RedisKeys.PENDING_MINTS.format(key="*"))
            
            for key in lock_keys:
                expired = await self._client.zrangebyscore(key, "-inf", cutoff_time)
                orphan_locks.extend(expired)
                if expired:
                    await self._client.zremrangebyscore(key, "-inf", cutoff_time)
            
            for key in mint_keys:
                expired = await self._client.zrangebyscore(key, "-inf", cutoff_time)
                orphan_mints.extend(expired)
                if expired:
                    await self._client.zremrangebyscore(key, "-inf", cutoff_time)
            
            # Update stats
            if orphan_locks:
                await self._client.hincrby(RedisKeys.STATS, "orphan_locks", len(orphan_locks))
            if orphan_mints:
                await self._client.hincrby(RedisKeys.STATS, "orphan_mints_expired", len(orphan_mints))
            
            return (orphan_locks, orphan_mints)
            
        except Exception as e:
            logger.error("redis_check_orphans_failed", error=str(e))
            return ([], [])
    
    # =========================================================================
    # Violations Storage
    # =========================================================================
    
    async def add_violation(
        self,
        violation_id: str,
        violation_data: Dict[str, Any],
        timestamp: Optional[datetime] = None
    ) -> bool:
        """Store a cross-chain violation."""
        if self._fallback_mode:
            return False
        
        try:
            timestamp = timestamp or datetime.now(timezone.utc)
            
            pipe = self._client.pipeline()
            
            # Store violation data
            violation_key = RedisKeys.VIOLATION_DATA.format(violation_id=violation_id)
            pipe.hset(violation_key, mapping={
                "violation_id": violation_id,
                "timestamp": timestamp.isoformat(),
                **{k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) 
                   for k, v in violation_data.items()}
            })
            pipe.expire(violation_key, int(self._event_ttl.total_seconds() * 7))  # Keep violations longer
            
            # Add to sorted set
            pipe.zadd(RedisKeys.VIOLATIONS, {violation_id: timestamp.timestamp()})
            
            # Update stats
            pipe.hincrby(RedisKeys.STATS, "violations_detected", 1)
            severity = violation_data.get("severity", "medium")
            pipe.hincrby(RedisKeys.STATS, f"violations_{severity}", 1)
            
            await pipe.execute()
            
            logger.warning(
                "violation_stored",
                violation_id=violation_id,
                severity=severity,
                type=violation_data.get("violation_type")
            )
            return True
            
        except Exception as e:
            logger.error("redis_add_violation_failed", violation_id=violation_id, error=str(e))
            return False
    
    async def get_violations(
        self,
        severity: Optional[str] = None,
        bridge_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get violations with optional filters."""
        if self._fallback_mode:
            return []
        
        try:
            # Get recent violation IDs
            violation_ids = await self._client.zrevrange(RedisKeys.VIOLATIONS, 0, limit - 1)
            
            violations = []
            for vid in violation_ids:
                violation_key = RedisKeys.VIOLATION_DATA.format(violation_id=vid)
                data = await self._client.hgetall(violation_key)
                
                if not data:
                    continue
                
                # Apply filters
                if severity and data.get("severity") != severity:
                    continue
                if bridge_id and data.get("bridge_id") != bridge_id:
                    continue
                
                violations.append(data)
            
            return violations
            
        except Exception as e:
            logger.error("redis_get_violations_failed", error=str(e))
            return []
    
    # =========================================================================
    # Incidents
    # =========================================================================
    
    async def add_incident(
        self,
        incident_id: str,
        incident_data: Dict[str, Any]
    ) -> bool:
        """Store an incident."""
        if self._fallback_mode:
            return False
        
        try:
            pipe = self._client.pipeline()
            
            incident_key = RedisKeys.INCIDENT.format(incident_id=incident_id)
            pipe.hset(incident_key, mapping={
                k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
                for k, v in incident_data.items()
            })
            
            # Track active incidents
            status = incident_data.get("status", "open").lower()
            if status in ("open", "investigating"):
                pipe.sadd(RedisKeys.INCIDENTS_ACTIVE, incident_id)
            
            # Index by severity
            severity = incident_data.get("severity", "medium").lower()
            severity_key = RedisKeys.INCIDENTS_BY_SEVERITY.format(severity=severity)
            pipe.sadd(severity_key, incident_id)
            
            # Update stats
            pipe.hincrby(RedisKeys.STATS, "total_incidents", 1)
            
            await pipe.execute()
            return True
            
        except Exception as e:
            logger.error("redis_add_incident_failed", incident_id=incident_id, error=str(e))
            return False
    
    async def update_incident_status(
        self,
        incident_id: str,
        status: str
    ) -> bool:
        """Update incident status."""
        if self._fallback_mode:
            return False
        
        try:
            incident_key = RedisKeys.INCIDENT.format(incident_id=incident_id)
            
            pipe = self._client.pipeline()
            pipe.hset(incident_key, "status", status)
            
            if status.lower() in ("resolved", "closed"):
                pipe.srem(RedisKeys.INCIDENTS_ACTIVE, incident_id)
            else:
                pipe.sadd(RedisKeys.INCIDENTS_ACTIVE, incident_id)
            
            await pipe.execute()
            return True
            
        except Exception as e:
            logger.error("redis_update_incident_failed", incident_id=incident_id, error=str(e))
            return False
    
    # =========================================================================
    # Stats & Chain Status
    # =========================================================================
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        if self._fallback_mode:
            return {"fallback_mode": True}
        
        try:
            stats = await self._client.hgetall(RedisKeys.STATS)
            
            # Get active incident count
            active_count = await self._client.scard(RedisKeys.INCIDENTS_ACTIVE)
            
            return {
                **{k: int(v) if v.isdigit() else v for k, v in stats.items()},
                "active_incidents": active_count,
                "redis_connected": True
            }
            
        except Exception as e:
            logger.error("redis_get_stats_failed", error=str(e))
            return {"error": str(e), "redis_connected": False}
    
    async def update_chain_status(
        self,
        chain_id: str,
        status: str,
        last_block: int = 0,
        error: Optional[str] = None
    ) -> bool:
        """Update chain listener status."""
        if self._fallback_mode:
            return False
        
        try:
            status_key = RedisKeys.CHAIN_STATUS.format(chain_id=chain_id)
            await self._client.hset(status_key, mapping={
                "chain_id": chain_id,
                "status": status,
                "last_block": str(last_block),
                "last_update": datetime.now(timezone.utc).isoformat(),
                "error": error or ""
            })
            await self._client.expire(status_key, 300)  # 5 min TTL
            return True
            
        except Exception as e:
            logger.error("redis_update_chain_status_failed", chain_id=chain_id, error=str(e))
            return False
    
    async def get_chain_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get all chain statuses."""
        if self._fallback_mode:
            return {}
        
        try:
            keys = await self._client.keys(RedisKeys.CHAIN_STATUS.format(chain_id="*"))
            statuses = {}
            
            for key in keys:
                data = await self._client.hgetall(key)
                if data and "chain_id" in data:
                    statuses[data["chain_id"]] = data
            
            return statuses
            
        except Exception as e:
            logger.error("redis_get_chain_statuses_failed", error=str(e))
            return {}
    
    # =========================================================================
    # Cleanup & Maintenance
    # =========================================================================
    
    async def cleanup_expired(self) -> Dict[str, int]:
        """Clean up expired data. Run periodically."""
        if self._fallback_mode:
            return {}
        
        try:
            cleaned = {}
            cutoff = (datetime.now(timezone.utc) - self._event_ttl).timestamp()
            
            # Clean expired events from indexes
            for pattern in [
                RedisKeys.EVENTS_BY_CHAIN.format(chain_id="*"),
                RedisKeys.EVENTS_BY_TYPE.format(event_type="*"),
                RedisKeys.EVENTS_BY_BRIDGE.format(bridge_id="*"),
            ]:
                keys = await self._client.keys(pattern)
                for key in keys:
                    count = await self._client.zremrangebyscore(key, "-inf", cutoff)
                    if count > 0:
                        cleaned[key] = count
            
            logger.info("redis_cleanup_completed", cleaned=cleaned)
            return cleaned
            
        except Exception as e:
            logger.error("redis_cleanup_failed", error=str(e))
            return {}
    
    # =========================================================================
    # Fallback Methods (Local Cache)
    # =========================================================================
    
    def _fallback_add_event(self, event_id: str, event_data: Dict[str, Any]) -> bool:
        """Fallback: Store event locally."""
        self._local_cache[f"event:{event_id}"] = event_data
        return True
    
    def _fallback_process_lock(
        self,
        event_id: str,
        event_data: Dict[str, Any],
        correlation_key: str,
        amount: float
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Fallback: Process lock locally."""
        # Simple in-memory fallback
        pending_key = f"pending_locks:{correlation_key}"
        if pending_key not in self._local_cache:
            self._local_cache[pending_key] = []
        self._local_cache[pending_key].append({"event_id": event_id, "amount": amount, "data": event_data})
        return ("PENDING", None)
    
    def _fallback_process_mint(
        self,
        event_id: str,
        event_data: Dict[str, Any],
        correlation_key: str,
        amount: float
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Fallback: Process mint locally."""
        pending_key = f"pending_locks:{correlation_key}"
        pending_locks = self._local_cache.get(pending_key, [])
        
        for lock in pending_locks:
            lock_amount = lock.get("amount", 0)
            if lock_amount > 0 and abs(amount - lock_amount) / lock_amount <= 0.01:
                pending_locks.remove(lock)
                return ("MATCHED", lock.get("data"))
        
        return ("ORPHAN", None)


# Global instance factory
async def get_redis_manager() -> RedisStateManager:
    """Get the global Redis state manager instance."""
    return await RedisStateManager.get_instance()

