"""
Shared State Manager for Sentinel3
===================================

This module provides unified state management with support for:
1. In-memory storage (development/single instance)
2. Redis backend (production/distributed)
3. PostgreSQL persistence (long-term storage)

The state manager automatically selects the appropriate backend based on
environment configuration.

Environment Variables:
- REDIS_ENABLED: Enable Redis backend (default: false)
- REDIS_URL: Redis connection URL
- POSTGRES_ENABLED: Enable PostgreSQL persistence (default: true)
"""

import asyncio
import os
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Callable, Awaitable
from dataclasses import dataclass, field, asdict
import threading
from collections import deque
from enum import Enum
import json

import structlog

logger = structlog.get_logger(__name__)

# Configuration
REDIS_ENABLED = os.getenv("REDIS_ENABLED", "false").lower() == "true"
POSTGRES_ENABLED = os.getenv("POSTGRES_ENABLED", "true").lower() == "true"


class StorageBackend(Enum):
    """Available storage backends."""
    MEMORY = "memory"
    REDIS = "redis"
    HYBRID = "hybrid"  # Redis + PostgreSQL


@dataclass
class LiveEvent:
    """A live blockchain event."""
    id: str
    chain: str
    event_type: str
    tx_hash: str
    block: int
    contract: str
    severity: str  # low, medium, high, critical
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)
    amount: Optional[float] = None
    amount_usd: Optional[float] = None
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    bridge_id: Optional[str] = None
    
    def to_db_dict(self) -> Dict[str, Any]:
        """Convert to database format."""
        return {
            "event_id": self.id,
            "chain_id": self.chain,
            "event_type": self.event_type,
            "tx_hash": self.tx_hash,
            "block_number": self.block,
            "block_timestamp": self.timestamp,
            "contract_address": self.contract,
            "severity": self.severity.upper(),
            "amount": self.amount,
            "amount_usd": self.amount_usd,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "raw_data": self.data,
        }
    
    def to_api_dict(self) -> Dict[str, Any]:
        """Convert to API response format."""
        return {
            "event_id": self.id,
            "chain_id": self.chain,
            "event_type": self.event_type,
            "tx_hash": self.tx_hash,
            "block_number": self.block,
            "block_timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "contract_address": self.contract,
            "severity": self.severity,
            "amount": self.amount,
            "amount_usd": self.amount_usd,
            "bridge_id": self.bridge_id,
            "data": self.data,
        }
    
    def to_redis_dict(self) -> Dict[str, str]:
        """Convert to Redis-compatible format (all strings)."""
        return {
            "event_id": self.id,
            "chain_id": self.chain,
            "event_type": self.event_type,
            "tx_hash": self.tx_hash,
            "block_number": str(self.block),
            "timestamp": self.timestamp.isoformat() if self.timestamp else "",
            "contract_address": self.contract,
            "severity": self.severity,
            "amount": str(self.amount) if self.amount else "",
            "amount_usd": str(self.amount_usd) if self.amount_usd else "",
            "from_address": self.from_address or "",
            "to_address": self.to_address or "",
            "bridge_id": self.bridge_id or "",
            "data": json.dumps(self.data),
        }


@dataclass 
class LiveIncident:
    """A live security incident."""
    id: str
    title: str
    severity: str  # low, medium, high, critical
    status: str  # open, investigating, resolved
    attack_type: str
    confidence: float
    total_loss_usd: float
    affected_chains: List[str]
    events: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    recommended_actions: List[str] = field(default_factory=list)
    detection_latency_blocks: int = 0
    bridge_id: Optional[str] = None
    
    def to_db_dict(self) -> Dict[str, Any]:
        """Convert to database format."""
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.title,
            "severity": self.severity.upper(),
            "status": self.status.upper(),
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "total_loss_usd": self.total_loss_usd,
            "affected_chains": self.affected_chains,
            "event_ids": self.events,
            "recommended_actions": self.recommended_actions,
            "detection_latency_blocks": self.detection_latency_blocks,
        }
    
    def to_api_dict(self) -> Dict[str, Any]:
        """Convert to API response format."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.upper(),
            "status": self.status,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "total_loss_usd": self.total_loss_usd,
            "affected_chains": self.affected_chains,
            "event_ids": self.events,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "detection_latency_blocks": self.detection_latency_blocks,
            "bridge_id": self.bridge_id,
        }


class MonitorState:
    """
    Unified state manager supporting multiple backends.
    
    Features:
    - Thread-safe singleton pattern
    - Automatic backend selection (Memory/Redis)
    - PostgreSQL persistence layer
    - Graceful degradation on backend failures
    """
    
    _instance: Optional["MonitorState"] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance
    
    def reset(self):
        """Reset all state - useful for restarts."""
        self._initialize()
    
    def _initialize(self):
        """Initialize the state manager."""
        # Determine backend
        self._backend = StorageBackend.REDIS if REDIS_ENABLED else StorageBackend.MEMORY
        
        # In-memory storage (always available as fallback)
        self._events: deque = deque(maxlen=10000)
        self._incidents: Dict[str, LiveIncident] = {}
        
        # Batch buffer for database writes
        self._event_buffer: List[LiveEvent] = []
        self._buffer_lock = threading.Lock()
        self._batch_size = int(os.getenv("DB_BATCH_SIZE", "10"))
        
        # Stats (always in-memory for speed)
        self.stats = {
            "total_events": 0,
            "total_incidents": 0,
            "active_incidents": 0,
            "events_by_chain": {},
            "events_by_type": {},
            "critical_alerts": 0,
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
            "blocks_scanned": 0,
            "start_time": None,
            "last_event_time": None,
            "uptime_seconds": 0,
            "db_events_persisted": 0,
            "db_incidents_persisted": 0,
            "backend": self._backend.value,
        }
        
        # Chain connection status
        self._chain_status: Dict[str, Dict[str, Any]] = {}
        
        # Thread locks
        self._event_lock = threading.Lock()
        self._incident_lock = threading.Lock()
        
        # Backend services (initialized lazily)
        self._redis_manager = None
        self._db_service = None
        self._db_initialized = False
        self._redis_initialized = False
        
        logger.info(
            "monitor_state_initialized",
            backend=self._backend.value,
            redis_enabled=REDIS_ENABLED,
            postgres_enabled=POSTGRES_ENABLED
        )
    
    # =========================================================================
    # Initialization
    # =========================================================================
    
    async def init_backends(self):
        """Initialize all enabled backends."""
        # Initialize Redis
        if REDIS_ENABLED:
            await self._init_redis()
        
        # Initialize PostgreSQL
        if POSTGRES_ENABLED:
            await self._init_database()
    
    async def _init_redis(self):
        """Initialize Redis connection."""
        if self._redis_initialized:
            return
        
        try:
            from .database.redis_manager import RedisStateManager, get_redis_manager
            
            self._redis_manager = await get_redis_manager()
            self._redis_initialized = self._redis_manager.is_connected
            
            if self._redis_initialized:
                self._backend = StorageBackend.REDIS
                self.stats["backend"] = "redis"
                logger.info("redis_backend_initialized")
            else:
                logger.warning("redis_not_connected_fallback_to_memory")
                self._backend = StorageBackend.MEMORY
                
        except Exception as e:
            logger.error("redis_init_failed", error=str(e))
            self._backend = StorageBackend.MEMORY
    
    async def _init_database(self):
        """Initialize PostgreSQL connection."""
        if self._db_initialized:
            return
        
        try:
            from .database import DatabaseManager, DatabaseService
            
            await DatabaseManager.initialize()
            await DatabaseManager.create_tables()
            self._db_service = DatabaseService
            self._db_initialized = True
            logger.info("database_connection_established")
            
        except Exception as e:
            logger.error("database_init_failed", error=str(e))
            logger.warning("continuing_without_persistence")
    
    # =========================================================================
    # Event Management
    # =========================================================================
    
    def add_event(self, event: LiveEvent):
        """
        Add an event to the state.
        
        Routes to appropriate backend based on configuration.
        """
        # Update in-memory stats immediately (for dashboard responsiveness)
        self._update_event_stats(event)
        
        # Route to backend
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            # Use asyncio to call Redis (fire and forget from sync context)
            asyncio.create_task(self._add_event_redis(event))
        else:
            self._add_event_memory(event)
        
        # Queue for PostgreSQL persistence
        if self._db_initialized:
            self._queue_event_for_persistence(event)
    
    async def add_event_async(self, event: LiveEvent):
        """Async version of add_event for use in async contexts."""
        self._update_event_stats(event)
        
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            await self._add_event_redis(event)
        else:
            self._add_event_memory(event)
        
        if self._db_initialized:
            self._queue_event_for_persistence(event)
    
    def _add_event_memory(self, event: LiveEvent):
        """Add event to in-memory storage."""
        with self._event_lock:
            self._events.append(event)
    
    async def _add_event_redis(self, event: LiveEvent):
        """Add event to Redis storage."""
        try:
            await self._redis_manager.add_event(
                event_id=event.id,
                event_data=event.to_redis_dict(),
                chain_id=event.chain,
                event_type=event.event_type,
                bridge_id=event.bridge_id,
                timestamp=event.timestamp
            )
        except Exception as e:
            logger.error("redis_add_event_error", error=str(e), event_id=event.id)
            # Fallback to memory
            self._add_event_memory(event)
    
    def _update_event_stats(self, event: LiveEvent):
        """Update statistics counters."""
        with self._event_lock:
            self.stats["total_events"] += 1
            self.stats["last_event_time"] = datetime.now(timezone.utc)
            
            # Chain stats
            chain = event.chain
            if chain not in self.stats["events_by_chain"]:
                self.stats["events_by_chain"][chain] = 0
            self.stats["events_by_chain"][chain] += 1
            
            # Type stats
            event_type = event.event_type
            if event_type not in self.stats["events_by_type"]:
                self.stats["events_by_type"][event_type] = 0
            self.stats["events_by_type"][event_type] += 1
            
            # Severity counts
            severity = event.severity.lower()
            if severity == "critical":
                self.stats["critical_alerts"] += 1
            elif severity == "high":
                self.stats["high_alerts"] += 1
            elif severity == "medium":
                self.stats["medium_alerts"] += 1
            else:
                self.stats["low_alerts"] += 1
    
    def _queue_event_for_persistence(self, event: LiveEvent):
        """Queue event for batch database persistence."""
        with self._buffer_lock:
            self._event_buffer.append(event)
            if len(self._event_buffer) >= self._batch_size:
                threading.Thread(target=self._sync_flush_events, daemon=True).start()
    
    def _sync_flush_events(self):
        """Synchronous flush of events to database."""
        try:
            from .database.sync_service import save_events_batch_sync
            
            with self._buffer_lock:
                if not self._event_buffer:
                    return
                events_to_save = self._event_buffer.copy()
                self._event_buffer.clear()
            
            batch_data = [e.to_db_dict() for e in events_to_save]
            count = save_events_batch_sync(batch_data)
            self.stats["db_events_persisted"] += count
            
        except Exception as e:
            logger.error("sync_flush_failed", error=str(e))
    
    def get_events(self, limit: int = 100) -> List[LiveEvent]:
        """Get recent events from memory."""
        with self._event_lock:
            events = list(self._events)
            return list(reversed(events[-limit:]))
    
    async def get_events_async(
        self,
        limit: int = 100,
        chain_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get events with optional filtering (async, uses best available backend)."""
        # Try Redis first
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            try:
                events = await self._redis_manager.get_events_by_chain(
                    chain_id=chain_id or "*",
                    start_time=start_time,
                    end_time=end_time,
                    limit=limit
                )
                return events
            except Exception as e:
                logger.error("redis_get_events_error", error=str(e))
        
        # Fallback to memory
        events = self.get_events(limit)
        result = [e.to_api_dict() for e in events]
        
        # Apply filters
        if chain_id:
            result = [e for e in result if e.get("chain_id") == chain_id]
        if start_time:
            result = [e for e in result if e.get("block_timestamp") and 
                     datetime.fromisoformat(e["block_timestamp"].replace('Z', '+00:00')) >= start_time]
        if end_time:
            result = [e for e in result if e.get("block_timestamp") and 
                     datetime.fromisoformat(e["block_timestamp"].replace('Z', '+00:00')) <= end_time]
        
        return result[:limit]
    
    # =========================================================================
    # Incident Management
    # =========================================================================
    
    def add_incident(self, incident: LiveIncident):
        """Add an incident to state."""
        with self._incident_lock:
            self._incidents[incident.id] = incident
            self.stats["total_incidents"] += 1
            self._update_active_count()
        
        # Redis storage
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            asyncio.create_task(self._add_incident_redis(incident))
        
        # Database persistence
        if self._db_initialized:
            asyncio.create_task(self._save_incident_to_db(incident))
    
    async def _add_incident_redis(self, incident: LiveIncident):
        """Store incident in Redis."""
        try:
            await self._redis_manager.add_incident(
                incident_id=incident.id,
                incident_data=incident.to_api_dict()
            )
        except Exception as e:
            logger.error("redis_add_incident_error", error=str(e))
    
    async def _save_incident_to_db(self, incident: LiveIncident):
        """Persist incident to database."""
        if not self._db_service:
            return
        
        try:
            await self._db_service.save_incident(incident.to_db_dict())
            self.stats["db_incidents_persisted"] += 1
        except Exception as e:
            logger.error("incident_persist_failed", error=str(e), incident_id=incident.id)
    
    def update_incident(self, incident_id: str, **kwargs):
        """Update an existing incident."""
        with self._incident_lock:
            if incident_id in self._incidents:
                incident = self._incidents[incident_id]
                for key, value in kwargs.items():
                    if hasattr(incident, key):
                        setattr(incident, key, value)
                
                self._update_active_count()
                
                # Update in Redis
                if self._backend == StorageBackend.REDIS and "status" in kwargs:
                    asyncio.create_task(
                        self._redis_manager.update_incident_status(incident_id, kwargs["status"])
                    )
                
                # Update in database
                if self._db_initialized and "status" in kwargs:
                    asyncio.create_task(
                        self._update_incident_status_db(incident_id, kwargs["status"])
                    )
    
    async def _update_incident_status_db(self, incident_id: str, status: str):
        """Update incident status in database."""
        if self._db_service:
            try:
                await self._db_service.update_incident_status(incident_id, status.upper())
            except Exception as e:
                logger.error("incident_status_update_failed", error=str(e))
    
    def _update_active_count(self):
        """Update active incidents count."""
        self.stats["active_incidents"] = len([
            i for i in self._incidents.values()
            if i.status.lower() in ("open", "investigating")
        ])
    
    def get_incidents(self) -> List[LiveIncident]:
        """Get all incidents from memory."""
        with self._incident_lock:
            return list(self._incidents.values())
    
    def get_incident(self, incident_id: str) -> Optional[LiveIncident]:
        """Get specific incident."""
        return self._incidents.get(incident_id)
    
    # =========================================================================
    # Chain Status Management
    # =========================================================================
    
    def update_chain_status(
        self,
        chain_id: str,
        status: str,
        chain_type: str = "evm",
        last_block: int = 0,
        error: Optional[str] = None
    ):
        """Update chain listener status."""
        self._chain_status[chain_id] = {
            "chain_id": chain_id,
            "chain_type": chain_type,
            "status": status,
            "last_block": last_block,
            "last_update": datetime.now(timezone.utc).isoformat(),
            "error": error,
            "events_count": self.stats.get("events_by_chain", {}).get(chain_id, 0)
        }
        
        # Also update in Redis
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            asyncio.create_task(
                self._redis_manager.update_chain_status(chain_id, status, last_block, error)
            )
    
    def get_chain_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all chain listeners."""
        for chain_id in self._chain_status:
            self._chain_status[chain_id]["events_count"] = \
                self.stats.get("events_by_chain", {}).get(chain_id, 0)
        return dict(self._chain_status)
    
    async def get_chain_status_async(self) -> Dict[str, Dict[str, Any]]:
        """Get chain status (async, prefers Redis)."""
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            try:
                return await self._redis_manager.get_chain_statuses()
            except Exception as e:
                logger.error("redis_get_chain_status_error", error=str(e))
        
        return self.get_chain_status()
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        stats = dict(self.stats)
        
        if stats.get("start_time"):
            stats["uptime_seconds"] = int((datetime.now(timezone.utc) - stats["start_time"]).total_seconds())
        
        stats["db_enabled"] = POSTGRES_ENABLED
        stats["db_connected"] = self._db_initialized
        stats["redis_enabled"] = REDIS_ENABLED
        stats["redis_connected"] = self._redis_initialized
        stats["backend"] = self._backend.value
        
        return stats
    
    async def get_stats_async(self) -> Dict[str, Any]:
        """Get stats (async, includes Redis stats if available)."""
        stats = self.get_stats()
        
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            try:
                redis_stats = await self._redis_manager.get_stats()
                stats["redis_stats"] = redis_stats
            except Exception as e:
                logger.error("redis_get_stats_error", error=str(e))
        
        return stats
    
    def set_start_time(self):
        """Set monitoring start time."""
        self.stats["start_time"] = datetime.now(timezone.utc)
    
    def add_blocks_scanned(self, count: int):
        """Increment blocks scanned counter."""
        self.stats["blocks_scanned"] += count
    
    # =========================================================================
    # Cross-Chain Correlation (Delegates to Redis Manager)
    # =========================================================================
    
    async def process_lock_event(
        self,
        event_id: str,
        event_data: Dict[str, Any],
        correlation_key: str,
        amount: float,
        timestamp: datetime
    ):
        """Process a lock event for cross-chain correlation."""
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            return await self._redis_manager.process_lock_event(
                event_id, event_data, correlation_key, amount, timestamp
            )
        return ("PENDING", None)
    
    async def process_mint_event(
        self,
        event_id: str,
        event_data: Dict[str, Any],
        correlation_key: str,
        amount: float,
        timestamp: datetime,
        message_id: Optional[str] = None
    ):
        """Process a mint event for cross-chain correlation."""
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            return await self._redis_manager.process_mint_event(
                event_id, event_data, correlation_key, amount, timestamp, message_id
            )
        return ("ORPHAN", None)
    
    async def add_violation(self, violation_id: str, violation_data: Dict[str, Any]):
        """Store a cross-chain violation."""
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            return await self._redis_manager.add_violation(violation_id, violation_data)
        return False
    
    async def get_violations(
        self,
        severity: Optional[str] = None,
        bridge_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get violations."""
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            return await self._redis_manager.get_violations(severity, bridge_id, limit)
        return []
    
    # =========================================================================
    # Cleanup & Shutdown
    # =========================================================================
    
    async def cleanup_expired(self) -> Dict[str, int]:
        """Clean up expired data."""
        if self._backend == StorageBackend.REDIS and self._redis_initialized:
            return await self._redis_manager.cleanup_expired()
        return {}
    
    async def shutdown(self):
        """Graceful shutdown."""
        logger.info("shutting_down_state")
        
        # Flush remaining events
        if self._event_buffer:
            self._sync_flush_events()
        
        # Close Redis
        if self._redis_manager:
            await self._redis_manager.disconnect()
        
        # Close database
        if self._db_initialized:
            try:
                from .database import DatabaseManager
                await DatabaseManager.close()
            except Exception as e:
                logger.error("db_close_failed", error=str(e))


# Global instance
monitor_state = MonitorState()
