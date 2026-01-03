"""
Shared state between monitor and API.
Combines in-memory caching for real-time performance with PostgreSQL persistence.
"""

import asyncio
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
import threading
from collections import deque

import structlog

logger = structlog.get_logger()

# Check if PostgreSQL is enabled
POSTGRES_ENABLED = os.getenv("POSTGRES_ENABLED", "true").lower() == "true"


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
    
    def to_db_dict(self) -> Dict[str, Any]:
        """Convert to database format."""
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.title,  # Use title as summary if not provided
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
        }


class MonitorState:
    """
    Thread-safe shared state for the monitor.
    Provides both in-memory caching and PostgreSQL persistence.
    """
    
    _instance = None
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
        """Initialize the state."""
        # In-memory storage (for real-time performance)
        self._events: deque = deque(maxlen=10000)  # Rolling buffer
        self._incidents: Dict[str, LiveIncident] = {}
        
        # Batch buffer for database writes
        self._event_buffer: List[LiveEvent] = []
        self._buffer_lock = threading.Lock()
        self._batch_size = int(os.getenv("DB_BATCH_SIZE", "10"))  # Lower for testing
        
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
        }
        
        self._event_lock = threading.Lock()
        self._incident_lock = threading.Lock()
        
        # Database service (initialized lazily)
        self._db_service = None
        self._db_initialized = False
    
    async def init_database(self):
        """Initialize database connection."""
        if not POSTGRES_ENABLED:
            logger.info("postgres_disabled", reason="POSTGRES_ENABLED=false")
            return
        
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
    
    def add_event(self, event: LiveEvent):
        """Add an event to the state and optionally persist."""
        
        with self._event_lock:
            # Always add to in-memory queue
            self._events.append(event)
            self.stats["total_events"] += 1
            self.stats["last_event_time"] = datetime.utcnow()
            
            # Update chain stats
            chain = event.chain
            if chain not in self.stats["events_by_chain"]:
                self.stats["events_by_chain"][chain] = 0
            self.stats["events_by_chain"][chain] += 1
            
            # Update type stats
            event_type = event.event_type
            if event_type not in self.stats["events_by_type"]:
                self.stats["events_by_type"][event_type] = 0
            self.stats["events_by_type"][event_type] += 1
            
            # Update severity counts
            severity = event.severity.lower()
            if severity == "critical":
                self.stats["critical_alerts"] += 1
            elif severity == "high":
                self.stats["high_alerts"] += 1
            elif severity == "medium":
                self.stats["medium_alerts"] += 1
            else:
                self.stats["low_alerts"] += 1
        
        # Add to buffer for batch persistence
        if self._db_initialized:
            with self._buffer_lock:
                self._event_buffer.append(event)
                buffer_len = len(self._event_buffer)
                if buffer_len >= self._batch_size:
                    logger.debug("triggering_flush", buffer_size=buffer_len, batch_size=self._batch_size)
                    # Trigger sync batch save (using thread)
                    threading.Thread(target=self._sync_flush_events, daemon=True).start()
    
    def _sync_flush_events(self):
        """Synchronous flush of events using psycopg2."""
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
            logger.info("events_flushed_to_db", count=count, total_persisted=self.stats["db_events_persisted"])
        except Exception as e:
            logger.error("sync_flush_failed", error=str(e))
    
    async def _flush_event_buffer(self):
        """Flush event buffer to database."""
        if not self._db_service:
            return
        
        with self._buffer_lock:
            if not self._event_buffer:
                return
            
            events_to_save = self._event_buffer.copy()
            self._event_buffer.clear()
        
        try:
            batch_data = [e.to_db_dict() for e in events_to_save]
            count = await self._db_service.save_events_batch(batch_data)
            self.stats["db_events_persisted"] += count
            logger.info("events_flushed_to_db", count=count, total_persisted=self.stats["db_events_persisted"])
        except Exception as e:
            logger.error("event_flush_failed", error=str(e))
            # Re-add to buffer on failure
            with self._buffer_lock:
                self._event_buffer.extend(events_to_save)
    
    def add_incident(self, incident: LiveIncident):
        """Add an incident to the state and persist."""
        with self._incident_lock:
            self._incidents[incident.id] = incident
            self.stats["total_incidents"] += 1
            self.stats["active_incidents"] = len([
                i for i in self._incidents.values() 
                if i.status.lower() in ("open", "investigating")
            ])
        
        # Persist to database
        if self._db_initialized:
            asyncio.create_task(self._save_incident_to_db(incident))
    
    async def _save_incident_to_db(self, incident: LiveIncident):
        """Save incident to database."""
        if not self._db_service:
            return
        
        try:
            await self._db_service.save_incident(incident.to_db_dict())
            self.stats["db_incidents_persisted"] += 1
            logger.info("incident_persisted", incident_id=incident.id)
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
                
                # Update active count
                self.stats["active_incidents"] = len([
                    i for i in self._incidents.values() 
                    if i.status.lower() in ("open", "investigating")
                ])
                
                # Persist update
                if self._db_initialized and "status" in kwargs:
                    asyncio.create_task(self._update_incident_status(
                        incident_id, kwargs.get("status")
                    ))
    
    async def _update_incident_status(self, incident_id: str, status: str):
        """Update incident status in database."""
        if not self._db_service:
            return
        
        try:
            await self._db_service.update_incident_status(incident_id, status.upper())
        except Exception as e:
            logger.error("incident_status_update_failed", error=str(e))
    
    def get_events(self, limit: int = 100) -> List[LiveEvent]:
        """Get recent events from memory."""
        with self._event_lock:
            events = list(self._events)
            return list(reversed(events[-limit:]))
    
    async def get_events_from_db(
        self,
        limit: int = 100,
        chain_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
    ) -> List[Dict]:
        """Get events from database (for historical queries)."""
        if not self._db_service:
            # Fall back to in-memory
            events = self.get_events(limit)
            return [e.to_api_dict() for e in events]
        
        try:
            db_events = await self._db_service.get_events(
                chain_id=chain_id,
                start_time=start_time,
                limit=limit,
            )
            return [
                {
                    "event_id": e.event_id,
                    "chain_id": e.chain_id,
                    "event_type": e.event_type,
                    "tx_hash": e.tx_hash,
                    "block_number": e.block_number,
                    "block_timestamp": e.block_timestamp.isoformat() if e.block_timestamp else None,
                    "severity": e.severity,
                    "amount_usd": float(e.amount_usd) if e.amount_usd else None,
                }
                for e in db_events
            ]
        except Exception as e:
            logger.error("db_events_query_failed", error=str(e))
            events = self.get_events(limit)
            return [e.to_api_dict() for e in events]
    
    def get_incidents(self) -> List[LiveIncident]:
        """Get all incidents from memory."""
        with self._incident_lock:
            return list(self._incidents.values())
    
    async def get_incidents_from_db(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict]:
        """Get incidents from database."""
        if not self._db_service:
            incidents = self.get_incidents()
            return [i.to_api_dict() for i in incidents[:limit]]
        
        try:
            db_incidents = await self._db_service.get_incidents(
                severity=severity.upper() if severity else None,
                status=status.upper() if status else None,
                limit=limit,
            )
            return [
                {
                    "id": i.incident_id,
                    "title": i.title,
                    "severity": i.severity,
                    "status": i.status,
                    "attack_type": i.attack_type,
                    "confidence": i.confidence,
                    "total_loss_usd": float(i.total_loss_usd) if i.total_loss_usd else 0,
                    "affected_chains": i.affected_chains or [],
                    "created_at": i.created_at.isoformat() if i.created_at else None,
                }
                for i in db_incidents
            ]
        except Exception as e:
            logger.error("db_incidents_query_failed", error=str(e))
            incidents = self.get_incidents()
            return [i.to_api_dict() for i in incidents[:limit]]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current stats."""
        stats = dict(self.stats)
        
        # Calculate uptime
        if stats.get("start_time"):
            stats["uptime_seconds"] = int((datetime.utcnow() - stats["start_time"]).total_seconds())
        
        # Add DB status
        stats["db_enabled"] = POSTGRES_ENABLED
        stats["db_connected"] = self._db_initialized
        
        return stats
    
    async def get_stats_from_db(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """Get stats from database for historical analytics."""
        if not self._db_service:
            return self.get_stats()
        
        try:
            db_stats = await self._db_service.get_dashboard_stats(time_range_hours)
            
            # Merge with in-memory stats
            stats = self.get_stats()
            stats.update(db_stats)
            return stats
        except Exception as e:
            logger.error("db_stats_query_failed", error=str(e))
            return self.get_stats()
    
    def set_start_time(self):
        """Set the monitoring start time."""
        self.stats["start_time"] = datetime.utcnow()
    
    def add_blocks_scanned(self, count: int):
        """Add to blocks scanned count."""
        self.stats["blocks_scanned"] += count
    
    async def shutdown(self):
        """Graceful shutdown - flush remaining data."""
        logger.info("shutting_down_state")
        
        # Flush remaining events
        if self._event_buffer:
            await self._flush_event_buffer()
        
        # Close database connection
        if self._db_initialized:
            try:
                from .database import DatabaseManager
                await DatabaseManager.close()
            except Exception as e:
                logger.error("db_close_failed", error=str(e))


# Global instance
monitor_state = MonitorState()
