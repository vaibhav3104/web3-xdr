"""
Synchronous Database Service for batch operations.
Uses psycopg2 directly to avoid async event loop issues.
Supports both direct connection and DATABASE_URL (for Cloud SQL).
"""

import os
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
import structlog

try:
    import psycopg2
    from psycopg2.extras import execute_values, Json
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

logger = structlog.get_logger()


def get_sync_connection():
    """Get a synchronous PostgreSQL connection."""
    if not PSYCOPG2_AVAILABLE:
        return None
    
    try:
        # Try DATABASE_URL first (Cloud SQL format)
        database_url = os.getenv("DATABASE_URL")
        if database_url:
            logger.debug("connecting_via_database_url")
            conn = psycopg2.connect(database_url)
            return conn
        
        # Fall back to individual env vars
        conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=os.getenv("POSTGRES_PORT", "5432"),
            user=os.getenv("POSTGRES_USER", "xdr"),
            password=os.getenv("POSTGRES_PASSWORD", "xdr_password"),
            database=os.getenv("POSTGRES_DB", "web3_xdr"),
        )
        return conn
    except Exception as e:
        logger.error("sync_db_connection_failed", error=str(e))
        return None


def ensure_tables_exist():
    """Create tables if they don't exist."""
    if not PSYCOPG2_AVAILABLE:
        return False
    
    conn = get_sync_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Create events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                event_id VARCHAR(255) UNIQUE NOT NULL,
                chain_id VARCHAR(50) NOT NULL,
                event_type VARCHAR(100) NOT NULL,
                tx_hash VARCHAR(255),
                block_number BIGINT,
                block_timestamp TIMESTAMP DEFAULT NOW(),
                contract_address VARCHAR(255),
                severity VARCHAR(20) DEFAULT 'LOW',
                amount DECIMAL(38, 18),
                amount_usd DECIMAL(18, 2),
                from_address VARCHAR(255),
                to_address VARCHAR(255),
                raw_data JSONB,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        
        # Create indexes for events
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_chain ON events(chain_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(block_timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
        
        # Create incidents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                incident_id VARCHAR(255) UNIQUE NOT NULL,
                title VARCHAR(500) NOT NULL,
                summary TEXT,
                severity VARCHAR(20) DEFAULT 'LOW',
                status VARCHAR(50) DEFAULT 'OPEN',
                attack_type VARCHAR(100),
                confidence DECIMAL(5, 4),
                total_loss_usd DECIMAL(18, 2),
                affected_chains TEXT[],
                event_ids TEXT[],
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
        
        # Create index for purge operations
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_created_at 
            ON events(created_at)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_created_at 
            ON incidents(created_at)
        """)
        
        # Create event_processing table for idempotency
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_processing (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                idempotency_key VARCHAR(128) UNIQUE NOT NULL,
                first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                processed_at TIMESTAMP WITH TIME ZONE,
                status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
                event_id VARCHAR(128),
                incident_id VARCHAR(128),
                error_message TEXT,
                retry_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS ix_event_processing_status 
            ON event_processing(status, first_seen_at)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS ix_event_processing_processed 
            ON event_processing(processed_at)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS ix_event_processing_idempotency_key 
            ON event_processing(idempotency_key)
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info("database_tables_ensured")
        return True
        
    except Exception as e:
        logger.error("ensure_tables_failed", error=str(e))
        if conn:
            conn.rollback()
            conn.close()
        return False


def purge_old_events(hours: int = 24) -> Dict[str, int]:
    """
    Purge events older than specified hours.
    Returns count of deleted events and incidents.
    """
    if not PSYCOPG2_AVAILABLE:
        return {"events_deleted": 0, "incidents_deleted": 0, "error": "psycopg2 not available"}
    
    conn = get_sync_connection()
    if not conn:
        return {"events_deleted": 0, "incidents_deleted": 0, "error": "connection failed"}
    
    try:
        cursor = conn.cursor()
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Delete old events
        cursor.execute(
            "DELETE FROM events WHERE created_at < %s",
            (cutoff_time,)
        )
        events_deleted = cursor.rowcount
        
        # Delete old resolved incidents (keep open ones)
        cursor.execute(
            "DELETE FROM incidents WHERE created_at < %s AND status = 'RESOLVED'",
            (cutoff_time,)
        )
        incidents_deleted = cursor.rowcount
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info("purge_completed", 
                   events_deleted=events_deleted, 
                   incidents_deleted=incidents_deleted,
                   cutoff_hours=hours)
        
        return {
            "events_deleted": events_deleted,
            "incidents_deleted": incidents_deleted,
            "cutoff_time": cutoff_time.isoformat(),
            "success": True
        }
        
    except Exception as e:
        logger.error("purge_failed", error=str(e))
        if conn:
            conn.rollback()
            conn.close()
        return {"events_deleted": 0, "incidents_deleted": 0, "error": str(e)}


def get_storage_stats() -> Dict[str, Any]:
    """Get storage statistics."""
    if not PSYCOPG2_AVAILABLE:
        return {"error": "psycopg2 not available"}
    
    conn = get_sync_connection()
    if not conn:
        return {"error": "connection failed"}
    
    try:
        cursor = conn.cursor()
        
        # Count events
        cursor.execute("SELECT COUNT(*) FROM events")
        event_count = cursor.fetchone()[0]
        
        # Count incidents
        cursor.execute("SELECT COUNT(*) FROM incidents")
        incident_count = cursor.fetchone()[0]
        
        # Get oldest event
        cursor.execute("SELECT MIN(created_at) FROM events")
        oldest_event = cursor.fetchone()[0]
        
        # Get newest event
        cursor.execute("SELECT MAX(created_at) FROM events")
        newest_event = cursor.fetchone()[0]
        
        # Events by chain
        cursor.execute("""
            SELECT chain_id, COUNT(*) 
            FROM events 
            GROUP BY chain_id 
            ORDER BY COUNT(*) DESC
        """)
        events_by_chain = dict(cursor.fetchall())
        
        # Events by severity
        cursor.execute("""
            SELECT severity, COUNT(*) 
            FROM events 
            GROUP BY severity
        """)
        events_by_severity = dict(cursor.fetchall())
        
        cursor.close()
        conn.close()
        
        return {
            "total_events": event_count,
            "total_incidents": incident_count,
            "oldest_event": oldest_event.isoformat() if oldest_event else None,
            "newest_event": newest_event.isoformat() if newest_event else None,
            "events_by_chain": events_by_chain,
            "events_by_severity": events_by_severity,
            "storage": "postgresql"
        }
        
    except Exception as e:
        logger.error("storage_stats_failed", error=str(e))
        if conn:
            conn.close()
        return {"error": str(e)}


def save_events_batch_sync(events: List[Dict[str, Any]]) -> int:
    """
    Save multiple events using synchronous psycopg2.
    Returns count of inserted events.
    """
    if not PSYCOPG2_AVAILABLE or not events:
        return 0
    
    conn = get_sync_connection()
    if not conn:
        return 0
    
    try:
        cursor = conn.cursor()
        
        # Prepare data for insert
        insert_sql = """
            INSERT INTO events (
                id, event_id, chain_id, event_type, tx_hash, block_number, 
                block_timestamp, contract_address, severity, amount, amount_usd,
                from_address, to_address, raw_data
            ) VALUES %s
            ON CONFLICT (event_id) DO NOTHING
        """
        
        values = []
        for e in events:
            # Properly serialize raw_data as JSON
            raw_data = e.get("raw_data")
            if raw_data:
                raw_data = Json(raw_data)
            
            values.append((
                str(uuid.uuid4()),  # Generate UUID for id column
                e.get("event_id"),
                e.get("chain_id"),
                e.get("event_type"),
                e.get("tx_hash"),
                e.get("block_number"),
                e.get("block_timestamp"),
                e.get("contract_address"),
                e.get("severity", "LOW"),
                e.get("amount"),
                e.get("amount_usd"),
                e.get("from_address"),
                e.get("to_address"),
                raw_data,
            ))
        
        execute_values(cursor, insert_sql, values)
        conn.commit()
        
        count = cursor.rowcount
        logger.info("sync_events_saved", count=count, attempted=len(events), event_ids=[e.get("event_id")[:16] for e in events[:3]])
        
        # Verify the insert by querying back
        cursor.execute("SELECT COUNT(*) FROM events WHERE event_id = ANY(%s)", ([e.get("event_id") for e in events],))
        verify_count = cursor.fetchone()[0]
        logger.info("sync_events_verified", inserted=count, found_in_db=verify_count)
        
        cursor.close()
        conn.close()
        
        return count
        
    except Exception as e:
        logger.error("sync_events_save_failed", error=str(e))
        if conn:
            conn.rollback()
            conn.close()
        return 0


def save_incident_sync(incident_data: Dict[str, Any]) -> bool:
    """
    Save an incident using synchronous psycopg2.
    """
    if not PSYCOPG2_AVAILABLE:
        return False
    
    conn = get_sync_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        insert_sql = """
            INSERT INTO incidents (
                incident_id, title, summary, severity, status, attack_type,
                confidence, total_loss_usd, affected_chains, event_ids
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (incident_id) DO UPDATE SET
                status = EXCLUDED.status,
                updated_at = NOW()
        """
        
        cursor.execute(insert_sql, (
            incident_data.get("id"),
            incident_data.get("title"),
            incident_data.get("summary", incident_data.get("title")),
            incident_data.get("severity", "LOW").upper(),
            incident_data.get("status", "OPEN").upper(),
            incident_data.get("attack_type", "UNKNOWN"),
            incident_data.get("confidence", 0.5),
            incident_data.get("total_loss_usd", 0),
            incident_data.get("affected_chains", []),
            incident_data.get("event_ids", []),
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info("sync_incident_saved", incident_id=incident_data.get("id"))
        return True
        
    except Exception as e:
        logger.error("sync_incident_save_failed", error=str(e))
        if conn:
            conn.rollback()
            conn.close()
        return False

