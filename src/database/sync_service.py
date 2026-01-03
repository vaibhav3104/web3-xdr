"""
Synchronous Database Service for batch operations.
Uses psycopg2 directly to avoid async event loop issues.
"""

import os
import json
import uuid
from typing import List, Dict, Any
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
        cursor.close()
        conn.close()
        
        logger.info("sync_events_saved", count=count)
        return count if count > 0 else len(events)
        
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

