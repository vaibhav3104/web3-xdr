"""
Database Service Layer for Sentinel3.
Provides high-level async methods for CRUD operations.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Tuple
import json
import asyncio

import structlog
from sqlalchemy import select, func, delete, update, and_, text

from .connection import DatabaseManager
from .models import (
    EventModel,
    IncidentModel,
)

logger = structlog.get_logger()


class DatabaseService:
    """
    Service class for all database operations.
    All methods are async and use connection pooling.
    """
    
    # =========================================================================
    # EVENT OPERATIONS
    # =========================================================================
    
    @staticmethod
    async def save_event(event_data: Dict[str, Any]) -> Optional[str]:
        """
        Save a single event to the database.
        Returns the event_id on success.
        """
        async with DatabaseManager.get_session() as session:
            try:
                event = EventModel(
                    event_id=event_data.get("event_id"),
                    chain_id=event_data.get("chain_id"),
                    event_type=event_data.get("event_type"),
                    tx_hash=event_data.get("tx_hash"),
                    block_number=event_data.get("block_number"),
                    block_timestamp=event_data.get("block_timestamp"),
                    log_index=event_data.get("log_index"),
                    contract_address=event_data.get("contract_address"),
                    from_address=event_data.get("from_address"),
                    to_address=event_data.get("to_address"),
                    amount=event_data.get("amount"),
                    amount_usd=event_data.get("amount_usd"),
                    asset_type=event_data.get("asset_type"),
                    asset_address=event_data.get("asset_address"),
                    severity=event_data.get("severity", "LOW"),
                    raw_data=event_data.get("raw_data"),
                    topics=event_data.get("topics"),
                )
                session.add(event)
                await session.flush()
                logger.debug("event_saved", event_id=event.event_id)
                return event.event_id
            except Exception as e:
                logger.error("event_save_failed", error=str(e), event_id=event_data.get("event_id"))
                raise
    
    @staticmethod
    async def save_events_batch(events: List[Dict[str, Any]]) -> int:
        """
        Save events using raw SQL (Nuclear Option).
        No ORM, no fancy RETURNING - just direct INSERT.
        Includes retry logic for connection timeouts.
        """
        if not events:
            return 0
        
        logger.info("save_events_batch_RAW_SQL_START", total_events=len(events), sample_tx=events[0].get("tx_hash", "N/A")[:16])
        
        # Retry logic for connection timeouts
        max_retries = 3
        retry_delay = 2.0
        
        from sqlalchemy import text
        
        for attempt in range(max_retries):
            try:
                # Get session - connection pool handles timeouts
                async with DatabaseManager.get_session() as session:
                    # Raw SQL INSERT - no ORM, no complications  
                    # IMPORTANT: All parameters must have explicit types to avoid asyncpg ambiguity
                    # Use direct CAST for all nullable fields - pass NULL from Python, not empty string
                    raw_insert_sql = text("""
                    INSERT INTO events (
                        id, event_id, chain_id, event_type, tx_hash, block_number,
                        block_timestamp, contract_address, severity, status, amount, amount_usd,
                        from_address, to_address, raw_data, log_index, created_at
                    ) VALUES (
                        gen_random_uuid(),
                        :event_id,
                        :chain_id,
                        :event_type,
                        :tx_hash,
                        :block_number,
                        CAST(:block_timestamp AS TIMESTAMP WITH TIME ZONE),
                        :contract_address,
                        COALESCE(:severity, 'LOW'),
                        'PENDING',
                        CAST(:amount AS NUMERIC(38, 18)),
                        CAST(:amount_usd AS NUMERIC(20, 2)),
                        :from_address,
                        :to_address,
                        CAST(:raw_data AS JSONB),
                        COALESCE(:log_index, 0),
                        NOW()
                    )
                    ON CONFLICT (chain_id, tx_hash, log_index) DO NOTHING
                    """)
                    
                    # Execute for each event in individual savepoints to handle errors
                    saved_count = 0
                    for event in events:
                        # Use savepoint for each event so one failure doesn't abort the whole transaction
                        savepoint = await session.begin_nested()
                        try:
                            # Prepare values - ensure all required fields are present
                            event_id = event.get("event_id")
                            if not event_id:
                                logger.warning("event_missing_id", event=event)
                                await savepoint.rollback()
                                continue
                            
                            # Convert amount/amount_usd to string for NUMERIC casting
                            # Pass None for NULL, or a valid numeric string
                            amount_val = event.get("amount")
                            amount_str = None
                            if amount_val is not None and amount_val != "":
                                try:
                                    # Try to convert to float first to validate it's numeric
                                    float_val = float(amount_val)
                                    amount_str = str(float_val)
                                except (ValueError, TypeError):
                                    amount_str = None
                            
                            amount_usd_val = event.get("amount_usd")
                            amount_usd_str = None
                            if amount_usd_val is not None and amount_usd_val != "":
                                try:
                                    float_val = float(amount_usd_val)
                                    amount_usd_str = str(float_val)
                                except (ValueError, TypeError):
                                    amount_usd_str = None
                            
                            # Parse block_timestamp - asyncpg requires datetime object, not string
                            block_ts = event.get("block_timestamp")
                            if block_ts is None:
                                block_ts_dt = datetime.now(timezone.utc)
                            elif isinstance(block_ts, datetime):
                                # Already a datetime - ensure it's timezone aware
                                if block_ts.tzinfo is None:
                                    block_ts_dt = block_ts.replace(tzinfo=timezone.utc)
                                else:
                                    block_ts_dt = block_ts
                            elif isinstance(block_ts, str):
                                # Parse ISO format string to datetime
                                try:
                                    # Handle various ISO formats
                                    block_ts_clean = block_ts.replace('Z', '+00:00')
                                    block_ts_dt = datetime.fromisoformat(block_ts_clean)
                                    if block_ts_dt.tzinfo is None:
                                        block_ts_dt = block_ts_dt.replace(tzinfo=timezone.utc)
                                except (ValueError, TypeError):
                                    logger.warning("invalid_block_timestamp", value=block_ts, event_id=event_id[:16])
                                    block_ts_dt = datetime.now(timezone.utc)
                            else:
                                block_ts_dt = datetime.now(timezone.utc)
                                
                            # Ensure severity is a valid string (some events pass 0 or other non-string values)
                            severity_val = event.get("severity")
                            if severity_val is None or severity_val == "" or severity_val == 0:
                                severity_str = "LOW"
                            elif isinstance(severity_val, str):
                                severity_str = severity_val.upper() if severity_val else "LOW"
                            else:
                                severity_str = str(severity_val).upper() if severity_val else "LOW"
                            
                            await session.execute(raw_insert_sql, {
                                "event_id": event_id,
                                "chain_id": event.get("chain_id") or "",
                                "event_type": event.get("event_type") or "",
                                "tx_hash": event.get("tx_hash") or "",
                                "block_number": event.get("block_number") or 0,
                                "block_timestamp": block_ts_dt,
                                "contract_address": event.get("contract_address") or "",
                                "severity": severity_str,
                                "amount": amount_str,
                                "amount_usd": amount_usd_str,
                                "from_address": event.get("from_address"),
                                "to_address": event.get("to_address"),
                                "raw_data": json.dumps(event.get("raw_data", {})) if event.get("raw_data") else None,
                                "log_index": event.get("log_index", 0),
                            })
                            await savepoint.commit()
                            saved_count += 1
                            logger.debug("raw_sql_insert_executed", event_id=event.get("event_id")[:16])
                        except Exception as e:
                            import traceback
                            # Rollback savepoint on error
                            await savepoint.rollback()
                            error_details = {
                                "error": str(e) if str(e) else "Empty error message",
                                "error_type": type(e).__name__,
                                "error_args": str(e.args) if e.args else "No args",
                                "traceback": traceback.format_exc()[-500:]  # Last 500 chars
                            }
                            logger.error("raw_sql_insert_failed", 
                                       event_id=event.get("event_id", "unknown")[:16],
                                       **error_details)
                    
                    # Commit the transaction
                    await session.commit()
                    logger.info("save_events_batch_RAW_SQL_COMMITTED", executed=saved_count, total=len(events))
                    return saved_count
                    
            except asyncio.TimeoutError as e:
                if attempt < max_retries - 1:
                    logger.warning("db_connection_timeout_retry", attempt=attempt+1, max_retries=max_retries, delay=retry_delay)
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    continue
                else:
                    logger.error("db_connection_timeout_failed", total_events=len(events), error=str(e))
                    return 0
            except Exception as e:
                import traceback
                error_details = {
                    "error": str(e) if str(e) else "Empty error message",
                    "error_type": type(e).__name__,
                    "error_args": str(e.args) if e.args else "No args",
                    "traceback": traceback.format_exc()[-500:]
                }
                logger.error("save_events_batch_failed", attempt=attempt+1, **error_details)
                if attempt < max_retries - 1 and "Timeout" in str(e):
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    return 0
        
        return 0
    
    @staticmethod
    async def get_events(
        chain_id: Optional[str] = None,
        event_type: Optional[str] = None,
        contract_address: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        cursor: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Query events with optional filters using raw SQL.
        Supports cursor-based pagination for better performance.
        
        Returns: (events_list, next_cursor)
        """
        from .cursor import encode_cursor, decode_cursor
        
        # ========== DEBUG: Log incoming parameters ==========
        logger.info("DEBUG_GET_EVENTS_CALLED", 
                    chain_id=chain_id,
                    event_type=event_type,
                    severity=severity,
                    status=status,
                    start_time=str(start_time) if start_time else None,
                    end_time=str(end_time) if end_time else None,
                    limit=limit,
                    cursor=cursor is not None)
        
        async with DatabaseManager.get_session() as session:
            # Build WHERE clause
            where_parts = []
            params = {}
            
            if chain_id:
                where_parts.append("chain_id = :chain_id")
                params['chain_id'] = chain_id
            if event_type:
                where_parts.append("event_type = :event_type")
                params['event_type'] = event_type
            if contract_address:
                where_parts.append("contract_address = :contract_address")
                params['contract_address'] = contract_address
            if start_time:
                # asyncpg requires datetime objects, not strings
                # Database stores offset-naive timestamps, so we need to pass naive datetimes
                if isinstance(start_time, datetime):
                    if start_time.tzinfo is not None:
                        # Convert to UTC and remove timezone info
                        start_time_dt = start_time.astimezone(timezone.utc).replace(tzinfo=None)
                    else:
                        start_time_dt = start_time
                else:
                    # Parse string to datetime (as naive)
                    try:
                        start_time_clean = str(start_time).replace('Z', '+00:00')
                        start_time_dt = datetime.fromisoformat(start_time_clean)
                        if start_time_dt.tzinfo is not None:
                            start_time_dt = start_time_dt.astimezone(timezone.utc).replace(tzinfo=None)
                    except (ValueError, TypeError):
                        start_time_dt = datetime.now(timezone.utc)
                where_parts.append("block_timestamp >= :start_time")
                params['start_time'] = start_time_dt
            if end_time:
                # asyncpg requires datetime objects, not strings
                # Database stores offset-naive timestamps, so we need to pass naive datetimes
                if isinstance(end_time, datetime):
                    if end_time.tzinfo is not None:
                        # Convert to UTC and remove timezone info
                        end_time_dt = end_time.astimezone(timezone.utc).replace(tzinfo=None)
                    else:
                        end_time_dt = end_time
                else:
                    # Parse string to datetime (as naive)
                    try:
                        end_time_clean = str(end_time).replace('Z', '+00:00')
                        end_time_dt = datetime.fromisoformat(end_time_clean)
                        if end_time_dt.tzinfo is not None:
                            end_time_dt = end_time_dt.astimezone(timezone.utc).replace(tzinfo=None)
                    except (ValueError, TypeError):
                        end_time_dt = datetime.now(timezone.utc)
                where_parts.append("block_timestamp <= :end_time")
                params['end_time'] = end_time_dt
            if severity:
                where_parts.append("severity = :severity")
                params['severity'] = severity.upper()
            # Note: status column doesn't exist in the actual table, ignoring status filter
            # if status:
            #     where_parts.append("status = :status")
            #     params['status'] = status.upper()
            
            # Cursor-based pagination (preferred over OFFSET)
            # Now using created_at for cursor since we order by created_at
            if cursor:
                cursor_data = decode_cursor(cursor)
                if cursor_data:
                    cursor_timestamp, cursor_id = cursor_data
                    # asyncpg requires datetime objects, database uses naive timestamps
                    if isinstance(cursor_timestamp, datetime):
                        if cursor_timestamp.tzinfo is not None:
                            cursor_ts_dt = cursor_timestamp.astimezone(timezone.utc).replace(tzinfo=None)
                        else:
                            cursor_ts_dt = cursor_timestamp
                    else:
                        cursor_ts_dt = datetime.fromisoformat(str(cursor_timestamp).replace('Z', '+00:00'))
                        if cursor_ts_dt.tzinfo is not None:
                            cursor_ts_dt = cursor_ts_dt.astimezone(timezone.utc).replace(tzinfo=None)
                    where_parts.append(
                        "(created_at, id) < (:cursor_timestamp, CAST(:cursor_id AS UUID))"
                    )
                    params['cursor_timestamp'] = cursor_ts_dt
                    params['cursor_id'] = cursor_id
            
            where_clause = " AND ".join(where_parts) if where_parts else "1=1"
            
            # Query using raw SQL with cursor pagination
            # Order by (block_timestamp DESC, id DESC) for stable cursor
            # Note: status column doesn't exist in the actual table, removed from query
            # Order by created_at DESC to show most recently ingested events first
            # This is more useful than block_timestamp which is when the block was mined
            sql = f"""
                SELECT id, event_id, chain_id, event_type, tx_hash, block_number,
                       block_timestamp, contract_address, severity, amount, amount_usd,
                       from_address, to_address, raw_data, created_at
                FROM events
                WHERE {where_clause}
                ORDER BY created_at DESC, id DESC
                LIMIT :limit
            """
            params['limit'] = limit + 1  # Fetch one extra to check if there's more
            
            # ========== DEBUG: Log the SQL query ==========
            logger.info("DEBUG_GET_EVENTS_SQL", 
                        sql=sql.replace('\n', ' ').strip(),
                        params=str(params),
                        where_clause=where_clause)
            
            # Execute query with timeout protection
            import asyncio
            try:
                result = await asyncio.wait_for(
                    session.execute(text(sql), params),
                    timeout=25.0  # 25 second timeout for query execution
                )
                rows = result.fetchall()
                
                # ========== DEBUG: Log row count ==========
                logger.info("DEBUG_GET_EVENTS_ROWS_FETCHED", row_count=len(rows))
                
            except asyncio.TimeoutError:
                logger.warning("DEBUG_GET_EVENTS_TIMEOUT", filters={"chain_id": chain_id, "limit": limit})
                return [], None  # Return empty result on timeout
            except Exception as e:
                import traceback
                logger.error("DEBUG_GET_EVENTS_QUERY_ERROR", 
                             error=str(e), 
                             error_type=type(e).__name__,
                             traceback=traceback.format_exc()[-500:])
                raise
            
            # Convert rows to dicts
            # Columns: id, event_id, chain_id, event_type, tx_hash, block_number,
            #          block_timestamp, contract_address, severity, amount, amount_usd,
            #          from_address, to_address, raw_data, created_at
            events = []
            for row in rows:
                events.append({
                    'id': str(row[0]),
                    'event_id': row[1],
                    'chain_id': row[2],
                    'event_type': row[3],
                    'tx_hash': row[4],
                    'block_number': row[5],
                    'block_timestamp': row[6],
                    'contract_address': row[7],
                    'severity': row[8],
                    'amount': float(row[9]) if row[9] else None,
                    'amount_usd': float(row[10]) if row[10] else None,
                    'from_address': row[11],
                    'to_address': row[12],
                    'raw_data': row[13] if isinstance(row[13], dict) else (json.loads(row[13]) if row[13] else {}),
                    'created_at': row[14],
                    'status': 'PENDING',  # Default status - column doesn't exist in DB
                })
            
            # Generate next cursor if there are more results
            next_cursor = None
            if len(events) > limit:
                # Remove the extra event
                last_event = events[limit - 1]
                next_cursor = encode_cursor(last_event['block_timestamp'], last_event['id'])
                events = events[:limit]
            
            # ========== DEBUG: Log final result ==========
            logger.info("DEBUG_GET_EVENTS_RETURNING", 
                        events_count=len(events),
                        has_next_cursor=next_cursor is not None,
                        first_event_id=events[0]['event_id'] if events else None,
                        first_event_chain=events[0]['chain_id'] if events else None)
            
            return events, next_cursor
    
    @staticmethod
    async def get_events_count(
        chain_id: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Optional[int]:
        """
        Get actual total count of events matching filters using raw SQL.
        Returns None if query times out (to avoid blocking API).
        """
        import asyncio
        async with DatabaseManager.get_session() as session:
            # Build WHERE clause (same logic as get_events)
            where_parts = []
            params = {}
            
            if chain_id:
                where_parts.append("chain_id = :chain_id")
                params['chain_id'] = chain_id
            if event_type:
                where_parts.append("event_type = :event_type")
                params['event_type'] = event_type
            if severity:
                where_parts.append("severity = :severity")
                params['severity'] = severity.upper()
            if start_time:
                if isinstance(start_time, datetime):
                    if start_time.tzinfo is None:
                        start_time = start_time.replace(tzinfo=timezone.utc)
                    else:
                        start_time = start_time.astimezone(timezone.utc)
                    start_time_str = start_time.isoformat()
                else:
                    start_time_str = str(start_time)
                where_parts.append("block_timestamp >= CAST(:start_time AS TIMESTAMP WITH TIME ZONE)")
                params['start_time'] = start_time_str
            if end_time:
                if isinstance(end_time, datetime):
                    if end_time.tzinfo is None:
                        end_time = end_time.replace(tzinfo=timezone.utc)
                    else:
                        end_time = end_time.astimezone(timezone.utc)
                    end_time_str = end_time.isoformat()
                else:
                    end_time_str = str(end_time)
                where_parts.append("block_timestamp <= CAST(:end_time AS TIMESTAMP WITH TIME ZONE)")
                params['end_time'] = end_time_str
            
            where_clause = " AND ".join(where_parts) if where_parts else "1=1"
            
            # Count query with timeout protection
            try:
                sql = f"SELECT COUNT(*) FROM events WHERE {where_clause}"
                result = await asyncio.wait_for(
                    session.execute(text(sql), params),
                    timeout=15.0  # 15 second timeout for COUNT queries
                )
                count = result.scalar()
                return count or 0
            except asyncio.TimeoutError:
                logger.warning("get_events_count_timeout", filters={"chain_id": chain_id, "event_type": event_type})
                return None  # Return None to indicate timeout
            except Exception as e:
                logger.error("get_events_count_error", error=str(e))
                return None
    
    @staticmethod
    async def count_events(
        chain_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """
        Count events matching filters (legacy method, use get_events_count instead).
        """
        return await DatabaseService.get_events_count(
            chain_id=chain_id,
            start_time=start_time,
            end_time=end_time
        )
    
    @staticmethod
    async def get_events_by_chain(
        chain: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50
    ) -> List[Dict]:
        """
        Get events for a specific chain or counts grouped by chain.
        If chain is provided, returns list of events.
        If chain is None, returns counts grouped by chain.
        """
        async with DatabaseManager.get_session() as session:
            if chain:
                # Return actual events for the chain
                query = select(EventModel).where(
                    EventModel.chain_id == chain
                ).order_by(EventModel.block_timestamp.desc()).limit(limit)
                
                conditions = []
                if start_time:
                    conditions.append(EventModel.block_timestamp >= start_time)
                if end_time:
                    conditions.append(EventModel.block_timestamp <= end_time)
                
                if conditions:
                    query = query.where(and_(*conditions))
                
                result = await session.execute(query)
                events = result.scalars().all()
                
                return [
                    {
                        "event_id": e.event_id,
                        "event_type": e.event_type,
                        "chain": e.chain_id,
                        "contract_address": e.contract_address,
                        "amount": float(e.amount or 0),
                        "amount_usd": float(e.amount_usd or 0),
                        "timestamp": e.block_timestamp.isoformat() if e.block_timestamp else "",
                        "tx_hash": e.tx_hash or "",
                        "severity": e.severity or "INFO"
                    }
                    for e in events
                ]
            else:
                # Return counts grouped by chain
                query = select(
                    EventModel.chain_id,
                    func.count(EventModel.id).label("count")
                ).group_by(EventModel.chain_id)
                
                conditions = []
                if start_time:
                    conditions.append(EventModel.block_timestamp >= start_time)
                if end_time:
                    conditions.append(EventModel.block_timestamp <= end_time)
                
                if conditions:
                    query = query.where(and_(*conditions))
                
                result = await session.execute(query)
                return {row.chain_id: row.count for row in result}
    
    @staticmethod
    async def get_events_by_contract(
        contract_address: str,
        limit: int = 50,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict]:
        """
        Get events for a specific contract address.
        """
        async with DatabaseManager.get_session() as session:
            query = select(EventModel).where(
                EventModel.contract_address == contract_address.lower()
            ).order_by(EventModel.block_timestamp.desc()).limit(limit)
            
            conditions = []
            if start_time:
                conditions.append(EventModel.block_timestamp >= start_time)
            if end_time:
                conditions.append(EventModel.block_timestamp <= end_time)
            
            if conditions:
                query = query.where(and_(*conditions))
            
            result = await session.execute(query)
            events = result.scalars().all()
            
            return [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "chain": e.chain_id,
                    "contract_address": e.contract_address,
                    "amount": float(e.amount or 0),
                    "amount_usd": float(e.amount_usd or 0),
                    "timestamp": e.block_timestamp.isoformat() if e.block_timestamp else "",
                    "tx_hash": e.tx_hash or "",
                    "severity": e.severity or "INFO"
                }
                for e in events
            ]
    
    @staticmethod
    async def get_event_by_id(event_id: str) -> Optional[Dict]:
        """
        Get a single event by its ID.
        """
        async with DatabaseManager.get_session() as session:
            query = select(EventModel).where(EventModel.event_id == event_id)
            result = await session.execute(query)
            event = result.scalar_one_or_none()

            if not event:
                return None

            return {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "chain": event.chain_id,
                "contract_address": event.contract_address,
                "amount": float(event.amount or 0),
                "amount_usd": float(event.amount_usd or 0),
                "timestamp": event.block_timestamp.isoformat() if event.block_timestamp else "",
                "tx_hash": event.tx_hash or "",
                "severity": event.severity or "INFO",
                "from_address": event.from_address,
                "to_address": event.to_address,
                "raw_data": event.raw_data
            }

    @staticmethod
    async def get_events_by_ids(event_ids: list, limit: int = 100) -> List[Dict]:
        """
        Batch-fetch events by a list of event_ids (single query, avoids N+1).
        """
        if not event_ids:
            return []
        async with DatabaseManager.get_session() as session:
            query = (
                select(EventModel)
                .where(EventModel.event_id.in_(event_ids[:limit]))
                .order_by(EventModel.block_timestamp.desc())
            )
            result = await session.execute(query)
            events = result.scalars().all()

            # Preserve the original ordering from event_ids
            event_map = {}
            for e in events:
                event_map[e.event_id] = {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "chain": e.chain_id,
                    "contract_address": e.contract_address,
                    "amount": float(e.amount or 0),
                    "amount_usd": float(e.amount_usd or 0),
                    "timestamp": e.block_timestamp.isoformat() if e.block_timestamp else "",
                    "tx_hash": e.tx_hash or "",
                    "severity": e.severity or "INFO",
                    "from_address": e.from_address,
                    "to_address": e.to_address,
                    "raw_data": e.raw_data,
                }
            return [event_map[eid] for eid in event_ids[:limit] if eid in event_map]
    
    @staticmethod
    async def get_events_by_type(
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, int]:
        """
        Get event counts grouped by type.
        """
        async with DatabaseManager.get_session() as session:
            query = select(
                EventModel.event_type,
                func.count(EventModel.id).label("count")
            ).group_by(EventModel.event_type)
            
            conditions = []
            if start_time:
                conditions.append(EventModel.block_timestamp >= start_time)
            if end_time:
                conditions.append(EventModel.block_timestamp <= end_time)
            
            if conditions:
                query = query.where(and_(*conditions))
            
            result = await session.execute(query)
            return {row.event_type: row.count for row in result}
    
    @staticmethod
    async def get_contract_deployment_stats() -> Dict[str, Any]:
        """
        Get statistics about contract deployment events from the database.
        Returns total count and breakdown by chain.
        """
        async with DatabaseManager.get_session() as session:
            try:
                # Count contract_deploy events by chain
                sql = text("""
                    SELECT 
                        chain_id,
                        COUNT(*) as count
                    FROM events 
                    WHERE event_type = 'contract_deploy'
                    GROUP BY chain_id
                """)
                result = await session.execute(sql)
                by_chain = {row.chain_id: row.count for row in result}
                
                # Total count
                total = sum(by_chain.values())
                
                return {
                    "total_contracts": total,
                    "by_chain": by_chain
                }
            except Exception as e:
                logger.error("get_contract_deployment_stats_error", error=str(e))
                return {"total_contracts": 0, "by_chain": {}}
    
    @staticmethod
    async def get_contract_deployment_stats_with_threats() -> Dict[str, Any]:
        """
        Get comprehensive statistics about contract deployment events including threats.
        Threats are identified by:
        - severity = 'CRITICAL' or 'HIGH'
        - raw_data containing is_threat = true
        """
        async with DatabaseManager.get_session() as session:
            try:
                # Count all contract_deploy events by chain
                chain_sql = text("""
                    SELECT 
                        chain_id,
                        COUNT(*) as count
                    FROM events 
                    WHERE event_type = 'contract_deploy'
                    GROUP BY chain_id
                """)
                chain_result = await session.execute(chain_sql)
                by_chain = {row.chain_id: row.count for row in chain_result}
                total = sum(by_chain.values())
                
                # Count threats (CRITICAL or HIGH severity)
                threat_sql = text("""
                    SELECT COUNT(*) as count
                    FROM events 
                    WHERE event_type = 'contract_deploy'
                    AND (severity = 'CRITICAL' OR severity = 'HIGH' OR severity = 'critical' OR severity = 'high')
                """)
                threat_result = await session.execute(threat_sql)
                total_threats = threat_result.scalar() or 0
                
                # Count threats in last 24 hours
                threat_24h_sql = text("""
                    SELECT COUNT(*) as count
                    FROM events 
                    WHERE event_type = 'contract_deploy'
                    AND (severity = 'CRITICAL' OR severity = 'HIGH' OR severity = 'critical' OR severity = 'high')
                    AND created_at >= NOW() - INTERVAL '24 hours'
                """)
                threat_24h_result = await session.execute(threat_24h_sql)
                threats_24h = threat_24h_result.scalar() or 0
                
                # Count by severity
                severity_sql = text("""
                    SELECT 
                        LOWER(severity) as severity,
                        COUNT(*) as count
                    FROM events 
                    WHERE event_type = 'contract_deploy'
                    GROUP BY LOWER(severity)
                """)
                severity_result = await session.execute(severity_sql)
                by_severity = {row.severity: row.count for row in severity_result}
                
                # Try to get threat categories from raw_data (may not always be available)
                by_category = {}
                try:
                    category_sql = text("""
                        SELECT 
                            raw_data->>'threat_category' as category,
                            COUNT(*) as count
                        FROM events 
                        WHERE event_type = 'contract_deploy'
                        AND raw_data IS NOT NULL
                        AND raw_data->>'threat_category' IS NOT NULL
                        AND raw_data->>'threat_category' != 'safe'
                        GROUP BY raw_data->>'threat_category'
                    """)
                    category_result = await session.execute(category_sql)
                    by_category = {row.category: row.count for row in category_result if row.category}
                except Exception as cat_err:
                    logger.debug("category_stats_query_failed", error=str(cat_err))
                
                logger.info(
                    "contract_deployment_stats_with_threats",
                    total=total,
                    threats=total_threats,
                    threats_24h=threats_24h,
                    by_severity=by_severity
                )
                
                return {
                    "total_contracts": total,
                    "by_chain": by_chain,
                    "total_threats": total_threats,
                    "threats_24h": threats_24h,
                    "by_severity": by_severity,
                    "by_category": by_category
                }
            except Exception as e:
                logger.error("get_contract_deployment_stats_with_threats_error", error=str(e))
                return {
                    "total_contracts": 0, 
                    "by_chain": {},
                    "total_threats": 0,
                    "threats_24h": 0,
                    "by_severity": {},
                    "by_category": {}
                }
    
    @staticmethod
    async def get_contract_deploy_alerts(
        chain_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get contract deployment events from the database for the alerts list.
        Returns events with event_type='contract_deploy'.
        """
        async with DatabaseManager.get_session() as session:
            try:
                where_parts = ["event_type = 'contract_deploy'"]
                params = {"limit": limit}
                
                if chain_id:
                    where_parts.append("chain_id = :chain_id")
                    params["chain_id"] = chain_id
                
                where_clause = " AND ".join(where_parts)
                
                sql = text(f"""
                    SELECT 
                        event_id, chain_id, tx_hash, block_number,
                        block_timestamp, contract_address, severity,
                        from_address, raw_data
                    FROM events 
                    WHERE {where_clause}
                    ORDER BY block_timestamp DESC
                    LIMIT :limit
                """)
                
                result = await session.execute(sql, params)
                rows = result.fetchall()
                
                logger.info("get_contract_deploy_alerts_query", 
                            rows_found=len(rows),
                            chain_filter=chain_id)
                
                alerts = []
                
                for row in rows:
                    # Parse raw_data - it may be a JSON string or dict
                    raw_data = row.raw_data if row.raw_data else {}
                    if isinstance(raw_data, str):
                        try:
                            import json
                            raw_data = json.loads(raw_data)
                        except (json.JSONDecodeError, TypeError):
                            raw_data = {}
                    
                    alerts.append({
                        "event_id": row.event_id,
                        "alert_id": raw_data.get("alert_id", row.event_id) if isinstance(raw_data, dict) else row.event_id,
                        "chain_id": row.chain_id,
                        "tx_hash": row.tx_hash,
                        "block_number": row.block_number,
                        "block_timestamp": row.block_timestamp.isoformat() if row.block_timestamp else "",
                        "contract_address": row.contract_address,
                        "severity": row.severity,
                        "from_address": row.from_address,
                        "raw_data": raw_data if isinstance(raw_data, dict) else {}
                    })
                
                return alerts
            except Exception as e:
                logger.error("get_contract_deploy_alerts_error", error=str(e))
                return []
    
    # =========================================================================
    # INCIDENT OPERATIONS
    # =========================================================================
    
    @staticmethod
    async def save_incident(incident_data: Dict[str, Any]) -> Optional[str]:
        """
        Save an incident to the database with idempotency.
        Uses cluster_key (dedupe_key) for deduplication.
        Returns the incident_id on success.
        """
        from .idempotency import IdempotencyService, generate_incident_dedupe_key
        
        # Generate or use provided dedupe key
        dedupe_key = incident_data.get("cluster_key") or incident_data.get("dedupe_key")
        if not dedupe_key:
            # Generate from incident data
            dedupe_key = generate_incident_dedupe_key(
                incident_type=incident_data.get("attack_type", "UNKNOWN"),
                protocol_id=incident_data.get("protocol_id", ""),
                primary_chain=incident_data.get("affected_chains", [""])[0] if incident_data.get("affected_chains") else "",
                attacker_cluster=incident_data.get("attacker_cluster"),
                time_bucket=incident_data.get("time_bucket")
            )
        
        # Check idempotency
        existing = await IdempotencyService.check_idempotency(dedupe_key)
        if existing and existing.get("status") == "PROCESSED" and existing.get("incident_id"):
            logger.debug("incident_already_processed", dedupe_key=dedupe_key[:16], incident_id=existing.get("incident_id"))
            return existing.get("incident_id")
        
        async with DatabaseManager.get_session() as session:
            try:
                incident_id = incident_data.get("incident_id") or incident_data.get("id")
                
                # Try to get existing incident by cluster_key
                if dedupe_key:
                    result = await session.execute(
                        select(IncidentModel).where(IncidentModel.cluster_key == dedupe_key)
                    )
                    existing_incident = result.scalar_one_or_none()
                    
                    if existing_incident:
                        # Update existing incident
                        existing_incident.status = incident_data.get("status", existing_incident.status).upper()
                        existing_incident.event_ids = incident_data.get("event_ids", existing_incident.event_ids) or []
                        existing_incident.event_count = len(existing_incident.event_ids) if existing_incident.event_ids else 0
                        await session.commit()
                        
                        # Mark as processed
                        await IdempotencyService.mark_processed(
                            idempotency_key=dedupe_key,
                            incident_id=existing_incident.incident_id
                        )
                        
                        logger.debug("incident_updated", incident_id=existing_incident.incident_id)
                        return existing_incident.incident_id
                
                # Create new incident
                if not incident_id:
                    incident_id = f"inc_{dedupe_key[:16]}_{int(datetime.now(timezone.utc).timestamp())}"
                
                incident = IncidentModel(
                    incident_id=incident_id,
                    cluster_key=dedupe_key,
                    title=incident_data.get("title"),
                    summary=incident_data.get("summary", incident_data.get("title")),
                    severity=incident_data.get("severity", "LOW").upper(),
                    status=incident_data.get("status", "OPEN_PENDING").upper(),
                    attack_type=incident_data.get("attack_type", "UNKNOWN"),
                    confidence=incident_data.get("confidence", 0.5),
                    total_loss_usd=incident_data.get("total_loss_usd", 0),
                    affected_chains=incident_data.get("affected_chains", []),
                    affected_contracts=incident_data.get("affected_contracts", []),  # Contract addresses
                    affected_addresses=incident_data.get("affected_addresses", []),  # Deployer/attacker addresses
                    event_ids=incident_data.get("event_ids", []),
                    violation_ids=incident_data.get("violation_ids", []),
                    rule_ids=incident_data.get("rule_ids", []),
                    recommended_actions=incident_data.get("recommended_actions", []),
                    event_count=len(incident_data.get("event_ids", []))
                )
                session.add(incident)
                await session.flush()
                
                # Mark as processed
                await IdempotencyService.mark_processed(
                    idempotency_key=dedupe_key,
                    incident_id=incident.incident_id
                )
                
                await session.commit()
                logger.debug("incident_saved", incident_id=incident.incident_id)
                return incident.incident_id
            except Exception as e:
                logger.error("incident_save_failed", error=str(e), incident_id=incident_data.get("incident_id"))
                await session.rollback()
                
                # Mark as failed
                await IdempotencyService.mark_failed(
                    idempotency_key=dedupe_key,
                    error_message=str(e)
                )
                raise
    
    @staticmethod
    async def get_incident(incident_id: str) -> Optional[IncidentModel]:
        """
        Get an incident by ID.
        """
        async with DatabaseManager.get_session() as session:
            query = select(IncidentModel).where(IncidentModel.incident_id == incident_id)
            result = await session.execute(query)
            return result.scalar_one_or_none()
    
    @staticmethod
    async def update_incident_status(
        incident_id: str,
        status: str,
        notes: Optional[str] = None,
        acknowledged_by: Optional[str] = None,
        resolved_by: Optional[str] = None,
    ) -> bool:
        """
        Update incident status and related fields.
        """
        async with DatabaseManager.get_session() as session:
            try:
                updates = {"status": status.upper(), "updated_at": datetime.now(timezone.utc)}
                
                if status.upper() == "ACKNOWLEDGED" and acknowledged_by:
                    updates["acknowledged_by"] = acknowledged_by
                    updates["acknowledged_at"] = datetime.now(timezone.utc)
                
                if status.upper() == "RESOLVED" and resolved_by:
                    updates["resolved_by"] = resolved_by
                    updates["resolved_at"] = datetime.now(timezone.utc)
                    if notes:
                        updates["resolution_notes"] = notes
                
                stmt = update(IncidentModel).where(
                    IncidentModel.incident_id == incident_id
                ).values(**updates)
                
                result = await session.execute(stmt)
                logger.info("incident_status_updated", incident_id=incident_id, status=status)
                return result.rowcount > 0
            except Exception as e:
                logger.error("incident_update_failed", error=str(e), incident_id=incident_id)
                raise
    
    @staticmethod
    async def get_incidents(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get incidents from the database with optional filtering.
        """
        async with DatabaseManager.get_session() as session:
            try:
                query = select(IncidentModel).order_by(IncidentModel.created_at.desc())
                
                if severity:
                    query = query.where(IncidentModel.severity == severity.upper())
                
                if status:
                    query = query.where(IncidentModel.status == status.upper())
                
                query = query.limit(limit)
                
                result = await session.execute(query)
                incidents = result.scalars().all()
                
                return [
                    {
                        "id": inc.incident_id,
                        "title": inc.title,
                        "severity": inc.severity.lower() if inc.severity else "medium",
                        "status": inc.status.lower() if inc.status else "open",
                        "attack_type": inc.attack_type or "unknown",
                        "confidence": inc.confidence or 0.5,
                        "total_loss_usd": inc.total_loss_usd or 0,
                        "affected_chains": inc.affected_chains or [],
                        "created_at": inc.created_at,
                        "event_count": inc.event_count or 0,
                        # Additional fields for ML-detected threats
                        "affected_contracts": inc.affected_contracts or [],
                        "affected_addresses": inc.affected_addresses or [],
                        "summary": inc.summary,
                        "recommended_actions": inc.recommended_actions or [],
                    }
                    for inc in incidents
                ]
            except Exception as e:
                logger.error("get_incidents_error", error=str(e))
                return []
    
    @staticmethod
    async def write_audit_log(
        incident_id: str,
        action: str,
        previous_status: str,
        new_status: str,
        analyst_id: str = None,
        notes: str = None,
        metadata: dict = None,
    ) -> bool:
        """Write an immutable audit log entry for an incident status change."""
        async with DatabaseManager.get_session() as session:
            try:
                from sqlalchemy import text
                await session.execute(
                    text("""
                        INSERT INTO incident_audit_log
                            (id, incident_id, action, previous_status, new_status, analyst_id, notes)
                        VALUES
                            (gen_random_uuid(), :incident_id, :action, :prev, :new, :analyst, :notes)
                    """),
                    {
                        "incident_id": incident_id,
                        "action": action,
                        "prev": previous_status,
                        "new": new_status,
                        "analyst": analyst_id,
                        "notes": notes,
                    }
                )
                await session.commit()
                return True
            except Exception as e:
                logger.error("write_audit_log_error", incident_id=incident_id, error=str(e))
                await session.rollback()
                return False

    @staticmethod
    async def get_incident_audit_log(incident_id: str) -> list:
        """Get all audit log entries for an incident."""
        async with DatabaseManager.get_session() as session:
            try:
                from sqlalchemy import text
                result = await session.execute(
                    text("""
                        SELECT id, incident_id, action, previous_status, new_status,
                               analyst_id, notes, metadata_json, created_at
                        FROM incident_audit_log
                        WHERE incident_id = :incident_id
                        ORDER BY created_at ASC
                    """),
                    {"incident_id": incident_id}
                )
                rows = result.fetchall()
                return [
                    {
                        "id": str(r[0]),
                        "incident_id": r[1],
                        "action": r[2],
                        "previous_status": r[3],
                        "new_status": r[4],
                        "analyst_id": r[5],
                        "notes": r[6],
                        "metadata": r[7],
                        "created_at": r[8].isoformat() if r[8] else None,
                    }
                    for r in rows
                ]
            except Exception as e:
                logger.error("get_audit_log_error", incident_id=incident_id, error=str(e))
                return []

    @staticmethod
    async def update_incident_feedback(
        incident_id: str,
        is_true_positive: bool,
        feedback_notes: Optional[str] = None,
        analyst_id: Optional[str] = None,
        new_status: Optional[str] = None
    ) -> bool:
        """
        Update incident with analyst feedback (TP/FP marking).
        
        Args:
            incident_id: The incident to update
            is_true_positive: Whether the incident is a true positive
            feedback_notes: Optional notes from analyst
            analyst_id: ID of the analyst providing feedback
            new_status: Optional new status to set
        
        Returns:
            True if successful, False otherwise
        """
        async with DatabaseManager.get_session() as session:
            try:
                import json
                
                # Find incident by incident_id
                query = select(IncidentModel).where(IncidentModel.incident_id == incident_id)
                result = await session.execute(query)
                incident = result.scalar_one_or_none()
                
                if not incident:
                    logger.warning("incident_not_found_for_feedback", incident_id=incident_id)
                    return False
                
                # Update raw_data with feedback
                raw_data = incident.raw_data or {}
                if isinstance(raw_data, str):
                    try:
                        raw_data = json.loads(raw_data)
                    except:
                        raw_data = {}
                
                raw_data["analyst_feedback"] = {
                    "is_true_positive": is_true_positive,
                    "feedback_notes": feedback_notes,
                    "analyst_id": analyst_id or "anonymous",
                    "feedback_time": datetime.now(timezone.utc).isoformat()
                }
                
                incident.raw_data = raw_data
                incident.updated_at = datetime.now(timezone.utc)
                
                # Update status if provided
                if new_status:
                    incident.status = new_status.upper()
                    if new_status.upper() == "RESOLVED":
                        incident.resolved_at = datetime.now(timezone.utc)
                        incident.resolved_by = analyst_id
                
                await session.commit()
                logger.info("incident_feedback_updated", 
                           incident_id=incident_id, 
                           is_tp=is_true_positive,
                           analyst=analyst_id)
                return True
                
            except Exception as e:
                logger.error("update_incident_feedback_error", incident_id=incident_id, error=str(e))
                await session.rollback()
                return False
    
    @staticmethod
    async def get_incident_stats() -> Dict[str, Any]:
        """
        Get incident statistics.
        """
        async with DatabaseManager.get_session() as session:
            # Total incidents
            total_query = select(func.count(IncidentModel.id))
            total_result = await session.execute(total_query)
            total_count = total_result.scalar() or 0
            
            # By severity
            severity_query = select(
                IncidentModel.severity,
                func.count(IncidentModel.id).label("count")
            ).group_by(IncidentModel.severity)
            severity_result = await session.execute(severity_query)
            by_severity = {row.severity: row.count for row in severity_result}
            
            # Active incidents
            active_query = select(func.count(IncidentModel.id)).where(
                IncidentModel.status.in_(["OPEN_PENDING", "OPEN_CONFIRMED"])
            )
            active_result = await session.execute(active_query)
            active_count = active_result.scalar() or 0
            
            return {
                "total": total_count,
                "by_severity": by_severity,
                "active": active_count,
            }
    
    # =========================================================================
    # ANALYTICS & STATS
    # =========================================================================
    
    @staticmethod
    async def get_dashboard_stats(
        time_range_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get dashboard statistics for the last N hours.
        """
        async with DatabaseManager.get_session() as session:
            start_time = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)
            
            # Event stats
            event_count = await session.execute(
                select(func.count(EventModel.id)).where(EventModel.created_at >= start_time)
            )
            total_events = event_count.scalar() or 0
            
            # Events by chain
            chain_query = select(
                EventModel.chain_id,
                func.count(EventModel.id).label("count")
            ).where(EventModel.created_at >= start_time).group_by(EventModel.chain_id)
            chain_result = await session.execute(chain_query)
            events_by_chain = {row.chain_id: row.count for row in chain_result}
            
            # Events by type
            type_query = select(
                EventModel.event_type,
                func.count(EventModel.id).label("count")
            ).where(EventModel.created_at >= start_time).group_by(EventModel.event_type)
            type_result = await session.execute(type_query)
            events_by_type = {row.event_type: row.count for row in type_result}
            
            # Incident stats
            incident_stats = await DatabaseService.get_incident_stats()
            
            return {
                "events": {
                    "total": total_events,
                    "by_chain": events_by_chain,
                    "by_type": events_by_type,
                },
                "incidents": incident_stats,
            }
    
    @staticmethod
    async def get_event_timeseries(
        chain_id: Optional[str] = None,
        interval_minutes: int = 60,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """
        Get event counts over time (for charts).
        """
        async with DatabaseManager.get_session() as session:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)
            
            data_points = []
            current_time = start_time
            
            while current_time < end_time:
                period_end = current_time + timedelta(minutes=interval_minutes)
                
                query = select(func.count(EventModel.id)).where(
                    and_(
                        EventModel.block_timestamp >= current_time,
                        EventModel.block_timestamp < period_end,
                    )
                )
                
                if chain_id:
                    query = query.where(EventModel.chain_id == chain_id)
                
                result = await session.execute(query)
                count = result.scalar() or 0
                
                data_points.append({
                    "timestamp": current_time.isoformat(),
                    "count": count,
                })
                
                current_time = period_end
            
            return data_points
    
    # =========================================================================
    # MAINTENANCE
    # =========================================================================
    
    @staticmethod
    async def cleanup_old_events(days: int = 90) -> int:
        """
        Delete events older than N days.
        Returns count of deleted events.
        """
        async with DatabaseManager.get_session() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            stmt = delete(EventModel).where(EventModel.created_at < cutoff)
            result = await session.execute(stmt)
            count = result.rowcount
            logger.info("old_events_cleaned", count=count, days=days)
            return count
    
    @staticmethod
    async def fix_stale_timestamps(hours_threshold: int = 3) -> Dict[str, Any]:
        """
        Fix events with stale block_timestamps.
        
        Some events were saved with incorrect block_timestamps (e.g., datetime.now() 
        instead of actual block timestamp). This method identifies and updates them
        by using created_at as a proxy for the actual timestamp.
        
        Events are considered "stale" if:
        - block_timestamp is more than hours_threshold hours before created_at
        - This indicates the block_timestamp was not the actual blockchain timestamp
        
        Returns stats about fixed events.
        """
        from sqlalchemy import text
        
        async with DatabaseManager.get_session() as session:
            try:
                # First, count affected events
                count_sql = text("""
                    SELECT COUNT(*) as cnt,
                           MIN(block_timestamp) as min_ts,
                           MAX(block_timestamp) as max_ts
                    FROM events 
                    WHERE created_at - block_timestamp > INTERVAL ':hours hours'
                """.replace(':hours', str(hours_threshold)))
                
                count_result = await session.execute(count_sql)
                count_row = count_result.fetchone()
                affected_count = count_row[0] if count_row else 0
                
                if affected_count == 0:
                    logger.info("no_stale_timestamps_found", threshold_hours=hours_threshold)
                    return {
                        "status": "ok",
                        "affected_count": 0,
                        "fixed_count": 0,
                        "message": "No stale timestamps found"
                    }
                
                logger.info(
                    "stale_timestamps_found",
                    affected_count=affected_count,
                    min_ts=str(count_row[1]) if count_row else None,
                    max_ts=str(count_row[2]) if count_row else None,
                    threshold_hours=hours_threshold
                )
                
                # Update stale timestamps to use created_at (which is when we actually received the event)
                # This is more accurate than the incorrect block_timestamp
                update_sql = text("""
                    UPDATE events 
                    SET block_timestamp = created_at
                    WHERE created_at - block_timestamp > INTERVAL ':hours hours'
                """.replace(':hours', str(hours_threshold)))
                
                result = await session.execute(update_sql)
                fixed_count = result.rowcount
                await session.commit()
                
                logger.info(
                    "stale_timestamps_fixed",
                    fixed_count=fixed_count,
                    threshold_hours=hours_threshold
                )
                
                return {
                    "status": "ok",
                    "affected_count": affected_count,
                    "fixed_count": fixed_count,
                    "message": f"Fixed {fixed_count} events with stale timestamps"
                }
                
            except Exception as e:
                logger.error("fix_stale_timestamps_error", error=str(e), exc_info=True)
                return {
                    "status": "error",
                    "error": str(e),
                    "affected_count": 0,
                    "fixed_count": 0
                }
