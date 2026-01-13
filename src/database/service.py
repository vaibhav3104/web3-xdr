"""
Database Service Layer for Sentinel3.
Provides high-level async methods for CRUD operations.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import List, Optional, Dict, Any, Tuple
import uuid
import json

import structlog
from sqlalchemy import select, func, delete, update, and_, or_, desc, text
from sqlalchemy.ext.asyncio import AsyncSession

from .connection import DatabaseManager
from .models import (
    EventModel,
    IncidentModel,
    ViolationModel,
    ChainStatsModel,
    AlertRuleModel,
    AuditLogModel,
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
        """
        if not events:
            return 0
        
        logger.info("save_events_batch_RAW_SQL_START", total_events=len(events), sample_tx=events[0].get("tx_hash", "N/A")[:16])
        
        try:
            async with DatabaseManager.get_session() as session:
                from sqlalchemy import text
                import json
                
                # Raw SQL INSERT - no ORM, no complications  
                # Use CAST instead of :: for type conversion
                raw_insert_sql = text("""
                    INSERT INTO events (
                        id, event_id, chain_id, event_type, tx_hash, block_number,
                        block_timestamp, contract_address, severity, amount, amount_usd,
                        from_address, to_address, raw_data, created_at
                    ) VALUES (
                        gen_random_uuid(), 
                        :event_id, 
                        :chain_id, 
                        :event_type, 
                        :tx_hash, 
                        :block_number,
                        CAST(:block_timestamp AS TIMESTAMP), 
                        :contract_address, 
                        :severity, 
                        :amount, 
                        :amount_usd,
                        :from_address, 
                        :to_address, 
                        CAST(:raw_data AS JSONB),
                        NOW()
                    )
                    ON CONFLICT (event_id) DO NOTHING
                """)
                
                # Execute for each event
                saved_count = 0
                for event in events:
                    try:
                        await session.execute(raw_insert_sql, {
                            "event_id": event.get("event_id"),
                            "chain_id": event.get("chain_id"),
                            "event_type": event.get("event_type"),
                            "tx_hash": event.get("tx_hash"),
                            "block_number": event.get("block_number"),
                            "block_timestamp": event.get("block_timestamp"),
                            "contract_address": event.get("contract_address"),
                            "severity": event.get("severity", "LOW"),
                            "amount": event.get("amount"),
                            "amount_usd": event.get("amount_usd"),
                            "from_address": event.get("from_address"),
                            "to_address": event.get("to_address"),
                            "raw_data": json.dumps(event.get("raw_data", {}))
                        })
                        saved_count += 1
                        logger.debug("raw_sql_insert_executed", event_id=event.get("event_id")[:16])
                    except Exception as e:
                        logger.error("raw_sql_insert_failed", event_id=event.get("event_id")[:16], error=str(e))
                
                # Commit the transaction
                await session.commit()
                logger.info("save_events_batch_RAW_SQL_COMMITTED", executed=saved_count, total=len(events))
                
            # VERIFICATION: Query database AFTER session closes (new session)
            try:
                async with DatabaseManager.get_session() as verify_session:
                    verify_sql = text("SELECT COUNT(*) FROM events WHERE created_at > NOW() - INTERVAL '10 seconds'")
                    result = await verify_session.execute(verify_sql)
                    actual_count = result.scalar()
                    
                    logger.info("save_events_batch_VERIFICATION", 
                               expected=saved_count, 
                               actual_in_db=actual_count,
                               match=actual_count >= saved_count)
            except Exception as verify_error:
                logger.warning("verification_query_failed", error=str(verify_error), error_type=type(verify_error).__name__)
            
            # Return the executed count
            return saved_count
            
        except Exception as e:
            logger.error("save_events_batch_RAW_SQL_FAILED", 
                        error=str(e), 
                        error_type=type(e).__name__,
                        total=len(events), 
                        exc_info=True)
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
            if severity:
                where_parts.append("severity = :severity")
                params['severity'] = severity.upper()
            if status:
                where_parts.append("status = :status")
                params['status'] = status.upper()
            
            # Cursor-based pagination (preferred over OFFSET)
            if cursor:
                cursor_data = decode_cursor(cursor)
                if cursor_data:
                    cursor_timestamp, cursor_id = cursor_data
                    where_parts.append(
                        "(block_timestamp, id) < (CAST(:cursor_timestamp AS TIMESTAMP WITH TIME ZONE), CAST(:cursor_id AS UUID))"
                    )
                    params['cursor_timestamp'] = cursor_timestamp.isoformat()
                    params['cursor_id'] = cursor_id
            
            where_clause = " AND ".join(where_parts) if where_parts else "1=1"
            
            # Query using raw SQL with cursor pagination
            # Order by (block_timestamp DESC, id DESC) for stable cursor
            sql = f"""
                SELECT id, event_id, chain_id, event_type, tx_hash, block_number,
                       block_timestamp, contract_address, severity, amount, amount_usd,
                       from_address, to_address, raw_data, created_at,
                       COALESCE(status, 'PENDING') as status
                FROM events
                WHERE {where_clause}
                ORDER BY block_timestamp DESC, id DESC
                LIMIT :limit
            """
            params['limit'] = limit + 1  # Fetch one extra to check if there's more
            
            result = await session.execute(text(sql), params)
            rows = result.fetchall()
            
            # Convert rows to dicts
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
                    'status': row[15] if len(row) > 15 else 'PENDING',
                })
            
            # Generate next cursor if there are more results
            next_cursor = None
            if len(events) > limit:
                # Remove the extra event
                last_event = events[limit - 1]
                next_cursor = encode_cursor(last_event['block_timestamp'], last_event['id'])
                events = events[:limit]
            
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
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, int]:
        """
        Get event counts grouped by chain.
        """
        async with DatabaseManager.get_session() as session:
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
