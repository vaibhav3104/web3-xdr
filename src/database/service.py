"""
Database Service Layer for Sentinel3.
Provides high-level async methods for CRUD operations.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import List, Optional, Dict, Any
import uuid

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
        BULLETPROOF event saving - simple, reliable, handles worker data format.
        Worker sends: ISO timestamp strings, int block_number, string/None amounts.
        """
        if not events:
            return 0
        
        import json
        
        saved = 0
        async with DatabaseManager.get_session() as session:
            for event in events:
                try:
                    # Required fields
                    event_id = str(event.get('event_id') or uuid.uuid4())
                    tx_hash = str(event.get('tx_hash') or '')
                    block_number = event.get('block_number')
                    
                    if not tx_hash or block_number is None:
                        continue
                    
                    block_number_int = int(block_number)
                    
                    # Timestamp: worker sends ISO string - convert to UTC datetime
                    # CRITICAL: Must be timezone-aware UTC for asyncpg
                    ts_str = event.get('block_timestamp') or event.get('timestamp')
                    if isinstance(ts_str, str):
                        try:
                            # Normalize Z to +00:00
                            if ts_str.endswith('Z'):
                                ts_str = ts_str[:-1] + '+00:00'
                            # Parse ISO string
                            dt = datetime.fromisoformat(ts_str)
                            # Ensure UTC timezone-aware
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            elif dt.tzinfo != timezone.utc:
                                dt = dt.astimezone(timezone.utc)
                        except Exception as e:
                            logger.debug("timestamp_parse_error", ts=ts_str, error=str(e))
                            dt = datetime.now(timezone.utc)
                    elif isinstance(ts_str, datetime):
                        # Normalize existing datetime to UTC
                        if ts_str.tzinfo is None:
                            dt = ts_str.replace(tzinfo=timezone.utc)
                        elif ts_str.tzinfo != timezone.utc:
                            dt = ts_str.astimezone(timezone.utc)
                        else:
                            dt = ts_str
                    else:
                        dt = datetime.now(timezone.utc)
                    
                    # Final check - must be UTC timezone-aware
                    if not isinstance(dt, datetime) or dt.tzinfo is None or dt.tzinfo != timezone.utc:
                        dt = datetime.now(timezone.utc)
                    
                    # Amounts: simple conversion
                    def to_decimal(val):
                        if val is None or val == '' or val == '0':
                            return None
                        try:
                            return Decimal(str(val))
                        except:
                            return None
                    
                    amount = to_decimal(event.get('amount'))
                    amount_usd = to_decimal(event.get('amount_usd'))
                    
                    # Raw data
                    raw = event.get('raw_data') or event
                    raw_json = json.dumps(raw) if isinstance(raw, (dict, list)) else '{}'
                    
                    # Simple INSERT - pass correct Python types, let asyncpg handle conversion
                    await session.execute(text("""
                        INSERT INTO events (id, event_id, chain_id, event_type, tx_hash, block_number,
                            block_timestamp, contract_address, severity, amount, amount_usd,
                            from_address, to_address, raw_data)
                        VALUES (CAST(:id AS UUID), :event_id, :chain_id, :event_type, :tx_hash, :block_number,
                            :block_timestamp, :contract_address, :severity, 
                            :amount, :amount_usd,
                            :from_address, :to_address, CAST(:raw_data AS JSONB))
                        ON CONFLICT (event_id) DO NOTHING
                    """), {
                        'id': str(uuid.uuid4()),
                        'event_id': event_id,
                        'chain_id': str(event.get('chain_id') or 'unknown'),
                        'event_type': str(event.get('event_type') or 'Unknown'),
                        'tx_hash': tx_hash,
                        'block_number': block_number_int,
                        'block_timestamp': dt,
                        'contract_address': str(event.get('contract_address') or ''),
                        'severity': str((event.get('severity') or 'LOW').upper()),
                        'amount': amount,
                        'amount_usd': amount_usd,
                        'from_address': event.get('from_address'),
                        'to_address': event.get('to_address'),
                        'raw_data': raw_json,
                    })
                    saved += 1
                except Exception as e:
                    logger.warning("event_save_skipped", event_id=event.get('event_id'), error=str(e)[:200])
            
        if saved > 0:
            logger.info("events_batch_saved", count=saved, total=len(events))
        return saved
    
    @staticmethod
    async def get_events(
        chain_id: Optional[str] = None,
        event_type: Optional[str] = None,
        contract_address: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EventModel]:
        """
        Query events with optional filters.
        """
        async with DatabaseManager.get_session() as session:
            query = select(EventModel)
            
            conditions = []
            if chain_id:
                conditions.append(EventModel.chain_id == chain_id)
            if event_type:
                conditions.append(EventModel.event_type == event_type)
            if contract_address:
                conditions.append(EventModel.contract_address == contract_address)
            if start_time:
                conditions.append(EventModel.block_timestamp >= start_time)
            if end_time:
                conditions.append(EventModel.block_timestamp <= end_time)
            if severity:
                conditions.append(EventModel.severity == severity)
            
            if conditions:
                query = query.where(and_(*conditions))
            
            query = query.order_by(desc(EventModel.block_timestamp))
            query = query.limit(limit).offset(offset)
            
            result = await session.execute(query)
            return result.scalars().all()
    
    @staticmethod
    async def count_events(
        chain_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """
        Count events matching filters.
        """
        async with DatabaseManager.get_session() as session:
            query = select(func.count(EventModel.id))
            
            conditions = []
            if chain_id:
                conditions.append(EventModel.chain_id == chain_id)
            if start_time:
                conditions.append(EventModel.block_timestamp >= start_time)
            if end_time:
                conditions.append(EventModel.block_timestamp <= end_time)
            
            if conditions:
                query = query.where(and_(*conditions))
            
            result = await session.execute(query)
            return result.scalar() or 0
    
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
        Save an incident to the database.
        Returns the incident_id on success.
        """
        async with DatabaseManager.get_session() as session:
            try:
                incident = IncidentModel(
                    incident_id=incident_data.get("incident_id") or incident_data.get("id"),
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
                )
                session.add(incident)
                await session.flush()
                logger.debug("incident_saved", incident_id=incident.incident_id)
                return incident.incident_id
            except Exception as e:
                logger.error("incident_save_failed", error=str(e), incident_id=incident_data.get("incident_id"))
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
