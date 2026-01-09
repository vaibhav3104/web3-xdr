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
        Save events to DB using raw SQL with base columns only.
        Compatible with events table that may lack status/block_hash columns.
        """
        if not events:
            return 0
        
        import json
        
        saved = 0
        errors = []
        async with DatabaseManager.get_session() as session:
            for event in events:
                try:
                    # Validate required fields
                    event_id = event.get('event_id')
                    tx_hash = event.get('tx_hash')
                    block_number = event.get('block_number')
                    
                    if not event_id or not tx_hash or block_number is None:
                        errors.append(f"Missing required fields: event_id={bool(event_id)}, tx_hash={bool(tx_hash)}, block_number={block_number is not None}")
                        continue
                    
                    # Prepare data
                    raw = event.get('raw_data') or event
                    raw_json = json.dumps(raw) if isinstance(raw, (dict, list)) else '{}'
                    
                    # Handle timestamp - convert to UTC timezone-aware datetime
                    # CRITICAL: asyncpg requires timezone-aware datetime, and all must be UTC to avoid subtraction errors
                    block_timestamp = event.get('block_timestamp')
                    if isinstance(block_timestamp, str):
                        try:
                            # Parse ISO string
                            if 'Z' in block_timestamp:
                                dt = datetime.fromisoformat(block_timestamp.replace('Z', '+00:00'))
                            elif '+' in block_timestamp or block_timestamp.count('-') > 2:
                                dt = datetime.fromisoformat(block_timestamp)
                            else:
                                # No timezone - parse as naive and add UTC
                                dt = datetime.strptime(block_timestamp, '%Y-%m-%dT%H:%M:%S.%f')
                                dt = dt.replace(tzinfo=timezone.utc)
                            
                            # Normalize to UTC (convert if in different timezone)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            else:
                                dt = dt.astimezone(timezone.utc)
                            block_timestamp = dt
                        except Exception as e:
                            logger.debug("timestamp_parse_failed", timestamp=block_timestamp, error=str(e))
                            block_timestamp = datetime.now(timezone.utc)
                    elif isinstance(block_timestamp, datetime):
                        # Normalize existing datetime to UTC
                        if block_timestamp.tzinfo is None:
                            block_timestamp = block_timestamp.replace(tzinfo=timezone.utc)
                        else:
                            block_timestamp = block_timestamp.astimezone(timezone.utc)
                    else:
                        # None or other type - use current UTC time
                        block_timestamp = datetime.now(timezone.utc)
                    
                    # Final validation - ensure it's UTC timezone-aware
                    if not isinstance(block_timestamp, datetime) or block_timestamp.tzinfo is None:
                        block_timestamp = datetime.now(timezone.utc)
                    elif block_timestamp.tzinfo != timezone.utc:
                        block_timestamp = block_timestamp.astimezone(timezone.utc)
                    
                    # Handle amount/amount_usd - convert to Decimal or None
                    def to_decimal_or_none(val):
                        if val is None or val == '':
                            return None
                        if isinstance(val, (int, float)):
                            return Decimal(str(val))
                        if isinstance(val, str):
                            try:
                                return Decimal(val) if val.strip() else None
                            except:
                                return None
                        return None
                    
                    amount = to_decimal_or_none(event.get('amount'))
                    amount_usd = to_decimal_or_none(event.get('amount_usd'))
                    
                    # Convert block_number to int with validation
                    try:
                        block_number_int = int(block_number)
                    except (ValueError, TypeError):
                        errors.append(f"Invalid block_number: {block_number}")
                        continue
                    
                    insert_sql = text("""
                        INSERT INTO events (id, event_id, chain_id, event_type, tx_hash, block_number,
                            block_timestamp, contract_address, severity, amount, amount_usd,
                            from_address, to_address, raw_data)
                        VALUES (CAST(:id AS UUID), :event_id, :chain_id, :event_type, :tx_hash, :block_number,
                            :block_timestamp, :contract_address, :severity, 
                            :amount, :amount_usd,
                            :from_address, :to_address, CAST(:raw_data AS JSONB))
                        ON CONFLICT (event_id) DO NOTHING
                    """)
                    
                    await session.execute(insert_sql, {
                        'id': str(uuid.uuid4()),
                        'event_id': str(event_id),
                        'chain_id': str(event.get('chain_id') or 'unknown'),
                        'event_type': str(event.get('event_type') or 'unknown'),
                        'tx_hash': str(tx_hash),
                        'block_number': block_number_int,
                        'block_timestamp': block_timestamp,
                        'contract_address': str(event.get('contract_address') or ''),
                        'severity': str((event.get('severity') or 'LOW').upper()),
                        'amount': amount,  # Decimal or None - asyncpg handles conversion
                        'amount_usd': amount_usd,  # Decimal or None
                        'from_address': event.get('from_address') or None,
                        'to_address': event.get('to_address') or None,
                        'raw_data': raw_json,
                    })
                    saved += 1
                except Exception as e:
                    error_msg = str(e)
                    errors.append(f"event_id={event.get('event_id', 'N/A')}: {error_msg[:200]}")
                    logger.warning("event_insert_failed", event_id=event.get('event_id'), error=error_msg[:500], exc_info=True)
            
            # get_session context manager auto-commits on success
        if saved > 0:
            logger.info("events_batch_saved", count=saved, total=len(events))
        if errors:
            logger.warning("events_batch_errors", error_count=len(errors), errors=errors[:5])
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
    async def get_event_count(
        chain_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """
        Get total event count with optional filters.
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
        Get event counts grouped by event type.
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
        Save a new incident to the database.
        """
        async with DatabaseManager.get_session() as session:
            try:
                incident = IncidentModel(
                    incident_id=incident_data.get("id") or incident_data.get("incident_id"),
                    title=incident_data.get("title"),
                    summary=incident_data.get("summary"),
                    severity=incident_data.get("severity"),
                    status=incident_data.get("status", "OPEN"),
                    attack_type=incident_data.get("attack_type"),
                    confidence=incident_data.get("confidence", 0.5),
                    total_loss_usd=incident_data.get("total_loss_usd"),
                    affected_chains=incident_data.get("affected_chains", []),
                    affected_contracts=incident_data.get("affected_contracts"),
                    affected_addresses=incident_data.get("affected_addresses"),
                    event_ids=incident_data.get("event_ids"),
                    violation_ids=incident_data.get("violation_ids"),
                    rule_ids=incident_data.get("rule_ids"),
                    detection_latency_blocks=incident_data.get("detection_latency_blocks"),
                    first_event_time=incident_data.get("first_event_time"),
                    last_event_time=incident_data.get("last_event_time"),
                    recommended_actions=incident_data.get("recommended_actions"),
                )
                session.add(incident)
                await session.flush()
                logger.info("incident_saved", incident_id=incident.incident_id, severity=incident.severity)
                return incident.incident_id
            except Exception as e:
                logger.error("incident_save_failed", error=str(e))
                raise
    
    @staticmethod
    async def get_incidents(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        attack_type: Optional[str] = None,
        chain_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[IncidentModel]:
        """
        Query incidents with optional filters.
        """
        async with DatabaseManager.get_session() as session:
            query = select(IncidentModel)
            
            conditions = []
            if severity:
                conditions.append(IncidentModel.severity == severity)
            if status:
                conditions.append(IncidentModel.status == status)
            if attack_type:
                conditions.append(IncidentModel.attack_type == attack_type)
            if chain_id:
                conditions.append(IncidentModel.affected_chains.contains([chain_id]))
            if start_time:
                conditions.append(IncidentModel.created_at >= start_time)
            if end_time:
                conditions.append(IncidentModel.created_at <= end_time)
            
            if conditions:
                query = query.where(and_(*conditions))
            
            query = query.order_by(desc(IncidentModel.created_at))
            query = query.limit(limit).offset(offset)
            
            result = await session.execute(query)
            return result.scalars().all()
    
    @staticmethod
    async def get_incident_by_id(incident_id: str) -> Optional[IncidentModel]:
        """
        Get a single incident by ID.
        """
        async with DatabaseManager.get_session() as session:
            query = select(IncidentModel).where(IncidentModel.incident_id == incident_id)
            result = await session.execute(query)
            return result.scalar_one_or_none()
    
    @staticmethod
    async def update_incident_status(
        incident_id: str,
        status: str,
        user: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> bool:
        """
        Update incident status.
        """
        async with DatabaseManager.get_session() as session:
            try:
                updates = {"status": status, "updated_at": datetime.utcnow()}
                
                if status == "ACKNOWLEDGED" and user:
                    updates["acknowledged_by"] = user
                    updates["acknowledged_at"] = datetime.utcnow()
                elif status == "RESOLVED" and user:
                    updates["resolved_by"] = user
                    updates["resolved_at"] = datetime.utcnow()
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
            # Total counts by severity
            severity_query = select(
                IncidentModel.severity,
                func.count(IncidentModel.id).label("count")
            ).group_by(IncidentModel.severity)
            severity_result = await session.execute(severity_query)
            by_severity = {row.severity: row.count for row in severity_result}
            
            # Active incidents
            active_query = select(func.count(IncidentModel.id)).where(
                IncidentModel.status.in_(["OPEN", "ACKNOWLEDGED"])
            )
            active_result = await session.execute(active_query)
            active_count = active_result.scalar() or 0
            
            # Total
            total_query = select(func.count(IncidentModel.id))
            total_result = await session.execute(total_query)
            total_count = total_result.scalar() or 0
            
            return {
                "total": total_count,
                "active": active_count,
                "by_severity": by_severity,
                "critical": by_severity.get("CRITICAL", 0),
                "high": by_severity.get("HIGH", 0),
                "medium": by_severity.get("MEDIUM", 0),
                "low": by_severity.get("LOW", 0),
            }
    
    # =========================================================================
    # VIOLATION OPERATIONS
    # =========================================================================
    
    @staticmethod
    async def save_violation(violation_data: Dict[str, Any]) -> Optional[str]:
        """
        Save an invariant violation.
        """
        async with DatabaseManager.get_session() as session:
            try:
                violation = ViolationModel(
                    violation_id=violation_data.get("id") or violation_data.get("violation_id"),
                    invariant_name=violation_data.get("invariant_name"),
                    invariant_type=violation_data.get("invariant_type"),
                    chain_id=violation_data.get("chain_id"),
                    expected_value=str(violation_data.get("expected_value")) if violation_data.get("expected_value") else None,
                    actual_value=str(violation_data.get("actual_value")) if violation_data.get("actual_value") else None,
                    deviation=violation_data.get("deviation"),
                    context=violation_data.get("context"),
                    related_events=violation_data.get("related_events"),
                )
                session.add(violation)
                await session.flush()
                logger.debug("violation_saved", violation_id=violation.violation_id)
                return violation.violation_id
            except Exception as e:
                logger.error("violation_save_failed", error=str(e))
                raise
    
    # =========================================================================
    # STATS & ANALYTICS
    # =========================================================================
    
    @staticmethod
    async def get_dashboard_stats(time_range_hours: int = 24) -> Dict[str, Any]:
        """
        Get aggregated stats for the dashboard.
        """
        start_time = datetime.utcnow() - timedelta(hours=time_range_hours)
        
        async with DatabaseManager.get_session() as session:
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
                "total_events": total_events,
                "events_by_chain": events_by_chain,
                "events_by_type": events_by_type,
                "total_incidents": incident_stats["total"],
                "active_incidents": incident_stats["active"],
                "critical_alerts": incident_stats["critical"],
                "high_alerts": incident_stats["high"],
                "medium_alerts": incident_stats["medium"],
                "low_alerts": incident_stats["low"],
                "time_range_hours": time_range_hours,
            }
    
    @staticmethod
    async def get_event_timeline(
        chain_id: Optional[str] = None,
        interval_minutes: int = 60,
        periods: int = 24,
    ) -> List[Dict[str, Any]]:
        """
        Get event counts over time for charting.
        """
        async with DatabaseManager.get_session() as session:
            results = []
            now = datetime.utcnow()
            
            for i in range(periods - 1, -1, -1):
                period_end = now - timedelta(minutes=i * interval_minutes)
                period_start = period_end - timedelta(minutes=interval_minutes)
                
                query = select(func.count(EventModel.id)).where(
                    and_(
                        EventModel.block_timestamp >= period_start,
                        EventModel.block_timestamp < period_end,
                    )
                )
                
                if chain_id:
                    query = query.where(EventModel.chain_id == chain_id)
                
                result = await session.execute(query)
                count = result.scalar() or 0
                
                results.append({
                    "timestamp": period_start.isoformat(),
                    "count": count,
                })
            
            return results
    
    # =========================================================================
    # AUDIT LOG
    # =========================================================================
    
    @staticmethod
    async def log_audit(
        action: str,
        entity_type: str,
        entity_id: Optional[str] = None,
        user: Optional[str] = None,
        old_value: Optional[Dict] = None,
        new_value: Optional[Dict] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """
        Create an audit log entry.
        """
        async with DatabaseManager.get_session() as session:
            try:
                log = AuditLogModel(
                    action=action,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    user=user,
                    old_value=old_value,
                    new_value=new_value,
                    ip_address=ip_address,
                )
                session.add(log)
                logger.debug("audit_log_created", action=action, entity=f"{entity_type}:{entity_id}")
            except Exception as e:
                logger.error("audit_log_failed", error=str(e))
    
    # =========================================================================
    # CLEANUP
    # =========================================================================
    
    @staticmethod
    async def cleanup_old_events(days: int = 30) -> int:
        """
        Delete events older than specified days.
        Returns count of deleted events.
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        async with DatabaseManager.get_session() as session:
            stmt = delete(EventModel).where(EventModel.created_at < cutoff)
            result = await session.execute(stmt)
            count = result.rowcount
            logger.info("old_events_cleaned", count=count, days=days)
            return count

