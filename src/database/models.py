"""
SQLAlchemy Models for Sentinel3 PostgreSQL Database.
Defines the schema for events, incidents, violations, and analytics.
"""

from datetime import datetime
from decimal import Decimal
from typing import List, Optional
import uuid

from sqlalchemy import (
    Column,
    String,
    Integer,
    BigInteger,
    Float,
    Boolean,
    DateTime,
    Text,
    Numeric,
    ForeignKey,
    Index,
    JSON,
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class EventModel(Base):
    """
    Stores all blockchain events captured by the XDR system.
    This is the primary telemetry data source.
    """
    __tablename__ = "events"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    
    # Event identification
    event_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    chain_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    
    # Transaction details
    tx_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    block_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    block_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)  # For reorg detection
    log_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    
    # Lifecycle status (NEW)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)  # PENDING/CONFIRMED/DROPPED
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    canonical_event_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)  # For deduplication
    
    # Contract & addresses
    contract_address: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    from_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    to_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    
    # Value information
    amount: Mapped[Optional[Decimal]] = mapped_column(Numeric(38, 18), nullable=True)
    amount_usd: Mapped[Optional[Decimal]] = mapped_column(Numeric(20, 2), nullable=True)
    asset_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    asset_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    
    # Severity & classification
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")
    
    # Raw data
    raw_data: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    topics: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    
    # Indexes for common queries
    __table_args__ = (
        Index("ix_events_chain_block", "chain_id", "block_number"),
        Index("ix_events_chain_timestamp", "chain_id", "block_timestamp"),
        Index("ix_events_contract_type", "contract_address", "event_type"),
        Index("ix_events_severity_timestamp", "severity", "block_timestamp"),
        Index("ix_events_status", "status", "chain_id"),  # For finality tracking
        Index("ix_events_unique_key", "chain_id", "tx_hash", "log_index", unique=True),  # Deduplication
    )
    
    def __repr__(self):
        return f"<Event {self.event_id} [{self.chain_id}] {self.event_type}>"


class IncidentModel(Base):
    """
    Stores security incidents detected by the XDR system.
    Incidents are created from correlated events and rule matches.
    """
    __tablename__ = "incidents"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    
    # Incident identification
    incident_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    cluster_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # Phase 4: Deduplication key
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Classification
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN_PENDING", index=True)  # OPEN_PENDING/OPEN_CONFIRMED/RESOLVED/FALSE_POSITIVE/STALE
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    
    # Confidence & analysis
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    total_loss_usd: Mapped[Optional[Decimal]] = mapped_column(Numeric(20, 2), nullable=True)
    explanation_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # Phase 4: Structured explanation
    
    # Phase 4: Event aggregation
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # Number of events in this incident
    
    # Affected scope
    affected_chains: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False, default=[])
    affected_contracts: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    affected_addresses: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    
    # Related data
    event_ids: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    violation_ids: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    rule_ids: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    
    # Detection metadata
    detection_latency_blocks: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    first_event_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Response
    recommended_actions: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )
    
    # Indexes
    __table_args__ = (
        Index("ix_incidents_severity_status", "severity", "status"),
        Index("ix_incidents_attack_type_created", "attack_type", "created_at"),
        Index("ix_incidents_cluster_key", "cluster_key"),  # Phase 4: For deduplication lookups
    )
    
    def __repr__(self):
        return f"<Incident {self.incident_id} [{self.severity}] {self.title[:50]}>"


class ViolationModel(Base):
    """
    Stores invariant violations detected by the system.
    """
    __tablename__ = "violations"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    
    violation_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    invariant_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    invariant_type: Mapped[str] = mapped_column(String(32), nullable=False)
    
    # Violation details
    chain_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    expected_value: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    actual_value: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    deviation: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    
    # Context
    context: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    related_events: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    
    # Timestamps
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    
    def __repr__(self):
        return f"<Violation {self.violation_id} [{self.invariant_name}]>"


class ChainStatsModel(Base):
    """
    Stores aggregated statistics per chain for analytics.
    Updated periodically for dashboard performance.
    """
    __tablename__ = "chain_stats"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    
    chain_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_type: Mapped[str] = mapped_column(String(16), nullable=False)  # hourly, daily, weekly
    
    # Counts
    total_events: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    total_incidents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_violations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    # Event breakdown
    events_by_type: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    events_by_severity: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    
    # Volume
    total_volume_usd: Mapped[Optional[Decimal]] = mapped_column(Numeric(24, 2), nullable=True)
    blocks_scanned: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    
    __table_args__ = (
        Index("ix_chain_stats_chain_period", "chain_id", "period_type", "period_start"),
    )
    
    def __repr__(self):
        return f"<ChainStats {self.chain_id} [{self.period_type}] {self.period_start}>"


class AlertRuleModel(Base):
    """
    Stores alert rules (persisted from YAML or created via API).
    """
    __tablename__ = "alert_rules"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    
    rule_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    
    # Rule definition
    detection: Mapped[dict] = mapped_column(JSONB, nullable=False)
    thresholds: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    actions: Mapped[Optional[List[dict]]] = mapped_column(JSONB, nullable=True)
    
    # Metadata
    author: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source_file: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    
    # Stats
    times_triggered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )
    
    def __repr__(self):
        return f"<AlertRule {self.rule_id} [{self.severity}] enabled={self.enabled}>"


class AuditLogModel(Base):
    """
    Audit log for tracking all system actions.
    """
    __tablename__ = "audit_logs"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    
    # Phase 5: Enhanced audit logging
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # e.g., "LOGIN", "PAUSE", "RULE_CREATE"
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)  # user or "system"
    resource_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)  # incident_id, rule_id, etc.
    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # Additional context
    
    # Legacy fields (kept for backward compatibility)
    action: Mapped[str] = mapped_column(String(64), nullable=True)  # Deprecated, use action_type
    entity_type: Mapped[str] = mapped_column(String(32), nullable=True)  # Deprecated, use details
    entity_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)  # Deprecated, use resource_id
    user: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)  # Deprecated, use actor_id
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    old_value: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    
    __table_args__ = (
        Index("ix_audit_logs_entity", "entity_type", "entity_id"),
    )
    
    def __repr__(self):
        return f"<AuditLog {self.action} {self.entity_type}:{self.entity_id}>"


class CorrelationKeyModel(Base):
    """
    Tracks correlation keys for cross-chain event matching.
    Prevents replay attacks and ensures idempotency.
    """
    __tablename__ = "correlation_keys"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    
    protocol_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    src_chain: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    dst_chain: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    correlation_key: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    
    # Event references
    source_event_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    dest_event_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    
    # Status
    matched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    matched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    
    __table_args__ = (
        Index("ix_correlation_keys_unique", "protocol_id", "src_chain", "dst_chain", "correlation_key", unique=True),
        Index("ix_correlation_keys_unmatched", "matched", "created_at"),
    )
    
    def __repr__(self):
        return f"<CorrelationKey {self.protocol_id}:{self.correlation_key[:16]} matched={self.matched}>"

