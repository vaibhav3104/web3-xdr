"""Initial schema - baseline from existing database.

Revision ID: 001
Revises: None
Create Date: 2026-04-10
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Events table
    op.create_table(
        "events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", sa.String(128), unique=True, nullable=False),
        sa.Column("chain_id", sa.String(32), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("tx_hash", sa.String(128), nullable=False),
        sa.Column("block_number", sa.BigInteger, nullable=False),
        sa.Column("block_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("block_hash", sa.String(128), nullable=True),
        sa.Column("log_index", sa.Integer, nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("canonical_event_hash", sa.String(128), nullable=True),
        sa.Column("contract_address", sa.String(128), nullable=False),
        sa.Column("from_address", sa.String(128), nullable=True),
        sa.Column("to_address", sa.String(128), nullable=True),
        sa.Column("amount", sa.Numeric(38, 18), nullable=True),
        sa.Column("amount_usd", sa.Numeric(20, 2), nullable=True),
        sa.Column("asset_type", sa.String(32), nullable=True),
        sa.Column("asset_address", sa.String(128), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="LOW"),
        sa.Column("raw_data", JSONB, nullable=True),
        sa.Column("topics", ARRAY(sa.String), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_events_event_id", "events", ["event_id"])
    op.create_index("ix_events_chain_id", "events", ["chain_id"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_tx_hash", "events", ["tx_hash"])
    op.create_index("ix_events_block_number", "events", ["block_number"])
    op.create_index("ix_events_block_timestamp", "events", ["block_timestamp"])
    op.create_index("ix_events_status", "events", ["status"])
    op.create_index("ix_events_contract_address", "events", ["contract_address"])
    op.create_index("ix_events_chain_block", "events", ["chain_id", "block_number"])
    op.create_index("ix_events_chain_timestamp", "events", ["chain_id", "block_timestamp"])
    op.create_index("ix_events_severity_timestamp", "events", ["severity", "block_timestamp"])
    op.create_index("ix_events_status_chain", "events", ["status", "chain_id"])
    op.create_index("ix_events_unique_key", "events", ["chain_id", "tx_hash", "log_index"], unique=True)
    op.create_index("ix_events_timestamp_id", "events", ["block_timestamp", "id"])

    # Incidents table
    op.create_table(
        "incidents",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", sa.String(128), unique=True, nullable=False),
        sa.Column("cluster_key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="OPEN_PENDING"),
        sa.Column("attack_type", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("total_loss_usd", sa.Numeric(20, 2), nullable=True),
        sa.Column("explanation_json", JSONB, nullable=True),
        sa.Column("event_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("affected_chains", ARRAY(sa.String), nullable=False),
        sa.Column("affected_contracts", ARRAY(sa.String), nullable=True),
        sa.Column("affected_addresses", ARRAY(sa.String), nullable=True),
        sa.Column("event_ids", ARRAY(sa.String), nullable=True),
        sa.Column("violation_ids", ARRAY(sa.String), nullable=True),
        sa.Column("rule_ids", ARRAY(sa.String), nullable=True),
        sa.Column("detection_latency_blocks", sa.Integer, nullable=True),
        sa.Column("first_event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recommended_actions", ARRAY(sa.Text), nullable=True),
        sa.Column("acknowledged_by", sa.String(256), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(256), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_incidents_incident_id", "incidents", ["incident_id"])
    op.create_index("ix_incidents_cluster_key", "incidents", ["cluster_key"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_attack_type", "incidents", ["attack_type"])
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])
    op.create_index("ix_incidents_severity_status", "incidents", ["severity", "status"])

    # Violations table
    op.create_table(
        "violations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("violation_id", sa.String(128), unique=True, nullable=False),
        sa.Column("invariant_name", sa.String(64), nullable=False),
        sa.Column("invariant_type", sa.String(32), nullable=False),
        sa.Column("chain_id", sa.String(32), nullable=False),
        sa.Column("expected_value", sa.String(256), nullable=True),
        sa.Column("actual_value", sa.String(256), nullable=True),
        sa.Column("deviation", sa.Float, nullable=True),
        sa.Column("context", JSONB, nullable=True),
        sa.Column("related_events", ARRAY(sa.String), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_violations_violation_id", "violations", ["violation_id"])
    op.create_index("ix_violations_invariant_name", "violations", ["invariant_name"])
    op.create_index("ix_violations_chain_id", "violations", ["chain_id"])

    # Audit logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=True),
        sa.Column("details", JSONB, nullable=True),
        sa.Column("action", sa.String(64), nullable=True),
        sa.Column("entity_type", sa.String(32), nullable=True),
        sa.Column("entity_id", sa.String(128), nullable=True),
        sa.Column("user", sa.String(256), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("old_value", JSONB, nullable=True),
        sa.Column("new_value", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_action_type", "audit_logs", ["action_type"])
    op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"])

    # Incident audit log table
    op.create_table(
        "incident_audit_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", sa.String(128), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("previous_status", sa.String(32), nullable=True),
        sa.Column("new_status", sa.String(32), nullable=False),
        sa.Column("analyst_id", sa.String(256), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("metadata_json", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_incident_audit_log_incident_id", "incident_audit_log", ["incident_id"])
    op.create_index("ix_audit_incident_time", "incident_audit_log", ["incident_id", "created_at"])

    # Event processing (idempotency) table
    op.create_table(
        "event_processing",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("idempotency_key", sa.String(128), unique=True, nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("event_id", sa.String(128), nullable=True),
        sa.Column("incident_id", sa.String(128), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("retry_count", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_index("ix_event_processing_idempotency_key", "event_processing", ["idempotency_key"])
    op.create_index("ix_event_processing_status", "event_processing", ["status"])

    # Chain stats table
    op.create_table(
        "chain_stats",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("chain_id", sa.String(32), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_type", sa.String(16), nullable=False),
        sa.Column("total_events", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("total_incidents", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_violations", sa.Integer, nullable=False, server_default="0"),
        sa.Column("events_by_type", JSONB, nullable=True),
        sa.Column("events_by_severity", JSONB, nullable=True),
        sa.Column("total_volume_usd", sa.Numeric(24, 2), nullable=True),
        sa.Column("blocks_scanned", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_chain_stats_chain_period", "chain_stats", ["chain_id", "period_type", "period_start"])

    # Alert rules table
    op.create_table(
        "alert_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", sa.String(128), unique=True, nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("detection", JSONB, nullable=False),
        sa.Column("thresholds", JSONB, nullable=True),
        sa.Column("actions", JSONB, nullable=True),
        sa.Column("author", sa.String(128), nullable=True),
        sa.Column("source_file", sa.String(256), nullable=True),
        sa.Column("times_triggered", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Correlation keys table
    op.create_table(
        "correlation_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("protocol_id", sa.String(64), nullable=False),
        sa.Column("src_chain", sa.String(32), nullable=False),
        sa.Column("dst_chain", sa.String(32), nullable=True),
        sa.Column("correlation_key", sa.String(256), nullable=False),
        sa.Column("source_event_id", sa.String(128), nullable=True),
        sa.Column("dest_event_id", sa.String(128), nullable=True),
        sa.Column("matched", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_correlation_keys_unique", "correlation_keys",
                     ["protocol_id", "src_chain", "dst_chain", "correlation_key"], unique=True)

    # Simulation runs table
    op.create_table(
        "simulation_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("chain_id", sa.String(32), nullable=False),
        sa.Column("block_number", sa.BigInteger, nullable=False),
        sa.Column("block_hash", sa.String(128), nullable=False),
        sa.Column("tx_hash", sa.String(128), nullable=False),
        sa.Column("tx_from", sa.String(128), nullable=True),
        sa.Column("tx_to", sa.String(128), nullable=True),
        sa.Column("tx_selector", sa.String(16), nullable=True),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("duration_ms", sa.Integer, nullable=False, server_default="0"),
        sa.Column("rpc_calls", sa.Integer, nullable=False, server_default="0"),
        sa.Column("state_diff_fingerprint", JSONB, nullable=True),
        sa.Column("invariant_results", JSONB, nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("confidence_reasons", JSONB, nullable=True),
        sa.Column("assumptions", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_simulation_runs_chain_block", "simulation_runs", ["chain_id", "block_number"])
    op.create_index("ix_simulation_runs_tx_hash", "simulation_runs", ["tx_hash"])

    # Predicted incidents table
    op.create_table(
        "predicted_incidents",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("chain_id", sa.String(32), nullable=False),
        sa.Column("tx_hash", sa.String(128), nullable=False),
        sa.Column("protocol_id", sa.String(64), nullable=True),
        sa.Column("predicted_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("status", sa.String(32), nullable=False, server_default="OPEN"),
        sa.Column("dedupe_key", sa.String(256), nullable=False),
        sa.Column("explanation_json", JSONB, nullable=True),
        sa.Column("evidence_json", JSONB, nullable=True),
        sa.Column("linked_simulation_run_id", UUID(as_uuid=True), sa.ForeignKey("simulation_runs.id"), nullable=True),
        sa.Column("confirmed_incident_id", UUID(as_uuid=True), sa.ForeignKey("incidents.id"), nullable=True),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("potential_loss_usd", sa.Numeric(20, 2), nullable=True),
        sa.Column("potential_loss_token_symbol", sa.String(16), nullable=True),
        sa.Column("financial_impact_json", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_predicted_incidents_chain_status", "predicted_incidents", ["chain_id", "status", "created_at"])
    op.create_index("ix_predicted_incidents_dedupe_key", "predicted_incidents", ["dedupe_key"])


def downgrade() -> None:
    op.drop_table("predicted_incidents")
    op.drop_table("simulation_runs")
    op.drop_table("correlation_keys")
    op.drop_table("alert_rules")
    op.drop_table("chain_stats")
    op.drop_table("event_processing")
    op.drop_table("incident_audit_log")
    op.drop_table("audit_logs")
    op.drop_table("violations")
    op.drop_table("incidents")
    op.drop_table("events")
