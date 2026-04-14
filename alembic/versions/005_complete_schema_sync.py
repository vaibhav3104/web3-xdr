"""Complete schema sync — ensure all models are reflected in the database.

Reconciliation migration that brings the database in line with every
SQLAlchemy model defined in src/database/models.py.  Every operation is
idempotent (tables are created only if missing, columns are added only
if absent, indexes use ``if_not_exists``), so the migration is safe to
run against databases that already received migrations 001-004.

Models covered (13 tables):
  events, event_processing, incidents, violations, chain_stats,
  alert_rules, audit_logs, correlation_keys, simulation_runs,
  predicted_incidents, incident_audit_log, customers, api_keys

Revision ID: 005
Revises: 004
Create Date: 2026-04-14
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _table_exists(name: str) -> bool:
    """Return True if *name* already exists as a table in the current schema."""
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT EXISTS ("
            "  SELECT 1 FROM information_schema.tables"
            "  WHERE table_schema = current_schema() AND table_name = :t"
            ")"
        ),
        {"t": name},
    )
    return result.scalar()


def _column_exists(table: str, column: str) -> bool:
    """Return True if *column* exists in *table*."""
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT EXISTS ("
            "  SELECT 1 FROM information_schema.columns"
            "  WHERE table_schema = current_schema()"
            "    AND table_name = :t AND column_name = :c"
            ")"
        ),
        {"t": table, "c": column},
    )
    return result.scalar()


def _index_exists(name: str) -> bool:
    """Return True if index *name* exists in the current schema."""
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :n"),
        {"n": name},
    )
    return result.scalar() is not None


def _create_index_safe(name: str, table: str, columns: list, **kw) -> None:
    """Create an index only if it does not already exist."""
    if not _index_exists(name):
        op.create_index(name, table, columns, **kw)


def _add_column_safe(table: str, column: sa.Column) -> None:
    """Add a column only if it does not already exist."""
    if not _column_exists(table, column.name):
        op.add_column(table, column)


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------

def upgrade() -> None:
    # ==================================================================
    # 1. events
    # ==================================================================
    if not _table_exists("events"):
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

    # Ensure all columns exist (covers models that may have added fields)
    _add_column_safe("events", sa.Column("block_hash", sa.String(128), nullable=True))
    _add_column_safe("events", sa.Column("log_index", sa.Integer, nullable=True))
    _add_column_safe("events", sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"))
    _add_column_safe("events", sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_safe("events", sa.Column("canonical_event_hash", sa.String(128), nullable=True))
    _add_column_safe("events", sa.Column("asset_type", sa.String(32), nullable=True))
    _add_column_safe("events", sa.Column("asset_address", sa.String(128), nullable=True))
    _add_column_safe("events", sa.Column("topics", ARRAY(sa.String), nullable=True))

    # Column-level indexes
    _create_index_safe("ix_events_event_id", "events", ["event_id"])
    _create_index_safe("ix_events_chain_id", "events", ["chain_id"])
    _create_index_safe("ix_events_event_type", "events", ["event_type"])
    _create_index_safe("ix_events_tx_hash", "events", ["tx_hash"])
    _create_index_safe("ix_events_block_number", "events", ["block_number"])
    _create_index_safe("ix_events_block_timestamp", "events", ["block_timestamp"])
    _create_index_safe("ix_events_block_hash", "events", ["block_hash"])
    _create_index_safe("ix_events_status", "events", ["status"])
    _create_index_safe("ix_events_canonical_event_hash", "events", ["canonical_event_hash"])
    _create_index_safe("ix_events_contract_address", "events", ["contract_address"])
    _create_index_safe("ix_events_from_address", "events", ["from_address"])
    _create_index_safe("ix_events_to_address", "events", ["to_address"])
    # Composite indexes
    _create_index_safe("ix_events_chain_block", "events", ["chain_id", "block_number"])
    _create_index_safe("ix_events_chain_timestamp", "events", ["chain_id", "block_timestamp"])
    _create_index_safe("ix_events_contract_type", "events", ["contract_address", "event_type"])
    _create_index_safe("ix_events_severity_timestamp", "events", ["severity", "block_timestamp"])
    _create_index_safe("ix_events_status_chain", "events", ["status", "chain_id"])
    _create_index_safe("ix_events_unique_key", "events", ["chain_id", "tx_hash", "log_index"], unique=True)
    _create_index_safe("ix_events_timestamp_id", "events", ["block_timestamp", "id"])

    # ==================================================================
    # 2. event_processing
    # ==================================================================
    if not _table_exists("event_processing"):
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

    _add_column_safe("event_processing", sa.Column("event_id", sa.String(128), nullable=True))
    _add_column_safe("event_processing", sa.Column("incident_id", sa.String(128), nullable=True))
    _add_column_safe("event_processing", sa.Column("error_message", sa.Text, nullable=True))
    _add_column_safe("event_processing", sa.Column("retry_count", sa.Integer, nullable=False, server_default="0"))

    _create_index_safe("ix_event_processing_idempotency_key", "event_processing", ["idempotency_key"])
    _create_index_safe("ix_event_processing_processed_at", "event_processing", ["processed_at"])
    _create_index_safe("ix_event_processing_status", "event_processing", ["status"])
    _create_index_safe("ix_event_processing_status_first_seen", "event_processing", ["status", "first_seen_at"])

    # ==================================================================
    # 3. incidents
    # ==================================================================
    if not _table_exists("incidents"):
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

    _add_column_safe("incidents", sa.Column("cluster_key", sa.String(64), nullable=False, server_default="unknown"))
    _add_column_safe("incidents", sa.Column("explanation_json", JSONB, nullable=True))
    _add_column_safe("incidents", sa.Column("event_count", sa.Integer, nullable=False, server_default="0"))
    _add_column_safe("incidents", sa.Column("detection_latency_blocks", sa.Integer, nullable=True))
    _add_column_safe("incidents", sa.Column("first_event_time", sa.DateTime(timezone=True), nullable=True))
    _add_column_safe("incidents", sa.Column("last_event_time", sa.DateTime(timezone=True), nullable=True))
    _add_column_safe("incidents", sa.Column("acknowledged_by", sa.String(256), nullable=True))
    _add_column_safe("incidents", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_safe("incidents", sa.Column("resolved_by", sa.String(256), nullable=True))
    _add_column_safe("incidents", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_safe("incidents", sa.Column("resolution_notes", sa.Text, nullable=True))

    _create_index_safe("ix_incidents_incident_id", "incidents", ["incident_id"])
    _create_index_safe("ix_incidents_cluster_key", "incidents", ["cluster_key"])
    _create_index_safe("ix_incidents_severity", "incidents", ["severity"])
    _create_index_safe("ix_incidents_status", "incidents", ["status"])
    _create_index_safe("ix_incidents_attack_type", "incidents", ["attack_type"])
    _create_index_safe("ix_incidents_created_at", "incidents", ["created_at"])
    _create_index_safe("ix_incidents_severity_status", "incidents", ["severity", "status"])
    _create_index_safe("ix_incidents_attack_type_created", "incidents", ["attack_type", "created_at"])

    # ==================================================================
    # 4. violations
    # ==================================================================
    if not _table_exists("violations"):
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

    _create_index_safe("ix_violations_violation_id", "violations", ["violation_id"])
    _create_index_safe("ix_violations_invariant_name", "violations", ["invariant_name"])
    _create_index_safe("ix_violations_chain_id", "violations", ["chain_id"])
    _create_index_safe("ix_violations_detected_at", "violations", ["detected_at"])

    # ==================================================================
    # 5. chain_stats
    # ==================================================================
    if not _table_exists("chain_stats"):
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

    _create_index_safe("ix_chain_stats_chain_id", "chain_stats", ["chain_id"])
    _create_index_safe("ix_chain_stats_chain_period", "chain_stats", ["chain_id", "period_type", "period_start"])

    # ==================================================================
    # 6. alert_rules
    # ==================================================================
    if not _table_exists("alert_rules"):
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

    _create_index_safe("ix_alert_rules_rule_id", "alert_rules", ["rule_id"])
    _create_index_safe("ix_alert_rules_severity", "alert_rules", ["severity"])
    _create_index_safe("ix_alert_rules_enabled", "alert_rules", ["enabled"])

    # ==================================================================
    # 7. audit_logs
    # ==================================================================
    if not _table_exists("audit_logs"):
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

    # Phase 5 enhanced audit columns (may be missing on older databases)
    _add_column_safe("audit_logs", sa.Column("action_type", sa.String(64), nullable=True))
    _add_column_safe("audit_logs", sa.Column("actor_id", sa.String(256), nullable=True))
    _add_column_safe("audit_logs", sa.Column("resource_id", sa.String(128), nullable=True))
    _add_column_safe("audit_logs", sa.Column("details", JSONB, nullable=True))

    _create_index_safe("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    _create_index_safe("ix_audit_logs_action_type", "audit_logs", ["action_type"])
    _create_index_safe("ix_audit_logs_actor_id", "audit_logs", ["actor_id"])
    _create_index_safe("ix_audit_logs_resource_id", "audit_logs", ["resource_id"])
    _create_index_safe("ix_audit_logs_ip_address", "audit_logs", ["ip_address"])
    _create_index_safe("ix_audit_logs_entity", "audit_logs", ["entity_type", "entity_id"])
    _create_index_safe("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # ==================================================================
    # 8. incident_audit_log
    # ==================================================================
    if not _table_exists("incident_audit_log"):
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

    _create_index_safe("ix_incident_audit_log_incident_id", "incident_audit_log", ["incident_id"])
    _create_index_safe("ix_audit_incident_time", "incident_audit_log", ["incident_id", "created_at"])

    # ==================================================================
    # 9. correlation_keys
    # ==================================================================
    if not _table_exists("correlation_keys"):
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

    _create_index_safe("ix_correlation_keys_protocol_id", "correlation_keys", ["protocol_id"])
    _create_index_safe("ix_correlation_keys_src_chain", "correlation_keys", ["src_chain"])
    _create_index_safe("ix_correlation_keys_dst_chain", "correlation_keys", ["dst_chain"])
    _create_index_safe("ix_correlation_keys_correlation_key", "correlation_keys", ["correlation_key"])
    _create_index_safe("ix_correlation_keys_unique", "correlation_keys",
                        ["protocol_id", "src_chain", "dst_chain", "correlation_key"], unique=True)
    _create_index_safe("ix_correlation_keys_unmatched", "correlation_keys", ["matched", "created_at"])

    # ==================================================================
    # 10. simulation_runs  (must exist before predicted_incidents FK)
    # ==================================================================
    if not _table_exists("simulation_runs"):
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

    _create_index_safe("ix_simulation_runs_chain_id", "simulation_runs", ["chain_id"])
    _create_index_safe("ix_simulation_runs_block_number", "simulation_runs", ["block_number"])
    _create_index_safe("ix_simulation_runs_tx_hash", "simulation_runs", ["tx_hash"])
    _create_index_safe("ix_simulation_runs_tx_to", "simulation_runs", ["tx_to"])
    _create_index_safe("ix_simulation_runs_status", "simulation_runs", ["status"])
    _create_index_safe("ix_simulation_runs_created_at", "simulation_runs", ["created_at"])
    _create_index_safe("ix_simulation_runs_chain_block", "simulation_runs", ["chain_id", "block_number"])
    _create_index_safe("ix_simulation_runs_status_created", "simulation_runs", ["status", "created_at"])

    # ==================================================================
    # 11. predicted_incidents  (has FKs to simulation_runs + incidents)
    # ==================================================================
    if not _table_exists("predicted_incidents"):
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
            sa.Column("linked_simulation_run_id", UUID(as_uuid=True),
                       sa.ForeignKey("simulation_runs.id"), nullable=True),
            sa.Column("confirmed_incident_id", UUID(as_uuid=True),
                       sa.ForeignKey("incidents.id"), nullable=True),
            sa.Column("matched_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("potential_loss_usd", sa.Numeric(20, 2), nullable=True),
            sa.Column("potential_loss_token_symbol", sa.String(16), nullable=True),
            sa.Column("financial_impact_json", JSONB, nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )

    # Phase 9 ROI Engine columns (may be absent on older databases)
    _add_column_safe("predicted_incidents", sa.Column("potential_loss_usd", sa.Numeric(20, 2), nullable=True))
    _add_column_safe("predicted_incidents", sa.Column("potential_loss_token_symbol", sa.String(16), nullable=True))
    _add_column_safe("predicted_incidents", sa.Column("financial_impact_json", JSONB, nullable=True))

    _create_index_safe("ix_predicted_incidents_chain_id", "predicted_incidents", ["chain_id"])
    _create_index_safe("ix_predicted_incidents_tx_hash", "predicted_incidents", ["tx_hash"])
    _create_index_safe("ix_predicted_incidents_protocol_id", "predicted_incidents", ["protocol_id"])
    _create_index_safe("ix_predicted_incidents_predicted_type", "predicted_incidents", ["predicted_type"])
    _create_index_safe("ix_predicted_incidents_severity", "predicted_incidents", ["severity"])
    _create_index_safe("ix_predicted_incidents_confidence", "predicted_incidents", ["confidence"])
    _create_index_safe("ix_predicted_incidents_status", "predicted_incidents", ["status"])
    _create_index_safe("ix_predicted_incidents_dedupe_key", "predicted_incidents", ["dedupe_key"])
    _create_index_safe("ix_predicted_incidents_linked_sim", "predicted_incidents", ["linked_simulation_run_id"])
    _create_index_safe("ix_predicted_incidents_confirmed", "predicted_incidents", ["confirmed_incident_id"])
    _create_index_safe("ix_predicted_incidents_potential_loss", "predicted_incidents", ["potential_loss_usd"])
    _create_index_safe("ix_predicted_incidents_created_at", "predicted_incidents", ["created_at"])
    _create_index_safe("ix_predicted_incidents_chain_status", "predicted_incidents", ["chain_id", "status", "created_at"])
    _create_index_safe("ix_predicted_incidents_severity_status", "predicted_incidents", ["severity", "status"])

    # ==================================================================
    # 12. customers
    # ==================================================================
    if not _table_exists("customers"):
        op.create_table(
            "customers",
            sa.Column("id", UUID(as_uuid=True), primary_key=True),
            sa.Column("customer_id", sa.String(64), unique=True, nullable=False),
            sa.Column("name", sa.String(256), nullable=False),
            sa.Column("tier", sa.String(32), nullable=False, server_default="starter"),
            sa.Column("active", sa.Boolean, nullable=False, server_default=sa.text("true")),
            sa.Column("admin_email", sa.String(256), nullable=True),
            sa.Column("alert_emails", ARRAY(sa.String), nullable=True),
            sa.Column("telegram_chat_id", sa.String(64), nullable=True),
            sa.Column("slack_webhook", sa.String(512), nullable=True),
            sa.Column("contracts", JSONB, nullable=True),
            sa.Column("features", ARRAY(sa.String), nullable=True),
            sa.Column("max_api_keys", sa.Integer, nullable=False, server_default="5"),
            sa.Column("max_contracts", sa.Integer, nullable=False, server_default="10"),
            sa.Column("max_chains", sa.Integer, nullable=False, server_default="3"),
            sa.Column("rate_limit_multiplier", sa.Float, nullable=False, server_default="1.0"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )

    # Columns that may have been added after the initial customers migration
    _add_column_safe("customers", sa.Column("telegram_chat_id", sa.String(64), nullable=True))
    _add_column_safe("customers", sa.Column("slack_webhook", sa.String(512), nullable=True))
    _add_column_safe("customers", sa.Column("features", ARRAY(sa.String), nullable=True))
    _add_column_safe("customers", sa.Column("max_api_keys", sa.Integer, nullable=False, server_default="5"))
    _add_column_safe("customers", sa.Column("max_contracts", sa.Integer, nullable=False, server_default="10"))
    _add_column_safe("customers", sa.Column("max_chains", sa.Integer, nullable=False, server_default="3"))
    _add_column_safe("customers", sa.Column("rate_limit_multiplier", sa.Float, nullable=False, server_default="1.0"))

    _create_index_safe("ix_customers_customer_id", "customers", ["customer_id"])

    # ==================================================================
    # 13. api_keys
    # ==================================================================
    if not _table_exists("api_keys"):
        op.create_table(
            "api_keys",
            sa.Column("id", UUID(as_uuid=True), primary_key=True),
            sa.Column("key_id", sa.String(64), unique=True, nullable=False),
            sa.Column("customer_id", sa.String(64), nullable=False),
            sa.Column("name", sa.String(256), nullable=False),
            sa.Column("key_hash", sa.String(128), unique=True, nullable=False),
            sa.Column("key_prefix", sa.String(32), nullable=False),
            sa.Column("scopes", ARRAY(sa.String), nullable=False),
            sa.Column("status", sa.String(32), nullable=False, server_default="active"),
            sa.Column("description", sa.Text, nullable=True),
            sa.Column("allowed_ips", ARRAY(sa.String), nullable=True),
            sa.Column("rate_limit_requests", sa.Integer, nullable=False, server_default="1000"),
            sa.Column("rate_limit_window", sa.Integer, nullable=False, server_default="3600"),
            sa.Column("total_requests", sa.BigInteger, nullable=False, server_default="0"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(256), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )

    _add_column_safe("api_keys", sa.Column("description", sa.Text, nullable=True))
    _add_column_safe("api_keys", sa.Column("allowed_ips", ARRAY(sa.String), nullable=True))
    _add_column_safe("api_keys", sa.Column("rate_limit_requests", sa.Integer, nullable=False, server_default="1000"))
    _add_column_safe("api_keys", sa.Column("rate_limit_window", sa.Integer, nullable=False, server_default="3600"))
    _add_column_safe("api_keys", sa.Column("total_requests", sa.BigInteger, nullable=False, server_default="0"))
    _add_column_safe("api_keys", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_safe("api_keys", sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_safe("api_keys", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_safe("api_keys", sa.Column("created_by", sa.String(256), nullable=True))

    _create_index_safe("ix_api_keys_key_id", "api_keys", ["key_id"])
    _create_index_safe("ix_api_keys_customer_id", "api_keys", ["customer_id"])
    _create_index_safe("ix_api_keys_key_hash", "api_keys", ["key_hash"])
    _create_index_safe("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])
    _create_index_safe("ix_api_keys_status", "api_keys", ["status"])
    _create_index_safe("ix_api_keys_customer_status", "api_keys", ["customer_id", "status"])


# ---------------------------------------------------------------------------
# downgrade — reverse everything this migration *may* have added.
#
# Only objects that did NOT exist in 001-004 need to be dropped here.
# Since this migration is purely a reconciliation layer (all objects
# already exist if 001-004 ran successfully), the downgrade is a
# selective no-op that only removes truly net-new objects.
#
# Net-new from this migration (not in any prior):
#   - Index: ix_customers_customer_id  (003 relied on column-level index=True
#     in op.create_table but never created a standalone index)
#   - Index: ix_api_keys_key_id, ix_api_keys_customer_id,
#     ix_api_keys_key_hash, ix_api_keys_key_prefix, ix_api_keys_status
#     (same — created implicitly by column index=True in 003, not explicit)
#
# We drop those explicitly-created standalone indexes.
# ---------------------------------------------------------------------------

def downgrade() -> None:
    # Drop standalone indexes that 005 may have explicitly created and
    # that no prior migration created as standalone ``op.create_index`` calls.

    _safe_drop_indexes = [
        # customers indexes (003 used column-level index=True, no standalone)
        ("ix_customers_customer_id", "customers"),
        # api_keys standalone indexes not in 003
        ("ix_api_keys_key_id", "api_keys"),
        ("ix_api_keys_customer_id", "api_keys"),
        ("ix_api_keys_key_hash", "api_keys"),
        ("ix_api_keys_key_prefix", "api_keys"),
        ("ix_api_keys_status", "api_keys"),
    ]

    for idx_name, table_name in _safe_drop_indexes:
        try:
            op.drop_index(idx_name, table_name=table_name)
        except Exception:
            pass  # Index may not exist if upgrade was a no-op
