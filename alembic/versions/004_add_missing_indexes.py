"""Add missing indexes to match model definitions.

Brings database indexes in line with SQLAlchemy model column-level
``index=True`` and composite ``__table_args__`` indexes that were not
included in the initial migration scripts.

Revision ID: 004
Revises: 003
Create Date: 2026-04-14
"""
from typing import Sequence, Union
from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _create_index_safe(name: str, table: str, columns: list, **kw) -> None:
    """Create an index only if it does not already exist."""
    try:
        op.create_index(name, table, columns, if_not_exists=True, **kw)
    except Exception:
        # Older Pg / Alembic versions may not support if_not_exists; fall back
        conn = op.get_bind()
        import sqlalchemy as sa
        exists = conn.execute(
            sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :n"),
            {"n": name},
        ).scalar()
        if not exists:
            op.create_index(name, table, columns, **kw)


def upgrade() -> None:
    # ── events ──────────────────────────────────────────────────
    _create_index_safe("ix_events_block_hash", "events", ["block_hash"])
    _create_index_safe("ix_events_canonical_event_hash", "events", ["canonical_event_hash"])
    _create_index_safe("ix_events_contract_type", "events", ["contract_address", "event_type"])

    # ── event_processing ────────────────────────────────────────
    _create_index_safe("ix_event_processing_processed_at", "event_processing", ["processed_at"])
    _create_index_safe(
        "ix_event_processing_status_first_seen", "event_processing",
        ["status", "first_seen_at"],
    )

    # ── alert_rules ─────────────────────────────────────────────
    _create_index_safe("ix_alert_rules_rule_id", "alert_rules", ["rule_id"])
    _create_index_safe("ix_alert_rules_severity", "alert_rules", ["severity"])
    _create_index_safe("ix_alert_rules_enabled", "alert_rules", ["enabled"])

    # ── audit_logs ──────────────────────────────────────────────
    _create_index_safe("ix_audit_logs_resource_id", "audit_logs", ["resource_id"])
    _create_index_safe("ix_audit_logs_ip_address", "audit_logs", ["ip_address"])
    _create_index_safe("ix_audit_logs_entity", "audit_logs", ["entity_type", "entity_id"])
    _create_index_safe("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # ── correlation_keys ────────────────────────────────────────
    _create_index_safe("ix_correlation_keys_protocol_id", "correlation_keys", ["protocol_id"])
    _create_index_safe("ix_correlation_keys_src_chain", "correlation_keys", ["src_chain"])
    _create_index_safe("ix_correlation_keys_dst_chain", "correlation_keys", ["dst_chain"])
    _create_index_safe("ix_correlation_keys_correlation_key", "correlation_keys", ["correlation_key"])
    _create_index_safe(
        "ix_correlation_keys_unmatched", "correlation_keys",
        ["matched", "created_at"],
    )

    # ── simulation_runs ─────────────────────────────────────────
    _create_index_safe("ix_simulation_runs_block_number", "simulation_runs", ["block_number"])
    _create_index_safe("ix_simulation_runs_chain_id", "simulation_runs", ["chain_id"])
    _create_index_safe("ix_simulation_runs_tx_to", "simulation_runs", ["tx_to"])
    _create_index_safe("ix_simulation_runs_status", "simulation_runs", ["status"])
    _create_index_safe("ix_simulation_runs_created_at", "simulation_runs", ["created_at"])
    _create_index_safe(
        "ix_simulation_runs_status_created", "simulation_runs",
        ["status", "created_at"],
    )

    # ── predicted_incidents ─────────────────────────────────────
    _create_index_safe("ix_predicted_incidents_chain_id", "predicted_incidents", ["chain_id"])
    _create_index_safe("ix_predicted_incidents_tx_hash", "predicted_incidents", ["tx_hash"])
    _create_index_safe("ix_predicted_incidents_protocol_id", "predicted_incidents", ["protocol_id"])
    _create_index_safe("ix_predicted_incidents_predicted_type", "predicted_incidents", ["predicted_type"])
    _create_index_safe("ix_predicted_incidents_severity", "predicted_incidents", ["severity"])
    _create_index_safe("ix_predicted_incidents_confidence", "predicted_incidents", ["confidence"])
    _create_index_safe("ix_predicted_incidents_status", "predicted_incidents", ["status"])
    _create_index_safe(
        "ix_predicted_incidents_linked_sim", "predicted_incidents",
        ["linked_simulation_run_id"],
    )
    _create_index_safe(
        "ix_predicted_incidents_confirmed", "predicted_incidents",
        ["confirmed_incident_id"],
    )
    _create_index_safe(
        "ix_predicted_incidents_potential_loss", "predicted_incidents",
        ["potential_loss_usd"],
    )
    _create_index_safe("ix_predicted_incidents_created_at", "predicted_incidents", ["created_at"])
    _create_index_safe(
        "ix_predicted_incidents_severity_status", "predicted_incidents",
        ["severity", "status"],
    )

    # ── chain_stats ─────────────────────────────────────────────
    _create_index_safe("ix_chain_stats_chain_id", "chain_stats", ["chain_id"])

    # ── violations ──────────────────────────────────────────────
    _create_index_safe("ix_violations_detected_at", "violations", ["detected_at"])


def downgrade() -> None:
    # Drop in reverse order
    op.drop_index("ix_violations_detected_at", table_name="violations")
    op.drop_index("ix_chain_stats_chain_id", table_name="chain_stats")

    for name in [
        "ix_predicted_incidents_severity_status",
        "ix_predicted_incidents_created_at",
        "ix_predicted_incidents_potential_loss",
        "ix_predicted_incidents_confirmed",
        "ix_predicted_incidents_linked_sim",
        "ix_predicted_incidents_status",
        "ix_predicted_incidents_confidence",
        "ix_predicted_incidents_severity",
        "ix_predicted_incidents_predicted_type",
        "ix_predicted_incidents_protocol_id",
        "ix_predicted_incidents_tx_hash",
        "ix_predicted_incidents_chain_id",
    ]:
        op.drop_index(name, table_name="predicted_incidents")

    for name in [
        "ix_simulation_runs_status_created",
        "ix_simulation_runs_created_at",
        "ix_simulation_runs_status",
        "ix_simulation_runs_tx_to",
        "ix_simulation_runs_chain_id",
        "ix_simulation_runs_block_number",
    ]:
        op.drop_index(name, table_name="simulation_runs")

    for name in [
        "ix_correlation_keys_unmatched",
        "ix_correlation_keys_correlation_key",
        "ix_correlation_keys_dst_chain",
        "ix_correlation_keys_src_chain",
        "ix_correlation_keys_protocol_id",
    ]:
        op.drop_index(name, table_name="correlation_keys")

    for name in [
        "ix_audit_logs_created_at",
        "ix_audit_logs_entity",
        "ix_audit_logs_ip_address",
        "ix_audit_logs_resource_id",
    ]:
        op.drop_index(name, table_name="audit_logs")

    for name in ["ix_alert_rules_enabled", "ix_alert_rules_severity", "ix_alert_rules_rule_id"]:
        op.drop_index(name, table_name="alert_rules")

    op.drop_index("ix_event_processing_status_first_seen", table_name="event_processing")
    op.drop_index("ix_event_processing_processed_at", table_name="event_processing")

    op.drop_index("ix_events_contract_type", table_name="events")
    op.drop_index("ix_events_canonical_event_hash", table_name="events")
    op.drop_index("ix_events_block_hash", table_name="events")
