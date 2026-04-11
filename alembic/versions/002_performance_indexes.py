"""Performance indexes for analytics queries.

Revision ID: 002
Revises: 001
Create Date: 2026-04-10
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Address-based risk scoring queries
    op.create_index("ix_events_from_address", "events", ["from_address"])
    # Address-based filtering
    op.create_index("ix_events_to_address", "events", ["to_address"])
    # Value-at-risk aggregations
    op.create_index("ix_events_amount_usd", "events", ["amount_usd"])
    # Analytics GROUP BY queries that filter by severity and time range
    op.create_index(
        "ix_events_severity_chain_timestamp",
        "events",
        ["severity", "chain_id", "block_timestamp"],
    )
    # Recent events queries (descending order)
    op.create_index(
        "ix_events_created_at",
        "events",
        [sa.text("created_at DESC")],
    )
    # Attack pattern analytics
    op.create_index(
        "ix_incidents_attack_type_created",
        "incidents",
        ["attack_type", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_incidents_attack_type_created", table_name="incidents")
    op.drop_index("ix_events_created_at", table_name="events")
    op.drop_index("ix_events_severity_chain_timestamp", table_name="events")
    op.drop_index("ix_events_amount_usd", table_name="events")
    op.drop_index("ix_events_to_address", table_name="events")
    op.drop_index("ix_events_from_address", table_name="events")
