"""Add customers and api_keys tables.

Revision ID: 003
Revises: 002
Create Date: 2026-04-12
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # -- customers table --
    if not conn.dialect.has_table(conn, "customers"):
      op.create_table(
        "customers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("customer_id", sa.String(64), unique=True, nullable=False, index=True),
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

    # -- api_keys table --
    if not conn.dialect.has_table(conn, "api_keys"):
      op.create_table(
        "api_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("key_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("customer_id", sa.String(64), nullable=False, index=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("key_hash", sa.String(128), unique=True, nullable=False, index=True),
        sa.Column("key_prefix", sa.String(32), nullable=False, index=True),
        sa.Column("scopes", ARRAY(sa.String), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active", index=True),
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

    op.create_index("ix_api_keys_customer_status", "api_keys", ["customer_id", "status"], if_not_exists=True)


def downgrade() -> None:
    op.drop_index("ix_api_keys_customer_status", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_table("customers")
