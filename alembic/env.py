"""
Alembic environment configuration for Sentinel3.

Reads database connection details from environment variables, supports both
sync and async migrations, and handles Cloud SQL Proxy Unix sockets on
Cloud Run.
"""

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool, create_engine
from alembic import context

# Import all models so Alembic can detect them for autogenerate
from src.database.models import Base

# Alembic Config object
config = context.config

# Set up logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate
target_metadata = Base.metadata


def get_url() -> str:
    """
    Build a **synchronous** database URL from environment variables.

    Mirrors the logic in ``DatabaseManager.get_database_url()`` but always
    returns a ``postgresql://`` (psycopg2) URL because Alembic runs
    migrations synchronously.

    Priority order:
      1. CLOUDSQL_INSTANCE  (Cloud Run Unix socket)
      2. DATABASE_URL       (direct connection string)
      3. Individual POSTGRES_* env vars
    """
    # ── Cloud SQL Proxy (Unix socket on Cloud Run) ──────────────
    cloudsql_instance = os.getenv("CLOUDSQL_INSTANCE")
    if cloudsql_instance:
        user = os.getenv("POSTGRES_USER") or os.getenv("DB_USER") or "xdr"
        password = os.getenv("POSTGRES_PASSWORD") or os.getenv("DB_PASSWORD") or ""
        database = os.getenv("POSTGRES_DB") or os.getenv("DB_NAME") or "web3_xdr"

        # Try to extract credentials from DATABASE_URL if set
        database_url = os.getenv("DATABASE_URL", "")
        if database_url and "@" in database_url:
            try:
                parts = database_url.split("@")
                cred_part = parts[0].split("//")[-1]
                if ":" in cred_part:
                    user, password = cred_part.split(":", 1)
                if len(parts) > 1:
                    db_part = parts[1].split("/")
                    if len(db_part) > 1:
                        database = db_part[-1].split("?")[0]
            except Exception:
                pass

        unix_socket_dir = f"/cloudsql/{cloudsql_instance}"
        # psycopg2 uses ?host= for Unix sockets
        return (
            f"postgresql://{user}:{password}@/{database}"
            f"?host={unix_socket_dir}"
        )

    # ── DATABASE_URL ────────────────────────────────────────────
    url = os.getenv("DATABASE_URL")
    if url:
        # Normalize to the sync psycopg2 driver
        for prefix in ("postgresql+asyncpg://", "postgres://"):
            if url.startswith(prefix):
                url = url.replace(prefix, "postgresql://", 1)
        return url

    # ── Individual env vars ─────────────────────────────────────
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    user = os.getenv("POSTGRES_USER", "xdr")
    password = os.getenv("POSTGRES_PASSWORD", "")
    database = os.getenv("POSTGRES_DB", "web3_xdr")
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode -- emits SQL to stdout."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database."""
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,         # Detect column type changes
            compare_server_default=True,  # Detect server_default changes
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
