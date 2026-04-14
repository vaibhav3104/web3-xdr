"""
Alembic migration helpers for Sentinel3 XDR.

Provides a startup check that reports the current database revision and
whether any pending migrations exist.  Does NOT auto-migrate -- that is
left to an explicit ``alembic upgrade head`` call (in CI/CD or a
pre-deploy step) so that schema changes are always intentional.

Legacy ad-hoc ALTER TABLE migrations have been replaced by proper Alembic
version files under ``alembic/versions/``.
"""

import os
import structlog
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

logger = structlog.get_logger(__name__)


def _get_sync_url() -> str:
    """Build a sync (psycopg2) database URL using the same logic as alembic/env.py."""
    cloudsql_instance = os.getenv("CLOUDSQL_INSTANCE")
    if cloudsql_instance:
        user = os.getenv("POSTGRES_USER") or os.getenv("DB_USER") or "xdr"
        password = os.getenv("POSTGRES_PASSWORD") or os.getenv("DB_PASSWORD") or ""
        database = os.getenv("POSTGRES_DB") or os.getenv("DB_NAME") or "web3_xdr"

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
        return (
            f"postgresql://{user}:{password}@/{database}"
            f"?host={unix_socket_dir}"
        )

    url = os.getenv("DATABASE_URL", "")
    if url:
        for prefix in ("postgresql+asyncpg://", "postgres://"):
            if url.startswith(prefix):
                url = url.replace(prefix, "postgresql://", 1)
        return url

    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    user = os.getenv("POSTGRES_USER", "xdr")
    password = os.getenv("POSTGRES_PASSWORD", "")
    database = os.getenv("POSTGRES_DB", "web3_xdr")
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


def check_alembic_revision() -> dict:
    """
    Check the current Alembic revision in the database and compare it
    against the latest revision known to this codebase.

    Returns a dict with:
      - current_rev: the revision currently stamped in the DB (or None)
      - head_rev: the latest revision defined in alembic/versions/
      - is_up_to_date: True if current == head
      - needs_migration: True if there are pending migrations
      - error: error string if the check failed
    """
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    result = {
        "current_rev": None,
        "head_rev": None,
        "is_up_to_date": False,
        "needs_migration": True,
        "error": None,
    }

    try:
        # Discover the head revision from the migration scripts
        alembic_cfg = Config("alembic.ini")
        script = ScriptDirectory.from_config(alembic_cfg)
        head_revs = script.get_heads()
        result["head_rev"] = head_revs[0] if head_revs else None

        # Read the current revision from the database
        engine = create_engine(_get_sync_url(), poolclass=NullPool)
        try:
            with engine.connect() as conn:
                # Check if alembic_version table exists
                row = conn.execute(
                    text(
                        "SELECT EXISTS ("
                        "  SELECT 1 FROM information_schema.tables "
                        "  WHERE table_name = 'alembic_version'"
                        ")"
                    )
                ).scalar()

                if row:
                    current = conn.execute(
                        text("SELECT version_num FROM alembic_version LIMIT 1")
                    ).scalar()
                    result["current_rev"] = current
                else:
                    # No alembic_version table -- database has never been stamped
                    result["current_rev"] = None
        finally:
            engine.dispose()

        result["is_up_to_date"] = result["current_rev"] == result["head_rev"]
        result["needs_migration"] = not result["is_up_to_date"]

    except Exception as exc:
        result["error"] = str(exc)
        logger.warning(
            "alembic_revision_check_failed",
            error=str(exc),
        )

    return result


async def log_migration_status() -> None:
    """
    Log the current Alembic migration status at startup.

    This is meant to be called from the FastAPI startup event.  It runs the
    check in a thread to avoid blocking the async event loop (the check uses
    a synchronous psycopg2 connection).
    """
    import asyncio

    try:
        status = await asyncio.to_thread(check_alembic_revision)

        if status["error"]:
            logger.warning(
                "alembic_status_check_error",
                error=status["error"],
            )
            return

        if status["is_up_to_date"]:
            logger.info(
                "alembic_schema_up_to_date",
                current_rev=status["current_rev"],
                head_rev=status["head_rev"],
            )
        elif status["current_rev"] is None:
            logger.warning(
                "alembic_no_revision_stamped",
                head_rev=status["head_rev"],
                hint="Run 'alembic stamp head' on an existing DB or 'alembic upgrade head' for a fresh DB",
            )
        else:
            logger.warning(
                "alembic_migration_pending",
                current_rev=status["current_rev"],
                head_rev=status["head_rev"],
                hint="Run 'alembic upgrade head' to apply pending migrations",
            )
    except Exception as exc:
        logger.warning("alembic_status_check_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Backward-compatible shim
# ---------------------------------------------------------------------------
# Some callers may still import ``run_migrations`` from the old module.
# Provide a no-op so they don't break.

async def run_migrations():
    """
    **Deprecated** -- migrations are now handled by Alembic.

    This function is kept as a backward-compatible no-op.  Run
    ``alembic upgrade head`` instead.
    """
    logger.info(
        "run_migrations_noop",
        message="Ad-hoc migrations replaced by Alembic. Run 'alembic upgrade head' instead.",
    )
