#!/bin/bash
set -e

# Run database migrations for API process before starting
if [ "$PROC_TYPE" = "api" ]; then
    echo "[ENTRYPOINT] Running database migrations..."
    if python -m alembic upgrade head 2>&1; then
        echo "[ENTRYPOINT] Migrations complete"
    else
        echo "[ENTRYPOINT] Migration failed (non-fatal) — DB may already be up to date"
    fi
    echo "[ENTRYPOINT] Starting API server..."
    exec python -m src.api.server
else
    echo "[ENTRYPOINT] Starting Worker..."
    exec python -m src.worker.main
fi
