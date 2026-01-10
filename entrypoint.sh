#!/bin/bash
set -e

if [ "$PROC_TYPE" = "api" ]; then
    echo "Starting API server..."
    exec python -m src.api.server
else
    echo "Starting Worker..."
    exec python -m src.worker.main
fi
