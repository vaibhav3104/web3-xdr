#!/bin/sh
# ============================================================================
# Sentinel3 - PostgreSQL Database Backup Script
# ============================================================================
# Creates compressed pg_dump backups with timestamp-based naming.
# Automatically removes backups older than 7 days.
#
# Environment variables (with defaults matching docker-compose.yml):
#   POSTGRES_HOST     - Database host (default: postgres)
#   POSTGRES_PORT     - Database port (default: 5432)
#   POSTGRES_USER     - Database user (default: xdr)
#   POSTGRES_PASSWORD - Database password (default: xdr_password)
#   POSTGRES_DB       - Database name (default: web3_xdr)
#   BACKUP_DIR        - Backup directory (default: /backups)
#   RETENTION_DAYS    - Days to keep backups (default: 7)
# ============================================================================

set -e

# Configuration
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-xdr}"
POSTGRES_DB="${POSTGRES_DB:-web3_xdr}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"

# Generate timestamp and filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="sentinel3_backup_${TIMESTAMP}.sql.gz"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_FILE}"

# Ensure backup directory exists
mkdir -p "${BACKUP_DIR}"

echo "[$(date -Iseconds)] Starting database backup..."
echo "[$(date -Iseconds)] Host: ${POSTGRES_HOST}:${POSTGRES_PORT}"
echo "[$(date -Iseconds)] Database: ${POSTGRES_DB}"
echo "[$(date -Iseconds)] Output: ${BACKUP_PATH}"

# Run pg_dump with compression
export PGPASSWORD="${POSTGRES_PASSWORD}"
if pg_dump \
    -h "${POSTGRES_HOST}" \
    -p "${POSTGRES_PORT}" \
    -U "${POSTGRES_USER}" \
    -d "${POSTGRES_DB}" \
    --no-owner \
    --no-privileges \
    | gzip > "${BACKUP_PATH}"; then

    BACKUP_SIZE=$(du -h "${BACKUP_PATH}" | cut -f1)
    echo "[$(date -Iseconds)] Backup completed successfully: ${BACKUP_FILE} (${BACKUP_SIZE})"
else
    echo "[$(date -Iseconds)] ERROR: Backup failed!"
    rm -f "${BACKUP_PATH}"
    exit 1
fi
unset PGPASSWORD

# Delete backups older than retention period
echo "[$(date -Iseconds)] Cleaning up backups older than ${RETENTION_DAYS} days..."
DELETED_COUNT=0
for f in "${BACKUP_DIR}"/sentinel3_backup_*.sql.gz; do
    [ -f "$f" ] || continue
    if [ "$(find "$f" -mtime +"${RETENTION_DAYS}" 2>/dev/null)" ]; then
        echo "[$(date -Iseconds)] Deleting old backup: $(basename "$f")"
        rm -f "$f"
        DELETED_COUNT=$((DELETED_COUNT + 1))
    fi
done
echo "[$(date -Iseconds)] Deleted ${DELETED_COUNT} old backup(s)"

# List remaining backups
TOTAL_BACKUPS=$(ls -1 "${BACKUP_DIR}"/sentinel3_backup_*.sql.gz 2>/dev/null | wc -l | tr -d ' ')
TOTAL_SIZE=$(du -sh "${BACKUP_DIR}" 2>/dev/null | cut -f1)
echo "[$(date -Iseconds)] Total backups: ${TOTAL_BACKUPS} (${TOTAL_SIZE} used)"
echo "[$(date -Iseconds)] Backup process complete"
