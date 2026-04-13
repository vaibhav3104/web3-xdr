# Data Retention Runbook

## Automatic Retention

The worker service runs a retention job automatically:

| Data Type | Default Retention | Env Var | Cleanup Interval |
|-----------|-------------------|---------|------------------|
| Events | 90 days | `EVENT_RETENTION_DAYS` | Every 6 hours |
| Resolved incidents | 365 days | `INCIDENT_RETENTION_DAYS` | Every 6 hours |
| Redis event cache | 24 hours | `EVENT_TTL_HOURS` | TTL-based (automatic) |
| In-memory patterns | Window-based | `PATTERN_WINDOW_MINUTES` | Per-evaluation |

### Verifying retention is running

Check worker logs for `data_retention_completed` events:
```bash
gcloud run services logs read web3-xdr-production-worker \
  --filter="data_retention"
```

Expected log fields: `events_deleted`, `incidents_deleted`, `duration_ms`

## Manual Purge

For immediate cleanup (e.g., disk pressure):

```bash
# Purge events older than 24 hours (requires admin auth + confirmation)
curl -X POST "https://<API_URL>/maintenance/purge?hours=24&confirm=true" \
  -H "Authorization: Bearer <admin-jwt>"
```

## Database Size Monitoring

```sql
-- Check table sizes
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;

-- Count rows by table
SELECT 'events' as tbl, count(*) FROM events
UNION ALL
SELECT 'incidents', count(*) FROM incidents
UNION ALL
SELECT 'simulation_runs', count(*) FROM simulation_runs;
```

## Emergency: Disk Full

1. Increase Cloud SQL disk: `gcloud sql instances patch web3-xdr-db --storage-size=<new-size-gb>`
2. Run manual purge with aggressive window: `hours=1`
3. Check for index bloat: `REINDEX TABLE events;`
4. Consider reducing retention: set `EVENT_RETENTION_DAYS=30` temporarily
