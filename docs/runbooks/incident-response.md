# Incident Response Runbook

## Alert: CriticalIncidentDetected

**Trigger**: Sentinel3 detected a critical-severity blockchain security incident.

### Triage (< 5 min)

1. Open Grafana dashboard: `<GRAFANA_URL>/d/sentinel3-incidents`
2. Check `/api/incidents?severity=CRITICAL&status=OPEN` for details
3. Identify the affected chain, protocol, and transaction hashes
4. Determine incident type: bridge exploit, flash loan, rug pull, governance attack

### Containment (< 15 min)

| Incident Type | Action |
|---------------|--------|
| Bridge exploit | Contact bridge operator via known channels; pause if admin key available |
| Flash loan attack | No immediate action needed — attack is atomic and already completed |
| Governance attack | Alert protocol team; check if timelock allows cancellation |
| Rug pull | Flag addresses on internal watchlist via `POST /guardian/block-address` |

### Investigation

1. Pull full event timeline: `GET /api/events?incident_id=<id>`
2. Check cross-chain correlation: `GET /api/analytics/cross-chain?incident_id=<id>`
3. Review ML confidence score — if < 0.7, consider false positive
4. Check transaction simulation results in incident evidence JSON

### Resolution

1. Update incident status: `PATCH /api/incidents/<id>` with resolution notes
2. If false positive: mark as `FALSE_POSITIVE` — this feeds the ML retraining queue
3. Post-mortem: document root cause, detection latency, and response time

---

## Alert: ChainDisconnected

**Trigger**: No RPC connectivity to a monitored blockchain for > 2 minutes.

### Triage

1. Check `/health/detailed` — look at the `checks` object
2. Verify RPC endpoint health: `curl <RPC_URL> -X POST -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'`
3. Check if this is a single-chain or multi-chain outage

### Resolution

| Cause | Fix |
|-------|-----|
| RPC provider down | The `RobustProviderManager` auto-rotates to backup RPCs. Check logs for `rpc_failover` events. If all RPCs are down, add a new one to `<CHAIN>_RPC_URL` env var. |
| Network partition | Check https://status.infura.io or provider status pages |
| Rate limited | Upgrade RPC plan or add more providers to rotation |
| DNS failure | Check Cloud Run VPC connector and DNS resolution |

### Escalation

If all RPC endpoints for a chain are down for > 10 minutes:
1. Events for that chain stop being processed (expected)
2. Worker logs will show `chain_reconnecting` with backoff intervals
3. No manual intervention needed — auto-recovery on RPC restoration
4. If > 30 min: check GCP VPC connector health in Cloud Console

---

## Alert: SlowEventProcessing

**Trigger**: P95 event processing latency > 1 second for 5 minutes.

### Triage

1. Check Prometheus: `histogram_quantile(0.95, rate(web3_xdr_event_processing_seconds_bucket[5m]))`
2. Check if a specific chain is slow: break down by `chain` label
3. Check DB connection pool: `GET /health/detailed` for postgres status

### Common Causes

| Cause | Indicator | Fix |
|-------|-----------|-----|
| DB connection pool exhaustion | Postgres check shows high latency | Increase `DB_POOL_SIZE` (default 10) |
| ML inference bottleneck | GPU/CPU saturation in container metrics | Scale worker instances or disable ML with `ENABLE_ML_DETECTION=false` |
| Large transaction batch | Spike correlates with high-value block | Transient — will self-resolve |
| Redis latency | Redis check shows > 100ms | Check Redis memory usage and eviction |

---

## Alert: AlertDeliveryFailure

**Trigger**: > 5 alert delivery failures (Slack/Telegram/PagerDuty) in 15 minutes.

### Triage

1. Check logs for `alert_delivery_failed` events
2. Verify webhook URLs are valid: `SLACK_WEBHOOK_URL`, `TELEGRAM_BOT_TOKEN`
3. Test manually: `curl -X POST <SLACK_WEBHOOK_URL> -d '{"text":"test"}'`

### Resolution

| Cause | Fix |
|-------|-----|
| Expired webhook | Regenerate in Slack/Telegram admin |
| Rate limited | Reduce alert frequency in alertmanager `repeat_interval` |
| Network issue | Check outbound HTTPS from Cloud Run |

Alerts are best-effort — delivery failure does NOT block event processing.
