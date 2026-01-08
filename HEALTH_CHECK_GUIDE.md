# Sentinel3 - Post-Deployment Health Check Guide

## 🔍 Quick Health Check

Run the automated health check script:

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr
./scripts/health_check.sh
```

---

## 📋 Manual Health Checks

### 1. Verify "Split Brain" (API vs Worker)

#### Check API Service

```bash
# Get API URL
API_URL=$(gcloud run services describe web3-xdr-production-api \
    --region=us-central1 \
    --format='value(status.url)')

echo "API URL: ${API_URL}"

# Test health endpoint
curl "${API_URL}/health"
```

**Expected Response:**
```json
{
  "status": "healthy",
  "service": "sentinel3-api"
}
```

**Also test:**
- Dashboard: Open `${API_URL}` in browser
- Swagger UI: `${API_URL}/docs`
- Metrics: `${API_URL}/metrics` (if available)

#### Check Worker Service

```bash
# Get Worker URL (will be private)
WORKER_URL=$(gcloud run services describe web3-xdr-production-worker \
    --region=us-central1 \
    --format='value(status.url)')

echo "Worker URL: ${WORKER_URL}"

# Try to access (should fail - it's private)
curl "${WORKER_URL}/health"  # Should return 403 or require auth
```

**Expected**: Worker is **private** (no public access). You must check logs.

---

### 2. Worker Log Audit (Critical)

Check the Worker logs for these **success signals**:

```bash
# View recent worker logs
gcloud logging read \
    "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
    --limit=100 \
    --format="table(timestamp,severity,textPayload)" \
    --project=web3-xdr
```

#### Success Signals to Look For:

✅ **Worker Initialization**
```
[INFO] worker_initialized
[INFO] Worker initialized
```
**Meaning**: `PROC_TYPE=worker` env var worked correctly.

✅ **Redis Connection**
```
[INFO] event_bus_initialized
[INFO] Connected to Redis
[INFO] redis
```
**Meaning**: Redis secret injection worked, Event Bus is connected.

✅ **Checkpoint Manager**
```
[INFO] checkpoint_redis_connected
[INFO] Checkpoint loaded: ethereum=0
[INFO] checkpoint_resolved
```
**Meaning**: CheckpointManager is active, can resume from last block.

✅ **Non-EVM Listeners**
```
[INFO] PassiveNonEVMListener started
[INFO] cosmos_listener initialized
[INFO] aptos_listener initialized
```
**Meaning**: Refactored listeners are working without threading issues.

✅ **Chain Listeners Started**
```
[INFO] chain_initialized
[INFO] Connected to Ethereum
[INFO] Connected to Polygon
```
**Meaning**: EVM chains are being monitored.

#### Error Signals to Watch For:

❌ **Redis Connection Failed**
```
[ERROR] redis connection failed
[ERROR] Failed to connect to Redis
```
**Action**: Check `web3-xdr-redis-url` secret exists and is accessible.

❌ **Database Connection Failed**
```
[ERROR] database connection failed
[ERROR] Failed to connect to PostgreSQL
```
**Action**: Check `web3-xdr-database-url` secret and Cloud SQL instance.

❌ **Missing Secrets**
```
[ERROR] Secret not found: web3-xdr-redis-url
[ERROR] Environment variable not set
```
**Action**: Verify all secrets exist in Secret Manager.

---

### 3. Database Connectivity

#### Check for Database Errors

```bash
# Check for database-related errors
gcloud logging read \
    "resource.type=cloud_run_revision AND (textPayload=~\"database\" OR textPayload=~\"postgres\" OR severity>=ERROR)" \
    --limit=20 \
    --format="table(timestamp,severity,textPayload)" \
    --project=web3-xdr
```

#### Good Signs:

✅ **Migration Logs** (if using Alembic)
```
[INFO] Running alembic migrations
[INFO] Creating table audit_logs
[INFO] Schema updated
```
**Meaning**: Database schema is being applied correctly.

✅ **Connection Success**
```
[INFO] Database connected
[INFO] PostgreSQL connection established
```
**Meaning**: Database connectivity is working.

---

## 🔧 Quick Diagnostic Commands

### Check Service Status

```bash
# List all services
gcloud run services list --region=us-central1 --project=web3-xdr

# Check API service details
gcloud run services describe web3-xdr-production-api \
    --region=us-central1 \
    --format="yaml(status)"

# Check Worker service details
gcloud run services describe web3-xdr-production-worker \
    --region=us-central1 \
    --format="yaml(status)"
```

### View Real-Time Logs

```bash
# API logs (streaming)
gcloud logging tail \
    "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-api" \
    --project=web3-xdr

# Worker logs (streaming)
gcloud logging tail \
    "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
    --project=web3-xdr
```

### Check Environment Variables

```bash
# API service env vars
gcloud run services describe web3-xdr-production-api \
    --region=us-central1 \
    --format="value(spec.template.spec.containers[0].env)" \
    --project=web3-xdr

# Worker service env vars
gcloud run services describe web3-xdr-production-worker \
    --region=us-central1 \
    --format="value(spec.template.spec.containers[0].env)" \
    --project=web3-xdr
```

---

## ✅ Health Check Checklist

- [ ] API service is accessible via public URL
- [ ] API `/health` endpoint returns `{"status": "healthy"}`
- [ ] Worker service is **private** (cannot access via public URL)
- [ ] Worker logs show "Worker initialized"
- [ ] Worker logs show Redis connection success
- [ ] Worker logs show checkpoint manager active
- [ ] Worker logs show chain listeners started
- [ ] No database connection errors
- [ ] No Redis connection errors
- [ ] No missing secret errors

---

## 🐛 Common Issues & Fixes

### Issue: Worker not starting

**Check:**
```bash
gcloud logging read \
    "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker AND severity>=ERROR" \
    --limit=20
```

**Common causes:**
- Missing `PROC_TYPE=worker` env var
- Redis secret not accessible
- Database connection failed

### Issue: API returns 500

**Check:**
```bash
gcloud logging read \
    "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-api AND severity>=ERROR" \
    --limit=20
```

**Common causes:**
- Database connection failed
- Missing JWT secret
- Import errors

### Issue: Worker crash loop

**Check logs for:**
- Redis connection failures
- Database connection failures
- Missing environment variables
- Import errors

---

## 📊 Expected Log Patterns

### Successful Worker Startup

```
[INFO] worker_initialized
[INFO] event_bus_initialized bus_type=RedisEventBus
[INFO] checkpoint_redis_connected
[INFO] checkpoint_resolved chain_id=ethereum resolved_start=0
[INFO] chain_initialized chain_id=ethereum rpc_count=2
[INFO] ingestion_loop_started
[INFO] detection_loop_started
```

### Successful API Startup

```
[INFO] API server started
[INFO] Routes registered
[INFO] Database connected
[INFO] JWT handler initialized
```

---

**Run the health check script for automated verification!**

```bash
./scripts/health_check.sh
```

