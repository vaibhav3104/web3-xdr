# 🚨 Fix: Events Not Appearing in Log Explorer

## 🔍 Root Cause Analysis

### Issue 1: Redis Connection Failures ❌
**Problem**: Worker cannot connect to Redis
- `redis_consume_failed: Timeout connecting to server`
- `redis_publish_failed: Timeout connecting to server`

**Impact**: 
- Events collected from blockchain ✅
- Events **CANNOT** be published to Redis bus ❌
- Detection loop **CANNOT** consume events ❌
- Events **NEVER** reach database ❌

### Issue 2: RPC Block Range Errors ⚠️
**Problem**: Trying to fetch too many blocks at once
- Ethereum: `query exceeds max results 20000`
- Polygon: `Block range is too large`

**Impact**: Ingestion fails for some chains

### Issue 3: Worker Stuck in "Starting" ⚠️
**Problem**: Worker health shows `ready: false` after 7+ minutes

**Impact**: Initialization may be incomplete

---

## ✅ Solutions

### Fix 1: Verify Redis Connection

**Check Redis URL Secret**:
```bash
gcloud run services describe web3-xdr-production-worker \
  --region us-central1 \
  --project web3-xdr \
  --format="value(spec.template.spec.containers[0].env)"
```

**Verify Redis Secret Exists**:
```bash
gcloud secrets list --project web3-xdr | grep redis
```

**Test Redis Connection** (if you have access):
```bash
# Get Redis URL from secret
REDIS_URL=$(gcloud secrets versions access latest --secret="web3-xdr-redis-url" --project web3-xdr)
echo $REDIS_URL
```

### Fix 2: Reduce Block Range Size

**File**: `src/telemetry/evm_listener.py` or similar

**Change**: Reduce batch size for block polling
- Current: May be fetching 1000+ blocks at once
- Recommended: Fetch 100-200 blocks per batch

### Fix 3: Add Fallback to Direct Database Save

**Option**: If Redis is unavailable, save events directly to database

**File**: `src/worker/main.py` - `ingestion_loop()`

**Add**: Direct database save when Redis publish fails

---

## 🚀 Immediate Actions

### Step 1: Check Redis Secret
```bash
gcloud secrets describe web3-xdr-redis-url --project web3-xdr
```

### Step 2: Verify Redis Instance
```bash
# Check if Redis instance exists
gcloud redis instances list --project web3-xdr --region us-central1
```

### Step 3: Update Redis URL (if needed)
```bash
# If Redis URL is wrong, update the secret
gcloud secrets versions add web3-xdr-redis-url \
  --data-file=- \
  --project web3-xdr
# Then paste the correct Redis URL
```

### Step 4: Restart Worker
```bash
# Force new revision
gcloud run services update web3-xdr-production-worker \
  --region us-central1 \
  --project web3-xdr \
  --no-traffic \
  --tag=restart

# Then route traffic back
gcloud run services update-traffic web3-xdr-production-worker \
  --region us-central1 \
  --project web3-xdr \
  --to-latest
```

---

## 🔧 Alternative: Direct Database Save (Bypass Redis)

If Redis continues to fail, we can modify the ingestion loop to save directly to database:

**File**: `src/worker/main.py`

**Change**: In `ingestion_loop()`, after collecting events, save directly to database instead of publishing to Redis.

---

## 📊 Expected Behavior After Fix

1. ✅ Redis connection established
2. ✅ Events published to Redis bus
3. ✅ Detection loop consumes events
4. ✅ Events saved to PostgreSQL
5. ✅ Events appear in Log Explorer

---

**Status**: 🔴 **BLOCKED** - Redis connection required for events to flow
