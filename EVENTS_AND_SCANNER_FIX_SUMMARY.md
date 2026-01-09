# ✅ FIXED: Missing Events & Contract Scanner Issues

## 🔍 Root Cause Analysis

### Issue 1: No Events in Log Explorer ✅ FIXED

**Problem**: Log explorer showed 0 events even though worker was running

**Root Cause**: 
- Worker was collecting events from blockchain ✅
- Worker was publishing events to Redis bus ✅
- Worker was consuming events from bus ✅
- **Worker was NOT saving events to PostgreSQL** ❌

**Location**: `src/worker/main.py` line 650-683 (`detection_loop()`)

**The Bug**:
```python
# Line 663: "Stub for Phase 3: Just log for now"
logger.info("processing_event", ...)  # Only logged, never saved!
```

**The Fix**:
- Added `DatabaseService.save_events_batch()` call
- Events are now batched and saved to PostgreSQL
- Uses efficient batch inserts with `ON CONFLICT DO NOTHING` for idempotency

---

### Issue 2: Smart Contract Scanner Not Running ✅ FIXED

**Problem**: Contract scanner exists but doesn't start automatically

**Root Cause**: 
- Scanner code exists in `src/api/ai_routes.py`
- Requires manual POST to `/api/collector/start`
- No auto-start mechanism

**The Fix**:
- Added auto-start in worker initialization
- Controlled by `AUTO_START_SCANNER` environment variable
- Starts automatically when worker initializes (if enabled)

---

## 🔧 Changes Made

### File: `src/worker/main.py`

**1. Updated `detection_loop()` method** (line 650-730):
- ✅ Added `DatabaseService` import
- ✅ Added batch event collection
- ✅ Added database persistence with `save_events_batch()`
- ✅ Added error handling for database failures
- ✅ Events now saved to PostgreSQL

**2. Updated `initialize()` method** (line 295-304):
- ✅ Added auto-start contract scanner
- ✅ Configurable via `AUTO_START_SCANNER` env var
- ✅ Configurable chains via `SCANNER_CHAINS` env var

---

## 🚀 Deployment Steps

### Step 1: Update Cloud Run Environment Variables

**For Worker Service** (`web3-xdr-production-worker`):

```bash
gcloud run services update web3-xdr-production-worker \
  --region us-central1 \
  --project web3-xdr \
  --update-env-vars "AUTO_START_SCANNER=true,SCANNER_CHAINS=ethereum,polygon,arbitrum"
```

**Or via GCP Console**:
1. Go to Cloud Run → `web3-xdr-production-worker`
2. Edit & Deploy New Revision
3. Variables & Secrets → Add Variable:
   - `AUTO_START_SCANNER` = `true`
   - `SCANNER_CHAINS` = `ethereum,polygon,arbitrum`

---

### Step 2: Deploy Updated Code

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr

# Push to GitHub (triggers auto-deployment)
git push origin main
```

**Or manual deployment**:
```bash
# Build and deploy
gcloud builds submit --tag gcr.io/web3-xdr/web3-xdr-worker:latest
gcloud run deploy web3-xdr-production-worker \
  --image gcr.io/web3-xdr/web3-xdr-worker:latest \
  --region us-central1
```

---

## ✅ Verification

### Test 1: Events Appear in Database

**Wait 5-10 minutes** after deployment, then:

```bash
# Check API
curl 'https://web3-xdr-production-api-1003459948096.us-central1.run.app/api/events?limit=5'

# Should return events (not empty array)
# Expected: {"total": X, "events": [...]}
```

**In Log Explorer**:
- Visit: https://web3-xdr-production-1003459948096.us-central1.run.app/frontend/logs.html
- Events should appear within 5-10 minutes
- Check "Last 15m" or "Last 1h" time range

---

### Test 2: Contract Scanner Running

```bash
# Check scanner status (if endpoint exists)
curl 'https://web3-xdr-production-api-1003459948096.us-central1.run.app/api/collector/status'

# Check worker logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
  --limit 50 --project web3-xdr \
  --format="table(timestamp,severity,textPayload)" \
  | grep -i scanner
```

**Expected Logs**:
- `contract_scanner_auto_started` ✅
- `Now monitoring X chains for new contract deployments` ✅

---

## 📊 Expected Behavior After Fix

### Before Fix:
- ❌ Log Explorer: 0 events
- ❌ Database: Empty
- ❌ Contract Scanner: Not running

### After Fix:
- ✅ Log Explorer: Shows events within 5-10 minutes
- ✅ Database: Events being saved
- ✅ Contract Scanner: Auto-starts (if enabled)

---

## 🔍 Troubleshooting

### If Events Still Don't Appear:

**1. Check Worker Logs**:
```bash
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
  --limit 100 --project web3-xdr \
  --format="table(timestamp,severity,textPayload)" \
  | grep -E "(events_saved|database_save|processing_event)"
```

**Look for**:
- ✅ `events_saved_to_database` - Events are being saved
- ❌ `database_save_failed` - Database connection issue
- ❌ `log_poll_failed` - RPC connection issue

**2. Check Database Connection**:
```bash
# Verify DATABASE_URL is set
gcloud run services describe web3-xdr-production-worker \
  --region us-central1 --project web3-xdr \
  --format="value(spec.template.spec.containers[0].env)"
```

**3. Check RPC Endpoints**:
- Verify RPC URLs in `config/chains.yaml` are valid
- Check if RPC providers are rate-limited
- Worker logs show `log_poll_failed` if RPCs are down

---

### If Scanner Doesn't Start:

**1. Check Environment Variable**:
```bash
gcloud run services describe web3-xdr-production-worker \
  --region us-central1 --project web3-xdr \
  --format="value(spec.template.spec.containers[0].env)" \
  | grep AUTO_START_SCANNER
```

**Should show**: `AUTO_START_SCANNER=true`

**2. Check Logs**:
```bash
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
  --limit 50 --project web3-xdr \
  --format="table(timestamp,severity,textPayload)" \
  | grep -i scanner
```

**Look for**:
- ✅ `contract_scanner_auto_started` - Success
- ❌ `scanner_auto_start_failed` - Error (check error message)
- ❌ `scanner_module_not_available` - Import error

---

## 📋 Summary

**What Was Fixed**:
1. ✅ Events now save to PostgreSQL database
2. ✅ Contract scanner auto-starts (when enabled)
3. ✅ Batch processing for efficient database writes
4. ✅ Proper error handling and logging

**What You Need to Do**:
1. ✅ Code is fixed and committed
2. ⏳ Deploy to production (git push or manual)
3. ⏳ Set `AUTO_START_SCANNER=true` in Cloud Run env vars
4. ⏳ Wait 5-10 minutes for events to appear
5. ⏳ Verify in log explorer

**Files Changed**:
- `src/worker/main.py` - Added database persistence + auto-start scanner
- `FIX_MISSING_EVENTS_AND_SCANNER.md` - Detailed fix documentation

---

## 🎯 Next Steps

1. **Deploy the fix**:
   ```bash
   git push origin main
   ```

2. **Set environment variable**:
   ```bash
   gcloud run services update web3-xdr-production-worker \
     --region us-central1 \
     --update-env-vars "AUTO_START_SCANNER=true"
   ```

3. **Monitor logs**:
   ```bash
   gcloud logging tail "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
     --project web3-xdr
   ```

4. **Verify events appear**:
   - Check log explorer after 5-10 minutes
   - Check API: `/api/events?limit=5`

---

**Status**: ✅ **CODE FIXED - READY TO DEPLOY**

The fixes are committed and ready. Deploy to production and events will start appearing! 🚀
