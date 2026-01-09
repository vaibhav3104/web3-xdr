# ✅ Deployment Verification Guide

## 🎉 Deployment Completed Successfully!

**Date**: $(date)
**Commit**: $(git rev-parse --short HEAD 2>/dev/null || echo "N/A")
**Status**: ✅ **DEPLOYED**

---

## 🔗 Service URLs

### Production Worker (War Room UI + Runtime Engine)
- **URL**: https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/
- **Health**: https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/health
- **Metrics**: https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/metrics

### Production API
- **URL**: https://web3-xdr-production-api-1003459948096.us-central1.run.app/
- **Health**: https://web3-xdr-production-api-1003459948096.us-central1.run.app/health
- **Events API**: https://web3-xdr-production-api-1003459948096.us-central1.run.app/api/events

### Log Explorer (Legacy UI)
- **URL**: https://web3-xdr-production-1003459948096.us-central1.run.app/frontend/logs.html

---

## ✅ Verification Checklist

### 1. Health Checks
```bash
# Worker Health
curl https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/health

# API Health
curl https://web3-xdr-production-api-1003459948096.us-central1.run.app/health
```

**Expected**: `{"status": "healthy", ...}`

---

### 2. War Room Dashboard
- **URL**: https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/
- **Check**: 
  - ✅ Page loads without errors
  - ✅ WebSocket connects (check browser console)
  - ✅ Threat feed displays (may be empty initially)
  - ✅ Cross-chain graph renders

---

### 3. Log Explorer
- **URL**: https://web3-xdr-production-1003459948096.us-central1.run.app/frontend/logs.html
- **Check**:
  - ✅ Page loads
  - ✅ Events table displays (may be empty initially)
  - ✅ Filters work

---

### 4. Events API
```bash
curl 'https://web3-xdr-production-api-1003459948096.us-central1.run.app/api/events?limit=5'
```

**Expected**: `{"total": X, "events": [...]}`

**Note**: Events may take 5-10 minutes to appear after deployment.

---

### 5. Runtime Security Plane
```bash
# Check worker logs for runtime engine initialization
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
  --limit 50 --project web3-xdr \
  --format="table(timestamp,severity,textPayload)" \
  | grep -E "(runtime_engine|events_saved|scanner_auto_started)"
```

**Expected Logs**:
- ✅ `runtime_engine_initialized`
- ✅ `events_saved_to_database`
- ✅ `contract_scanner_auto_started` (if AUTO_START_SCANNER=true)

---

### 6. Database Persistence
```bash
# Check if events are being saved
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
  --limit 100 --project web3-xdr \
  --format="table(timestamp,severity,textPayload)" \
  | grep -i "events_saved\|database\|postgres"
```

**Expected**: Logs showing `events_saved_to_database` or similar.

---

## 🐛 Troubleshooting

### Issue: War Room shows "No data"
**Solution**: 
- Wait 5-10 minutes for events to start flowing
- Check WebSocket connection in browser console
- Verify Redis is accessible

### Issue: Log Explorer shows "No events"
**Solution**:
- Wait 10-15 minutes after deployment
- Check worker logs for `events_saved_to_database`
- Verify `AUTO_START_SCANNER=true` is set

### Issue: Health check fails
**Solution**:
```bash
# Check service status
gcloud run services describe web3-xdr-production-worker \
  --region us-central1 --project web3-xdr

# Check recent logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
  --limit 50 --project web3-xdr
```

---

## 📊 Monitoring

### View Logs
```bash
# Worker logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
  --limit 100 --project web3-xdr

# API logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-api" \
  --limit 100 --project web3-xdr
```

### Metrics
- **Worker Metrics**: https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/metrics
- **GCP Console**: https://console.cloud.google.com/run?project=web3-xdr

---

## 🎯 Next Steps

1. ✅ **Verify Health**: Check all health endpoints
2. ✅ **Test War Room**: Open dashboard and verify UI loads
3. ✅ **Test Log Explorer**: Verify events appear (may take 10-15 min)
4. ✅ **Monitor Logs**: Watch for runtime engine activity
5. ✅ **Check Events**: Verify events are being saved to database

---

## 📝 Deployment Summary

**Services Deployed**:
- ✅ Production Worker (War Room UI + Runtime Engine)
- ✅ Production API
- ✅ Log Explorer (Legacy UI)

**Features Enabled**:
- ✅ Runtime Security Plane
- ✅ Event Persistence (Database)
- ✅ Auto-start Contract Scanner (if configured)
- ✅ bloXroute Mempool Integration (if configured)

**Environment Variables**:
- ✅ `AUTO_START_SCANNER=true` (set in workflow)
- ✅ `RUNTIME_ENABLED=true`
- ✅ `MEMPOOL_SOURCE=pseudo` (or `bloxroute` if configured)

---

**Status**: ✅ **DEPLOYMENT SUCCESSFUL**

Monitor the services and verify functionality over the next 15-30 minutes.
