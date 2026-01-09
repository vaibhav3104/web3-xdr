# 🔧 Fix: Missing Events & Contract Scanner Issues

## 🚨 Issues Identified

### Issue 1: No Events in Log Explorer ❌
**Root Cause**: Worker collects events but **doesn't save them to database**

**Location**: `src/worker/main.py` line 637-683 (`detection_loop()`)

**Problem**: 
- Events are collected from blockchain ✅
- Events are published to Redis bus ✅  
- Events are consumed from bus ✅
- Events are **NOT saved to PostgreSQL** ❌

**Code Issue**:
```python
# Line 663: "Stub for Phase 3: Just log for now"
logger.info("processing_event", ...)  # Only logs, doesn't save!
```

---

### Issue 2: Smart Contract Scanner Not Running ❌
**Root Cause**: Scanner requires manual API call to start

**Location**: `src/api/ai_routes.py` - `/api/collector/start` endpoint

**Problem**:
- Scanner exists but doesn't auto-start
- Needs manual POST request to `/api/collector/start`
- Should start automatically when worker initializes

---

## ✅ Solutions

### Fix 1: Add Database Persistence to Worker

**File**: `src/worker/main.py`

**Change**: Update `detection_loop()` to save events to database

**Before** (line 658-676):
```python
for message in messages:
    try:
        event_data = message.event_data
        chain_id = event_data.get("chain_id", "unknown")
        
        # Stub for Phase 3: Just log for now
        logger.info("processing_event", ...)
```

**After**:
```python
from src.database.service import DatabaseService

# Batch events for efficient saving
events_to_save = []

for message in messages:
    try:
        event_data = message.event_data
        chain_id = event_data.get("chain_id", "unknown")
        
        # Prepare event for database
        db_event = {
            "event_id": event_data.get("event_id"),
            "chain_id": chain_id,
            "event_type": event_data.get("event_type"),
            "tx_hash": event_data.get("tx_hash"),
            "block_number": event_data.get("block_number"),
            "block_timestamp": event_data.get("block_timestamp"),
            "contract_address": event_data.get("contract_address"),
            "from_address": event_data.get("from_address"),
            "to_address": event_data.get("to_address"),
            "amount": event_data.get("amount"),
            "amount_usd": event_data.get("amount_usd"),
            "severity": event_data.get("severity", "LOW"),
            "raw_data": event_data.get("raw_data", {}),
        }
        events_to_save.append(db_event)
        
        logger.info("processing_event", ...)
        
# Save batch to database
if events_to_save:
    try:
        saved_count = await DatabaseService.save_events_batch(events_to_save)
        logger.info("events_saved_to_database", count=saved_count)
    except Exception as e:
        logger.error("database_save_failed", error=str(e))
```

---

### Fix 2: Auto-Start Contract Scanner

**Option A**: Add to worker initialization (recommended)

**File**: `src/worker/main.py`

**Add to `initialize()` method**:
```python
# Auto-start contract scanner if enabled
if os.getenv("AUTO_START_SCANNER", "false").lower() == "true":
    try:
        from src.ai.collectors import start_auto_collection
        chains = self.config.get("scanner_chains", ["ethereum", "polygon", "arbitrum"])
        await start_auto_collection(chains=chains)
        logger.info("contract_scanner_auto_started", chains=chains)
    except Exception as e:
        logger.warning("scanner_auto_start_failed", error=str(e))
```

**Option B**: Add to API server startup

**File**: `src/api/server.py`

**Add to `create_app()`**:
```python
@app.on_event("startup")
async def startup_event():
    # Auto-start contract scanner
    if os.getenv("AUTO_START_SCANNER", "false").lower() == "true":
        try:
            from src.ai.collectors import start_auto_collection
            chains = ["ethereum", "polygon", "arbitrum"]
            await start_auto_collection(chains=chains)
            logger.info("contract_scanner_started", chains=chains)
        except Exception as e:
            logger.warning("scanner_start_failed", error=str(e))
```

---

## 🚀 Implementation Steps

1. **Fix detection_loop()** - Add database persistence
2. **Add auto-start scanner** - Choose Option A or B
3. **Update environment variables** - Add `AUTO_START_SCANNER=true`
4. **Test locally** - Verify events appear in database
5. **Deploy** - Push to production

---

## 🧪 Testing

### Test 1: Events Appear in Database
```bash
# Check API
curl 'https://web3-xdr-production-api-1003459948096.us-central1.run.app/api/events?limit=5'

# Should return events (not empty array)
```

### Test 2: Contract Scanner Running
```bash
# Check scanner status
curl 'https://web3-xdr-production-api-1003459948096.us-central1.run.app/api/collector/status'

# Should return running status
```

---

## 📋 Environment Variables to Add

```bash
# Auto-start contract scanner
AUTO_START_SCANNER=true

# Scanner chains (optional, defaults to ethereum, polygon, arbitrum)
SCANNER_CHAINS=ethereum,polygon,arbitrum
```

---

## ⚠️ Important Notes

1. **Database Connection**: Ensure `DATABASE_URL` is set correctly
2. **Redis Connection**: Events still use Redis bus (for real-time), but also saved to DB
3. **Performance**: Batch saving is more efficient than individual saves
4. **Idempotency**: Uses `ON CONFLICT DO NOTHING` to prevent duplicates

---

## 🎯 Expected Results After Fix

1. ✅ Events appear in log explorer within minutes
2. ✅ Contract scanner starts automatically
3. ✅ Database has event records
4. ✅ Log explorer shows real-time data
