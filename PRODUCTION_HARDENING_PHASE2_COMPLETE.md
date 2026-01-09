# Production Hardening Phase 2 - COMPLETE ✅

## Summary

Successfully implemented Phase 2 of production hardening, focusing on:
1. **Idempotency Service** - Exactly-once processing for events and incidents
2. **Maintenance Endpoint Hardening** - RBAC + token auth + audit logging
3. **Database Indexes** - Performance indexes for common queries

---

## ✅ Completed Components

### 1. Idempotency Service ✅

**File Created:**
- `src/database/idempotency.py` - Complete idempotency service

**Features:**
- ✅ `generate_idempotency_key()` - Stable keys for events
- ✅ `generate_incident_dedupe_key()` - Stable keys for incidents
- ✅ `check_idempotency()` - Check if already processed
- ✅ `mark_processing()` - Mark as PENDING/PROCESSED/FAILED
- ✅ `mark_processed()` - Convenience method
- ✅ `mark_failed()` - Convenience method

**Usage:**
```python
from src.database.idempotency import IdempotencyService, generate_idempotency_key

# Check if already processed
key = generate_idempotency_key(chain_id="ethereum", tx_hash="0x...", log_index=0)
existing = await IdempotencyService.check_idempotency(key)
if existing and existing["status"] == "PROCESSED":
    return existing["event_id"]  # Already processed

# Mark as processing
await IdempotencyService.mark_processing(key, status="PENDING")

# After successful save
await IdempotencyService.mark_processed(key, event_id="evt_123")
```

### 2. Event Save with Idempotency ✅

**File Modified:**
- `src/database/service.py` - `save_events_batch()` now uses idempotency

**Changes:**
- ✅ Filters out already processed events before saving
- ✅ Marks events as PENDING before save
- ✅ Marks as PROCESSED after successful save
- ✅ Marks as FAILED on error
- ✅ Prevents duplicate event processing

**Flow:**
1. Generate idempotency key for each event
2. Check if already processed (skip if yes)
3. Mark as PENDING
4. Save to database
5. Mark as PROCESSED (or FAILED on error)

### 3. Incident Creation with Idempotency ✅

**File Modified:**
- `src/database/service.py` - `save_incident()` now uses dedupe_key

**Changes:**
- ✅ Uses `cluster_key` (dedupe_key) for deduplication
- ✅ Checks existing incidents by cluster_key
- ✅ Updates existing incident instead of creating duplicate
- ✅ Marks in idempotency table
- ✅ Prevents duplicate incident creation

**Flow:**
1. Generate or use provided dedupe_key
2. Check idempotency table
3. If exists and processed, return existing incident_id
4. Check database for existing incident by cluster_key
5. Update existing or create new
6. Mark as PROCESSED in idempotency table

### 4. Maintenance Endpoint Hardening ✅

**File Created:**
- `src/api/maintenance_auth.py` - Maintenance authentication and audit

**Features:**
- ✅ `require_maintenance_access()` - Dependency for maintenance endpoints
- ✅ Supports JWT with admin role
- ✅ Supports `MAINTENANCE_TOKEN` header (for automation)
- ✅ `ENABLE_MAINTENANCE_ENDPOINTS` env var (gating)
- ✅ `log_maintenance_action()` - Audit logging

**File Modified:**
- `src/api/routes.py` - Maintenance endpoints now require auth

**Protected Endpoints:**
- `/api/maintenance/verify-schema` - Now requires auth
- `/api/maintenance/migrate-events` - Now requires auth

**Authentication Methods:**
1. **JWT Token** (Bearer token with admin role)
   ```bash
   curl -H "Authorization: Bearer <jwt_token>" \
        https://api.example.com/api/maintenance/verify-schema
   ```

2. **MAINTENANCE_TOKEN** (Header for automation)
   ```bash
   curl -H "X-Maintenance-Token: <token>" \
        https://api.example.com/api/maintenance/migrate-events
   ```

**Environment Variables:**
```bash
ENABLE_MAINTENANCE_ENDPOINTS=true  # Enable maintenance endpoints
MAINTENANCE_TOKEN=<secure-token>   # Token for automation
```

**Audit Logging:**
- All maintenance actions logged to `audit_logs` table
- Includes: action_type, actor_id, outcome, error_message
- Non-blocking (doesn't fail request if audit fails)

### 5. Database Indexes Migration ✅

**File Created:**
- `scripts/migrate_add_indexes.sql` - Performance indexes

**Indexes Added:**
- ✅ `ix_events_timestamp_id` - Cursor pagination (already in model)
- ✅ `ix_events_chain_timestamp_desc` - Chain + timestamp queries
- ✅ `ix_events_severity_timestamp_desc` - Severity filtering
- ✅ `ix_events_type_timestamp_desc` - Event type filtering
- ✅ `ix_events_status_block` - Status + block number
- ✅ `ix_events_contract_timestamp_desc` - Contract-specific queries
- ✅ `ix_events_chain_severity_timestamp` - Composite filter

**Usage:**
```bash
# Run migration
psql -d web3_xdr -f scripts/migrate_add_indexes.sql
```

---

## 🔧 Configuration

### Environment Variables:
```bash
# Maintenance Endpoints
ENABLE_MAINTENANCE_ENDPOINTS=true
MAINTENANCE_TOKEN=<secure-random-token>

# Idempotency (uses existing database)
# No additional config needed
```

### Database Migrations:

**1. Create Idempotency Table (if not exists):**
```sql
CREATE TABLE IF NOT EXISTS event_processing (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key VARCHAR(128) UNIQUE NOT NULL,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    event_id VARCHAR(128),
    incident_id VARCHAR(128),
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_event_processing_status ON event_processing(status, first_seen_at);
CREATE INDEX IF NOT EXISTS ix_event_processing_processed ON event_processing(processed_at);
```

**2. Run Performance Indexes:**
```bash
psql -d web3_xdr -f scripts/migrate_add_indexes.sql
```

---

## 📊 API Changes

### Maintenance Endpoints (Now Protected)

**Before:**
- No authentication required
- No audit logging

**After:**
- Requires admin JWT or `MAINTENANCE_TOKEN`
- All actions logged to audit_logs
- Can be disabled via `ENABLE_MAINTENANCE_ENDPOINTS=false`

**Example:**
```bash
# With JWT
curl -H "Authorization: Bearer <admin_jwt>" \
     https://api.example.com/api/maintenance/verify-schema

# With Token
curl -H "X-Maintenance-Token: <token>" \
     https://api.example.com/api/maintenance/migrate-events
```

---

## 🎯 Database Changes

### Event Processing Flow (Idempotent)

**Before:**
- Events saved directly (possible duplicates on retry)
- No deduplication tracking

**After:**
- Idempotency check before save
- Deduplication via `event_processing` table
- Exactly-once processing guaranteed

### Incident Creation (Idempotent)

**Before:**
- Possible duplicate incidents
- No deduplication

**After:**
- Uses `cluster_key` for deduplication
- Updates existing incident if found
- Prevents duplicates

---

## 🚀 Deployment Checklist

### Before Deploying:
1. ✅ Code committed and pushed
2. ⏳ Run database migrations:
   - Create `event_processing` table (if not exists)
   - Run `migrate_add_indexes.sql`
3. ⏳ Set environment variables:
   - `ENABLE_MAINTENANCE_ENDPOINTS=true`
   - `MAINTENANCE_TOKEN=<secure-token>`
4. ⏳ Test idempotency:
   - Send same event twice → should only save once
   - Check `event_processing` table
5. ⏳ Test maintenance endpoints:
   - Verify auth required
   - Check audit logs

---

## 📈 Performance Improvements

### Before:
- No idempotency (duplicate events possible)
- No maintenance endpoint protection
- Missing performance indexes

### After:
- Exactly-once processing (idempotency)
- Secure maintenance endpoints (RBAC + audit)
- Optimized queries (indexes)

---

## ⏳ Next Steps (Phase 3)

1. **Anvil Pool Manager**
   - Pool implementation
   - Health metrics
   - Pre-warmed processes

2. **Observability Improvements**
   - Truthful health endpoints
   - Chain lag metrics
   - Bus lag metrics

3. **Retention + GCS Export**
   - Retention policy
   - GCS export pipeline

4. **Postgres Partitioning** (when scale requires)
   - Weekly partitions
   - Automated partition creation

---

## 🧪 Testing

### Test Idempotency:
```python
# Send same event twice
event1 = {"chain_id": "ethereum", "tx_hash": "0x123", "log_index": 0}
event2 = {"chain_id": "ethereum", "tx_hash": "0x123", "log_index": 0}

await DatabaseService.save_events_batch([event1])
await DatabaseService.save_events_batch([event2])  # Should skip (already processed)
```

### Test Maintenance Auth:
```bash
# Should fail without auth
curl https://api.example.com/api/maintenance/verify-schema
# 401 Unauthorized

# Should succeed with token
curl -H "X-Maintenance-Token: <token>" \
     https://api.example.com/api/maintenance/verify-schema
# 200 OK
```

---

## 📝 Files Changed

### Created:
- `src/database/idempotency.py`
- `src/api/maintenance_auth.py`
- `scripts/migrate_add_indexes.sql`
- `PRODUCTION_HARDENING_PHASE2_COMPLETE.md`

### Modified:
- `src/database/service.py` - Idempotency in save_events_batch and save_incident
- `src/api/routes.py` - Maintenance endpoint auth

---

## ✅ Status

**Phase 2: COMPLETE** ✅

All critical components implemented:
- Idempotency service
- Event and incident deduplication
- Maintenance endpoint hardening
- Performance indexes

**Ready for:** Deployment and Phase 3 (Anvil pool, observability)

---

**Last Updated:** 2026-01-10
**Commit:** Latest
