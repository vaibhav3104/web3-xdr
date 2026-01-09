# Production Hardening Implementation Plan

## Status: In Progress

This document tracks the implementation of production-grade improvements for Sentinel3.

## Completed ✅

1. **Redis Streams Bus Enhancement**
   - ✅ Created `src/runtime/bus/base.py` with `EventBus` interface
   - ✅ Enhanced `src/runtime/bus/redis_streams.py` with:
     - Consumer groups support
     - Dead letter queue (DLQ)
     - Pending message recovery (XCLAIM)
     - Metrics tracking
   - ✅ Added `BusMessageEnvelope` for ack/nack support

2. **Idempotency Table**
   - ✅ Added `EventProcessingModel` to `src/database/models.py`
   - ✅ Tracks idempotency keys, processing status, retry count

## In Progress 🔄

3. **Cursor Pagination for /api/events**
   - 🔄 Implementing cursor-based pagination in `DatabaseService.get_events()`
   - 🔄 Updating API route to support cursor parameter
   - 🔄 Frontend update to use server-side filtering

4. **Database Indexes**
   - 🔄 Adding indexes for cursor pagination: `(block_timestamp DESC, id DESC)`
   - 🔄 Additional indexes for common queries

## Pending ⏳

5. **Postgres Partitioning**
   - Migration plan for time-series partitioning
   - Automated partition creation

6. **Maintenance Endpoint Hardening**
   - RBAC + token authentication
   - Audit logging
   - CLI migration tools

7. **Anvil Pool Manager**
   - Pool implementation with health metrics
   - Reuse and lifecycle management

8. **Cloud Run Role Clarity**
   - API serves frontend only
   - Worker only processing

9. **Retention + GCS Export**
   - Retention policy implementation
   - GCS export pipeline

10. **Observability**
    - Truthful health endpoints
    - Lag metrics
    - Bus backlog monitoring

---

## Implementation Notes

### Redis Streams Bus
- Uses consumer groups for distributed processing
- DLQ for poison messages
- Automatic pending message recovery every 5 minutes
- Metrics: publish_total, consume_total, ack_total, dlq_total, pending_count

### Idempotency
- `event_processing` table tracks all processing attempts
- Prevents duplicate event/incident creation
- Supports retry tracking

### Cursor Pagination
- Cursor encodes: `(block_timestamp, id)`
- SQL: `WHERE (block_timestamp, id) < (:cursor_ts, :cursor_id)`
- No OFFSET for large tables (better performance)

---

## Next Steps

1. Complete cursor pagination implementation
2. Update frontend to use server-side filtering
3. Add database indexes
4. Create partitioning migration script
5. Harden maintenance endpoints
6. Implement Anvil pool
7. Add retention/export
8. Improve observability
