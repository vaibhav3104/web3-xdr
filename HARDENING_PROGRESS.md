# Sentinel3 Hardening & Reliability Implementation Progress

## Overview

This document tracks the implementation of the comprehensive "Fix Everything" hardening requirements for Sentinel3. The work is organized into 6 phases as specified in the requirements.

---

## ✅ Phase 1: Foundation (IN PROGRESS)

### Completed Components

#### 1. Event Lifecycle Management (`src/models/events.py`)
- ✅ Added `EventStatus` enum (PENDING/CONFIRMED/DROPPED)
- ✅ Added `status`, `confirmed_at`, `block_hash`, `canonical_event_hash` fields to `SecurityEvent`
- ✅ Added `get_unique_key()` method for deduplication
- ✅ Enhanced serialization/deserialization

#### 2. Finality & Reorg Tracking (`src/telemetry/finality_tracker.py`)
- ✅ `FinalityTracker` class for per-chain finality tracking
- ✅ Chain-specific finality configs (Ethereum: 12 blocks, Polygon: 128, etc.)
- ✅ Reorg detection via parent hash verification
- ✅ Block window management with pruning
- ✅ `FinalityTrackerManager` for multi-chain coordination
- ✅ Status reporting and metrics

#### 3. Multi-RPC Client (`src/telemetry/rpc_client.py`)
- ✅ `MultiRpcProvider` with automatic failover
- ✅ Health scoring (HEALTHY/DEGRADED/UNHEALTHY)
- ✅ Endpoint rotation with round-robin
- ✅ Quorum verification for critical reads
- ✅ Exponential backoff for unhealthy endpoints
- ✅ Head lag tracking
- ✅ Comprehensive metrics and stats

#### 4. Event Bus (`src/pipeline/bus.py`)
- ✅ `EventBus` abstract interface
- ✅ `InMemoryBus` for development (with warnings)
- ✅ `RedisStreamsBus` for production
- ✅ Idempotency key support
- ✅ Backpressure handling (bounded queues)
- ✅ Drop policies (never/oldest/low_severity)
- ✅ Queue depth monitoring

#### 5. Database Schema Updates (`src/database/models.py`)
- ✅ Added `status`, `block_hash`, `canonical_event_hash`, `confirmed_at` to `EventModel`
- ✅ Added unique constraint on `(chain_id, tx_hash, log_index)`
- ✅ Updated `IncidentModel.status` to support OPEN_PENDING/OPEN_CONFIRMED/RESOLVED/FALSE_POSITIVE
- ✅ Added `explanation_json` JSONB field to `IncidentModel`
- ✅ Created `CorrelationKeyModel` for replay detection
- ✅ Enhanced indexes for finality tracking

#### 6. Bridge Adapter Interface (`src/bridges/adapters/base.py`)
- ✅ `BridgeAdapter` abstract base class
- ✅ `CorrelationKey` dataclass
- ✅ `BridgeEventSemantic` enum
- ✅ `ExpectedAmounts` dataclass
- ✅ Protocol identification and classification methods

---

## 🚧 Phase 2: Worker/API Split + Backpressure (TODO)

### Required Work

1. **Worker Entry Point** (`src/worker/main.py`)
   - [ ] Create standalone worker process
   - [ ] Initialize event bus
   - [ ] Start chain listeners
   - [ ] Process events from bus
   - [ ] Health endpoints

2. **API Server Updates** (`src/api/server.py`)
   - [ ] Remove listener initialization
   - [ ] Add worker status endpoint
   - [ ] Add queue depth endpoint

3. **Dockerfile Updates**
   - [ ] Support `PROC_TYPE` env var (api/worker)
   - [ ] Update CMD based on PROC_TYPE

4. **CI/CD Updates** (`.github/workflows/deploy.yml`)
   - [ ] Deploy two Cloud Run services (api + worker)
   - [ ] Use same image with different commands

5. **Backpressure Controls**
   - [ ] Lag alarms (processing head vs chain head)
   - [ ] Queue depth alerts
   - [ ] Rate limiting

6. **Metrics** (`src/metrics/collector.py`)
   - [ ] Queue depth metrics
   - [ ] Head lag metrics
   - [ ] RPC endpoint health metrics
   - [ ] Event processing rate

---

## 🚧 Phase 3: Bridge Adapters + Protocol-Specific Invariants (TODO)

### Required Work

1. **Concrete Bridge Adapters**
   - [ ] `src/bridges/adapters/wormhole.py`
   - [ ] `src/bridges/adapters/layerzero.py`
   - [ ] `src/bridges/adapters/stargate.py`
   - [ ] `src/bridges/adapters/across.py`
   - [ ] `src/bridges/adapters/hop.py`
   - [ ] `src/bridges/adapters/synapse.py`
   - [ ] `src/bridges/adapters/celer.py`

2. **Adapter Registry** (`src/bridges/registry.py`)
   - [ ] Auto-detect protocol from event
   - [ ] Route events to correct adapter

3. **Invariant Engine Refactor** (`src/invariants/engine.py`)
   - [ ] Protocol-aware invariant selection
   - [ ] Native unit support (no USD required)
   - [ ] Confidence calculation (finality + correlation + margin)
   - [ ] Tolerance per (protocol, route, token)

4. **Correlation Graph Updates** (`src/correlation/`)
   - [ ] Multi-hop path building
   - [ ] Entity graph with chain context
   - [ ] Aggregator/router support

---

## 🚧 Phase 4: Explainability + Incident Lifecycle (TODO)

### Required Work

1. **Event Confirmer** (`src/pipeline/confirmer.py`)
   - [ ] Background job to mark events CONFIRMED
   - [ ] Reorg handling (mark DROPPED)
   - [ ] Update incidents based on event status

2. **Explainability Engine** (`src/explainability/engine.py`)
   - [ ] Structured JSON explanations
   - [ ] Timeline table generation
   - [ ] Formula + evidence + confidence
   - [ ] Assumptions documentation
   - [ ] Recommended actions

3. **Incident Builder** (`src/correlation/incident_builder.py`)
   - [ ] Deduplication keys
   - [ ] Merge logic (update vs create)
   - [ ] Status transitions (OPEN_PENDING -> OPEN_CONFIRMED)
   - [ ] Confidence aggregation

---

## 🚧 Phase 5: Guardian Hardening + RBAC (TODO)

### Required Work

1. **Pause Policy** (`src/response/pause_policy.py`)
   - [ ] Require CONFIRMED incidents
   - [ ] Require confidence threshold
   - [ ] Require multiple signals
   - [ ] Per-protocol cooldown
   - [ ] Two-stage mode (recommend vs auto)

2. **Signer Abstraction** (`src/response/signers.py`)
   - [ ] `LocalPrivateKeySigner`
   - [ ] `ExternalSigner` interface (for KMS/HSM)

3. **RBAC** (`src/auth/rbac.py`)
   - [ ] Role enum (viewer/operator/admin)
   - [ ] JWT claims extension
   - [ ] Endpoint gating

4. **Audit Logging** (`src/database/audit.py`)
   - [ ] Log rule changes
   - [ ] Log parser changes
   - [ ] Log guardian actions
   - [ ] Log config changes

5. **Rule Safety** (`src/rules/validation.py`)
   - [ ] Pydantic schema validation
   - [ ] Dry-run endpoint
   - [ ] Versioning + rollback

---

## 🚧 Phase 6: Non-EVM Fixes + Polish (TODO)

### Required Work

1. **Non-EVM Listener Updates**
   - [ ] Remove fragile background threads
   - [ ] Use asyncio tasks in worker lifecycle
   - [ ] Resume from last confirmed block

2. **Config Schema Migration** (`config/chains.yaml`)
   - [ ] Add `rpc_urls` (list)
   - [ ] Add `finality.confirmations`
   - [ ] Add `finality.max_reorg_depth`
   - [ ] Add `ingestion` settings
   - [ ] Add `protocol_overrides`
   - [ ] Migration script for old `rpc_url`

3. **Documentation**
   - [ ] Migration guide
   - [ ] Deployment guide
   - [ ] Testing guide

---

## Testing Requirements

### Unit Tests
- [ ] Finality tracker reorg simulation
- [ ] RPC client failover
- [ ] Event bus idempotency
- [ ] Bridge adapter correlation key extraction
- [ ] Invariant evaluation with confidence

### Integration Tests
- [ ] End-to-end event flow (listener -> bus -> processor)
- [ ] Reorg handling (events marked DROPPED)
- [ ] Multi-hop correlation
- [ ] Liquidity bridge (no false positives)

### CI/CD
- [ ] Test suite runs in CI
- [ ] Docker builds succeed
- [ ] Deployment workflow updated

---

## Migration Guide

### Database Migration

1. **Run Alembic migration** (or manual SQL):
```sql
-- Add new columns to events table
ALTER TABLE events ADD COLUMN status VARCHAR(16) DEFAULT 'PENDING';
ALTER TABLE events ADD COLUMN block_hash VARCHAR(128);
ALTER TABLE events ADD COLUMN canonical_event_hash VARCHAR(128);
ALTER TABLE events ADD COLUMN confirmed_at TIMESTAMP WITH TIME ZONE;

-- Add unique constraint
CREATE UNIQUE INDEX ix_events_unique_key ON events(chain_id, tx_hash, log_index);

-- Update incidents status
ALTER TABLE incidents ALTER COLUMN status SET DEFAULT 'OPEN_PENDING';
ALTER TABLE incidents ADD COLUMN explanation_json JSONB;

-- Create correlation_keys table
CREATE TABLE correlation_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    protocol_id VARCHAR(64) NOT NULL,
    src_chain VARCHAR(32) NOT NULL,
    dst_chain VARCHAR(32),
    correlation_key VARCHAR(256) NOT NULL,
    source_event_id VARCHAR(128),
    dest_event_id VARCHAR(128),
    matched BOOLEAN DEFAULT FALSE,
    matched_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX ix_correlation_keys_unique ON correlation_keys(protocol_id, src_chain, dst_chain, correlation_key);
```

### Environment Variables

Add to `.env`:
```bash
# Event Bus
REDIS_URL=redis://localhost:6379  # Required for production

# Process Type
PROC_TYPE=api  # or "worker"

# Finality (optional, uses defaults)
ETHEREUM_FINALITY_CONFIRMATIONS=12
POLYGON_FINALITY_CONFIRMATIONS=128
```

### Config Migration

Update `config/chains.yaml`:
```yaml
chains:
  - chain_id: "ethereum"
    rpc_urls:  # NEW: list instead of single rpc_url
      - "https://eth.llamarpc.com"
      - "https://rpc.ankr.com/eth"
    finality:  # NEW
      confirmations: 12
      max_reorg_depth: 12
    ingestion:  # NEW
      start_block: null  # null = from head
      max_blocks_per_poll: 1000
      poll_interval_ms: 2000
    protocol_overrides:  # NEW
      wormhole:
        tolerance_bps: 50  # 0.5%
        max_latency_seconds: 300
```

---

## Deployment

### Local Development

```bash
# Start all services
docker-compose up -d

# Start API
PROC_TYPE=api python -m src.api.server

# Start Worker (in separate terminal)
PROC_TYPE=worker python -m src.worker.main
```

### Production (GCP Cloud Run)

```bash
# Build image
docker build -t gcr.io/PROJECT_ID/sentinel3:latest .

# Push to registry
docker push gcr.io/PROJECT_ID/sentinel3:latest

# Deploy API service
gcloud run deploy sentinel3-api \
  --image gcr.io/PROJECT_ID/sentinel3:latest \
  --set-env-vars PROC_TYPE=api,REDIS_URL=... \
  --platform managed

# Deploy Worker service
gcloud run deploy sentinel3-worker \
  --image gcr.io/PROJECT_ID/sentinel3:latest \
  --set-env-vars PROC_TYPE=worker,REDIS_URL=... \
  --platform managed \
  --cpu 2 \
  --memory 2Gi
```

---

## Known Limitations & Next Steps

### Current Limitations

1. **Bridge Adapters**: Only interface defined, concrete implementations needed
2. **Worker Process**: Not yet separated from API
3. **Event Confirmer**: Background job not implemented
4. **Explainability**: Structured explanations not generated
5. **Guardian**: Pause policy not hardened

### Immediate Next Steps

1. **Complete Phase 2**: Worker/API split
2. **Implement Wormhole Adapter**: First concrete adapter
3. **Add Event Confirmer**: Mark events CONFIRMED
4. **Update Invariant Engine**: Protocol-aware selection

---

## Summary

**Phase 1 (Foundation)**: ~60% complete
- ✅ Event lifecycle
- ✅ Finality tracking
- ✅ Multi-RPC client
- ✅ Event bus
- ✅ Database schema
- ✅ Bridge adapter interface

**Remaining Phases**: 0% complete (interfaces defined, implementations needed)

**Estimated Time to Complete**: 3-5 days of focused development

---

## Questions & Support

For questions about the implementation, see:
- `docs/ARCHITECTURE.md` - System architecture
- `docs/BLUEPRINT.md` - Detailed design
- `SENTINEL3_PROMPT.md` - Original requirements

