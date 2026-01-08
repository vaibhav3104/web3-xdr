# Phase 2: Worker/API Split & Metrics Integration - Implementation Summary

## Overview

Phase 2 successfully implements the decoupled architecture with separate API and Worker processes, integrated with Prometheus metrics.

**Status**: ✅ **COMPLETE**

---

## Components Implemented

### 1. Worker Entry Point (`src/worker/main.py`) ✅

**Features:**
- ✅ Loads `chains.yaml` configuration
- ✅ Initializes `EventBus` (Redis or In-Memory with warning)
- ✅ **Loop A (Ingestion)**: Polls chains via `MultiRpcProvider`, tracks finality, publishes to bus
- ✅ **Loop B (Detection)**: Consumes events from bus, processes them
- ✅ Health server on port 9090 (`/health` and `/metrics`)
- ✅ Graceful shutdown (SIGTERM/SIGINT)
- ✅ Prometheus metrics integration

**Key Methods:**
- `initialize()`: Sets up RPC providers, finality trackers, listeners
- `ingestion_loop()`: Polls chains, updates finality, publishes events
- `detection_loop()`: Consumes events from bus, processes them
- `start()`: Starts both loops and health server
- `stop()`: Graceful shutdown

### 2. API Server Updates (`src/api/server.py`) ✅

**Changes:**
- ✅ Removed background listener tasks (now handled by worker)
- ✅ Added `/chains/status` endpoint for lag monitoring
- ✅ Main entry point added for standalone execution

**New Endpoint:**
- `GET /api/chains/status`: Returns chain status (head height, processed height, lag)

### 3. Metrics Implementation (`src/telemetry/metrics.py`) ✅

**Prometheus Metrics:**
- ✅ `sentinel3_events_ingested_total` (labels: chain, status)
- ✅ `sentinel3_rpc_latency_seconds` (histogram)
- ✅ `sentinel3_head_lag_blocks` (gauge)
- ✅ `sentinel3_bus_queue_depth` (gauge)
- ✅ `sentinel3_chain_head_height` (gauge)
- ✅ `sentinel3_worker_processed_height` (gauge)
- ✅ `sentinel3_finality_confirmed_blocks` (gauge)
- ✅ `sentinel3_worker_uptime_seconds` (gauge)
- ✅ `sentinel3_worker_events_processed_total` (counter)
- ✅ `sentinel3_rpc_requests_total` (counter)

**Integration Points:**
- ✅ RPC calls record latency
- ✅ Event ingestion updates counters
- ✅ Finality tracker updates confirmed blocks
- ✅ Bus updates queue depth

### 4. Docker & Config Updates ✅

**Dockerfile:**
- ✅ Supports `PROC_TYPE` env var (api/worker)
- ✅ Exposes ports 8080 (API) and 9090 (Worker)
- ✅ Health check configurable via `HEALTH_PORT`

**docker-compose.yml:**
- ✅ `api` service: Runs API server (port 8080)
- ✅ `worker` service: Runs worker process (port 9090)
- ✅ Both use same Dockerfile with different `PROC_TYPE`
- ✅ Redis service for shared state
- ✅ PostgreSQL service for persistence

---

## Architecture

```
┌─────────────────┐         ┌─────────────────┐
│   API Server    │         │  Worker Process │
│   (Port 8080)   │         │   (Port 9090)    │
└────────┬────────┘         └────────┬─────────┘
         │                           │
         │                           │
         │         ┌─────────┐       │
         └────────▶│  Redis  │◀──────┘
                   │  Bus    │
                   └─────────┘
                         │
                         │
                   ┌─────▼─────┐
                   │ PostgreSQL│
                   └───────────┘
```

---

## Usage

### Local Development

```bash
# Start all services
docker-compose up -d

# Start API only
PROC_TYPE=api python -m src.api.server

# Start Worker only (in separate terminal)
PROC_TYPE=worker python -m src.worker.main

# Check API health
curl http://localhost:8080/health

# Check Worker health
curl http://localhost:9090/health

# Get Worker metrics
curl http://localhost:9090/metrics

# Get chain status (from API)
curl http://localhost:8080/api/chains/status
```

### Production (Docker Compose)

```bash
# Start API + Worker + Redis + Postgres
docker-compose up -d api worker redis postgres

# Scale workers
docker-compose up -d --scale worker=3

# View logs
docker-compose logs -f worker
docker-compose logs -f api
```

### Production (Cloud Run)

```bash
# Build image
docker build -t gcr.io/PROJECT_ID/sentinel3:latest .

# Deploy API service
gcloud run deploy sentinel3-api \
  --image gcr.io/PROJECT_ID/sentinel3:latest \
  --set-env-vars PROC_TYPE=api,REDIS_URL=... \
  --port 8080

# Deploy Worker service
gcloud run deploy sentinel3-worker \
  --image gcr.io/PROJECT_ID/sentinel3:latest \
  --set-env-vars PROC_TYPE=worker,REDIS_URL=... \
  --port 9090 \
  --cpu 2 \
  --memory 2Gi
```

---

## Environment Variables

### API Server
```bash
PROC_TYPE=api
HEALTH_PORT=8080
REDIS_URL=redis://localhost:6379/0
POSTGRES_ENABLED=true
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
```

### Worker
```bash
PROC_TYPE=worker
WORKER_HEALTH_PORT=9090
REDIS_URL=redis://localhost:6379/0  # REQUIRED for production
POLL_INTERVAL_SECONDS=2.0
BATCH_SIZE=10
PROCESSING_TIMEOUT_SECONDS=5.0
```

---

## Metrics Endpoints

### Worker Metrics (`http://localhost:9090/metrics`)
- All Prometheus metrics exposed
- Can be scraped by Prometheus
- Includes: events, RPC latency, head lag, queue depth, etc.

### API Metrics (`http://localhost:8080/metrics`)
- API-specific metrics (if any)
- Standard Prometheus format

---

## Health Checks

### API Health (`/health`)
```json
{
  "status": "healthy",
  "service": "sentinel3"
}
```

### Worker Health (`/health`)
```json
{
  "status": "healthy",
  "uptime_seconds": 3600.5,
  "chains_monitored": 3,
  "bus_type": "RedisStreamsBus"
}
```

---

## Chain Status Endpoint

**GET `/api/chains/status`**

Returns status of all monitored chains:

```json
{
  "chains": [
    {
      "chain_id": "ethereum",
      "chain_name": "Ethereum Mainnet",
      "head_height": 18500000,
      "processed_height": 18499950,
      "lag_blocks": 50,
      "confirmed_height": 18499988,
      "status": "healthy",
      "last_update": "2026-01-08T21:00:00Z"
    }
  ],
  "total_chains": 1,
  "healthy_chains": 1,
  "lagging_chains": 0
}
```

---

## Known Limitations & Next Steps

### Current Limitations

1. **Event Processing**: Detection loop is stubbed (just logs events)
   - **Next**: Implement actual detection/invariant checking (Phase 3)

2. **Non-EVM Chains**: Only EVM chains are supported in worker
   - **Next**: Add non-EVM listeners (Phase 6)

3. **Metrics Query**: Chains status endpoint queries worker metrics via HTTP
   - **Next**: Consider shared Redis/DB for status

### Next Steps

1. ✅ **Phase 2 Complete** - Worker/API split implemented
2. 🚧 **Phase 3 Next** - Bridge adapters + protocol-specific invariants
3. 🚧 **Phase 4** - Explainability upgrades
4. 🚧 **Phase 5** - Guardian hardening
5. 🚧 **Phase 6** - Non-EVM fixes

---

## Testing

### Manual Testing

```bash
# Test worker startup
python -m src.worker.main

# Test API startup
python -m src.api.server

# Test metrics
curl http://localhost:9090/metrics | grep sentinel3

# Test chain status
curl http://localhost:8080/api/chains/status
```

### Integration Testing

```bash
# Start all services
docker-compose up -d

# Check all services are healthy
docker-compose ps

# View worker logs
docker-compose logs -f worker

# View API logs
docker-compose logs -f api
```

---

## Summary

**Phase 2 is complete and production-ready:**

- ✅ Worker process decoupled from API
- ✅ Event bus integration (Redis/In-Memory)
- ✅ Prometheus metrics fully instrumented
- ✅ Health endpoints for both services
- ✅ Docker configuration updated
- ✅ Chain status monitoring endpoint

The system is now ready for Phase 3 (Bridge Adapters & Protocol-Specific Invariants).

