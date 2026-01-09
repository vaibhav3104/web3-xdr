# Web3 XDR (Sentinel3) - Comprehensive System Blueprint

## 🎯 System Overview

**Web3 XDR (Sentinel3)** is a cross-chain bridge attack detection and runtime security platform that monitors blockchain events in real-time, detects anomalies, and provides explainable threat intelligence. The system is built as a microservices architecture deployed on Google Cloud Run with PostgreSQL (Cloud SQL) for persistence and Redis (Memorystore) for event bus/pub-sub.

### Core Mission
- **Real-time monitoring** of cross-chain bridge transactions
- **0-block detection** using bloXroute mempool integration
- **Runtime security** with economic invariant detection
- **Explainable AI** for threat analysis and incident response
- **Multi-chain support** (Ethereum, Polygon, Arbitrum, Optimism, Base, Solana)

---

## 🏗️ Architecture Layers

### Layer 1: Telemetry Collection
**Purpose**: Collect raw blockchain events from multiple chains

**Components**:
- `src/telemetry/` - Chain-specific telemetry collectors
  - `evm_listener.py` - EVM chain event listener (logs, transactions)
  - `solana_listener.py` - Solana transaction listener
  - `multi_rpc_provider.py` - RPC failover and load balancing
  - `finality_tracker.py` - Block finality tracking per chain

**Data Flow**:
1. Worker initializes RPC providers for each configured chain
2. `EVMListener` polls for new blocks/logs via `get_logs` RPC
3. Events are normalized to `SecurityEvent` objects
4. Events are published to Redis event bus OR saved directly to PostgreSQL (fallback)

**Key Files**:
- `src/worker/main.py` - Main worker orchestrator (`Sentinel3Worker`)
- `src/telemetry/evm_listener.py` - EVM chain event collection
- `config/chains.yaml` - Chain configurations (RPC URLs, finality settings)

---

### Layer 2: Normalization & Event Bus
**Purpose**: Normalize events across chains and distribute via pub/sub

**Components**:
- `src/runtime/pubsub.py` - Redis Pub/Sub event bus
- `src/database/service.py` - PostgreSQL persistence layer
- `src/shared_state.py` - Unified state manager (Memory/Redis/PostgreSQL)

**Data Flow**:
1. Raw events from Layer 1 → Normalized `SecurityEvent` objects
2. Events published to Redis Streams/Channels (if Redis available)
3. **Fallback**: If Redis fails, events saved directly to PostgreSQL
4. Events stored with schema: `event_id`, `chain_id`, `tx_hash`, `block_number`, `block_timestamp`, `event_type`, `severity`, `raw_data` (JSONB)

**Key Files**:
- `src/database/service.py` - `DatabaseService.save_events_batch()` - Batch event persistence
- `src/database/sync_service.py` - Synchronous PostgreSQL operations (psycopg2 fallback)
- `src/database/models.py` - SQLAlchemy ORM models (`EventModel`, `IncidentModel`)

**Database Schema** (PostgreSQL):
```sql
events (
    id UUID PRIMARY KEY,
    event_id VARCHAR(128) UNIQUE,
    chain_id VARCHAR(32),
    event_type VARCHAR(64),
    tx_hash VARCHAR(128),
    block_number BIGINT,
    block_timestamp TIMESTAMP WITH TIME ZONE,
    contract_address VARCHAR(128),
    severity VARCHAR(16),
    amount DECIMAL,
    amount_usd DECIMAL,
    from_address VARCHAR(128),
    to_address VARCHAR(128),
    raw_data JSONB,
    status VARCHAR(16) DEFAULT 'PENDING',
    block_hash VARCHAR(128),
    canonical_event_hash VARCHAR(128),
    confirmed_at TIMESTAMP WITH TIME ZONE,
    log_index INTEGER,
    topics VARCHAR(128)[],
    asset_type VARCHAR(32),
    asset_address VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
)
```

---

### Layer 3: Detection & Analysis
**Purpose**: Detect anomalies, violations, and threats

**Components**:
- `src/detection/` - Threat detection engine
- `src/invariants/` - Economic invariant validators
- `src/runtime/` - Runtime security plane
  - `engine.py` - `RuntimeEngine` - Main detection orchestrator
  - `intent_sources/` - Intent sources (bloXroute mempool, RPC)
  - `simulator.py` - `AnvilSimulator` - Transaction simulation
  - `invariant_engine.py` - Invariant evaluation

**Data Flow**:
1. Events from Layer 2 → `RuntimeEngine`
2. `RuntimeEngine` evaluates economic invariants (e.g., balance conservation, slippage limits)
3. Violations trigger `Incident` creation
4. Incidents stored in PostgreSQL `incidents` table
5. Alerts published to notification channels

**Key Files**:
- `src/runtime/engine.py` - `RuntimeEngine` class
- `src/invariants/` - Invariant validators (balance, slippage, etc.)
- `src/runtime/intent_sources/bloxroute_source.py` - bloXroute mempool integration

---

### Layer 4: Correlation & XDR
**Purpose**: Cross-chain correlation and threat intelligence

**Components**:
- `src/correlation/` - XDR correlation engine
- `src/ai/` - AI/ML models for threat classification
- `src/explainability/` - Explainable AI for incident analysis

**Data Flow**:
1. Incidents from Layer 3 → Correlation engine
2. Cross-chain pattern matching (e.g., same attacker across chains)
3. ML models classify threat severity
4. Explainability engine generates human-readable reports

**Key Files**:
- `src/correlation/` - Correlation algorithms
- `src/ai/models/` - ML models (bytecode analysis, threat classification)

---

### Layer 5: API & Frontend
**Purpose**: Expose data via REST API and web UI

**Components**:
- `src/api/` - FastAPI REST API
  - `server.py` - FastAPI app initialization
  - `routes.py` - API endpoints
- `frontend/` - Static HTML/CSS/JS frontend
  - `logs.html` - Log Explorer (main UI)
  - `dashboard.html`, `analytics.html`, etc.

**API Endpoints**:
- `GET /api/events` - List events (supports filtering, pagination, Lucene queries)
- `GET /api/incidents` - List incidents
- `GET /api/health` - Health check
- `GET /api/metrics` - Prometheus metrics
- `POST /api/maintenance/migrate-events` - Database schema migration

**Data Flow**:
1. Frontend requests events via `/api/events?limit=1000`
2. API queries PostgreSQL using `DatabaseService.get_events()`
3. Events returned as JSON with `total`, `returned`, `events[]`
4. Frontend applies client-side filtering (time range, chain, severity)
5. Events rendered in HTML table with pagination

**Key Files**:
- `src/api/routes.py` - API endpoint definitions
- `frontend/logs.html` - Log Explorer UI (vanilla JS, no framework)
- `src/database/service.py` - `DatabaseService.get_events()` - Event retrieval

---

## 🔄 End-to-End Data Flow

### Event Ingestion Flow
```
Blockchain (Ethereum/Polygon/etc.)
    ↓
RPC Provider (MultiRpcProvider with failover)
    ↓
EVMListener.get_logs() → SecurityEvent objects
    ↓
Worker.ingestion_loop() → EventBus.publish() OR DatabaseService.save_events_batch()
    ↓
Redis Streams/Channels (if available) OR PostgreSQL (fallback)
    ↓
Events stored in `events` table
```

### Event Retrieval Flow
```
Frontend (logs.html)
    ↓
fetch('/api/events?limit=1000')
    ↓
API Server (FastAPI)
    ↓
DatabaseService.get_events() → Raw SQL query
    ↓
PostgreSQL → Returns event rows
    ↓
API formats events as JSON
    ↓
Frontend receives events → Client-side filtering → renderTable()
    ↓
Events displayed in HTML table
```

### Detection Flow
```
Events from ingestion
    ↓
RuntimeEngine.evaluate_intent()
    ↓
AnvilSimulator.simulate() → State diff extraction
    ↓
InvariantEngine.evaluate() → Violation detection
    ↓
Incident creation → Stored in `incidents` table
    ↓
Alerts/Notifications
```

---

## 🗂️ Key Directory Structure

```
web3-xdr/
├── src/
│   ├── worker/
│   │   └── main.py              # Main worker orchestrator (ingestion loop, detection loop)
│   ├── api/
│   │   ├── server.py            # FastAPI app initialization
│   │   └── routes.py             # API endpoints (events, incidents, health)
│   ├── telemetry/
│   │   ├── evm_listener.py      # EVM chain event listener
│   │   ├── multi_rpc_provider.py # RPC failover/load balancing
│   │   └── finality_tracker.py   # Block finality tracking
│   ├── database/
│   │   ├── connection.py        # DatabaseManager (async SQLAlchemy)
│   │   ├── service.py           # DatabaseService (async operations)
│   │   ├── sync_service.py      # Synchronous operations (psycopg2 fallback)
│   │   └── models.py             # SQLAlchemy ORM models
│   ├── runtime/
│   │   ├── engine.py            # RuntimeEngine (detection orchestrator)
│   │   ├── simulator.py         # AnvilSimulator (transaction simulation)
│   │   ├── invariant_engine.py # Invariant evaluation
│   │   ├── pubsub.py            # Redis Pub/Sub event bus
│   │   └── intent_sources/
│   │       └── bloxroute_source.py # bloXroute mempool integration
│   ├── detection/               # Threat detection
│   ├── correlation/             # XDR correlation
│   ├── ai/                      # ML models and AI
│   ├── invariants/              # Economic invariant validators
│   └── shared_state.py          # Unified state manager
├── frontend/
│   ├── logs.html                # Log Explorer (main UI)
│   ├── dashboard.html           # Dashboard
│   └── *.html                   # Other static pages
├── config/
│   ├── chains.yaml              # Chain configurations
│   └── parsers.yaml             # Event parser configurations
├── deploy/
│   ├── aws/                      # AWS deployment configs
│   ├── gcp/                      # GCP deployment configs
│   └── kubernetes/              # K8s manifests
└── .github/workflows/
    └── deploy.yml                # GitHub Actions CI/CD
```

---

## 🔧 Key Technologies & Patterns

### Backend
- **Python 3.11** - Main language
- **FastAPI** - API framework
- **SQLAlchemy** (async) - ORM for PostgreSQL
- **psycopg2** - Synchronous PostgreSQL driver (fallback)
- **asyncpg** - Async PostgreSQL driver
- **Redis** (redis-py) - Event bus/pub-sub
- **aiohttp** - Async HTTP client/server
- **structlog** - Structured logging
- **web3.py** - Ethereum/EVN interaction
- **Anvil** (via subprocess) - Transaction simulation

### Frontend
- **Vanilla JavaScript** - No frameworks
- **HTML5/CSS3** - Static pages
- **Fetch API** - HTTP requests
- **Client-side filtering** - Time range, chain, severity filters

### Infrastructure
- **Google Cloud Run** - Serverless containers
- **Cloud SQL (PostgreSQL)** - Database
- **Memorystore (Redis)** - Event bus
- **VPC Connector** - Private network access
- **GitHub Actions** - CI/CD

### Patterns
- **Microservices** - Separate API and Worker services
- **Event-driven** - Redis Pub/Sub for event distribution
- **Fallback mechanisms** - Direct DB save if Redis fails
- **RPC failover** - MultiRpcProvider with health checks
- **Async/await** - Asynchronous I/O throughout
- **Dependency injection** - DatabaseManager, EventBus singletons

---

## 📊 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://user:pass@host/db

# Redis
REDIS_URL=redis://host:port

# RPC Providers
INFURA_API_KEY=...
ALCHEMY_API_KEY=...

# Runtime Security
RUNTIME_ENABLED=true
AUTO_START_SCANNER=true

# Service Type
PROC_TYPE=worker  # or 'api'
PORT=9090  # Worker port (API uses 8080)
```

### Chain Configuration (`config/chains.yaml`)
```yaml
chains:
  - chain_id: ethereum
    chain_name: Ethereum
    chain_type: evm
    rpc_urls:
      - https://eth-mainnet.g.alchemy.com/v2/KEY
    finality:
      confirmations: 12
      block_time_seconds: 12.0
```

---

## 🚀 Deployment Architecture

### Services
1. **web3-xdr-production-api** (Cloud Run)
   - Port: 8080
   - Handles API requests
   - Connects to Cloud SQL and Redis

2. **web3-xdr-production-worker** (Cloud Run)
   - Port: 9090
   - Runs ingestion and detection loops
   - Connects to Cloud SQL and Redis
   - Serves static frontend files

### Infrastructure
- **Cloud SQL (PostgreSQL)** - Private IP, accessed via VPC Connector
- **Memorystore (Redis)** - Private IP, accessed via VPC Connector
- **VPC Connector** (`sentinel3-connector`) - Enables Cloud Run → Private network access

### CI/CD
- **GitHub Actions** (`.github/workflows/deploy.yml`)
  - Builds Docker image
  - Pushes to GCP Artifact Registry
  - Deploys to Cloud Run (staging → production)
  - Retry logic for deployment conflicts

---

## 🔍 Critical Code Paths

### Event Ingestion (Worker)
```python
# src/worker/main.py
class Sentinel3Worker:
    async def ingestion_loop(self):
        # 1. Get latest block for each chain
        # 2. Fetch logs via RPC: rpc_provider.get_logs(from_block, to_block)
        # 3. Convert logs to SecurityEvent objects
        # 4. Try Redis publish, fallback to direct DB save
        # 5. Update processed block checkpoint
```

### Event Persistence
```python
# src/database/service.py
async def save_events_batch(events):
    # Uses asyncio.to_thread to call sync_service.save_events_batch_sync()
    # sync_service uses psycopg2 for reliable batch inserts
    # Handles schema mismatches gracefully (legacy-compatible inserts)
```

### Event Retrieval
```python
# src/api/routes.py
@router.get("/api/events")
async def list_events():
    # 1. Get total count: DatabaseService.get_events_count()
    # 2. Fetch events: DatabaseService.get_events(limit=2000)
    # 3. Format events as JSON
    # 4. Return: {"total": count, "returned": len(events), "events": [...]}
```

### Frontend Filtering
```javascript
// frontend/logs.html
async function loadEvents() {
    // 1. Fetch from API: /api/events?limit=1000 (no time filters)
    // 2. Receive events with UTC timestamps
    // 3. Apply client-side filters (time range, chain, severity)
    // 4. Render table with pagination
}
```

---

## 🐛 Known Issues & Solutions

### Issue: Events not appearing in frontend
**Root Cause**: Timezone conversion bug in `datetime-local` inputs
**Solution**: Use `Date.UTC()` to parse inputs as UTC, matching event timestamps

### Issue: Database schema mismatch
**Root Cause**: `status` column missing in `events` table
**Solution**: Migration endpoint `/api/maintenance/migrate-events` adds missing columns

### Issue: Redis connection failures
**Root Cause**: Cloud Run can't access private Redis IP
**Solution**: VPC Connector configured with `vpc-egress=private-ranges-only`

### Issue: Deployment conflicts
**Root Cause**: Concurrent deployments cause version conflicts
**Solution**: Retry logic + `LAST_DEPLOY` env var to force new revisions

---

## 📝 Key Design Decisions

1. **Dual persistence**: Redis (fast) + PostgreSQL (durable)
   - Fallback to direct DB save if Redis fails
   - Ensures no event loss

2. **Client-side filtering**: Frontend filters events after fetching
   - Avoids timezone conversion issues
   - Reduces API complexity
   - Better UX (instant filtering)

3. **Synchronous DB fallback**: `psycopg2` for event saves
   - More reliable than `asyncpg` for batch inserts
   - Avoids datetime timezone issues
   - Used via `asyncio.to_thread()`

4. **Raw SQL queries**: Avoid ORM for event retrieval
   - Handles schema mismatches gracefully
   - Better performance for large datasets
   - Direct control over query optimization

5. **Multi-stage deployment**: Separate API and Worker services
   - Independent scaling
   - Clear separation of concerns
   - Worker can serve static files

---

## 🎯 System Capabilities

### Current Features
- ✅ Multi-chain event collection (Ethereum, Polygon, Arbitrum, etc.)
- ✅ Real-time event ingestion and persistence
- ✅ Log Explorer UI with filtering and pagination
- ✅ Runtime security detection (economic invariants)
- ✅ bloXroute mempool integration (0-block detection)
- ✅ Database schema migration endpoint
- ✅ Health checks and metrics
- ✅ CI/CD via GitHub Actions

### Future Enhancements
- ML-based threat classification
- Cross-chain correlation engine
- Explainable AI for incident analysis
- Real-time alerting and notifications
- Advanced analytics dashboard

---

## 🔐 Security Considerations

- **Private networking**: VPC Connector for Cloud SQL/Redis access
- **Secrets management**: Google Secret Manager
- **Non-root containers**: Docker runs as `xdr` user
- **Input validation**: API validates all inputs
- **SQL injection protection**: Parameterized queries
- **CORS**: Configured for frontend origin

---

## 📚 Additional Resources

- `README.md` - High-level project overview
- `ARCHITECTURE.md` - Detailed architecture documentation
- `ULTRA_COMPREHENSIVE_OVERVIEW.md` - Complete project overview
- `DEPLOYMENT_STATUS.md` - Deployment status and URLs
- `config/chains.yaml` - Chain configurations
- `.github/workflows/deploy.yml` - CI/CD pipeline

---

## 🎓 For LLM Context

This blueprint provides a complete understanding of:
1. **System architecture** - Layers, components, data flow
2. **Code organization** - Directory structure, key files
3. **Technology stack** - Languages, frameworks, infrastructure
4. **Deployment** - Cloud Run, CI/CD, networking
5. **Critical paths** - Event ingestion, persistence, retrieval
6. **Known issues** - Problems and solutions
7. **Design decisions** - Why certain choices were made

Use this document to:
- Understand how the system works end-to-end
- Navigate the codebase effectively
- Make informed changes
- Debug issues
- Extend functionality

---

**Last Updated**: 2026-01-09
**Version**: 1.0
**Status**: Production (Events displaying in Log Explorer ✅)
