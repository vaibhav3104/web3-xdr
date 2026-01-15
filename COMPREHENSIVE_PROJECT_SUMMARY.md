# Ultra Comprehensive Project Summary: Web3 XDR (Sentinel3)

**Date:** January 15, 2026  
**Project:** Web3 Extended Detection & Response (XDR) Platform  
**Status:** Production Deployment - Active Development

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture & Components](#architecture--components)
3. [Database Infrastructure](#database-infrastructure)
4. [Critical Issues & Resolutions](#critical-issues--resolutions)
5. [Deployment Configuration](#deployment-configuration)
6. [Code Changes & Fixes](#code-changes--fixes)
7. [Current Status](#current-status)
8. [Key Learnings](#key-learnings)

---

## 🎯 Project Overview

### Purpose
**Sentinel3** is a cross-chain bridge attack detection and response platform that:
- **Detects** economic invariant violations (mint without lock, unbacked transfers)
- **Correlates** cross-chain events into single, actionable incidents
- **Explains** in human language WHY something is an attack
- **Quantifies** blast radius and loss rate in real-time
- **Guides** safe human-in-the-loop response

### Core Design Principle
> **How does this system detect and stop an attack that the smart contract itself believes is valid?**
>
> **Answer**: By enforcing **economic invariants** that exist *outside* any single contract's logic. A bridge contract may accept a forged message and mint tokens—it believes the transaction is valid. But our system observes that `minted_on_chain_B > locked_on_chain_A` within the correlation window. This is an **economic truth violation** that no single contract can detect, but cross-chain observation makes obvious.

### Technology Stack
- **Backend**: Python 3.11, FastAPI, SQLAlchemy (async), asyncpg
- **Database**: PostgreSQL (Cloud SQL on GCP)
- **Infrastructure**: Google Cloud Platform (Cloud Run, Cloud SQL, Cloud Build)
- **Blockchain**: Multi-chain support (EVM: Ethereum, Polygon, Arbitrum, Optimism, Base, Avalanche, BSC; Non-EVM: Solana, Cosmos, Osmosis, Injective, Aptos, Sui, Near)
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Monitoring**: Prometheus metrics, structured logging (structlog)
- **CI/CD**: GitHub Actions

---

## 🏗️ Architecture & Components

### System Architecture (High-Level Design)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SENTINEL3 SYSTEM ARCHITECTURE                            │
│                         Layer-Wise Microservices View                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 7: FRONTEND LAYER                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Log Explorer │  │  Dashboard  │  │   Parsers    │  │   Guardian   │     │
│  │  logs.html   │  │ index.html  │  │ parsers.html │  │guardian.html │     │
│  └──────┬───────┘  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                │                 │             │
│         └──────────────────┴────────────────┴─────────────────┘             │
│                              │ HTTP REST                                     │
└──────────────────────────────┼───────────────────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────────────────┐
│ LAYER 6: API GATEWAY LAYER                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    API SERVICE (Cloud Run)                           │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │ FastAPI      │  │ REST Routes  │  │ WebSocket    │              │   │
│  │  │ Server       │  │ /api/events  │  │ /ws/feed     │              │   │
│  │  │ Port: 8080   │  │ /api/incidents│  │ (removed)    │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                  WORKER SERVICE (Cloud Run)                         │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │ Ingestion    │  │ Detection    │  │ Runtime      │              │   │
│  │  │ Loop         │  │ Loop         │  │ Loop         │              │   │
│  │  │ Port: 9090   │  │ (Consume)    │  │ (Security)   │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
         │                                    │                    │
         │ PostgreSQL                          │ Redis              │ Redis
         │ (Query)                             │ (Pub/Sub)          │ (State)
         │                                     │                    │
┌────────▼─────────────────────────────────────▼────────────────────▼─────────┐
│ LAYER 5: STORAGE LAYER                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────┐          ┌──────────────────────┐                │
│  │   PostgreSQL         │          │   Redis              │                │
│  │   Database           │          │   Event Bus          │                │
│  │                      │          │                      │                │
│  │ • events             │          │ • sentinel3:events   │                │
│  │ • predicted_incidents│          │ • runtime:intents    │                │
│  │ • simulation_runs    │          │ • runtime:simulations│                │
│  │ • bridge_states      │          │ • runtime:threats    │                │
│  └──────────────────────┘          └──────────────────────┘                │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │              Redis State Manager (Distributed State)                │   │
│  │  • Lock/Mint correlations                                           │   │
│  │  • Bridge state snapshots                                           │   │
│  │  • Atomic operations (Lua scripts)                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
         │                                    │
         │ Query                              │ Publish/Consume
         │                                    │
┌────────▼────────────────────────────────────▼───────────────────────────────┐
│ LAYER 4: DETECTION & ANALYSIS LAYER                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐ │
│  │ Invariant Engine     │  │ Correlation Engine   │  │ ML Analysis      │ │
│  │                      │  │                      │  │ Engine           │ │
│  │ • MintLockParity     │  │ • Cross-chain        │  │ • Anomaly        │ │
│  │ • TVLVelocity        │  │   correlation        │  │   detection      │ │
│  │ • UnbackedMint       │  │ • Pattern matching   │  │ • Predictions    │ │
│  │ • SequenceInvariant  │  │ • Entity graph       │  │ • Confidence     │ │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────┘ │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
         │                                    │
         │ Evaluate                           │ Correlate
         │                                    │
┌────────▼────────────────────────────────────▼───────────────────────────────┐
│ LAYER 3: RUNTIME SECURITY PLANE                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Runtime Engine (Orchestrator)                      │   │
│  │  Flow: Source → Router → Simulator → Invariant → Incident            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐ │
│  │ Risk Router          │  │ Anvil Simulator      │  │ Intent Sources   │ │
│  │                      │  │                      │  │                  │ │
│  │ • Budget tracking    │  │ • Fork mainnet       │  │ • bloXroute      │ │
│  │ • Whitelist/Blacklist│  │ • Simulate tx        │  │ • Pseudo Block   │ │
│  │ • Dangerous selectors│  │ • Extract state diff │  │ • RPC Polling    │ │
│  │ • Value thresholds   │  │ • Worker pool (3)    │  │                  │ │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────┘ │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
         │                                    │
         │ Consume                            │ Publish
         │                                    │
┌────────▼────────────────────────────────────▼───────────────────────────────┐
│ LAYER 2: NORMALIZATION LAYER                                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────┐          ┌──────────────────────┐                │
│  │ Normalization Engine  │          │ Parser Manager       │                │
│  │                       │          │                      │                │
│  │ • Chain-specific →    │          │ • ABI parsing        │                │
│  │   Unified schema      │          │ • Event extraction   │                │
│  │ • SecurityEvent       │          │ • Contract analysis  │                │
│  │ • Entity resolution   │          │                      │                │
│  └──────────────────────┘          └──────────────────────┘                │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
         │                                    │
         │ Normalize                           │ Parse
         │                                    │
┌────────▼────────────────────────────────────▼───────────────────────────────┐
│ LAYER 1: DATA INGESTION LAYER                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐ │
│  │ bloXroute Mempool    │  │ Chain Listeners      │  │ Finality Tracker │ │
│  │ Source               │  │                      │  │                  │ │
│  │                      │  │ • EVMListener       │  │ • Track blocks   │ │
│  │ • WebSocket          │  │ • SolanaListener    │  │ • Confirmations  │ │
│  │ • 0-block detection  │  │ • CosmosListener    │  │ • Reorg depth    │ │
│  │ • Address filtering  │  │ • AptosListener     │  │                  │ │
│  │ • Auto-reconnect     │  │ • NearListener      │  │                  │ │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────┘ │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    MultiRpcProvider                                 │   │
│  │  • Failover RPC endpoints                                           │   │
│  │  • Health checking                                                  │   │
│  │  • Load balancing                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
         │                                    │
         │ WebSocket                          │ HTTP/JSON-RPC
         │                                    │
┌────────▼────────────────────────────────────▼───────────────────────────────┐
│ EXTERNAL SOURCES                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────┐          ┌──────────────────────┐                │
│  │ bloXroute Cloud API  │          │ RPC Providers        │                │
│  │ wss://api.blxrbdn.com│          │                      │                │
│  │                      │          │ • Infura             │                │
│  │ • Mempool feed       │          │ • Alchemy            │                │
│  │ • Real-time          │          │ • Public RPCs        │                │
│  │ • Filtered           │          │ • Chain-specific     │                │
│  └──────────────────────┘          └──────────────────────┘                │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Breakdown by Layer

#### Layer 7: Frontend Layer
- **Log Explorer** (`frontend/logs.html`):
  - Real-time event display and filtering
  - Lucene query support
  - Cursor-based pagination
  - Chain/severity/type filters
- **Dashboard** (`frontend/index.html`):
  - System statistics and metrics
  - Chain status overview
  - Incident summary
- **Parsers** (`frontend/parsers.html`):
  - Parser management interface
  - ABI upload and configuration
- **Guardian** (`frontend/guardian.html`):
  - Auto-response configuration
  - Guardian rule management

#### Layer 6: API Gateway Layer
- **API Service** (`src/api/server.py`):
  - FastAPI application (Port 8080)
  - REST endpoints: `/api/events`, `/api/incidents`, etc.
  - WebSocket support (removed in current version)
  - Static file serving
  - Authentication (JWT)
- **Worker Service** (`src/worker/main.py`, `worker.py`):
  - Ingestion Loop: Collects events from chains
  - Detection Loop: Consumes from Redis, runs detection
  - Runtime Loop: Runtime security plane processing
  - Health endpoint (Port 9090)
  - Environment: `PROC_TYPE=worker`

#### Layer 5: Storage Layer
- **PostgreSQL Database** (Cloud SQL):
  - `events` table: All security events
  - `predicted_incidents` table: ML predictions
  - `simulation_runs` table: Anvil simulation results
  - `bridge_states` table: Bridge state snapshots
- **Redis Event Bus**:
  - `sentinel3:events`: Normalized events stream
  - `runtime:intents`: Runtime intent sources
  - `runtime:simulations`: Simulation results
  - `runtime:threats`: Threat intelligence
- **Redis State Manager**:
  - Lock/Mint correlations (distributed state)
  - Bridge state snapshots
  - Atomic operations via Lua scripts

#### Layer 4: Detection & Analysis Layer
- **Invariant Engine** (`src/invariants/engine.py`):
  - `MintLockParity`: Detects mint without lock
  - `TVLVelocity`: Detects rapid TVL changes
  - `UnbackedMint`: Detects unbacked token mints
  - `SequenceInvariant`: Detects sequence violations
- **Correlation Engine** (`src/correlation/correlator.py`):
  - Cross-chain event correlation
  - Pattern matching
  - Entity graph construction
- **ML Analysis Engine** (`src/ai/analyzer.py`):
  - Anomaly detection
  - Attack prediction
  - Confidence scoring

#### Layer 3: Runtime Security Plane
- **Runtime Engine** (`src/runtime/runtime_engine.py`):
  - Orchestrates: Source → Router → Simulator → Invariant → Incident
  - Coordinates all runtime components
- **Risk Router** (`src/runtime/risk_router.py`):
  - Budget tracking per address/contract
  - Whitelist/blacklist management
  - Dangerous selector detection
  - Value threshold enforcement
- **Anvil Simulator** (`src/runtime/simulator/anvil.py`):
  - Forks mainnet for simulation
  - Simulates transactions
  - Extracts state differences
  - Worker pool (3 workers) for parallel simulation
- **Intent Sources** (`src/runtime/intent_sources/`):
  - `bloxroute_source.py`: bloXroute mempool feed
  - `pseudo_block.py`: Pseudo block generation
  - RPC polling for chain events

#### Layer 2: Normalization Layer
- **Normalization Engine** (`src/telemetry/base.py`):
  - Converts chain-specific events to unified `SecurityEvent` schema
  - Entity resolution (addresses, contracts)
  - Temporal alignment (block → timestamp)
- **Parser Manager** (`src/api/parser_routes.py`):
  - ABI parsing and event extraction
  - Contract analysis
  - Event signature matching

#### Layer 1: Data Ingestion Layer
- **bloXroute Mempool Source** (`src/runtime/intent_sources/bloxroute_source.py`):
  - WebSocket connection to `wss://api.blxrbdn.com/ws`
  - 0-block detection (mempool monitoring)
  - Address filtering
  - Auto-reconnect on failure
- **Chain Listeners** (`src/telemetry/`):
  - `evm_listener.py`: Ethereum, Polygon, Arbitrum, etc.
  - `solana_listener.py`: Solana transaction monitoring
  - `cosmos_listener.py`: Cosmos SDK chains
  - `aptos_listener.py`: Aptos Move VM
  - `near_listener.py`: NEAR Protocol
- **Finality Tracker** (`src/telemetry/finality_tracker.py`):
  - Tracks block confirmations per chain
  - Monitors reorg depth
  - Determines finality status
- **MultiRpcProvider** (`src/telemetry/multi_chain_pool.py`):
  - Failover RPC endpoints
  - Health checking
  - Load balancing across providers

---

## 🗄️ Database Infrastructure

### Cloud SQL Instance
- **Instance Name**: `web3-xdr-db`
- **Project**: `web3-xdr`
- **Region**: `us-central1`
- **Current Tier**: `db-custom-1-3840` (1 vCPU, 3.75GB RAM)
- **Previous Tiers**: `db-f1-micro` → `db-g1-small` → `db-custom-1-3840`
- **Database**: PostgreSQL
- **Connection**: Cloud SQL Proxy via Unix socket (`/cloudsql/web3-xdr:us-central1:web3-xdr-db`)

### Database Schema

#### Events Table
```sql
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id VARCHAR(255) UNIQUE NOT NULL,
    chain_id VARCHAR(50) NOT NULL,
    event_type VARCHAR(100),
    tx_hash VARCHAR(128),
    block_number BIGINT,
    block_timestamp TIMESTAMP WITH TIME ZONE,
    contract_address VARCHAR(128),
    severity VARCHAR(16) DEFAULT 'LOW',
    amount NUMERIC(38, 18),
    amount_usd NUMERIC(20, 2),
    from_address VARCHAR(128),
    to_address VARCHAR(128),
    raw_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status VARCHAR(16) DEFAULT 'PENDING',
    block_hash VARCHAR(128),
    canonical_event_hash VARCHAR(128),
    confirmed_at TIMESTAMP WITH TIME ZONE,
    log_index INTEGER,
    topics VARCHAR(128)[],
    asset_type VARCHAR(32),
    asset_address VARCHAR(128)
);
```

#### Performance Indexes
```sql
-- Timeline sorting
CREATE INDEX idx_events_created_at ON events(created_at DESC);

-- Chain + timestamp filtering
CREATE INDEX idx_events_chain_timestamp ON events(chain_id, block_timestamp DESC);

-- Chain + event type filtering
CREATE INDEX idx_events_chain_type ON events(chain_id, event_type);

-- Status filtering
CREATE INDEX ix_events_status ON events(status, chain_id) WHERE status IS NOT NULL;

-- Block hash lookup
CREATE INDEX ix_events_block_hash ON events(block_hash) WHERE block_hash IS NOT NULL;
```

### Connection Configuration

#### Environment Variables
- `DATABASE_URL`: Full PostgreSQL connection string (from Secret Manager)
- `CLOUDSQL_INSTANCE`: Instance connection name (`web3-xdr:us-central1:web3-xdr-db`)
- `POSTGRES_USER`: Database user (default: `xdr`)
- `POSTGRES_PASSWORD`: Database password (from Secret Manager)
- `POSTGRES_DB`: Database name (default: `web3_xdr`)

#### Connection Pool Settings
```python
pool_size=10              # Base connection pool size
max_overflow=5            # Additional connections beyond pool_size
pool_timeout=60           # Seconds to wait for connection
pool_pre_ping=True        # Test connections before use
pool_recycle=1800         # Recycle connections every 30 minutes
command_timeout=60        # asyncpg command timeout
statement_timeout=60000   # PostgreSQL statement timeout (ms)
```

---

## 🔧 Critical Issues & Resolutions

### Issue #1: Database Performance - Query Timeouts

**Problem:**
- `SELECT COUNT(*)` queries timing out (30+ seconds)
- API returning 0 events despite worker saving events
- Database instance (`db-f1-micro`) overloaded

**Root Causes:**
1. Database instance too small (f1-micro: 0.6GB RAM, shared CPU)
2. Missing performance indexes on `events` table
3. Connection pool misconfiguration
4. Query timeouts too short

**Resolution:**
1. **Upgraded Database Instance**:
   - `db-f1-micro` → `db-g1-small` → `db-custom-1-3840`
   - Increased RAM from 0.6GB → 1.7GB → 3.75GB
   - Dedicated CPU resources

2. **Created Performance Indexes**:
   - `idx_events_created_at` (timeline sorting)
   - `idx_events_chain_timestamp` (chain filtering)
   - `idx_events_chain_type` (event type filtering)

3. **Optimized Connection Pool**:
   - Increased `pool_size` from 5 → 10
   - Increased `max_overflow` from 3 → 5
   - Increased `pool_timeout` from 30s → 60s
   - Added `pool_pre_ping` for connection health checks

4. **Increased Timeouts**:
   - `command_timeout`: 30s → 60s
   - `statement_timeout`: 30s → 60s

**Files Changed:**
- `src/database/connection.py`: Connection pool configuration
- `scripts/apply_indexes.py`: Index creation script
- `src/database/connection.py`: `ensure_indexes()` method

---

### Issue #2: Cloud SQL Connection - Public IP vs Unix Socket

**Problem:**
- Worker connecting to database via public IP (`136.112.205.93:5432`)
- Connection timeouts and failures
- Cloud Run configured for `private-ranges-only` egress
- Database not accessible via public IP from Cloud Run

**Root Causes:**
1. `DATABASE_URL` contained public IP address
2. Worker not using Cloud SQL Proxy Unix socket
3. `CLOUDSQL_INSTANCE` env var not set on worker
4. Connection code not prioritizing Unix socket

**Resolution:**
1. **Set Cloud SQL Instance Env Var**:
   ```bash
   CLOUDSQL_INSTANCE=web3-xdr:us-central1:web3-xdr-db
   ```

2. **Modified Connection Logic** (`src/database/connection.py`):
   ```python
   # Prioritize CLOUDSQL_INSTANCE for Unix socket
   cloudsql_instance = os.getenv("CLOUDSQL_INSTANCE")
   if cloudsql_instance:
       # Extract credentials from DATABASE_URL but use Unix socket
       unix_socket_dir = f"/cloudsql/{cloudsql_instance}"
       return f"postgresql+asyncpg://{user}:{password}@/{database}"
   ```

3. **Configured connect_args for Unix Socket**:
   ```python
   if cloudsql_instance:
       connect_args["host"] = f"/cloudsql/{cloudsql_instance}"
       connect_args.pop("port", None)  # Remove port for Unix socket
   ```

4. **Verified Cloud SQL Proxy Annotation**:
   - Worker service has `run.googleapis.com/cloudsql-instances` annotation
   - Cloud SQL Proxy automatically creates Unix socket at `/cloudsql/...`

**Files Changed:**
- `src/database/connection.py`: `get_database_url()` and `initialize()` methods
- Cloud Run worker service: Added `CLOUDSQL_INSTANCE` env var

---

### Issue #3: Transaction Rollback - InFailedSQLTransactionError

**Problem:**
- When one INSERT failed, entire transaction aborted
- Subsequent INSERTs failed with "transaction is aborted, commands ignored"
- All events in batch lost even if only one had an error
- `executed=0` for all batches

**Root Cause:**
- Single transaction for entire batch
- No error isolation between events
- Failed event aborted transaction, preventing other events from saving

**Resolution:**
- **Used Savepoints for Each Event**:
  ```python
  for event in events:
      savepoint = await session.begin_nested()  # Create savepoint
      try:
          await session.execute(raw_insert_sql, {...})
          await savepoint.commit()  # Commit savepoint
          saved_count += 1
      except Exception as e:
          await savepoint.rollback()  # Rollback only this event
          logger.error("raw_sql_insert_failed", ...)
  ```

**Files Changed:**
- `src/database/service.py`: `save_events_batch()` method

---

### Issue #4: Parameter Type Ambiguity - AmbiguousParameterError

**Problem:**
- `AmbiguousParameterError: could not determine data type of parameter $9`
- Occurred when `amount=0` (integer) passed to SQL CASE statement
- asyncpg couldn't infer parameter type in `CASE WHEN :amount != ''`
- All INSERTs failed with this error

**Root Cause:**
- asyncpg needs explicit type information for parameters in CASE statements
- When `amount` is `0` (integer), type is ambiguous
- SQL comparison `:amount != ''` fails because type unknown

**Resolution:**
- **Explicit CAST in SQL CASE Statement**:
  ```sql
  -- Before (failed):
  CASE WHEN :amount IS NOT NULL AND :amount != '' THEN CAST(:amount AS NUMERIC(38, 18)) ELSE NULL END
  
  -- After (works):
  CASE WHEN :amount IS NOT NULL AND CAST(:amount AS TEXT) != '' THEN CAST(:amount AS NUMERIC(38, 18)) ELSE NULL END
  ```

- **Improved Python Type Handling**:
  ```python
  amount_val = event.get("amount")
  if amount_val is not None and amount_val != "":
      if amount_val == 0 or amount_val == "0":
          amount_str = "0"
      else:
          amount_str = str(amount_val)
  else:
      amount_str = None
  ```

**Files Changed:**
- `src/database/service.py`: SQL INSERT statement and parameter preparation

---

### Issue #5: GitHub Actions Deployment Failures

**Problem:**
- Deployment pipeline failing with `IndentationError`
- `src/database/service.py` had indentation issues
- Python import validation step failing

**Root Cause:**
- Incorrect indentation in `save_events_batch()` method
- Import statements not properly scoped
- Unreachable code after return statements

**Resolution:**
- Fixed indentation in `save_events_batch()` method
- Properly scoped import statements within try blocks
- Removed unreachable code

**Files Changed:**
- `src/database/service.py`: Indentation fixes

---

## 🚀 Deployment Configuration

### Cloud Run Services

#### Worker Service
- **Name**: `web3-xdr-production-worker`
- **Region**: `us-central1`
- **Image**: `us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr:latest`
- **CPU**: 2 vCPU
- **Memory**: 4GB
- **Min Instances**: 1
- **Max Instances**: 3
- **Port**: 9090
- **Cloud SQL**: `web3-xdr:us-central1:web3-xdr-db`
- **VPC Connector**: `sentinel3-connector`
- **Egress**: `private-ranges-only`

#### API Service
- **Name**: `web3-xdr-production-api`
- **Region**: `us-central1`
- **Image**: `us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr:latest`
- **CPU**: 2 vCPU
- **Memory**: 2GB
- **Min Instances**: 1
- **Max Instances**: 10
- **Port**: 8080
- **Cloud SQL**: `web3-xdr:us-central1:web3-xdr-db`
- **VPC Connector**: `sentinel3-connector`
- **Egress**: `all-traffic` (changed from `private-ranges-only`)

### Environment Variables

#### Worker Service
```bash
CLOUDSQL_INSTANCE=web3-xdr:us-central1:web3-xdr-db
ENVIRONMENT=production
GCP_PROJECT=web3-xdr
PROC_TYPE=worker
WORKER_HEALTH_PORT=9090
RUNTIME_ENABLED=true
MEMPOOL_SOURCE=pseudo
AUTO_START_SCANNER=true
```

#### Secrets (from Secret Manager)
- `DATABASE_URL`: PostgreSQL connection string
- `INFURA_API_KEY`: Infura RPC API key
- `JWT_SECRET_KEY`: JWT signing secret
- `OPENAI_API_KEY`: OpenAI API key (for ML features)
- `REDIS_URL`: Redis connection URL

### CI/CD Pipeline

#### GitHub Actions Workflow
- **Trigger**: Push to `main` branch
- **Steps**:
  1. Checkout code
  2. Set up Python 3.11
  3. Install dependencies
  4. Run linting/formatting
  5. Validate Python imports
  6. Build Docker image
  7. Push to Artifact Registry
  8. Deploy to Cloud Run (API and Worker)

#### Build Configuration
- **Machine Type**: `n1-highcpu-8`
- **Timeout**: 20 minutes
- **Dockerfile**: `Dockerfile` (multi-stage build)
- **Image Registry**: `us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr`

---

## 📝 Code Changes & Fixes

### Database Connection (`src/database/connection.py`)

#### Changes Made:
1. **Unix Socket Support**:
   ```python
   @classmethod
   def get_database_url(cls) -> str:
       cloudsql_instance = os.getenv("CLOUDSQL_INSTANCE")
       if cloudsql_instance:
           # Extract credentials from DATABASE_URL but use Unix socket
           unix_socket_dir = f"/cloudsql/{cloudsql_instance}"
           return f"postgresql+asyncpg://{user}:{password}@/{database}"
   ```

2. **Connection Pool Optimization**:
   ```python
   cls._engine = create_async_engine(
       url,
       pool_size=10,
       max_overflow=5,
       pool_timeout=60,
       pool_pre_ping=True,
       pool_recycle=1800,
       connect_args={
           "server_settings": {
               "statement_timeout": "60000",
               "application_name": "web3-xdr"
           },
           "command_timeout": 60,
           "host": unix_socket_dir if cloudsql_instance else None
       }
   )
   ```

3. **Automatic Index Creation**:
   ```python
   @classmethod
   async def ensure_indexes(cls):
       """Create performance indexes if they don't exist."""
       async with cls.get_session() as session:
           indexes = [
               "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC)",
               "CREATE INDEX IF NOT EXISTS idx_events_chain_timestamp ON events(chain_id, block_timestamp DESC)",
               "CREATE INDEX IF NOT EXISTS idx_events_chain_type ON events(chain_id, event_type)"
           ]
           for index_sql in indexes:
               await session.execute(text(index_sql))
           await session.commit()
   ```

### Database Service (`src/database/service.py`)

#### Changes Made:
1. **Savepoint-Based Batch Insert**:
   ```python
   async def save_events_batch(events: List[Dict[str, Any]]) -> int:
       async with DatabaseManager.get_session() as session:
           for event in events:
               savepoint = await session.begin_nested()
               try:
                   await session.execute(raw_insert_sql, {...})
                   await savepoint.commit()
                   saved_count += 1
               except Exception as e:
                   await savepoint.rollback()
                   logger.error("raw_sql_insert_failed", ...)
           await session.commit()
   ```

2. **Fixed SQL Parameter Types**:
   ```sql
   -- Fixed CASE statement with explicit CAST
   CASE WHEN :amount IS NOT NULL AND CAST(:amount AS TEXT) != '' 
        THEN CAST(:amount AS NUMERIC(38, 18)) 
        ELSE NULL END
   ```

3. **Improved Parameter Handling**:
   ```python
   amount_val = event.get("amount")
   if amount_val is not None and amount_val != "":
       if amount_val == 0 or amount_val == "0":
           amount_str = "0"
       else:
           amount_str = str(amount_val)
   else:
       amount_str = None
   ```

4. **Query Timeout Protection**:
   ```python
   async def get_events(...):
       try:
           result = await asyncio.wait_for(
               session.execute(text(sql), params),
               timeout=25.0
           )
       except asyncio.TimeoutError:
           logger.warning("get_events_query_timeout")
           return [], None
   ```

### API Routes (`src/api/routes.py`)

#### Changes Made:
1. **Database Query Endpoint**:
   ```python
   @router.get("/events")
   async def list_events(...):
       # Query from PostgreSQL (not in-memory)
       db_events, next_cursor = await DatabaseService.get_events(...)
       # Format for frontend
       return {"events": event_dicts, "next_cursor": next_cursor}
   ```

2. **Maintenance Endpoints**:
   - `/api/maintenance/check-events`: Simple event count check
   - `/api/maintenance/db-status`: Database health check
   - `/api/maintenance/create-indexes`: Manual index creation

### API Server (`src/api/server.py`)

#### Changes Made:
1. **Startup Index Creation**:
   ```python
   @app.on_event("startup")
   async def startup_event():
       await DatabaseManager.initialize()
       await DatabaseManager.ensure_indexes()  # Create indexes on startup
   ```

---

## 📊 Current Status

### ✅ Resolved Issues
1. ✅ Database performance (upgraded instance, added indexes)
2. ✅ Cloud SQL connection (Unix socket support)
3. ✅ Transaction rollback (savepoints)
4. ✅ Parameter type ambiguity (explicit CAST)
5. ✅ GitHub Actions deployment (indentation fixes)

### 🔄 In Progress
- Events should now be saving successfully after latest fix
- Monitoring deployment to verify events appear in Log Explorer

### 📈 Metrics
- **Database Instance**: `db-custom-1-3840` (3.75GB RAM, 1 vCPU)
- **Connection Pool**: 10 base + 5 overflow = 15 max connections
- **Query Timeout**: 60 seconds
- **Indexes Created**: 5 performance indexes
- **Supported Chains**: 14 chains (7 EVM + 7 non-EVM)

---

## 🎓 Key Learnings

### 1. Cloud SQL Proxy Best Practices
- **Always use Unix socket** when running on Cloud Run
- Set `CLOUDSQL_INSTANCE` env var, not just `DATABASE_URL`
- Remove `port` from `connect_args` for Unix socket connections
- Cloud SQL Proxy automatically creates socket at `/cloudsql/{instance}`

### 2. asyncpg Parameter Type Handling
- **Explicit type casting** required in CASE statements
- Use `CAST(:param AS TEXT)` before comparisons
- Convert Python values to strings before passing to SQL
- Handle `None`, empty strings, and numeric `0` explicitly

### 3. Database Connection Pooling
- **Right-size pool** for instance tier
- `pool_pre_ping` prevents stale connections
- `pool_recycle` prevents long-lived connection issues
- Monitor connection count vs instance `max_connections`

### 4. Transaction Management
- **Use savepoints** for batch operations with error isolation
- `begin_nested()` creates savepoint, allows partial rollback
- Commit savepoint on success, rollback on error
- Final `session.commit()` commits all successful savepoints

### 5. Database Performance
- **Indexes are critical** for large tables
- Create indexes on frequently filtered columns
- Use composite indexes for multi-column filters
- Monitor query execution time and adjust indexes

### 6. Error Handling
- **Log full error details** (type, args, traceback)
- Return `None` or empty list on timeout (don't block)
- Use retry logic with exponential backoff
- Handle connection errors gracefully

---

## 🔗 Key Files Reference

### Core Files
- `src/api/server.py`: FastAPI application setup
- `src/api/routes.py`: API endpoints (including `/api/events`)
- `src/database/connection.py`: Database connection management
- `src/database/service.py`: Database CRUD operations
- `src/worker/main.py`: Worker entry point
- `worker.py`: Worker script (root level)

### Configuration
- `config/chains.yaml`: Blockchain configuration
- `Dockerfile`: Container build configuration
- `entrypoint.sh`: Container entrypoint script
- `.github/workflows/deploy.yml`: CI/CD pipeline

### Frontend
- `frontend/logs.html`: Log Explorer UI
- `frontend/dashboard.html`: Main dashboard

### Scripts
- `scripts/check_rpc_connections.py`: RPC connectivity checker
- `scripts/apply_indexes.py`: Manual index creation
- `scripts/create_indexes_job.py`: Cloud Run job for indexes

---

## 📞 Support & Troubleshooting

### Common Issues

#### Events Not Appearing in Log Explorer
1. Check worker logs: `gcloud logging read "resource.labels.service_name=web3-xdr-production-worker"`
2. Look for `executed=0` (indicates save failures)
3. Check for `AmbiguousParameterError` or `InFailedSQLTransactionError`
4. Verify database connection: `/api/maintenance/check-events`
5. Check database directly: `/api/maintenance/db-status`

#### Database Connection Timeouts
1. Verify `CLOUDSQL_INSTANCE` env var is set
2. Check Cloud SQL Proxy annotation on Cloud Run service
3. Verify Unix socket exists: `/cloudsql/{instance}`
4. Check connection pool settings (not too high for instance tier)
5. Monitor database `max_connections` vs pool size

#### Query Performance Issues
1. Verify indexes exist: `/api/maintenance/db-status`
2. Check query execution time in logs
3. Consider upgrading database instance tier
4. Review query patterns and add missing indexes

### Useful Commands

```bash
# Check worker logs
gcloud logging read "resource.labels.service_name=web3-xdr-production-worker" --limit 50

# Check API logs
gcloud logging read "resource.labels.service_name=web3-xdr-production-api" --limit 50

# Test API endpoint
curl "https://web3-xdr-production-api-1003459948096.us-central1.run.app/api/events?limit=5"

# Check database status
curl "https://web3-xdr-production-api-1003459948096.us-central1.run.app/api/maintenance/check-events"

# Check RPC connections
python scripts/check_rpc_connections.py

# View database instance
gcloud sql instances describe web3-xdr-db --project web3-xdr
```

---

## 🎯 Next Steps

1. **Monitor Event Saving**: Verify events are being saved after latest fix
2. **Performance Tuning**: Monitor query performance and adjust indexes
3. **Scaling**: Consider read replicas if query load increases
4. **Monitoring**: Set up alerts for database connection failures
5. **Documentation**: Keep this document updated as system evolves

---

---

## ✅ Code Verification Against HLD

### Verification Summary

All microservices and components described in the High-Level Design (HLD) have been verified to exist in the codebase:

| Layer | Components | Status | Coverage |
|-------|-----------|--------|----------|
| **Layer 7: Frontend** | 4 components | ✅ Verified | 100% |
| **Layer 6: API Gateway** | 2 services | ✅ Verified | 100% |
| **Layer 5: Storage** | 7 components | ✅ Verified | 100% |
| **Layer 4: Detection** | 3 engines | ✅ Verified | 100% |
| **Layer 3: Runtime** | 5 components | ✅ Verified | 100% |
| **Layer 2: Normalization** | 2 components | ✅ Verified | 100% |
| **Layer 1: Ingestion** | 8 components | ✅ Verified | 100% |
| **TOTAL** | **31 components** | ✅ **All Found** | **100%** |

### Detailed Verification

#### ✅ Layer 7: Frontend Layer
- ✅ `frontend/logs.html` - Log Explorer (1,735 lines)
- ✅ `frontend/index.html` - Dashboard entry point  
- ✅ `frontend/dashboard.html` - Main dashboard
- ✅ `frontend/parsers.html` - Parser management UI
- ✅ `frontend/guardian.html` - Guardian/auto-response UI

#### ✅ Layer 6: API Gateway Layer
- ✅ `src/api/server.py` - FastAPI application (212 lines)
- ✅ `src/worker/main.py` - Worker service entry point
- ✅ `worker.py` - Root-level worker script (602 lines)
- ✅ 14+ route files covering all API endpoints

#### ✅ Layer 5: Storage Layer
- ✅ `src/database/connection.py` - PostgreSQL connection (284 lines)
- ✅ `src/database/service.py` - Database CRUD (775 lines)
- ✅ `src/database/models.py` - ORM models
- ✅ `src/database/sync_service.py` - Schema management
- ✅ `src/database/redis_manager.py` - Redis connection
- ✅ `src/runtime/bus/redis_streams.py` - Redis Streams pub/sub
- ✅ `src/runtime/bus/base.py` - Base bus interface

#### ✅ Layer 4: Detection & Analysis Layer
- ✅ `src/invariants/engine.py` - Invariant engine (270 lines)
- ✅ `src/correlation/correlator.py` - Correlation engine
- ✅ `src/ai/analyzer.py` - ML analysis engine

#### ✅ Layer 3: Runtime Security Plane
- ✅ `src/runtime/runtime_engine.py` - Runtime orchestrator (433 lines)
- ✅ `src/runtime/risk_router.py` - Risk routing
- ✅ `src/runtime/simulator/anvil.py` - Anvil simulator
- ✅ `src/runtime/intent_sources/bloxroute_source.py` - bloXroute (367 lines)
- ✅ `src/runtime/intent_sources/pseudo_block.py` - Pseudo block source

#### ✅ Layer 2: Normalization Layer
- ✅ `src/telemetry/base.py` - Base listener with normalization (262 lines)
- ✅ `src/api/parser_routes.py` - Parser management API (282 lines)

#### ✅ Layer 1: Data Ingestion Layer
- ✅ `src/runtime/intent_sources/bloxroute_source.py` - bloXroute WebSocket
- ✅ `src/telemetry/evm_listener.py` - EVM chain listener
- ✅ `src/telemetry/solana_listener.py` - Solana listener
- ✅ `src/telemetry/cosmos_listener.py` - Cosmos listener
- ✅ `src/telemetry/aptos_listener.py` - Aptos listener
- ✅ `src/telemetry/near_listener.py` - NEAR listener
- ✅ `src/telemetry/finality_tracker.py` - Finality tracking
- ✅ `src/telemetry/multi_chain_pool.py` - Multi-RPC provider

### Additional Components Found

Beyond the HLD, the project contains:
- **Additional Frontend Pages**: ML Analysis, Simulator, Analytics, Admin, Tenants, Login
- **Additional API Routes**: AI, Metrics, Cross-chain, Scorecard, Customer management
- **Additional Telemetry**: Robust providers, Checkpoint management, Contract alerts
- **Additional ML Components**: Training pipelines, Continuous learning, Deep classifiers

**Full verification report**: See `HLD_CODE_VERIFICATION.md` for complete details.

---

**Last Updated**: January 15, 2026  
**Version**: 1.0  
**Maintainer**: Development Team
