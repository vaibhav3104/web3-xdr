# 🎨 Sentinel3 Architecture Diagrams

## 📊 Quick Reference: Layer-Wise Microservices

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SENTINEL3 SYSTEM ARCHITECTURE                        │
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

---

## 🔄 Complete Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE DATA FLOW - EVENT LIFECYCLE                      │
└─────────────────────────────────────────────────────────────────────────────┘

[EXTERNAL]                    [LAYER 1]              [LAYER 2]              [LAYER 3]
bloXroute ──WebSocket──> BloxrouteSource ──PendingTx─> Normalization ──SecurityEvent─> RuntimeEngine
   │                         │                        │                        │
   │                         │                        │                        ├─> RiskRouter
RPC Nodes ──HTTP/RPC──> ChainListeners ──RawEvent──> ParserManager            │     │
   │                         │                        │                        │     ├─> Decision
   │                         │                        │                        │     │   (SIM_FULL)
   │                         │                        │                        │     │
   │                         │                        │                        │     └─> AnvilSimulator
   │                         │                        │                        │           │
   │                         │                        │                        │           ├─> Fork Mainnet
   │                         │                        │                        │           ├─> Simulate Tx
   │                         │                        │                        │           └─> Extract State Diff
   │                         │                        │                        │
   │                         │                        │                        └─> InvariantEngine
   │                         │                        │                              │
   │                         │                        │                              ├─> Query DB (Historical)
   │                         │                        │                              ├─> Check MintWithoutLock
   │                         │                        │                              ├─> Check TVLVelocity
   │                         │                        │                              └─> Return Violation
   │                         │                        │
   │                         │                        └─> Redis Event Bus
   │                         │                              │
   │                         │                              ├─> sentinel3:events
   │                         │                              ├─> runtime:intents
   │                         │                              ├─> runtime:simulations
   │                         │                              └─> runtime:threats
   │                         │
   │                         └─> FinalityTracker ──Finality─> Redis State Manager
   │                                                              │
   │                                                              └─> Bridge State
   │
[LAYER 4]                    [LAYER 5]              [LAYER 6]              [LAYER 7]
CorrelationEngine ──Query──> PostgreSQL ──Query──> API Service ──HTTP──> Frontend
   │                        │                        │                        │
   │                        │ • events               │ • /api/events         │ • Log Explorer
   │                        │ • incidents            │ • /api/incidents      │ • Dashboard
   │                        │ • simulations          │ • /api/runtime/*       │ • Parsers
   │                        │ • bridge_states        │                        │
   │                        │                        │                        │
MLAnalysisEngine ──Query──> Redis ──Consume──> Worker Service
   │                        │                        │
   │                        │ • Event Bus            │ • Ingestion Loop
   │                        │ • Pub/Sub              │ • Detection Loop
   │                        │ • State                │ • Runtime Loop
   │                        │                        │
   │                        └─> Save Batch ──────────┘
   │
   └─> Save Predictions ──> PostgreSQL
```

---

## 🌐 Deployment Architecture (GCP Cloud Run)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GOOGLE CLOUD PLATFORM                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ CLOUD RUN SERVICES                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  API SERVICE                                                         │   │
│  │  Name: web3-xdr-production-api                                       │   │
│  │  URL: https://web3-xdr-production-api-ipje7qz66q-uc.a.run.app      │   │
│  │  Port: 8080                                                          │   │
│  │  VPC: sentinel3-connector                                            │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │ FastAPI      │  │ REST Routes  │  │ Static Files │              │   │
│  │  │ Server       │  │ /api/*       │  │ /frontend/*  │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  WORKER SERVICE                                                      │   │
│  │  Name: web3-xdr-production-worker                                    │   │
│  │  URL: https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app   │   │
│  │  Port: 9090                                                          │   │
│  │  VPC: sentinel3-connector                                            │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │ Ingestion    │  │ Detection    │  │ Runtime      │              │   │
│  │  │ Loop         │  │ Loop         │  │ Security     │              │   │
│  │  │ Health: /health│ │ Consume Bus │  │ Plane        │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
         │                                    │
         │ VPC Connector                      │ VPC Connector
         │ (sentinel3-connector)              │ (sentinel3-connector)
         │                                    │
┌────────▼────────────────────────────────────▼───────────────────────────────┐
│ VPC NETWORK (default)                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  VPC CONNECTOR                                                       │   │
│  │  Name: sentinel3-connector                                           │   │
│  │  IP Range: 10.8.0.0/28                                               │   │
│  │  Status: READY                                                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌──────────────────────┐          ┌──────────────────────┐                │
│  │ Redis Memorystore    │          │ Cloud SQL            │                │
│  │                      │          │ (PostgreSQL)         │                │
│  │ Name: sentinel3-redis │          │                      │                │
│  │ IP: 10.92.40.83:6379 │          │ Private IP           │                │
│  │ Network: default     │          │ Database: web3_xdr   │                │
│  │ Status: READY         │          │                      │                │
│  └──────────────────────┘          └──────────────────────┘                │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
         │                                    │
         │ External                            │ External
         │                                    │
┌────────▼────────────────────────────────────▼───────────────────────────────┐
│ EXTERNAL SERVICES                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────┐          ┌──────────────────────┐                │
│  │ bloXroute Cloud API  │          │ RPC Providers        │                │
│  │ wss://api.blxrbdn.com│          │                      │                │
│  │                      │          │ • Infura (Ethereum)  │                │
│  │ • WebSocket          │          │ • Polygon RPC        │                │
│  │ • Mempool feed       │          │ • Arbitrum RPC        │                │
│  │ • Auth required      │          │ • Other chains        │                │
│  └──────────────────────┘          └──────────────────────┘                │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔗 Communication Patterns Matrix

| From Component | To Component | Protocol | Port | Purpose | Data Type |
|---------------|--------------|----------|------|---------|-----------|
| **Frontend** | API Service | HTTP/HTTPS | 443 | REST API calls | JSON |
| **API Service** | PostgreSQL | PostgreSQL | 5432 | Query events/incidents | SQL |
| **API Service** | Redis | Redis | 6379 | Read state (optional) | Redis commands |
| **Worker Service** | Redis | Redis Streams | 6379 | Publish/consume events | Redis Streams |
| **Worker Service** | PostgreSQL | PostgreSQL | 5432 | Save events/incidents | SQL (async) |
| **Worker Service** | bloXroute | WebSocket | 443 | Mempool feed | WebSocket messages |
| **Worker Service** | RPC Providers | HTTP/HTTPS | 443 | Block/log queries | JSON-RPC |
| **Runtime Engine** | Anvil Simulator | HTTP | 8545-8547 | Fork/simulate | JSON-RPC |
| **Invariant Engine** | PostgreSQL | PostgreSQL | 5432 | Query historical events | SQL |
| **Chain Listeners** | RPC Providers | HTTP/HTTPS | 443 | Subscribe/poll blocks | JSON-RPC |
| **bloXroute Source** | bloXroute API | WebSocket | 443 | Mempool subscription | WebSocket |

---

## 📦 Microservices Inventory

### Cloud Run Services (2)
1. **API Service** (`web3-xdr-production-api`)
   - Purpose: REST API + Static file serving
   - Port: 8080
   - Scaling: 1-10 instances
   - VPC: ✅ Connected

2. **Worker Service** (`web3-xdr-production-worker`)
   - Purpose: Background processing
   - Port: 9090
   - Scaling: 1-3 instances
   - VPC: ✅ Connected

### Internal Components (15+)
1. **BloxrouteMempoolSource** - Mempool monitoring
2. **MultiRpcProvider** - RPC failover
3. **EVMListener** - EVM chain listener
4. **SolanaListener** - Solana listener
5. **FinalityTrackerManager** - Block finality
6. **NormalizationEngine** - Event normalization
7. **ParserManager** - ABI parsing
8. **RuntimeEngine** - Runtime security orchestrator
9. **RiskRouter** - Transaction routing
10. **AnvilSimulator** - Transaction simulation
11. **InvariantEngine** - Invariant checking
12. **CorrelationEngine** - Cross-chain correlation
13. **MLAnalysisEngine** - ML anomaly detection
14. **DatabaseService** - Database operations
15. **RedisStreamsBus** - Event bus

### External Services (3)
1. **PostgreSQL** (Cloud SQL) - Persistent storage
2. **Redis** (Memorystore) - Event bus + state
3. **VPC Connector** - Network connectivity

---

## 🎯 Key Communication Flows

### Flow 1: Event Ingestion
```
Chain → Listener → Redis Streams → Worker → Database
```

### Flow 2: Runtime Security
```
bloXroute → Intent Source → Runtime Engine → Risk Router → Simulator → Invariant → Database
```

### Flow 3: API Query
```
Frontend → API Service → PostgreSQL → Frontend
```

### Flow 4: Cross-Chain Correlation
```
Chain A → Listener → Redis → Correlation Engine → Database
Chain B → Listener → Redis → Correlation Engine → Database
```

---

**Last Updated**: 2025-01-27  
**Version**: 2.0  
**Status**: Production Ready ✅
