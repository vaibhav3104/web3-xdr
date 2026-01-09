# 🎯 Sentinel3 - Quick Architecture Reference

## 🏗️ 7-Layer Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 7: Frontend          │ Log Explorer, Dashboard, Parsers │
├─────────────────────────────────────────────────────────────────┤
│ LAYER 6: API Gateway       │ FastAPI (REST) + Worker (Background)│
├─────────────────────────────────────────────────────────────────┤
│ LAYER 5: Storage           │ PostgreSQL + Redis (Event Bus)     │
├─────────────────────────────────────────────────────────────────┤
│ LAYER 4: Detection         │ Invariant + Correlation + ML       │
├─────────────────────────────────────────────────────────────────┤
│ LAYER 3: Runtime Security  │ Risk Router + Simulator + Engine   │
├─────────────────────────────────────────────────────────────────┤
│ LAYER 2: Normalization     │ Normalization + Parser Services     │
├─────────────────────────────────────────────────────────────────┤
│ LAYER 1: Data Ingestion    │ bloXroute + Chain Listeners + RPC  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Main Data Flows

### Flow 1: Event Collection → Storage
```
Chain Listeners → Redis Event Bus → Worker → PostgreSQL
```

### Flow 2: Runtime Security Detection
```
bloXroute → Runtime Engine → Risk Router → Simulator → Invariant → Database
```

### Flow 3: Frontend Query
```
Frontend → API Service → PostgreSQL → Frontend
```

---

## 📦 Microservices Summary

| Layer | Component | Type | Communication |
|-------|-----------|------|---------------|
| **L1** | bloXroute Source | Component | WebSocket → Redis |
| **L1** | Chain Listeners | Component | HTTP/RPC → Redis |
| **L2** | Normalization | Component | Redis → Redis |
| **L3** | Runtime Engine | Orchestrator | Redis → Redis → DB |
| **L3** | Risk Router | Component | Internal |
| **L3** | Anvil Simulator | Component | HTTP (local) |
| **L4** | Invariant Engine | Component | DB → DB |
| **L5** | PostgreSQL | Storage | SQL |
| **L5** | Redis | Storage | Redis Streams/PubSub |
| **L6** | API Service | Microservice | HTTP → DB |
| **L6** | Worker Service | Microservice | Redis → DB |
| **L7** | Frontend | Static | HTTP → API |

---

## 🌐 Deployment (GCP Cloud Run)

```
┌─────────────────────────────────────────┐
│  API Service (Port 8080)                │
│  • FastAPI REST API                     │
│  • Static file serving                  │
│  • VPC: sentinel3-connector             │
└─────────────────────────────────────────┘
              │
              ├─> PostgreSQL (Cloud SQL)
              └─> Redis (Memorystore)
              
┌─────────────────────────────────────────┐
│  Worker Service (Port 9090)             │
│  • Ingestion Loop                       │
│  • Detection Loop                       │
│  • Runtime Security Loop                │
│  • VPC: sentinel3-connector             │
└─────────────────────────────────────────┘
              │
              ├─> PostgreSQL (Cloud SQL)
              ├─> Redis (Memorystore)
              ├─> bloXroute (WebSocket)
              └─> RPC Providers (HTTP)
```

---

## 🔗 Key Communication Protocols

- **HTTP/HTTPS**: Frontend ↔ API, API ↔ Database, Worker ↔ RPC
- **WebSocket**: bloXroute ↔ Worker, Chain Listeners ↔ RPC
- **Redis Streams**: Event bus (publish/consume)
- **Redis Pub/Sub**: Runtime security events
- **PostgreSQL**: Persistent storage (async SQLAlchemy)
- **HTTP (local)**: Worker ↔ Anvil Simulator

---

**Quick Links**:
- Full Blueprint: `docs/SYSTEM_BLUEPRINT.md`
- Visual Diagrams: `docs/ARCHITECTURE_DIAGRAMS.md`
- Architecture Deep Dive: `docs/ARCHITECTURE.md`
