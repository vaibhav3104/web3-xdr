# Sentinel3 - Web3 Extended Detection & Response

Real-time security monitoring, invariant detection, and automated response for EVM bridges, DeFi protocols, and multi-chain ecosystems.

![Deploy](https://github.com/vaibhav3104/sentinel3/actions/workflows/deploy-gcp.yml/badge.svg)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Architecture

Sentinel3 runs as two cooperating processes behind a shared PostgreSQL database and Redis cache:

```
                       Internet
                          |
               +----------+----------+
               |   Cloud Run (API)   |    FastAPI + static frontend
               |   /api/* + /frontend|    JWT auth, rate limiting, CORS
               +----------+----------+
                          |
          +---------------+---------------+
          |                               |
   +------+------+               +-------+-------+
   |  PostgreSQL  |               |     Redis     |
   |  (events,    |               |  (shared state|
   |   incidents, |               |   pub/sub,    |
   |   audit log) |               |   caching)    |
   +------+------+               +-------+-------+
          |                               |
               +----------+----------+
               | Cloud Run (Worker)  |    Blockchain listeners, rule engine,
               | Listener + ML       |    ML inference, alerting
               +----------+----------+
                          |
          +-------+-------+-------+-------+
          | ETH   | Polygon| Arbitrum| ... |   RPC / WebSocket
          +-------+-------+-------+-------+

Optional:
  - Neo4j          Security graph (fund tracing, attack paths)
  - Vertex AI      Managed ML inference (GPU)
  - Foundry/Anvil  Transaction simulation (runtime security)
```

**API process** (`PROC_TYPE=api`): FastAPI server serving the REST API, interactive docs, WebSocket streams, and the glassmorphism frontend.

**Worker process** (`PROC_TYPE=worker`): Long-running blockchain listeners (EVM + Cosmos/Aptos/Near/Solana), rule engine evaluation, ML anomaly detection, cross-chain correlation, and alert dispatch.

---

## Key Features

- **Invariant Detection Engine** -- economic, temporal, governance, and liquidity invariants enforced across chains (lock/mint parity, velocity thresholds, admin key monitoring)
- **Cross-Chain Correlation** -- links events across EVM and non-EVM chains into unified incidents with configurable time windows and amount tolerance
- **MEV & Mempool Monitoring** -- pre-confirmation threat detection via bloXroute mempool source with real-time alerting
- **Forensics & Fund Tracing** -- Neo4j-backed security graph for attack path reconstruction and fund flow visualization
- **Guardian Response** -- automated or human-in-the-loop pause/unpause of bridge contracts via local keys or Cloud KMS signing
- **Multi-Tenant Isolation** -- tenant middleware, per-tenant API keys, and role-based access (admin / operator / viewer)
- **ML Anomaly Detection** -- transformer, CNN, ensemble, and random forest classifiers for contract bytecode and transaction patterns; continuous learning from production data
- **WebSocket Streaming** -- real-time event and incident feeds to the frontend dashboard
- **Threat Intelligence** -- integrated threat intel feeds with wallet/contract risk scoring
- **Alerting** -- Telegram, Slack, email (SMTP / SendGrid), and PagerDuty notifications with configurable severity thresholds
- **Runtime Security Plane** -- Foundry/Anvil-based transaction simulation with per-chain and per-protocol budgets

---

## Quick Start (Local Development)

```bash
# Clone
git clone https://github.com/vaibhav3104/sentinel3.git
cd sentinel3

# Python environment
python3.11 -m venv .venv
source .venv/bin/activate

# Dependencies (PyTorch CPU-only is installed automatically)
pip install -r requirements.txt

# Environment
cp .env.example .env
# Edit .env -- at minimum set DATABASE_URL, REDIS_URL, and one XDR_USER_* account

# Start backing services (PostgreSQL + Redis)
docker compose up -d postgres redis

# Run database migrations
python -m alembic upgrade head

# Start API server (port 8080 by default)
python -m src.api.server

# In a second terminal -- start the worker
python worker.py                         # all chains
python worker.py --chains ethereum       # single chain
python worker.py --type evm              # EVM chains only
```

The dashboard is served at `http://localhost:8080` and interactive API docs at `http://localhost:8080/api/docs`.

---

## Deployment (GCP Cloud Run)

Production deployment is handled by Cloud Build (`cloudbuild-deploy.yaml`) and deploys three Cloud Run services:

| Service | Purpose | Resources |
|---------|---------|-----------|
| `sentinel3` | GPU-accelerated ML inference | 16 GiB / 4 vCPU / 1x NVIDIA L4 |
| `web3-xdr-production-api` | API + frontend | 4 GiB / 2 vCPU |
| `web3-xdr-production-worker` | Blockchain listeners | 4 GiB / 2 vCPU (always-on) |

The pipeline runs seven phases:
1. **SAST** -- Bandit (code), Safety (dependencies), detect-secrets
2. **Docker build** -- multi-stage (builder + slim runtime)
3. **Container scan** -- Trivy for CRITICAL/HIGH CVEs
4. **Push** to Artifact Registry
5. **Deploy** all three Cloud Run services
6. **DAST** -- SQLi, XSS, path traversal, auth bypass, header checks
7. **Security report** -- aggregated pass/fail summary

Secrets are injected from GCP Secret Manager via `--update-secrets`.

---

## API Documentation

Interactive Swagger UI is available at `/api/docs` and ReDoc at `/api/redoc` on any running API instance.

Authentication: all `/v1/*` endpoints require an `X-API-Key` header. Rate limits apply per tier (Free 100/min, Pro 1000/min, Enterprise custom).

---

## Project Structure

```
sentinel3/
|-- src/
|   |-- api/            # FastAPI routes, middleware, WebSocket, auth
|   |-- auth/           # JWT handler, tenant middleware
|   |-- ai/             # LLM integration, ML training, bytecode collector
|   |-- ml/             # Threat detector, anomaly models, Vertex AI
|   |-- telemetry/      # EVM / Cosmos / Aptos / Near / Solana listeners
|   |-- invariants/     # Invariant definitions and validation engine
|   |-- correlation/    # Cross-chain event correlation
|   |-- rules/          # Detection rule engine, feedback loop, spike detection
|   |-- runtime/        # Mempool alerter, simulation, risk router
|   |-- response/       # Guardian, PagerDuty, email, Slack, Telegram
|   |-- graph/          # Neo4j security graph
|   |-- forensics/      # Fund tracing and attack reconstruction
|   |-- database/       # PostgreSQL connection, Redis manager, sync service
|   |-- pipeline/       # Event bus (Redis Streams)
|   |-- worker/         # Production worker main loop
|   |-- scanner/        # Contract bytecode scanner
|   |-- config/         # Centralized settings
|   `-- explainability/ # Human-readable incident explanations
|-- frontend/           # Static HTML/JS dashboard (glassmorphism UI)
|-- config/             # Chain YAML configs, detection rules
|-- alembic/            # Database migrations
|-- scripts/            # Operational scripts (training, graph, verification)
|-- serving/            # Model serving endpoint
|-- monitoring/         # Grafana dashboards, Prometheus config
|-- Dockerfile          # Multi-stage production image
|-- docker-compose.yml  # Local dev stack
|-- cloudbuild-deploy.yaml  # CI/CD pipeline
|-- worker.py           # Standalone worker entry point
|-- monitor.py          # Lightweight monitor process
|-- entrypoint.sh       # Container entry (API vs Worker via PROC_TYPE)
`-- requirements.txt    # Python dependencies
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI, Uvicorn, Pydantic v2 |
| Frontend | Vanilla JS, Alpine.js, glassmorphism design system |
| Database | PostgreSQL (asyncpg + SQLAlchemy 2.0), Alembic |
| Cache / Pub-Sub | Redis 5+ (redis-py, Redis Streams) |
| Graph DB | Neo4j 5+ |
| ML / AI | PyTorch, scikit-learn, XGBoost, ONNX Runtime |
| LLM | Google Gemini, Anthropic Claude (via AI routes) |
| Blockchain | web3.py (EVM), solana-py, anchorpy, custom Cosmos/Aptos/Near clients |
| Simulation | Foundry (Anvil, Cast, Forge) |
| Auth | JWT (PyJWT + python-jose), API key tiers |
| Observability | Prometheus, OpenTelemetry, structlog |
| Infra | GCP Cloud Run, Artifact Registry, Secret Manager, Cloud Build |
| Security | Bandit, Safety, detect-secrets, Trivy |

---

## License

MIT License -- see `LICENSE` for details.
