# Sentinel3 - Explainable Web3 XDR

## Cross-Chain Bridge Attack Detection & Response Platform

> **Mission**: Detect, explain, and stop cross-chain bridge exploits at runtime—before irreversible loss.

---

## 🎯 Executive Summary

Sentinel3 is a **runtime security layer** for cross-chain bridges that:

1. **Detects** economic invariant violations (mint without lock, unbacked transfers)
2. **Correlates** cross-chain events into single, actionable incidents
3. **Explains** in human language WHY something is an attack
4. **Quantifies** blast radius and loss rate in real-time
5. **Guides** safe human-in-the-loop response

### Core Design Principle: On-Chain Truth Only

> **How does this system detect and stop an attack that the smart contract itself believes is valid?**

**Answer**: By enforcing **economic invariants** that exist *outside* any single contract's logic. A bridge contract may accept a forged message and mint tokens—it believes the transaction is valid. But our system observes that `minted_on_chain_B > locked_on_chain_A` within the correlation window. This is an **economic truth violation** that no single contract can detect, but cross-chain observation makes obvious.

**We rely ONLY on on-chain truth:**
- ✅ Blockchain event logs
- ✅ Transaction data
- ✅ Block headers
- ✅ Cross-chain correlation keys
- ❌ NO bridge messages/attestations
- ❌ NO trust assumptions
- ❌ NO audits or code reviews

---

## 📊 Architecture Overview

### Split Architecture (API vs Worker)

```mermaid
graph TB
    subgraph "API Service (Port 8080)"
        API[FastAPI Server]
        Dashboard[Admin Dashboard UI]
        Routes[API Routes]
        Auth[JWT Auth + RBAC]
    end
    
    subgraph "Worker Service (Port 9090)"
        Worker[Worker Process]
        Ingestion[Ingestion Loop]
        Detection[Detection Loop]
        Health[Health Server]
    end
    
    subgraph "Blockchain Layer"
        EVM[EVM Chains<br/>Ethereum, Polygon, Arbitrum]
        Cosmos[Cosmos Chains<br/>Cosmos Hub, Osmosis]
        Aptos[Aptos/Sui]
    end
    
    subgraph "Storage Layer"
        Redis[(Redis<br/>Event Bus + Checkpoints)]
        Postgres[(PostgreSQL<br/>Events + Incidents)]
    end
    
    EVM --> Worker
    Cosmos --> Worker
    Aptos --> Worker
    
    Worker --> Ingestion
    Ingestion --> Redis
    Detection --> Redis
    Detection --> Postgres
    
    API --> Postgres
    API --> Redis
    Dashboard --> API
    
    Worker --> Health
```

### Component Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SENTINEL3 ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Ethereum   │  │   Polygon   │  │   Cosmos    │  │   Aptos     │        │
│  │  Listener   │  │  Listener   │  │  Listener   │  │  Listener   │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
│         │                │                │                │                │
│         └────────────────┴────────────────┴────────────────┘                │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    WORKER: Ingestion Loop                            │   │
│  │  • Poll chains (EVM: eth_getLogs, Cosmos: Tendermint, Aptos: REST) │   │
│  │  • Track finality (reorg detection)                                │   │
│  │  • Checkpoint management (resume after restart)                    │   │
│  │  • Publish to Event Bus (Redis Streams)                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    NORMALIZATION LAYER                               │   │
│  │  • Unified SecurityEvent schema                                      │   │
│  │  • Chain-agnostic asset/entity mapping                              │   │
│  │  • Temporal alignment (block → timestamp)                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    WORKER: Detection Loop                              │   │
│  │  • Consume from Event Bus                                            │   │
│  │  • Bridge Adapter identification (Wormhole, LayerZero, Stargate)     │   │
│  │  • Protocol-specific invariants (MINT_LOCK_PARITY, LIQUIDITY_PARITY)│   │
│  │  • Cross-chain correlation (CorrelationKey matching)                 │   │
│  │  • Incident building (deduplication, clustering)                    │   │
│  │  • Explainability (structured explanations)                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    API SERVICE                                       │   │
│  │  • Dashboard UI (incidents, events, chains status)                  │   │
│  │  • Admin Console (rules, chains, users)                             │   │
│  │  • Guardian Controls (pause, override)                             │   │
│  │  • Audit Logs (all actions logged)                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    GUARDIAN SYSTEM                                    │   │
│  │  • Pause Policy (safety checks, cooldown, thresholds)               │   │
│  │  • Secure Signer (whitelist verification)                            │   │
│  │  • Automated Response (with human approval for high-value)          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Threat Model Coverage

| Attack Type | Detection Method | Invariant |
|------------|------------------|-----------|
| **Mint without Lock** | Cross-chain balance correlation | `minted ≤ locked` |
| **Forged Bridge Message** | Source chain verification | `message_exists_on_source = true` |
| **Validator Key Compromise** | Multi-sig threshold monitoring | `valid_signatures ≥ threshold` |
| **Liquidity Drain** | TVL velocity monitoring | `Δ TVL / Δt < threshold` |
| **Flash Loan Amplification** | Single-block pattern detection | `borrow → exploit → repay ∈ same_block` |
| **Cross-Chain Laundering** | Entity graph tracing | `funds_traced_to_source = true` |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- PostgreSQL 14+
- Redis 6+
- Docker & Docker Compose (optional)

### Local Development

```bash
# Clone repository
git clone https://github.com/vaibhav3104/web3-xdr.git
cd web3-xdr

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export REDIS_URL="redis://localhost:6379/0"
export DATABASE_URL="postgresql://xdr:xdr_password@localhost:5432/web3_xdr"
export JWT_SECRET_KEY="your-secret-key-here"

# Run verification script
python scripts/verify_system.py

# Start services with Docker Compose
docker-compose up -d

# Or run manually:
# Terminal 1: Worker
PROC_TYPE=worker python -m src.worker.main

# Terminal 2: API
PROC_TYPE=api python -m src.api.server
```

### Access Dashboard

- **API**: http://localhost:8080
- **Dashboard**: http://localhost:8080 (served by API)
- **Worker Health**: http://localhost:9090/health
- **Metrics**: http://localhost:9090/metrics

---

## 📁 Project Structure

```
web3-xdr/
├── src/
│   ├── api/              # FastAPI server (Dashboard + API)
│   ├── worker/           # Worker process (Ingestion + Detection)
│   ├── telemetry/        # Chain listeners (EVM, Cosmos, Aptos)
│   ├── invariants/       # Invariant detection engine
│   ├── bridges/          # Bridge adapters (Wormhole, LayerZero, etc.)
│   ├── correlation/      # Cross-chain correlation engine
│   ├── explainability/   # Explanation generation
│   ├── response/         # Guardian system (pause, signer, policy)
│   ├── database/         # Models, migrations, audit logs
│   └── auth/             # JWT authentication + RBAC
├── config/
│   ├── chains.yaml       # Chain configurations
│   └── rules/            # YAML detection rules
├── scripts/
│   └── verify_system.py  # Pre-flight verification
├── docker-compose.yml    # Local development
├── Dockerfile            # Production image
└── README.md             # This file
```

---

## 🔧 Configuration

### Chains Configuration (`config/chains.yaml`)

```yaml
chains:
  - chain_id: ethereum
    chain_name: Ethereum Mainnet
    chain_type: evm
    rpc_urls:
      - https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
      - https://mainnet.infura.io/v3/YOUR_KEY
    finality:
      confirmations: 12
      max_reorg_depth: 20
      block_time_seconds: 12.0
  
  - chain_id: cosmos
    chain_name: Cosmos Hub
    chain_type: cosmos
    tendermint_rpc: https://rpc.cosmos.network
    ibc_channels:
      - channel-0
      - channel-141
```

### Environment Variables

See `DEPLOYMENT.md` for full reference.

**Critical:**
- `REDIS_URL`: Redis connection (Event Bus)
- `DATABASE_URL`: PostgreSQL connection
- `JWT_SECRET_KEY`: JWT signing key

**Optional:**
- `GUARDIAN_PRIVATE_KEY`: Guardian wallet (dev/test only)
- `RPC_TIMEOUT`: RPC request timeout (default: 30s)
- `POLL_INTERVAL_SECONDS`: Polling interval (default: 2s)

---

## 🛡️ Security Features

### Phase 5: Guardian Hardening

- **Pause Policy**: Multiple safety checks before pause
- **Secure Signer**: Whitelist verification, KMS support (stub)
- **RBAC**: Role-based access control (viewer, operator, admin)
- **Audit Logging**: All actions logged with actor ID
- **Rule Validation**: Dry-run before deployment

### Phase 6: Reliability

- **Checkpointing**: Resume from last processed block
- **Finality Tracking**: Reorg detection and handling
- **Multi-RPC Failover**: Automatic failover with health tracking
- **Event Bus**: Decoupled ingestion and detection

---

## 📚 Documentation

- **DEPLOYMENT.md**: Production deployment guide (GCP Cloud Run)
- **PHASE5_IMPLEMENTATION.md**: Guardian hardening details
- **API Documentation**: http://localhost:8080/docs (Swagger UI)

---

## 🧪 Testing

```bash
# Run verification script
python scripts/verify_system.py

# Run tests (if available)
pytest tests/

# Test specific component
python -c "from src.telemetry.checkpoint import CheckpointManager; print('OK')"
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Run verification script
5. Submit pull request

---

## 📄 License

MIT License - See LICENSE file

---

## 🆘 Support

- **Issues**: https://github.com/vaibhav3104/web3-xdr/issues
- **Documentation**: See `DEPLOYMENT.md` for deployment help

---

**Built with ❤️ for Web3 Security**

