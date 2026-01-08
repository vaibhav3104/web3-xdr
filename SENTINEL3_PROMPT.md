# SENTINEL3 - Explainable Web3 XDR System
## Ultra-Comprehensive Development Prompt

---

## 🎯 PRIMARY OBJECTIVE

You are developing **Sentinel3**, an Explainable Web3 Extended Detection and Response (XDR) system focused on:
- **Detecting** cross-chain bridge and DeFi protocol exploits in real-time
- **Explaining** detections with human-readable context (what happened, why it's bad, what to do)
- **Responding** with automated or manual intervention (pause contracts, alert teams)

### Core Principles
1. **On-chain truth only** - Never trust off-chain data or bridge messages
2. **Economic invariants** - Detect violations like "mint without lock"
3. **Deterministic logic** - Prefer rules over probabilistic ML for critical alerts
4. **Explainability** - Every alert must explain WHY it triggered
5. **Multi-chain correlation** - Track attacks across blockchains

---

## 🏗️ ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SENTINEL3 ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    BLOCKCHAIN TELEMETRY LAYER                        │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  EVM Listener     │ Solana Listener │ Cosmos │ Aptos │ Near        │   │
│  │  (Eth, Polygon,   │ (via JSON-RPC)  │ (IBC)  │ (Move)│ (Rainbow)   │   │
│  │   Arb, Base...)   │                 │        │       │             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    NORMALIZATION LAYER                               │   │
│  │  Raw Events → Unified SecurityEvent Schema → Enrichment             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    DETECTION ENGINE                                  │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  Invariant Engine │ YAML Rules │ ML Contract │ Cross-Chain         │   │
│  │  (Economic/Velocity)│ (Custom)  │ Classifier  │ Correlator          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    EXPLAINABILITY ENGINE                             │   │
│  │  Detection → Human Explanation → Recommended Actions                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    RESPONSE LAYER                                    │   │
│  │  Alerting (Slack/Telegram) │ Guardian (Pause) │ Dashboard           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 PROJECT STRUCTURE

```
web3-xdr/
├── monitor.py                 # Main entry point - multi-chain monitoring
├── config/
│   ├── chains.yaml           # Chain configurations (RPCs, contracts)
│   └── parsers.yaml          # Event parser definitions
├── src/
│   ├── api/                  # FastAPI REST endpoints
│   │   ├── server.py         # Main FastAPI app
│   │   ├── routes.py         # Core API routes (/stats, /events, /incidents)
│   │   ├── admin_routes.py   # Admin console API
│   │   ├── auth_routes.py    # JWT authentication
│   │   ├── ai_routes.py      # ML/AI endpoints
│   │   ├── guardian_routes.py # Contract pause system
│   │   ├── simulator_routes.py # Attack simulation
│   │   └── ...
│   ├── telemetry/            # Blockchain listeners
│   │   ├── evm_listener.py   # Ethereum-compatible chains
│   │   ├── solana_listener.py
│   │   ├── cosmos_listener.py # IBC chains
│   │   ├── aptos_listener.py  # Move-based chains
│   │   ├── near_listener.py
│   │   └── event_signatures.py # Known event hashes
│   ├── invariants/           # Economic invariant detection
│   │   ├── engine.py         # Orchestrates all invariants
│   │   ├── economic.py       # Mint/Lock parity, TVL
│   │   ├── velocity.py       # Rate-based detection
│   │   ├── threshold.py      # Signature count, admin actions
│   │   └── temporal.py       # Time-based patterns
│   ├── correlation/          # Cross-chain analysis
│   │   ├── cross_chain.py    # Bridge event correlation
│   │   ├── entity_graph.py   # Address/contract relationships
│   │   └── incident_builder.py
│   ├── explainability/       # Human-readable explanations
│   │   ├── engine.py
│   │   └── templates.py
│   ├── ai/                   # ML-based detection
│   │   ├── models/
│   │   │   ├── contract_classifier.py  # Bytecode analysis
│   │   │   └── deep_classifier.py      # PyTorch models
│   │   ├── training/
│   │   │   └── pipeline.py   # Training orchestration
│   │   ├── data/
│   │   │   ├── attack_database.py     # Historical attacks
│   │   │   ├── exploit_database.py    # Known exploit contracts
│   │   │   └── bytecode_extractor.py  # Feature extraction
│   │   └── collectors/
│   │       └── auto_collector.py      # Real-time contract collection
│   ├── response/             # Automated response
│   │   ├── guardian.py       # Contract pause system
│   │   ├── alerting.py       # Alert dispatch
│   │   ├── telegram.py
│   │   └── slack.py
│   ├── database/             # PostgreSQL persistence
│   │   ├── models.py         # SQLAlchemy models
│   │   ├── service.py        # Async DB operations
│   │   └── sync_service.py   # Sync DB operations
│   ├── query/                # Log search
│   │   └── lucene_parser.py  # Lucene-style query support
│   ├── shared_state.py       # In-memory state management
│   └── models/               # Data models
│       ├── events.py
│       ├── incidents.py
│       └── invariants.py
├── frontend/                 # Web UI
│   ├── index.html           # Main dashboard
│   ├── admin.html           # Admin console
│   ├── logs.html            # Log explorer
│   ├── guardian.html        # Pause system UI
│   ├── simulator.html       # Attack simulator
│   ├── ml-analysis.html     # Contract scanner
│   └── parsers.html         # Parser management
├── scripts/                  # Utility scripts
│   ├── train_deep_models.py
│   ├── collect_bytecode.py
│   └── validate_before_push.py
├── tests/                    # Test suite
├── .github/workflows/
│   └── deploy.yml           # CI/CD to GCP Cloud Run
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🔗 CHAINS MONITORED

### EVM Chains (Working ✅)
| Chain | RPC | Status |
|-------|-----|--------|
| Ethereum | eth.llamarpc.com | ✅ Active |
| Polygon | polygon-rpc.com | ✅ Active |
| Arbitrum | arb1.arbitrum.io/rpc | ✅ Active |
| Optimism | mainnet.optimism.io | ✅ Active |
| Base | mainnet.base.org | ✅ Active |
| Avalanche | api.avax.network | ✅ Active |
| BSC | bsc-dataseed.binance.org | ✅ Active |

### Non-EVM Chains (Configured, Initialization Issues)
| Chain | Type | RPC |
|-------|------|-----|
| Cosmos Hub | Cosmos/IBC | cosmos-rpc.polkachu.com |
| Osmosis | Cosmos/IBC | osmosis-rpc.polkachu.com |
| Injective | Cosmos/IBC | injective-rpc.polkachu.com |
| Aptos | Move | fullnode.mainnet.aptoslabs.com |
| Sui | Move | fullnode.mainnet.sui.io |
| Near | Near | rpc.mainnet.near.org |

---

## 🌉 BRIDGE PROTOCOLS MONITORED

| Protocol | Type | Chains |
|----------|------|--------|
| Wormhole | Messaging | All major chains |
| LayerZero | Messaging | EVM chains |
| Stargate | Liquidity | EVM chains |
| Across | Liquidity | L2s |
| Hop Protocol | Liquidity | L2s |
| Synapse | Liquidity | Multi-chain |
| Celer cBridge | Liquidity | Multi-chain |

---

## 🔍 DETECTION CAPABILITIES

### 1. Invariant-Based Detection (Rule Engine)

```yaml
# Example: Mint without Lock detection
type: invariant
invariant: MINT_LOCK_PARITY
conditions:
  - field: minted_amount
    operator: gt
    compare_to: locked_amount
    tolerance: 0.01
time_window: 10m
correlation:
  source_chain: any
  dest_chain: any
  require_bridge_match: true
```

**Invariant Types:**
- `MINT_LOCK_PARITY` - Tokens minted must equal tokens locked
- `VALIDATOR_THRESHOLD` - Minimum signatures required
- `TVL_VELOCITY` - Sudden liquidity drain detection
- `ADMIN_ACTION_RATE` - Suspicious admin activity
- `LARGE_TRANSACTION` - High-value transfer alerts

### 2. YAML-Based Custom Rules

```yaml
# Example: Flash Loan Attack Detection
name: "Flash Loan Attack Pattern"
type: event
severity: critical
conditions:
  - field: event_type
    operator: contains
    value: "FlashLoan"
  - field: amount_usd
    operator: gt
    value: 1000000
actions:
  - alert
  - log
```

### 3. ML Contract Classification

**Models Available:**
- RandomForest (default)
- MLP (Multi-Layer Perceptron)
- CNN (Convolutional Neural Network)
- Transformer
- Ensemble

**Threat Categories:**
- `safe` - Normal contract
- `flash_loan_exploit` - Flash loan attack pattern
- `reentrancy_exploit` - Reentrancy vulnerability
- `bridge_exploit` - Bridge-specific attack
- `rug_pull` - Token scam pattern
- `price_manipulation` - Oracle manipulation

### 4. Cross-Chain Correlation

Detects attacks spanning multiple chains:
```
Lock on Ethereum → Mint on Polygon
           ↓
    Correlation Engine
           ↓
    Violation if: mint > lock
```

---

## 🛡️ GUARDIAN SYSTEM (Automated Response)

The Guardian system can pause smart contracts when attacks are detected:

```python
# Register a protocol for automated pause
POST /api/guardian/protocols
{
    "protocol_id": "my-defi",
    "name": "My DeFi Protocol",
    "chain_id": "ethereum",
    "pause_contract": "0x...",
    "pause_function": "pause()",
    "guardian_address": "0x...",
    "auto_pause_enabled": true,
    "pause_threshold": "critical"
}
```

**Pause Triggers:**
- Critical severity incident
- Cross-chain parity violation
- ML-detected exploit contract deployment

---

## 🖥️ API ENDPOINTS

### Core Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | System statistics |
| `/api/events` | GET | List security events |
| `/api/incidents` | GET | List incidents |
| `/api/incidents/{id}` | GET | Incident details |
| `/health` | GET | Health check |

### Admin Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/chains` | GET | Chain configurations |
| `/api/admin/rules` | GET/POST | Detection rules |
| `/api/admin/parsers` | GET/POST | Event parsers |

### AI/ML Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ai/analyze` | POST | Analyze contract bytecode |
| `/api/ai/collector/start` | POST | Start contract collector |
| `/api/contracts/analyze/{address}` | GET | Analyze deployed contract |

### Guardian Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/guardian/protocols` | GET/POST | Manage protocols |
| `/api/guardian/pause/{id}` | POST | Trigger pause |
| `/api/guardian/status` | GET | Guardian status |

### Query Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/events?query=...` | GET | Lucene-style search |
| `/api/chains/status` | GET | Chain connection status |
| `/api/chains/test-rpc` | GET | Test RPC connections |

---

## 🔐 AUTHENTICATION

JWT-based authentication for admin operations:

```python
# Login
POST /api/auth/login
{"username": "admin", "password": "..."}
→ {"access_token": "eyJ..."}

# Use token
GET /api/admin/rules
Authorization: Bearer eyJ...
```

---

## 📊 DASHBOARD FEATURES

### Main Dashboard (`/frontend/index.html`)
- Real-time incident count (Critical/High/Medium/Low)
- Active incidents list with details
- Events per chain visualization
- System health indicators

### Log Explorer (`/frontend/logs.html`)
- Lucene-style query support
- Time range filtering (5m, 15m, 1h, 24h, custom)
- Chain/severity/type filters
- Event details expansion

### Admin Console (`/frontend/admin.html`)
- Chain & RPC configuration
- Detection rules management
- Alert configuration (Slack/Telegram)
- User management

### Attack Simulator (`/frontend/simulator.html`)
- Flash Loan Attack simulation
- Reentrancy Attack simulation
- Bridge Exploit simulation
- Rug Pull simulation
- Money Laundering simulation

### Contract Scanner (`/frontend/ml-analysis.html`)
- Analyze contract by address
- Bytecode threat classification
- Risk scoring

### Guardian (`/frontend/guardian.html`)
- Register protocols
- Manual pause triggers
- Pause history

---

## ☁️ DEPLOYMENT

### GCP Cloud Run (Production)
```
Production URL: https://web3-xdr-production-1003459948096.us-central1.run.app
Repository: https://github.com/vaibhav3104/web3-xdr
```

### CI/CD Pipeline (`.github/workflows/deploy.yml`)
1. Run tests
2. Build Docker image
3. Push to Artifact Registry
4. Deploy to Cloud Run

### Environment Variables
```bash
POSTGRES_ENABLED=true
DATABASE_URL=postgresql://...
OPENAI_API_KEY=sk-...  # For AI analysis
INFURA_API_KEY=...     # Optional: premium RPCs
```

---

## 🧪 TESTING

```bash
# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src

# Pre-push validation
python scripts/validate_before_push.py
```

---

## 📈 METRICS & MONITORING

### Prometheus Metrics (`/metrics`)
- `sentinel3_events_total` - Total events processed
- `sentinel3_incidents_total` - Total incidents created
- `sentinel3_blocks_scanned` - Blocks scanned per chain
- `sentinel3_detection_latency` - Detection speed

### Health Checks
- `/health` - Basic health
- `/api/stats` - Detailed statistics
- `/api/chains/status` - Chain connection health

---

## 🔧 KNOWN ISSUES & LIMITATIONS

1. **Non-EVM Chains**: Cosmos, Aptos, Sui, Near chains configured but not initializing in Cloud Run (background thread issue)
2. **Solana**: Listener exists but not fully integrated
3. **ML Models**: Trained on limited data, needs more real exploit contracts
4. **Guardian**: Requires protocol integration (smart contract must grant pauser role)

---

## 🎯 THREAT MODEL

Attacks the system is designed to detect:

| Attack Type | Detection Method |
|-------------|------------------|
| Mint without Lock | MINT_LOCK_PARITY invariant |
| Forged Bridge Messages | Validator signature count |
| Validator Key Compromise | Signature threshold violation |
| Flash Loan Attacks | Event pattern + ML classification |
| Reentrancy | Bytecode analysis + event patterns |
| Governance Abuse | Admin action velocity |
| Liquidity Drain | TVL velocity monitoring |
| Cross-chain Laundering | Multi-chain correlation |

---

## 🚀 FUTURE ENHANCEMENTS

1. **More Chains**: Full Solana, Cosmos IBC support
2. **Real-time Prevention**: Mempool monitoring + front-running defense
3. **Advanced ML**: GNN for attack graph analysis
4. **Grafana Dashboards**: Professional visualization
5. **Multi-tenancy**: Support multiple customer organizations
6. **Smart Contract Validation**: Pre-deployment vulnerability scanning

---

## 📝 QUICK START

```bash
# Clone and setup
git clone https://github.com/vaibhav3104/web3-xdr.git
cd web3-xdr
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure chains (copy and edit)
cp config/chains.example.yaml config/chains.yaml

# Run locally
python monitor.py

# Access dashboard
open http://localhost:8080/frontend/index.html
```

---

## 💡 KEY CODE PATTERNS

### Adding a New Detection Rule
```python
# src/invariants/custom.py
class CustomInvariant(BaseInvariant):
    async def evaluate(self, context: InvariantContext) -> Optional[Violation]:
        # Your detection logic
        if suspicious_condition:
            return Violation(
                type="CUSTOM_VIOLATION",
                severity="critical",
                description="What happened",
                evidence={"data": "..."}
            )
        return None
```

### Adding a New Chain Listener
```python
# src/telemetry/new_chain_listener.py
class NewChainListener(BaseListener):
    async def connect(self) -> bool:
        # Connect to RPC
        pass
    
    async def scan_events(self) -> List[SecurityEvent]:
        # Fetch and normalize events
        pass
```

### Adding an API Endpoint
```python
# src/api/routes.py
@router.get("/custom-endpoint")
async def custom_endpoint():
    return {"data": "..."}
```

---

## 🔑 IMPORTANT CONSTANTS

```python
# Bridge contract addresses (Ethereum)
WORMHOLE_CORE = "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"
LAYERZERO_ENDPOINT = "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675"
STARGATE_ROUTER = "0x8731d54E9D02c286767d56ac03e8037C07e01e98"

# Event signatures (keccak256)
TRANSFER_TOPIC = "0xddf252ad..."
WORMHOLE_MESSAGE = "0x6eb22..."
```

---

---

## 📋 DATA MODELS

### SecurityEvent (Unified Event Schema)
```python
@dataclass
class SecurityEvent:
    # Identity
    event_id: str           # UUID
    chain_id: str           # "ethereum", "polygon", etc.
    block_number: int
    block_timestamp: datetime
    tx_hash: str
    log_index: int
    
    # Classification
    event_type: EventType   # TRANSFER, LOCK, MINT, FLASH_BORROW, etc.
    severity: Severity      # INFO, LOW, MEDIUM, HIGH, CRITICAL
    
    # Entities
    source_address: str     # Sender
    dest_address: str       # Recipient
    contract_address: str   # Contract emitting event
    
    # Asset information
    asset_type: str         # Token symbol or "NATIVE"
    asset_address: str      # Token contract
    amount: Decimal
    amount_usd: Decimal
    
    # Bridge-specific
    bridge_id: Optional[str]
    message_hash: Optional[str]
    source_chain: Optional[str]
    dest_chain: Optional[str]
```

### EventType Enum
```python
class EventType(Enum):
    # Asset movements
    TRANSFER = "transfer"
    LOCK = "lock"
    UNLOCK = "unlock"
    MINT = "mint"
    BURN = "burn"
    
    # Bridge operations
    BRIDGE_DEPOSIT = "bridge_deposit"
    BRIDGE_WITHDRAW = "bridge_withdraw"
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    
    # Governance
    PROPOSAL_CREATED = "proposal_created"
    PROPOSAL_EXECUTED = "proposal_executed"
    ADMIN_ACTION = "admin_action"
    
    # Flash loans
    FLASH_BORROW = "flash_borrow"
    FLASH_REPAY = "flash_repay"
    
    # DeFi operations
    SWAP = "swap"
    LIQUIDITY_ADD = "liquidity_add"
    LIQUIDITY_REMOVE = "liquidity_remove"
    
    # Contract operations
    CONTRACT_DEPLOY = "contract_deploy"
```

### CrossChainViolation
```python
@dataclass
class CrossChainViolation:
    id: str
    violation_type: ViolationType  # MINT_WITHOUT_LOCK, AMOUNT_MISMATCH, etc.
    severity: str
    bridge_id: str
    source_chain: str
    dest_chain: str
    timestamp: datetime
    
    lock_amount: float
    mint_amount: float
    amount_difference: float
    estimated_loss_usd: float
    
    description: str
    evidence: Dict[str, Any]
```

---

## 🔐 EVENT SIGNATURES (keccak256)

### Bridge Protocols
```python
BRIDGE_SIGNATURES = {
    # WORMHOLE
    "0x6eb224fb...": {"name": "LogMessagePublished", "type": MESSAGE_SENT, "protocol": "wormhole"},
    "0xcaf280c8...": {"name": "TransferRedeemed", "type": MESSAGE_RECEIVED, "protocol": "wormhole"},
    
    # LAYERZERO
    "0xe9bded5f...": {"name": "Packet", "type": MESSAGE_SENT, "protocol": "layerzero"},
    "0x32ed1a40...": {"name": "SendToChain", "type": BRIDGE_DEPOSIT, "protocol": "layerzero"},
    
    # STARGATE
    "0x34660fc8...": {"name": "Swap", "type": BRIDGE_DEPOSIT, "protocol": "stargate"},
    
    # ACROSS
    "0x8ab9dc6c...": {"name": "FilledRelay", "type": BRIDGE_WITHDRAW, "protocol": "across"},
    "0xafc4df68...": {"name": "FundsDeposited", "type": BRIDGE_DEPOSIT, "protocol": "across"},
    
    # HOP
    "0xe35dddd4...": {"name": "TransferSent", "type": BRIDGE_DEPOSIT, "protocol": "hop"},
    
    # SYNAPSE
    "0xda527370...": {"name": "TokenDeposit", "type": BRIDGE_DEPOSIT, "protocol": "synapse"},
    
    # CELER
    "0x89d8051e...": {"name": "Send", "type": BRIDGE_DEPOSIT, "protocol": "celer"},
}
```

### DeFi Protocols
```python
DEFI_SIGNATURES = {
    # AAVE
    "0x631042c8...": {"name": "FlashLoan", "type": FLASH_BORROW, "protocol": "aave", "severity": "critical"},
    "0xe413a321...": {"name": "LiquidationCall", "type": UNKNOWN, "protocol": "aave", "severity": "high"},
    
    # UNISWAP V3
    "0xc42079f9...": {"name": "Swap", "type": SWAP, "protocol": "uniswap"},
    "0xbdbdb71d...": {"name": "Flash", "type": FLASH_BORROW, "protocol": "uniswap", "severity": "critical"},
    
    # BALANCER
    "0x0d7d75e0...": {"name": "FlashLoan", "type": FLASH_BORROW, "protocol": "balancer", "severity": "critical"},
}
```

---

## 🔄 CROSS-CHAIN CORRELATION

### How It Works
```
┌─────────────────┐                    ┌─────────────────┐
│   Ethereum      │                    │    Polygon      │
│                 │                    │                 │
│  LOCK Event     │──────────────────▶│  MINT Event     │
│  - amount: 100  │   Correlation      │  - amount: 100  │
│  - token: USDC  │   Engine checks:   │  - token: USDC  │
│  - recipient:0x │   1. message_id    │  - recipient:0x │
│  - timestamp:T1 │   2. amounts match │  - timestamp:T2 │
│                 │   3. time < 1 hour │                 │
└─────────────────┘                    └─────────────────┘
                            │
                            ▼
              ┌─────────────────────────┐
              │   Violation Detected?   │
              │                         │
              │ • MINT > LOCK → CRITICAL│
              │ • MINT without LOCK     │
              │ • Amounts differ > 1%   │
              │ • Time anomaly          │
              └─────────────────────────┘
```

### ViolationType Enum
```python
class ViolationType(Enum):
    MINT_WITHOUT_LOCK = "mint_without_lock"      # Critical - Wormhole-style attack
    LOCK_WITHOUT_MINT = "lock_without_mint"      # Funds stuck
    AMOUNT_MISMATCH = "amount_mismatch"          # Amounts differ
    SEQUENCE_VIOLATION = "sequence_violation"   # Message out of order
    REPLAY_ATTACK = "replay_attack"             # Same message twice
    TIME_ANOMALY = "time_anomaly"               # Mint before lock!
```

---

## 🤖 ML CONTRACT CLASSIFICATION

### Threat Categories
```python
class ThreatCategory(Enum):
    SAFE = "safe"
    FLASH_LOAN_EXPLOIT = "flash_loan_exploit"
    REENTRANCY_EXPLOIT = "reentrancy_exploit"
    BRIDGE_EXPLOIT = "bridge_exploit"
    RUG_PULL = "rug_pull"
    PRICE_MANIPULATION = "price_manipulation"
    ACCESS_CONTROL_EXPLOIT = "access_control_exploit"
```

### Bytecode Features Extracted
```python
# Features extracted from contract bytecode:
features = {
    "total_opcodes": int,        # Total opcode count
    "unique_opcodes": int,       # Distinct opcodes
    "call_count": int,           # External calls
    "delegatecall_count": int,   # Dangerous delegatecalls
    "selfdestruct_count": int,   # Selfdestruct presence
    "sstore_count": int,         # Storage writes
    "sload_count": int,          # Storage reads
    "create_count": int,         # Contract creation
    "create2_count": int,        # Deterministic creation
    "calldataload_count": int,   # Input parsing
    "jumpi_count": int,          # Conditional jumps
    "jumpdest_count": int,       # Jump destinations
    "push1_to_push32_counts": {}, # Data sizes pushed
    "codecopy_count": int,       # Code copying
    "extcodesize_count": int,    # External code inspection
    "dangerous_opcode_ratio": float,
}
```

### Available Models
| Model | Type | Best For |
|-------|------|----------|
| RandomForest | Traditional ML | Fast, interpretable |
| MLP | Deep Learning | Feature-based |
| CNN | Deep Learning | Sequential patterns |
| Transformer | Deep Learning | Complex patterns |
| Ensemble | Hybrid | Best accuracy |

---

## 🔧 CONFIGURATION FILES

### chains.yaml Structure
```yaml
chains:
  - chain_id: "ethereum"
    chain_name: "Ethereum Mainnet"
    rpc_url: "https://eth.llamarpc.com"
    ws_url: "wss://..."  # Optional WebSocket
    
    bridge_contracts:
      # Wormhole
      - "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"  # Token Bridge
      - "0x3ee18B2214AFF97000D974cf647E7C347E8fa585"  # Core
      # LayerZero
      - "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675"
      # Stargate
      - "0x8731d54E9D02c286767d56ac03e8037C07e01e98"
    
    defi_contracts:
      # Aave V3
      - "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"
      # Uniswap V3
      - "0xE592427A0AEce92De3Edee1F18E0157C05861564"
    
    tokens:
      - symbol: "WETH"
        address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        decimals: 18
      - symbol: "USDC"
        address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        decimals: 6
```

### parsers.yaml Structure
```yaml
parsers:
  - name: "wormhole_message"
    description: "Parses Wormhole LogMessagePublished events"
    event_signature: "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"
    protocol: "wormhole"
    fields:
      - name: "sender"
        source: "topics[1]"
        type: "address"
      - name: "sequence"
        source: "data[0:8]"
        type: "uint64"
      - name: "payload"
        source: "data[8:]"
        type: "bytes"
```

---

## 🔌 LUCENE QUERY SYNTAX (Log Explorer)

### Examples
```
# Simple field search
chain:ethereum

# Boolean operators
chain:ethereum AND severity:critical

# Wildcards
event_type:FLASH*

# Phrase search
description:"flash loan"

# Range queries
amount:[1000 TO 1000000]

# Negation
NOT chain:polygon

# Combined
(chain:ethereum OR chain:polygon) AND severity:high AND NOT event_type:TRANSFER
```

---

## 🚀 DEVELOPMENT WORKFLOW

### Adding a New Detection Rule
1. Define the rule in YAML or create an Invariant class
2. Register in the rule engine
3. Add event signature if needed
4. Test with simulator
5. Deploy via CI/CD

### Adding a New Chain
1. Add chain config to `config/chains.yaml`
2. Implement listener if new protocol (or use existing EVM/Cosmos/etc.)
3. Add bridge contract addresses
4. Add token configurations
5. Test locally, deploy

### Adding a New Bridge Protocol
1. Add event signatures to `event_signatures.py`
2. Add contract addresses to `chains.yaml` under `bridge_contracts`
3. Add protocol-specific correlation rules if needed
4. Test with real transactions

---

## 📊 HISTORICAL ATTACKS DATABASE

The system includes a curated database of historical attacks for ML training:

| Attack | Date | Protocol | Loss | Type |
|--------|------|----------|------|------|
| Ronin Bridge | Mar 2022 | Ronin | $625M | Validator Compromise |
| Wormhole | Feb 2022 | Wormhole | $326M | Signature Bypass |
| Nomad | Aug 2022 | Nomad | $190M | Merkle Root |
| Euler Finance | Mar 2023 | Euler | $197M | Flash Loan |
| Penpie | Sep 2024 | Penpie | $28M | Reentrancy |

---

## 🔑 ENVIRONMENT VARIABLES REFERENCE

```bash
# Database
POSTGRES_ENABLED=true
DATABASE_URL=postgresql://user:pass@host:5432/sentinel3

# AI/ML
OPENAI_API_KEY=sk-...       # For AI analysis explanations
ANTHROPIC_API_KEY=sk-...    # Alternative LLM

# RPCs (Premium)
INFURA_API_KEY=...          # Optional: Infura premium
ALCHEMY_API_KEY=...         # Optional: Alchemy premium

# Alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...

# Auth
JWT_SECRET_KEY=...          # For dashboard authentication
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30

# Guardian (Automated Response)
GUARDIAN_ENABLED=true
GUARDIAN_PRIVATE_KEY=...    # For pause transactions
```

---

## 📈 PERFORMANCE CHARACTERISTICS

| Metric | Value |
|--------|-------|
| Event ingestion rate | ~1000 events/sec per chain |
| Detection latency | <100ms for rule-based |
| ML inference latency | <500ms per contract |
| Memory usage (7 chains) | ~500MB |
| Events retained (in-memory) | 10,000 rolling |

---

## 🎯 BUSINESS MODEL

### Target Customers
1. **Bridge Protocols** - Wormhole, LayerZero, Stargate (detect attacks on their bridges)
2. **DeFi Protocols** - Aave, Compound, Uniswap (detect exploits on their contracts)
3. **DAOs/Treasuries** - Manage multi-sig security
4. **Security Firms** - Real-time threat intelligence
5. **Insurance Protocols** - Risk assessment

### Value Proposition
- **Real-time detection** vs. post-mortem analysis
- **Explainable alerts** vs. opaque ML scores
- **Automated response** vs. manual intervention
- **Multi-chain visibility** vs. single-chain tools

---

*This prompt represents the complete Sentinel3 Web3 XDR system as of January 2026.*

