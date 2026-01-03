# Sentinel3 - Web3 XDR Platform
## Complete System Blueprint & Technical Documentation

---

# Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Layer 1: Blockchain Telemetry Collection](#3-layer-1-blockchain-telemetry-collection)
4. [Layer 2: Normalization & Event Processing](#4-layer-2-normalization--event-processing)
5. [Layer 3: Invariant Detection Engine](#5-layer-3-invariant-detection-engine)
6. [Layer 4: Correlation & XDR Core](#6-layer-4-correlation--xdr-core)
7. [Layer 5: Explainability Engine](#7-layer-5-explainability-engine)
8. [Layer 6: Response & Alerting](#8-layer-6-response--alerting)
9. [Frontend Applications](#9-frontend-applications)
10. [API Reference](#10-api-reference)
11. [Detection Rules](#11-detection-rules)
12. [Database Schema](#12-database-schema)
13. [Deployment Architecture](#13-deployment-architecture)
14. [Security Features](#14-security-features)
15. [Monitoring & Observability](#15-monitoring--observability)

---

# 1. Executive Summary

## What is Sentinel3?

Sentinel3 is a **Web3 Extended Detection and Response (XDR) platform** designed to detect, explain, and stop cross-chain bridge exploits and DeFi attacks in real-time.

## The Problem We Solve

| Year | Bridge Hacks | Total Losses |
|------|--------------|--------------|
| 2022 | 15+ | $2.5 Billion |
| 2023 | 10+ | $800 Million |
| 2024 | 8+ | $400 Million |

**Root Cause:** Traditional security tools can't detect attacks that the smart contract itself believes are valid.

## Our Solution

Sentinel3 uses **economic invariant monitoring** to detect attacks that bypass smart contract logic:

```
Traditional Security:  "Is this transaction valid?" → Yes → Allow
Sentinel3:            "Does this violate economic truth?" → Yes → ALERT!
```

## Key Capabilities

| Capability | Description |
|------------|-------------|
| **Multi-Chain Monitoring** | 8 chains (Ethereum, Polygon, Arbitrum, Solana, BSC, Avalanche, Optimism, Base) |
| **Bridge Coverage** | 8 protocols (Wormhole, LayerZero, Stargate, Across, Hop, Synapse, Multichain, cBridge) |
| **Detection Rules** | 33 rules across 4 severity levels |
| **Real-time Alerts** | Telegram, Slack, Webhooks |
| **AI Analysis** | LLM-powered incident explanation |
| **Multi-tenancy** | Support for multiple organizations |

---

# 2. System Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SENTINEL3 ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    LAYER 6: RESPONSE & ALERTING                      │   │
│  │  [Telegram] [Slack] [Webhooks] [PagerDuty] [Email]                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    LAYER 5: EXPLAINABILITY ENGINE                    │   │
│  │  [AI Analysis] [Template Engine] [Runbook Generator]                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    LAYER 4: CORRELATION & XDR CORE                   │   │
│  │  [Entity Graph] [Pattern Matcher] [Incident Builder] [Attack DB]   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    LAYER 3: INVARIANT DETECTION ENGINE               │   │
│  │  [Economic] [Temporal] [Velocity] [Threshold] [Pattern]            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    LAYER 2: NORMALIZATION LAYER                      │   │
│  │  [Event Parser] [Schema Mapper] [Enrichment] [Deduplication]       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    LAYER 1: BLOCKCHAIN TELEMETRY                     │   │
│  │  [EVM Listener] [Solana Listener] [WebSocket] [RPC Polling]        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         BLOCKCHAIN NETWORKS                          │   │
│  │  [Ethereum] [Polygon] [Arbitrum] [Solana] [BSC] [Avalanche] [...]  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Blockchain Event
      │
      ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Capture   │ ──▶ │  Normalize  │ ──▶ │   Detect    │
│   (Layer 1) │     │  (Layer 2)  │     │  (Layer 3)  │
└─────────────┘     └─────────────┘     └─────────────┘
                                              │
                                              ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    Alert    │ ◀── │   Explain   │ ◀── │  Correlate  │
│  (Layer 6)  │     │  (Layer 5)  │     │  (Layer 4)  │
└─────────────┘     └─────────────┘     └─────────────┘
```

---

# 3. Layer 1: Blockchain Telemetry Collection

## Purpose
Capture raw blockchain events from multiple chains with minimal latency.

## Components

### 3.1 EVM Listener (`src/telemetry/evm_listener.py`)

```python
class EVMListener:
    """
    Listens to EVM-compatible chains (Ethereum, Polygon, Arbitrum, etc.)
    
    Features:
    - RPC polling with configurable intervals
    - WebSocket subscription for real-time events
    - Automatic reconnection on failures
    - Block range processing for historical data
    """
    
    def __init__(self, chain_id: str, rpc_url: str, contracts: List[str]):
        self.chain_id = chain_id
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.contracts = contracts
    
    async def listen(self):
        # Poll for new blocks every 12 seconds (Ethereum block time)
        # Extract Transfer, Lock, Mint, Burn events
        # Forward to normalization layer
```

**Monitored Event Types:**
| Event | Signature | Purpose |
|-------|-----------|---------|
| Transfer | `Transfer(address,address,uint256)` | Token movements |
| Lock | `Lock(address,uint256,bytes32)` | Bridge deposits |
| Mint | `Mint(address,uint256)` | Wrapped token creation |
| Burn | `Burn(address,uint256)` | Wrapped token destruction |
| Approval | `Approval(address,address,uint256)` | Token approvals |

### 3.2 Solana Listener (`src/telemetry/solana_listener.py`)

```python
class SolanaListener:
    """
    Listens to Solana blockchain via RPC.
    
    Differences from EVM:
    - Account-based model (not event logs)
    - Program interactions instead of contract calls
    - Higher throughput (65,000 TPS)
    """
```

### 3.3 Listener Pool (`src/telemetry/listener_pool.py`)

```python
class ListenerPool:
    """
    Manages multiple chain listeners concurrently.
    
    Features:
    - Async execution of all listeners
    - Health monitoring per chain
    - Automatic restart on failures
    - Stats aggregation
    """
```

## Configuration

```yaml
# config/chains.yaml
chains:
  - chain_id: ethereum
    chain_name: Ethereum Mainnet
    rpc_url: https://mainnet.infura.io/v3/${INFURA_KEY}
    poll_interval_seconds: 12
    bridge_contracts:
      - "0x3ee18B2214AFF97000D974cf647E7C347E8fa585"  # Wormhole
      - "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675"  # LayerZero
```

---

# 4. Layer 2: Normalization & Event Processing

## Purpose
Convert chain-specific events into a unified schema for cross-chain analysis.

## Unified Event Schema

```python
@dataclass
class NormalizedEvent:
    """Universal event format across all chains."""
    
    # Identity
    event_id: str           # Unique identifier
    chain_id: str           # Source chain (ethereum, solana, etc.)
    tx_hash: str            # Transaction hash
    block_number: int       # Block number
    block_timestamp: datetime
    
    # Event Details
    event_type: str         # Transfer, Lock, Mint, Burn, etc.
    contract_address: str   # Smart contract that emitted event
    
    # Financial Data
    amount: Decimal         # Raw token amount
    amount_usd: float       # USD value at time of event
    token_address: str      # Token contract
    token_symbol: str       # Token symbol (ETH, USDC, etc.)
    
    # Participants
    from_address: str       # Sender
    to_address: str         # Receiver
    
    # Enrichment
    severity: str           # low, medium, high, critical
    bridge_id: str          # Which bridge protocol
    
    # Raw Data
    raw_data: dict          # Original chain-specific data
```

## Normalization Process

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  EVM Event      │     │  Solana Event   │     │  Other Chain    │
│  {              │     │  {              │     │  {              │
│   topics: [...],│     │   accounts:[...],    │   ...           │
│   data: "0x..." │     │   data: base64  │     │  }              │
│  }              │     │  }              │     │                 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │   NORMALIZATION LAYER   │
                    │                         │
                    │  • Parse chain format   │
                    │  • Map to unified schema│
                    │  • Enrich with USD value│
                    │  • Add metadata         │
                    └────────────┬────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │   NormalizedEvent       │
                    │   (Universal Format)    │
                    └─────────────────────────┘
```

---

# 5. Layer 3: Invariant Detection Engine

## Purpose
Detect violations of economic and security invariants that indicate attacks.

## Core Concept: Economic Invariants

**An invariant is a condition that must ALWAYS be true.**

| Invariant | Rule | Violation = Attack |
|-----------|------|-------------------|
| **Mint-Lock Parity** | Minted tokens ≤ Locked tokens | Unbacked mint (Wormhole hack) |
| **Total Supply** | Total supply ≤ Backing assets | Supply inflation |
| **Burn-Unlock** | Unlocked ≤ Burned | Unauthorized redemption |
| **Validator Threshold** | Signatures ≥ Required | Key compromise |

## Invariant Types

### 5.1 Economic Invariants (`src/invariants/economic.py`)

```python
class MintLockParityInvariant:
    """
    RULE: For every mint on Chain B, there must be a corresponding 
          lock on Chain A within a time window.
    
    Detection Logic:
    1. See Mint event on Chain B
    2. Search for Lock event on Chain A (same amount, same token)
    3. If no matching Lock found within 10 minutes → VIOLATION
    
    Real Attack Example:
    - Wormhole Hack ($320M): Attacker minted wETH on Solana
      without locking ETH on Ethereum
    """
    
    def evaluate(self, mint_event: NormalizedEvent) -> Optional[Violation]:
        # Search for corresponding lock
        lock = self.find_matching_lock(
            token=mint_event.token_address,
            amount=mint_event.amount,
            time_window=timedelta(minutes=10)
        )
        
        if lock is None:
            return Violation(
                type="UNBACKED_MINT",
                severity="CRITICAL",
                confidence=0.95,
                details={
                    "minted_amount": mint_event.amount_usd,
                    "missing_lock": True,
                    "chain": mint_event.chain_id
                }
            )
        return None
```

### 5.2 Temporal Invariants (`src/invariants/temporal.py`)

```python
class TimelockInvariant:
    """
    RULE: Governance actions must respect timelock delays.
    
    Detection:
    - Proposal created at T1
    - Execution allowed at T1 + DELAY (e.g., 48 hours)
    - If execution happens before delay → VIOLATION
    """
```

### 5.3 Velocity Invariants (`src/invariants/velocity.py`)

```python
class VelocityInvariant:
    """
    RULE: Rate of change should not exceed thresholds.
    
    Examples:
    - TVL drain > 10% per hour
    - Transactions > 500 per minute
    - Volume > 5x average
    """
```

### 5.4 Threshold Invariants (`src/invariants/threshold.py`)

```python
class ThresholdInvariant:
    """
    RULE: Values should stay within defined bounds.
    
    Examples:
    - Price deviation < 5% from oracle
    - Stablecoin peg deviation < 2%
    - Liquidity ratio > minimum
    """
```

## Invariant Engine (`src/invariants/engine.py`)

```python
class InvariantEngine:
    """
    Orchestrates all invariant evaluations.
    
    Process:
    1. Receive normalized event
    2. Determine applicable invariants
    3. Evaluate each invariant
    4. Collect violations
    5. Forward to correlation layer
    """
    
    def __init__(self):
        self.invariants = [
            MintLockParityInvariant(),
            TotalSupplyInvariant(),
            BurnUnlockInvariant(),
            ValidatorThresholdInvariant(),
            TVLVelocityInvariant(),
            PriceDeviationInvariant(),
        ]
    
    async def evaluate(self, event: NormalizedEvent) -> List[Violation]:
        violations = []
        for invariant in self.invariants:
            if invariant.applies_to(event):
                violation = await invariant.evaluate(event)
                if violation:
                    violations.append(violation)
        return violations
```

---

# 6. Layer 4: Correlation & XDR Core

## Purpose
Connect related events across chains and time to build complete attack pictures.

## Components

### 6.1 Entity Graph (`src/correlation/entity_graph.py`)

```python
class EntityGraph:
    """
    Tracks relationships between addresses, contracts, and transactions.
    
    Graph Structure:
    - Nodes: Addresses, Contracts, Transactions
    - Edges: Transfers, Interactions, Ownership
    
    Use Cases:
    - Track attacker wallet across chains
    - Identify connected addresses
    - Detect money laundering paths
    """
    
    # Example Graph:
    #
    #  [Attacker Wallet] ──transfer──▶ [Tornado Cash]
    #         │                              │
    #         │ bridge                       │ withdraw
    #         ▼                              ▼
    #  [Polygon Wallet] ◀─────────── [Clean Wallet]
```

### 6.2 Pattern Matcher (`src/correlation/pattern_matcher.py`)

```python
class PatternMatcher:
    """
    Matches known attack patterns against observed events.
    
    Patterns:
    - Flash Loan Attack: borrow → manipulate → profit → repay (same block)
    - Sandwich Attack: front-run → victim tx → back-run (same block)
    - Laundering: chain-hop → mixer → chain-hop → exchange
    """
    
    PATTERNS = {
        "flash_loan_attack": {
            "sequence": ["FlashLoan", "Swap+", "Swap+", "Repay"],
            "constraints": {"same_block": True, "min_operations": 5}
        },
        "sandwich_attack": {
            "sequence": ["Swap", "Swap", "Swap"],
            "constraints": {"same_block": True, "same_pair": True}
        },
        "cross_chain_laundering": {
            "sequence": ["Bridge", "Bridge+", "Exchange"],
            "constraints": {"min_chains": 3, "time_window": "1h"}
        }
    }
```

### 6.3 Incident Builder (`src/correlation/incident_builder.py`)

```python
class IncidentBuilder:
    """
    Aggregates related violations into incidents.
    
    Logic:
    1. Group violations by attack type
    2. Merge if same attacker address
    3. Merge if within time window
    4. Calculate total impact
    5. Assign severity
    """
    
    def build_incident(self, violations: List[Violation]) -> Incident:
        return Incident(
            id=generate_id(),
            title=self.generate_title(violations),
            severity=max(v.severity for v in violations),
            attack_type=self.determine_attack_type(violations),
            total_loss_usd=sum(v.amount_usd for v in violations),
            affected_chains=list(set(v.chain for v in violations)),
            events=violations,
            status="open"
        )
```

---

# 7. Layer 5: Explainability Engine

## Purpose
Convert technical detections into human-readable explanations.

## Components

### 7.1 AI Analyzer (`src/ai/analyzer.py`)

```python
class AIAnalyzer:
    """
    Uses LLMs to generate natural language explanations.
    
    Backends:
    - OpenAI GPT-4
    - Anthropic Claude
    - Local rule-based fallback
    """
    
    async def analyze_incident(self, incident: Incident) -> AIAnalysis:
        prompt = f"""
        Analyze this Web3 security incident:
        
        Attack Type: {incident.attack_type}
        Chains: {incident.affected_chains}
        Value at Risk: ${incident.total_loss_usd:,.2f}
        
        Provide:
        1. What happened (simple explanation)
        2. Why it's dangerous
        3. Recommended actions
        """
        
        response = await self.llm.generate(prompt)
        return AIAnalysis(
            summary=response.summary,
            technical_details=response.technical,
            recommendations=response.actions
        )
```

### 7.2 Template Engine (`src/explainability/templates.py`)

```python
EXPLANATION_TEMPLATES = {
    "UNBACKED_MINT": {
        "what": "Tokens were minted on {dest_chain} without corresponding deposit on {source_chain}",
        "why": "This bypasses the bridge's security model, creating tokens from nothing",
        "impact": "Attacker can drain ${amount:,.2f} from the bridge",
        "action": [
            "Pause bridge immediately",
            "Alert exchange partners",
            "Begin incident response"
        ]
    },
    "FLASH_LOAN_ATTACK": {
        "what": "Large flash loan ({amount}) used to manipulate {protocol}",
        "why": "Price manipulation via borrowed funds that are repaid in same transaction",
        "impact": "Protocol lost ${loss:,.2f} to arbitrage",
        "action": [
            "Check oracle configuration",
            "Add flash loan guards",
            "Review price impact limits"
        ]
    }
}
```

---

# 8. Layer 6: Response & Alerting

## Purpose
Deliver alerts to security teams through multiple channels.

## Alert Channels

### 8.1 Telegram (`src/response/telegram.py`)

```python
class TelegramAlerter:
    """
    Sends formatted alerts to Telegram channels.
    
    Features:
    - Markdown formatting
    - Priority-based channels
    - Rate limiting
    - Inline action buttons
    """
    
    async def send_alert(self, incident: Incident):
        message = f"""
🚨 *CRITICAL SECURITY ALERT*

*{incident.title}*

📊 *Details:*
• Attack Type: `{incident.attack_type}`
• Severity: {incident.severity}
• Value at Risk: ${incident.total_loss_usd:,.2f}
• Chains: {', '.join(incident.affected_chains)}

🔗 [View Dashboard](https://sentinel3.io/incidents/{incident.id})
        """
        
        await self.bot.send_message(
            chat_id=self.critical_channel,
            text=message,
            parse_mode="Markdown"
        )
```

### 8.2 Slack (`src/response/slack.py`)

```python
class SlackAlerter:
    """
    Sends rich alerts to Slack via webhooks.
    
    Features:
    - Block Kit formatting
    - Thread-based updates
    - Action buttons
    - Mention security team
    """
```

### 8.3 Webhooks

```python
class WebhookAlerter:
    """
    Generic webhook integration for custom systems.
    
    Payload:
    {
        "incident_id": "INC-001",
        "severity": "critical",
        "title": "Unbacked Mint Detected",
        "details": {...},
        "timestamp": "2024-01-01T00:00:00Z"
    }
    """
```

---

# 9. Frontend Applications

## 9.1 Main Dashboard (`frontend/index.html`)

**Purpose:** Real-time security monitoring

**Features:**
| Feature | Description |
|---------|-------------|
| Incident List | Active security incidents with severity |
| Stats Widgets | Events, incidents, blocks scanned |
| Severity Filter | Filter by Critical/High/Medium/Low |
| AI Analysis | One-click incident explanation |
| Real-time Updates | Auto-refresh every 5 seconds |

**Screenshot Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  🛡️ Sentinel3    [Simulator] [Analytics] [Admin] [Logout]  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐                   │
│  │ 6   │ │ 3   │ │ 125 │ │ 50K │ │ 2h  │                   │
│  │Incid│ │Crit │ │Event│ │Block│ │ Up  │                   │
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘                   │
├─────────────────────────────────────────────────────────────┤
│  Active Incidents              │  Chain Activity            │
│  ┌───────────────────────────┐ │  ┌────────────────────┐   │
│  │ 🔴 Unbacked Mint ($145M)  │ │  │ Ethereum: ████░ 65%│   │
│  │ 🔴 Flash Loan ($39M)      │ │  │ Polygon:  ███░░ 25%│   │
│  │ 🟠 Liquidity Drain ($21M) │ │  │ Arbitrum: ██░░░ 10%│   │
│  └───────────────────────────┘ │  └────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## 9.2 Attack Simulator (`frontend/simulator.html`)

**Purpose:** Demo and testing of detection capabilities

**Features:**
- 6 attack types available
- Configurable chain, value, speed
- Real-time attack log
- Detection metrics

## 9.3 Analytics Dashboard (`frontend/analytics.html`)

**Purpose:** Historical analysis and risk scoring

**Features:**
- Incidents over time chart
- Chain distribution pie chart
- Attack types bar chart
- Wallet risk scoring

## 9.4 Admin Console (`frontend/admin.html`)

**Purpose:** Configuration management

**Features:**
- Rule management (33 rules)
- Chain configuration
- Alerting setup (Telegram/Slack)
- System logs

## 9.5 Multi-Tenancy (`frontend/tenants.html`)

**Purpose:** Organization management

**Features:**
- Create/manage organizations
- Plan management (Free/Pro/Enterprise)
- User management
- Usage limits

---

# 10. API Reference

## Base URL
```
Production: https://web3-xdr-production-xxx.run.app/api
Local: http://localhost:8080/api
```

## Authentication
```
Header: Authorization: Bearer <JWT_TOKEN>
```

## Endpoints

### Incidents

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/incidents` | List all incidents |
| GET | `/api/incidents/{id}` | Get incident details |
| POST | `/api/incidents/{id}/resolve` | Resolve incident |

### Events

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/events` | List recent events |
| GET | `/api/events?chain_id=ethereum` | Filter by chain |

### Statistics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | System statistics |
| GET | `/api/chains` | Chain status |
| GET | `/api/bridges` | Bridge status |

### Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/rules` | List all rules |
| POST | `/api/admin/rules` | Create rule |
| PUT | `/api/admin/rules/{id}` | Update rule |
| DELETE | `/api/admin/rules/{id}` | Delete rule |

### AI Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ai/analyze/{id}` | AI analysis of incident |
| GET | `/api/ai/patterns` | Detected patterns |

### Simulator

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/simulator/attack` | Execute simulated attack |
| GET | `/api/simulator/attacks` | List attack types |

---

# 11. Detection Rules

## Rule Structure

```yaml
- id: rule-unique-id
  name: Human Readable Name
  description: What this rule detects
  severity: critical | high | medium | low
  confidence: 0.0 - 1.0
  enabled: true | false
  
  detection:
    type: invariant | event | velocity | pattern
    # Type-specific configuration
  
  thresholds:
    min_amount_usd: 10000
    # Rule-specific thresholds
  
  actions:
    - type: alert
      channels: [telegram, slack]
      priority: P1
```

## Rules by Category

### Critical Rules (4)
| ID | Name | Detection Type |
|----|------|----------------|
| unbacked-mint-001 | Unbacked Cross-Chain Mint | Invariant |
| unbacked-redemption-002 | Unauthorized Redemption | Event |
| validator-bypass-003 | Validator Threshold Bypass | Invariant |
| supply-inflation-004 | Token Supply Inflation | Invariant |

### High Rules (6)
| ID | Name | Detection Type |
|----|------|----------------|
| large-bridge-transfer-101 | Large Cross-Chain Transfer | Event |
| tvl-drain-102 | Abnormal TVL Drain | Invariant |
| bridge-message-spike-103 | Bridge Message Spike | Velocity |
| suspicious-withdrawal-104 | Suspicious Withdrawal | Event |
| timelock-bypass-105 | Timelock Bypass | Invariant |
| flash-loan-106 | Flash Loan Attack | Pattern |

### DeFi Protocol Rules (16)
| Protocol | Rules |
|----------|-------|
| Aave | Flash Loan, Mass Liquidation, Borrow Spike |
| Uniswap | Large Swap, Pool Drain, Sandwich Attack |
| Compound | Oracle Manipulation, Governance Attack |
| MakerDAO | Vault Liquidation, DAI Peg |
| Curve | Pool Imbalance, Stablecoin Depeg |
| Lido | stETH Depeg |
| Generic | Reentrancy, Access Control, Token Approval |

### Medium/Low Rules (7)
| ID | Name | Severity |
|----|------|----------|
| velocity-spike-201 | Transaction Velocity Spike | Medium |
| new-address-transfer-202 | New Address Large Transfer | Medium |
| admin-action-203 | Admin Action Detected | Medium |
| arbitrage-pattern-204 | Cross-Chain Arbitrage | Medium |
| contract-anomaly-205 | Contract Anomaly | Medium |
| failed-tx-spike-301 | Failed Transaction Spike | Low |
| token-approval-302 | Large Token Approval | Low |

---

# 12. Database Schema

## PostgreSQL Tables

### events
```sql
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(255) UNIQUE NOT NULL,
    chain_id VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    tx_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    block_timestamp TIMESTAMP,
    contract_address VARCHAR(255),
    severity VARCHAR(20),
    amount DECIMAL(38, 18),
    amount_usd DECIMAL(18, 2),
    from_address VARCHAR(255),
    to_address VARCHAR(255),
    raw_data JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_events_chain ON events(chain_id);
CREATE INDEX idx_events_timestamp ON events(block_timestamp);
CREATE INDEX idx_events_severity ON events(severity);
```

### incidents
```sql
CREATE TABLE incidents (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(255) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    summary TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'OPEN',
    attack_type VARCHAR(100),
    confidence DECIMAL(5, 4),
    total_loss_usd DECIMAL(18, 2),
    affected_chains TEXT[],
    event_ids TEXT[],
    recommended_actions TEXT[],
    ai_analysis JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP
);
```

### violations
```sql
CREATE TABLE violations (
    id SERIAL PRIMARY KEY,
    violation_id VARCHAR(255) UNIQUE NOT NULL,
    invariant_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    event_id VARCHAR(255) REFERENCES events(event_id),
    incident_id VARCHAR(255) REFERENCES incidents(incident_id),
    details JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

# 13. Deployment Architecture

## Current Production Setup (GCP)

```
┌─────────────────────────────────────────────────────────────────┐
│                     GOOGLE CLOUD PLATFORM                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────────┐    ┌─────────────────────┐           │
│   │   Cloud Run         │    │   Cloud SQL         │           │
│   │   (Sentinel3 App)   │───▶│   (PostgreSQL)      │           │
│   │   Auto-scaling      │    │   Managed DB        │           │
│   └──────────┬──────────┘    └─────────────────────┘           │
│              │                                                   │
│   ┌──────────┴──────────┐                                       │
│   │   Secret Manager    │                                       │
│   │   - Infura API Key  │                                       │
│   │   - OpenAI API Key  │                                       │
│   │   - JWT Secret      │                                       │
│   └─────────────────────┘                                       │
│                                                                  │
│   ┌─────────────────────┐    ┌─────────────────────┐           │
│   │   Artifact Registry │    │   Cloud Build       │           │
│   │   (Docker Images)   │◀───│   (CI/CD)           │           │
│   └─────────────────────┘    └─────────────────────┘           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │   GitHub        │
                    │   (Source Code) │
                    │   Auto-deploy   │
                    └─────────────────┘
```

## Local Development

```
┌─────────────────────────────────────────┐
│           LOCAL MACHINE                  │
│                                          │
│   ┌──────────────┐  ┌──────────────┐   │
│   │  Sentinel3   │  │  PostgreSQL  │   │
│   │  (Python)    │  │  (Docker)    │   │
│   └──────────────┘  └──────────────┘   │
│                                          │
│   ┌──────────────┐  ┌──────────────┐   │
│   │  Prometheus  │  │  Grafana     │   │
│   │  (Metrics)   │  │  (Dashboards)│   │
│   └──────────────┘  └──────────────┘   │
│                                          │
└─────────────────────────────────────────┘
```

---

# 14. Security Features

## Authentication & Authorization

| Feature | Implementation |
|---------|----------------|
| JWT Tokens | HS256 signed, 24h expiry |
| Role-Based Access | Admin, Operator, Viewer |
| API Keys | Per-tenant API keys |
| Rate Limiting | 100 requests/minute |

## Data Security

| Feature | Implementation |
|---------|----------------|
| Encryption at Rest | GCP default encryption |
| Encryption in Transit | TLS 1.3 |
| Secrets Management | GCP Secret Manager |
| Audit Logging | All admin actions logged |

## Multi-Tenancy Isolation

| Feature | Implementation |
|---------|----------------|
| Data Isolation | Tenant ID on all records |
| API Isolation | Tenant header required |
| Config Isolation | Per-tenant rules & chains |

---

# 15. Monitoring & Observability

## Prometheus Metrics

```python
# src/metrics/collector.py

# Counters
events_processed = Counter('sentinel3_events_total', 'Total events processed', ['chain'])
incidents_created = Counter('sentinel3_incidents_total', 'Total incidents', ['severity'])
violations_detected = Counter('sentinel3_violations_total', 'Violations', ['type'])

# Gauges
active_incidents = Gauge('sentinel3_active_incidents', 'Currently active incidents')
chain_status = Gauge('sentinel3_chain_status', 'Chain connection status', ['chain'])

# Histograms
detection_latency = Histogram('sentinel3_detection_latency_seconds', 'Detection latency')
```

## Grafana Dashboards

| Dashboard | Panels |
|-----------|--------|
| Overview | Incidents, Events, Chain Health |
| Incidents | Timeline, by Severity, by Chain |
| Performance | Latency, Throughput, Errors |
| Chains | Per-chain metrics, Block lag |

## Alert Rules

```yaml
# Prometheus alert rules
groups:
  - name: sentinel3
    rules:
      - alert: HighCriticalIncidents
        expr: sentinel3_active_incidents{severity="critical"} > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Critical incident detected"
      
      - alert: ChainDisconnected
        expr: sentinel3_chain_status == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Chain {{ $labels.chain }} disconnected"
```

---

# Appendix A: File Structure

```
web3-xdr/
├── src/
│   ├── api/
│   │   ├── server.py          # FastAPI app
│   │   ├── routes.py          # Main API routes
│   │   ├── admin_routes.py    # Admin API
│   │   ├── auth_routes.py     # Authentication
│   │   ├── ai_routes.py       # AI analysis
│   │   ├── tenant_routes.py   # Multi-tenancy
│   │   └── simulator_routes.py # Attack simulator
│   ├── telemetry/
│   │   ├── evm_listener.py    # EVM chains
│   │   ├── solana_listener.py # Solana
│   │   └── listener_pool.py   # Pool manager
│   ├── invariants/
│   │   ├── economic.py        # Economic invariants
│   │   ├── temporal.py        # Time-based
│   │   ├── velocity.py        # Rate-based
│   │   └── engine.py          # Orchestration
│   ├── correlation/
│   │   ├── entity_graph.py    # Address tracking
│   │   ├── pattern_matcher.py # Attack patterns
│   │   └── incident_builder.py # Incident creation
│   ├── explainability/
│   │   ├── templates.py       # Alert templates
│   │   └── engine.py          # Explanation gen
│   ├── ai/
│   │   ├── analyzer.py        # LLM integration
│   │   └── prompts.py         # AI prompts
│   ├── response/
│   │   ├── telegram.py        # Telegram alerts
│   │   └── slack.py           # Slack alerts
│   ├── auth/
│   │   ├── jwt_handler.py     # JWT tokens
│   │   └── models.py          # User models
│   ├── database/
│   │   ├── connection.py      # DB connection
│   │   ├── models.py          # ORM models
│   │   └── service.py         # CRUD operations
│   ├── metrics/
│   │   └── collector.py       # Prometheus metrics
│   └── shared_state.py        # In-memory state
├── config/
│   ├── chains.yaml            # Chain config
│   └── rules/
│       ├── critical_alerts.yaml
│       ├── high_alerts.yaml
│       ├── medium_alerts.yaml
│       └── defi_protocols.yaml
├── frontend/
│   ├── index.html             # Main dashboard
│   ├── admin.html             # Admin console
│   ├── simulator.html         # Attack simulator
│   ├── analytics.html         # Analytics
│   ├── tenants.html           # Multi-tenancy
│   └── login.html             # Login page
├── deploy/
│   ├── gcp/                   # GCP deployment
│   ├── aws/                   # AWS deployment
│   ├── kubernetes/            # K8s manifests
│   └── grafana/               # Monitoring
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   └── BLUEPRINT.md           # This document
├── monitor.py                 # Main entry point
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

# Appendix B: Quick Start Commands

```bash
# Local Development
cd web3-xdr
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python monitor.py

# Docker
docker-compose up -d

# Deploy to GCP
gcloud builds submit --tag gcr.io/PROJECT/sentinel3
gcloud run deploy sentinel3 --image gcr.io/PROJECT/sentinel3

# Access
Dashboard: http://localhost:8080/frontend/index.html
API Docs:  http://localhost:8080/api/docs
```

---

# Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Last Updated | January 2025 |
| Author | Sentinel3 Team |
| Status | Production Ready |

---

*This document is confidential and intended for internal use.*

