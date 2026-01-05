# Explainable Sentinel3

## Cross-Chain Bridge Attack Detection & Response Platform

> **Mission**: Detect, explain, and stop cross-chain bridge exploits at runtime—before irreversible loss.

---

## 🎯 Executive Summary

This system is a **runtime security layer** for cross-chain bridges that:

1. **Detects** economic invariant violations (mint without lock, unbacked transfers)
2. **Correlates** cross-chain events into single, actionable incidents
3. **Explains** in human language WHY something is an attack
4. **Quantifies** blast radius and loss rate in real-time
5. **Guides** safe human-in-the-loop response

### Core Design Principle

> **How does this system detect and stop an attack that the smart contract itself believes is valid?**

**Answer**: By enforcing **economic invariants** that exist *outside* any single contract's logic. A bridge contract may accept a forged message and mint tokens—it believes the transaction is valid. But our system observes that `minted_on_chain_B > locked_on_chain_A` within the correlation window. This is an **economic truth violation** that no single contract can detect, but cross-chain observation makes obvious.

---

## 📊 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        EXPLAINABLE WEB3 XDR                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Ethereum   │  │   Solana    │  │   Polygon   │  │   Arbitrum  │        │
│  │  Listener   │  │  Listener   │  │  Listener   │  │  Listener   │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
│         │                │                │                │                │
│         └────────────────┴────────────────┴────────────────┘                │
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
│  │                    INVARIANT DETECTION ENGINE                        │   │
│  │  • Economic invariants (lock/mint parity)                           │   │
│  │  • Temporal invariants (sequence violations)                        │   │
│  │  • Governance invariants (admin key usage)                          │   │
│  │  • Liquidity invariants (pool balance thresholds)                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    XDR CORRELATION ENGINE                            │   │
│  │  • Entity graph (wallets, bridges, validators)                      │   │
│  │  • Attack pattern matching                                          │   │
│  │  • Cross-chain event linking                                        │   │
│  │  • Incident aggregation                                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    EXPLAINABILITY ENGINE                             │   │
│  │  • Deterministic explanation templates                              │   │
│  │  • Attack narrative generation                                      │   │
│  │  • Blast radius calculation                                         │   │
│  │  • Response recommendation                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    RESPONSE LAYER                                    │   │
│  │  • Telegram / Slack / PagerDuty alerts                              │   │
│  │  • Runbook execution guidance                                       │   │
│  │  • Safe response templates (no blind automation)                    │   │
│  │  • Incident lifecycle management                                    │   │
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
| **Governance Abuse** | Timelock & proposal tracking | `execution_delay ≥ timelock` |
| **Liquidity Drain** | TVL velocity monitoring | `Δ TVL / Δt < threshold` |
| **Flash Loan Amplification** | Single-block pattern detection | `borrow → exploit → repay ∈ same_block` |
| **Cross-Chain Laundering** | Entity graph tracing | `funds_traced_to_source = true` |
| **Insider Admin Abuse** | Admin key usage patterns | `admin_action_frequency < threshold` |

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure chains
cp config/chains.example.yaml config/chains.yaml
# Edit with your RPC endpoints

# Run the XDR engine
python -m src.main

# Run attack simulation
python -m examples.wormhole_simulation
```

---

## 📁 Project Structure

```
sentinel3/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── docs/
│   ├── ARCHITECTURE.md          # Deep architecture docs
│   ├── THREAT_MODEL.md          # Full threat model
│   ├── INVARIANTS.md            # Invariant specifications
│   └── RUNBOOKS.md              # Response runbooks
├── config/
│   ├── chains.yaml              # Chain configurations
│   ├── bridges.yaml             # Bridge contract addresses
│   └── invariants.yaml          # Invariant thresholds
├── src/
│   ├── __init__.py
│   ├── main.py                  # Entry point
│   ├── telemetry/               # Blockchain listeners
│   ├── normalization/           # Event normalization
│   ├── invariants/              # Invariant detection
│   ├── correlation/             # XDR correlation
│   ├── explainability/          # Explanation generation
│   └── response/                # Alerting & response
├── tests/
│   ├── test_invariants.py
│   ├── test_correlation.py
│   └── test_explainability.py
└── examples/
    ├── wormhole_simulation.py   # Wormhole-style attack
    └── ronin_simulation.py      # Ronin-style attack
```

---

## 🎯 MVP Scope (6-8 Weeks)

### IN SCOPE
- ✅ Ethereum ↔ Polygon bridge monitoring
- ✅ 1 bridge protocol (configurable)
- ✅ 5 core invariants (lock/mint, velocity, admin, timelock, threshold)
- ✅ Telegram + Slack alerting
- ✅ Deterministic explanations
- ✅ Attack simulation framework

### OUT OF SCOPE (v1)
- ❌ Automated response execution
- ❌ Historical forensics
- ❌ Multi-tenant SaaS
- ❌ Custom invariant DSL
- ❌ ML-based anomaly detection

---

## 💰 Business Context

**Buyer**: Bridge team security leads, protocol security officers

**Value Proposition**:
- Detection speed: **< 3 blocks** from first exploit transaction
- Explanation clarity: Human-readable, decision-grade
- False positive rate: **< 0.1%** (deterministic invariants)
- Coverage: Zero-day capable (invariant-based, not signature-based)

---

## 📜 License

MIT License - See LICENSE file


## Deployment Status
![Deploy](https://github.com/vaibhav3104/sentinel3/actions/workflows/deploy-gcp.yml/badge.svg)
# CI/CD trigger Tue Jan  6 00:09:38 IST 2026
