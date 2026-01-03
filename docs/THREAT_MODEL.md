# Web3 XDR Threat Model

## Overview

This document details the threat model for the Explainable Web3 XDR system, covering attack vectors, detection mechanisms, and response strategies.

## Core Assumption

> **Attackers use valid transactions that smart contracts believe are legitimate.**

Our detection is based on **economic invariants** that exist outside any single contract's logic, not on transaction validity or signature verification.

---

## Attack Categories

### 1. Unbacked Token Minting

**Attack Pattern:**
```
1. Attacker finds vulnerability in bridge verification
2. Submits forged/manipulated proof of lock
3. Bridge mints tokens on destination chain
4. No actual lock occurred on source chain
```

**Real-World Examples:**
- Wormhole ($320M, Feb 2022) - Signature verification bypass
- Ronin ($620M, Mar 2022) - Validator key compromise

**Detection:**

```python
INVARIANT: minted_on_destination ≤ locked_on_source

# Detection logic
if sum(mints_in_window) > sum(locks_in_window):
    raise Incident(type="UNBACKED_MINT", severity=CRITICAL)
```

**Why This Works:**
- We observe BOTH chains simultaneously
- Lock events are immutable on-chain facts
- Even valid-looking mints fail if no lock exists

---

### 2. Validator/Guardian Key Compromise

**Attack Pattern:**
```
1. Attacker obtains validator private keys
2. Signs malicious bridge messages
3. Submits messages meeting signature threshold
4. Bridge executes unauthorized operations
```

**Detection:**

```python
INVARIANT: operations_require_valid_source_events

# Detection logic
for operation in bridge_operations:
    if not find_corresponding_source_event(operation):
        raise Incident(type="VALIDATOR_COMPROMISE")
```

**Why This Works:**
- Compromised keys can sign, but can't forge source chain events
- We verify source chain state, not just signatures

---

### 3. Governance/Timelock Bypass

**Attack Pattern:**
```
1. Attacker gains governance control (flash loan, key compromise)
2. Bypasses timelock delay
3. Executes malicious governance action immediately
4. Changes critical parameters or drains funds
```

**Detection:**

```python
INVARIANT: execution_time - proposal_time ≥ timelock_delay

# Detection logic
if execution.timestamp - proposal.timestamp < required_delay:
    raise Incident(type="GOVERNANCE_ATTACK")
```

**Why This Works:**
- Timelock bypass is observable on-chain
- Legitimate governance follows predictable patterns

---

### 4. Liquidity Drain Attacks

**Attack Pattern:**
```
1. Attacker exploits vulnerability repeatedly
2. Each transaction within normal limits
3. Cumulative drain depletes protocol
4. Attack may span hours/days
```

**Detection:**

```python
INVARIANT: tvl_change_rate < threshold

# Detection logic  
if tvl_drain_percent_per_hour > 10%:
    raise Incident(type="LIQUIDITY_DRAIN")
```

**Why This Works:**
- Aggregate behavior reveals coordinated extraction
- Normal withdrawals are distributed over time

---

### 5. Flash Loan Amplified Attacks

**Attack Pattern:**
```
1. Borrow massive capital via flash loan
2. Exploit vulnerability (oracle, reentrancy, logic)
3. Repay loan with profit
4. All in single transaction/block
```

**Detection:**

```python
INVARIANT: high_value_operations_not_concentrated_in_single_block

# Detection logic
if block_operation_count > threshold AND block_volume > $1M:
    raise Incident(type="FLASH_LOAN_EXPLOIT")
```

**Why This Works:**
- Single-block concentration is highly unusual
- Flash loan patterns are distinctive

---

### 6. Cross-Chain Laundering

**Attack Pattern:**
```
1. Steal funds from protocol
2. Bridge to chain A
3. Swap and bridge to chain B
4. Repeat to obfuscate trail
5. Exit via CEX or mixer
```

**Detection:**

```python
# Detection via entity graph
trace = entity_graph.trace_funds(stolen_funds_address)
if trace.involves_multiple_bridges AND trace.ends_at_unknown:
    raise Alert(type="CROSS_CHAIN_LAUNDERING")
```

**Why This Works:**
- Entity graph tracks cross-chain relationships
- Laundering leaves observable patterns

---

### 7. Insider/Admin Abuse

**Attack Pattern:**
```
1. Admin with privileged access
2. Executes unauthorized operations
3. May disguise as maintenance
4. Gradually extracts value
```

**Detection:**

```python
INVARIANT: admin_action_frequency < threshold

# Detection logic
if admin_actions_per_hour > 5:
    raise Alert(type="ADMIN_ABUSE", severity=HIGH)
```

**Why This Works:**
- Normal admin activity is infrequent
- Abuse requires repeated privileged operations

---

## Detection Matrix

| Attack Type | Primary Invariant | Secondary Indicators | Confidence |
|-------------|------------------|---------------------|------------|
| Unbacked Mint | MINT_LOCK_PARITY | Missing source events | 95% |
| Validator Compromise | SIGNATURE_THRESHOLD | Unusual signer patterns | 90% |
| Governance Attack | TIMELOCK_RESPECTED | Rapid execution | 95% |
| Liquidity Drain | TVL_VELOCITY | Volume concentration | 85% |
| Flash Loan | SINGLE_BLOCK_CONCENTRATION | Large borrowed amounts | 90% |
| Laundering | ENTITY_GRAPH_ANALYSIS | Multi-hop patterns | 75% |
| Admin Abuse | ADMIN_ACTION_FREQUENCY | Unusual timing | 80% |

---

## False Positive Mitigation

### Why Our Approach Has Low False Positives

1. **Deterministic Invariants**: Mathematical conditions, not heuristics
2. **Multiple Confirmation**: Require multiple indicators before alerting
3. **Context-Aware Thresholds**: Adaptive to protocol-specific patterns
4. **Tolerance Windows**: Account for bridge latency

### Known Edge Cases

| Scenario | Potential FP | Mitigation |
|----------|-------------|------------|
| Bridge latency | Temporary imbalance | 10-minute tolerance window |
| Reorg/rollback | Events disappear | Wait for confirmations |
| Legitimate large transfer | Volume alert | Per-protocol thresholds |
| Protocol upgrade | Admin actions | Whitelist scheduled maintenance |

---

## Response Recommendations

### CRITICAL Severity

**Immediate Actions (< 5 minutes):**
1. Notify on-call security
2. Prepare emergency pause
3. Begin incident documentation
4. Alert exchange partners

**If Confirmed Attack:**
1. Execute emergency pause
2. Freeze attacker addresses (if identified)
3. Begin forensic analysis
4. Coordinate response with affected parties

### HIGH Severity

**Actions (< 30 minutes):**
1. Review incident details
2. Assess blast radius
3. Determine if escalation needed
4. Monitor for continuation

### MEDIUM/LOW Severity

**Actions (< 4 hours):**
1. Review during normal hours
2. Update detection rules if needed
3. Document for pattern analysis

---

## Limitations

### What We Cannot Detect

1. **Vulnerabilities before exploitation**: We detect attacks, not bugs
2. **Off-chain attacks**: Phishing, social engineering, etc.
3. **Intra-contract exploits**: Some complex reentrancy
4. **Zero-value attacks**: Governance manipulation without fund movement

### Why These Limitations Exist

Our approach is based on **economic truth observation**. If an attack doesn't create observable economic imbalance, we may not detect it. However, attacks that don't create economic impact typically have limited damage.

---

## Continuous Improvement

### Adding New Attack Detection

1. Analyze post-mortem of new exploit
2. Identify economic invariant that was violated
3. Implement invariant check
4. Backtest against historical data
5. Deploy with appropriate thresholds

### Threshold Tuning

1. Monitor false positive rate
2. Adjust thresholds based on protocol behavior
3. Re-evaluate after major protocol changes

---

## References

- [Wormhole Exploit Analysis](https://rekt.news/wormhole-rekt/)
- [Ronin Bridge Hack](https://rekt.news/ronin-rekt/)
- [Bridge Security Best Practices](https://github.com/0xsomnus/bridge-security)

