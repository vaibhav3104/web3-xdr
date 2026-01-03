# Web3 XDR Architecture Deep Dive

## Design Philosophy

### The Core Problem

Traditional smart contract security relies on:
1. **Audits** - Point-in-time, miss runtime exploits
2. **Trust assumptions** - Bridges trust guardians, validators, messages
3. **Contract-level validation** - Each contract only sees its own state

**The gap**: When an attacker forges a bridge message, the destination chain contract *believes* it's valid. The contract has no way to verify source chain state.

### Our Solution: Economic Truth Observation

We observe **cross-chain economic invariants** that exist outside any single contract:

```
INVARIANT: tokens_minted_on_dest ≤ tokens_locked_on_source
```

This is true regardless of what any individual contract believes. By observing both chains simultaneously, we can detect violations that no single contract can see.

---

## Layer 1: Blockchain Telemetry Collection

### Design Goals
- **Low latency**: < 500ms from block finality to event ingestion
- **High reliability**: No missed blocks, automatic reconnection
- **Zero trust**: Direct RPC, no intermediary services
- **Chain agnostic**: Unified interface for EVM, Solana, etc.

### Architecture

```
                    ┌─────────────────────────────────────┐
                    │         Chain Listener Pool         │
                    └─────────────────────────────────────┘
                                      │
           ┌──────────────────────────┼──────────────────────────┐
           │                          │                          │
           ▼                          ▼                          ▼
    ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
    │   EVM       │           │   Solana    │           │   Cosmos    │
    │  Listener   │           │  Listener   │           │  Listener   │
    └─────────────┘           └─────────────┘           └─────────────┘
           │                          │                          │
           ▼                          ▼                          ▼
    ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
    │ eth_subscribe│          │ accountSub  │           │  /block     │
    │ newHeads    │           │ programSub  │           │  /tx_search │
    └─────────────┘           └─────────────┘           └─────────────┘
```

### Event Types Monitored

| Event Type | EVM Method | Solana Method | Priority |
|------------|-----------|---------------|----------|
| Token Lock | `Transfer` to bridge | SPL Transfer | CRITICAL |
| Token Mint | `Mint` event | Token mint | CRITICAL |
| Token Burn | `Burn` event | Token burn | CRITICAL |
| Bridge Message | Custom event | Account update | CRITICAL |
| Admin Action | Role grant/revoke | Authority change | HIGH |
| Governance | Proposal/Execute | DAO instruction | HIGH |
| Large Transfer | Transfer > threshold | SPL transfer | MEDIUM |

### Latency Budget

```
Block Finality → WebSocket Push:     ~100ms
WebSocket → Event Parse:              ~10ms
Parse → Normalize:                    ~20ms
Normalize → Invariant Check:          ~50ms
─────────────────────────────────────────────
Total: < 200ms per event
```

---

## Layer 2: Normalization

### Unified Event Schema

All chain-specific events are normalized to a single schema:

```python
@dataclass
class SecurityEvent:
    # Identity
    event_id: str              # UUID
    chain_id: str              # "ethereum", "solana", etc.
    block_number: int          # Native block number
    block_timestamp: datetime  # UTC timestamp
    tx_hash: str               # Transaction hash
    
    # Classification
    event_type: EventType      # LOCK, MINT, BURN, TRANSFER, ADMIN, etc.
    severity: Severity         # INFO, LOW, MEDIUM, HIGH, CRITICAL
    
    # Entities
    source_address: str        # Sender
    dest_address: str          # Receiver
    contract_address: str      # Emitting contract
    
    # Asset
    asset_type: str            # Token symbol or "NATIVE"
    asset_address: str         # Token contract address
    amount: Decimal            # Raw amount
    amount_usd: Decimal        # USD value at event time
    
    # Bridge-specific
    bridge_id: Optional[str]   # Bridge protocol identifier
    message_hash: Optional[str] # Bridge message hash
    source_chain: Optional[str] # For cross-chain events
    dest_chain: Optional[str]   # For cross-chain events
    
    # Raw data
    raw_event: dict            # Original chain-specific event
```

### Entity Resolution

```python
class EntityResolver:
    """
    Resolves addresses to known entities across chains.
    """
    
    def resolve(self, address: str, chain: str) -> Entity:
        # Check known bridges
        if bridge := self.bridges.get((chain, address)):
            return Entity(type="BRIDGE", name=bridge.name, ...)
        
        # Check known protocols
        if protocol := self.protocols.get((chain, address)):
            return Entity(type="PROTOCOL", name=protocol.name, ...)
        
        # Check validator sets
        if validator := self.validators.get((chain, address)):
            return Entity(type="VALIDATOR", name=validator.name, ...)
        
        # Unknown - track as wallet
        return Entity(type="WALLET", address=address, ...)
```

---

## Layer 3: Invariant Detection Engine

### Invariant Types

#### 1. Economic Invariants

```python
class MintLockParityInvariant(Invariant):
    """
    Core invariant: minted tokens must not exceed locked tokens.
    
    INVARIANT: Σ(minted_on_dest) ≤ Σ(locked_on_source)
    """
    
    name = "MINT_LOCK_PARITY"
    severity = Severity.CRITICAL
    
    def __init__(self, bridge_id: str, tolerance_window: timedelta):
        self.bridge_id = bridge_id
        self.tolerance_window = tolerance_window  # e.g., 10 minutes
        
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        # Get all mints on destination chain in window
        mints = await context.get_events(
            chain=self.dest_chain,
            event_type=EventType.MINT,
            bridge_id=self.bridge_id,
            window=self.tolerance_window
        )
        
        # Get all locks on source chain in window
        locks = await context.get_events(
            chain=self.source_chain,
            event_type=EventType.LOCK,
            bridge_id=self.bridge_id,
            window=self.tolerance_window
        )
        
        total_minted = sum(e.amount for e in mints)
        total_locked = sum(e.amount for e in locks)
        
        if total_minted > total_locked:
            return InvariantResult(
                violated=True,
                invariant=self,
                violation_amount=total_minted - total_locked,
                evidence={
                    "mints": [e.to_dict() for e in mints],
                    "locks": [e.to_dict() for e in locks],
                    "delta": float(total_minted - total_locked)
                }
            )
        
        return InvariantResult(violated=False, invariant=self)
```

#### 2. Temporal Invariants

```python
class SequenceInvariant(Invariant):
    """
    Bridge operations must follow correct sequence:
    LOCK → MESSAGE → VERIFY → MINT
    """
    
    name = "BRIDGE_SEQUENCE"
    severity = Severity.CRITICAL
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        # Find mints without corresponding verified messages
        recent_mints = await context.get_events(
            event_type=EventType.MINT,
            window=timedelta(minutes=5)
        )
        
        for mint in recent_mints:
            if not mint.message_hash:
                continue
                
            # Check if message was verified before mint
            verification = await context.find_event(
                event_type=EventType.MESSAGE_VERIFIED,
                message_hash=mint.message_hash,
                before=mint.block_timestamp
            )
            
            if not verification:
                return InvariantResult(
                    violated=True,
                    invariant=self,
                    evidence={
                        "mint": mint.to_dict(),
                        "missing": "MESSAGE_VERIFIED"
                    }
                )
        
        return InvariantResult(violated=False, invariant=self)
```

#### 3. Velocity Invariants

```python
class TVLVelocityInvariant(Invariant):
    """
    TVL should not decrease faster than threshold.
    
    Rapid TVL drain indicates ongoing exploit.
    """
    
    name = "TVL_VELOCITY"
    severity = Severity.HIGH
    
    def __init__(
        self,
        bridge_id: str,
        max_drain_percent_per_hour: float = 10.0,
        min_drain_usd: float = 1_000_000
    ):
        self.bridge_id = bridge_id
        self.max_drain_rate = max_drain_percent_per_hour / 100
        self.min_drain_usd = min_drain_usd
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        # Get TVL at start and end of window
        tvl_now = await context.get_tvl(self.bridge_id)
        tvl_1h_ago = await context.get_tvl(self.bridge_id, offset=timedelta(hours=1))
        
        if tvl_1h_ago == 0:
            return InvariantResult(violated=False, invariant=self)
        
        drain_rate = (tvl_1h_ago - tvl_now) / tvl_1h_ago
        drain_usd = tvl_1h_ago - tvl_now
        
        if drain_rate > self.max_drain_rate and drain_usd > self.min_drain_usd:
            return InvariantResult(
                violated=True,
                invariant=self,
                violation_amount=drain_usd,
                evidence={
                    "tvl_now": float(tvl_now),
                    "tvl_1h_ago": float(tvl_1h_ago),
                    "drain_rate_percent": drain_rate * 100,
                    "drain_usd": float(drain_usd)
                }
            )
        
        return InvariantResult(violated=False, invariant=self)
```

#### 4. Governance Invariants

```python
class TimelockInvariant(Invariant):
    """
    Admin actions must respect timelock periods.
    """
    
    name = "TIMELOCK_RESPECTED"
    severity = Severity.CRITICAL
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        # Find recent admin executions
        executions = await context.get_events(
            event_type=EventType.ADMIN_EXECUTE,
            window=timedelta(hours=1)
        )
        
        for execution in executions:
            # Find corresponding proposal
            proposal = await context.find_event(
                event_type=EventType.ADMIN_PROPOSE,
                proposal_id=execution.proposal_id
            )
            
            if not proposal:
                return InvariantResult(
                    violated=True,
                    invariant=self,
                    evidence={
                        "execution": execution.to_dict(),
                        "issue": "No proposal found"
                    }
                )
            
            elapsed = execution.block_timestamp - proposal.block_timestamp
            required_delay = await context.get_timelock_delay(execution.contract_address)
            
            if elapsed < required_delay:
                return InvariantResult(
                    violated=True,
                    invariant=self,
                    evidence={
                        "execution": execution.to_dict(),
                        "proposal": proposal.to_dict(),
                        "elapsed_seconds": elapsed.total_seconds(),
                        "required_seconds": required_delay.total_seconds()
                    }
                )
        
        return InvariantResult(violated=False, invariant=self)
```

---

## Layer 4: XDR Correlation Engine

### Entity Graph

```python
class EntityGraph:
    """
    Maintains relationships between entities across chains.
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.entity_index: Dict[str, Entity] = {}
    
    def add_event(self, event: SecurityEvent):
        # Add/update source entity
        source = self.get_or_create_entity(event.source_address, event.chain_id)
        
        # Add/update dest entity
        dest = self.get_or_create_entity(event.dest_address, event.chain_id)
        
        # Add edge with event data
        self.graph.add_edge(
            source.id,
            dest.id,
            event_id=event.event_id,
            event_type=event.event_type,
            amount=event.amount,
            timestamp=event.block_timestamp
        )
    
    def get_attack_subgraph(
        self,
        seed_entity: str,
        hops: int = 3,
        time_window: timedelta = timedelta(hours=1)
    ) -> nx.DiGraph:
        """
        Extract subgraph around suspicious entity.
        """
        # BFS from seed entity within time window
        visited = set()
        queue = [(seed_entity, 0)]
        subgraph = nx.DiGraph()
        
        while queue:
            entity_id, depth = queue.pop(0)
            if depth > hops or entity_id in visited:
                continue
            visited.add(entity_id)
            
            # Get edges within time window
            for _, neighbor, data in self.graph.edges(entity_id, data=True):
                if self._within_window(data['timestamp'], time_window):
                    subgraph.add_edge(entity_id, neighbor, **data)
                    queue.append((neighbor, depth + 1))
        
        return subgraph
```

### Attack Pattern Matching

```python
class AttackPatternMatcher:
    """
    Matches event sequences to known attack patterns.
    """
    
    PATTERNS = {
        "UNBACKED_MINT": [
            PatternStep(event_type=EventType.MINT, chain="dest"),
            PatternStep(
                event_type=EventType.LOCK,
                chain="source",
                required=False,  # Missing = violation
                time_relation="before"
            )
        ],
        "FLASH_LOAN_EXPLOIT": [
            PatternStep(event_type=EventType.FLASH_BORROW),
            PatternStep(event_type=EventType.SWAP, min_count=1),
            PatternStep(event_type=EventType.FLASH_REPAY),
            PatternStep(
                constraint=lambda events: events[0].tx_hash == events[-1].tx_hash,
                description="All in same transaction"
            )
        ],
        "VALIDATOR_COMPROMISE": [
            PatternStep(event_type=EventType.SIGNATURE_SUBMIT),
            PatternStep(
                constraint=lambda events: self._check_signature_threshold(events),
                description="Below threshold signatures with execution"
            ),
            PatternStep(event_type=EventType.BRIDGE_EXECUTE)
        ]
    }
    
    async def match(
        self,
        events: List[SecurityEvent],
        pattern_name: str
    ) -> Optional[PatternMatch]:
        pattern = self.PATTERNS.get(pattern_name)
        if not pattern:
            return None
        
        # Attempt to match pattern steps to events
        matched_events = []
        for step in pattern:
            matching = [e for e in events if step.matches(e)]
            if step.required and not matching:
                return None
            matched_events.extend(matching)
        
        # Verify constraints
        for step in pattern:
            if step.constraint and not step.constraint(matched_events):
                return None
        
        return PatternMatch(
            pattern_name=pattern_name,
            events=matched_events,
            confidence=self._calculate_confidence(matched_events, pattern)
        )
```

### Incident Aggregation

```python
class IncidentAggregator:
    """
    Aggregates related violations into single incidents.
    """
    
    async def aggregate(
        self,
        violations: List[InvariantResult],
        time_window: timedelta = timedelta(minutes=15)
    ) -> List[Incident]:
        # Group violations by bridge and time
        groups = self._group_violations(violations, time_window)
        
        incidents = []
        for group in groups:
            incident = Incident(
                id=str(uuid.uuid4()),
                created_at=datetime.utcnow(),
                severity=max(v.invariant.severity for v in group),
                status=IncidentStatus.OPEN,
                violations=group,
                affected_chains=list(set(v.chain for v in group)),
                affected_bridges=list(set(v.bridge_id for v in group if v.bridge_id)),
                total_loss_usd=sum(v.violation_amount for v in group),
                attack_graph=self._build_attack_graph(group)
            )
            incidents.append(incident)
        
        return incidents
```

---

## Layer 5: Explainability Engine

### Deterministic Explanation Templates

```python
class ExplanationEngine:
    """
    Generates deterministic, human-readable explanations.
    
    NO AI hallucination - purely template-based with evidence.
    """
    
    TEMPLATES = {
        "MINT_LOCK_PARITY": """
## 🚨 CRITICAL: Unbacked Cross-Chain Mint Detected

### What Happened
{minted_amount} {asset} was minted on {dest_chain} without corresponding lock on {source_chain}.

### Evidence
- **Mints detected**: {mint_count} transactions totaling {minted_amount} {asset}
- **Locks detected**: {lock_count} transactions totaling {locked_amount} {asset}
- **Gap**: {gap_amount} {asset} ({gap_usd} USD) minted without backing

### Why This Is Dangerous
This indicates one of:
1. **Forged bridge message**: Attacker submitted fake proof of lock
2. **Validator compromise**: Attacker controls enough validators to approve fake messages
3. **Contract vulnerability**: Mint function bypassed lock verification

### Blast Radius
- **Current loss**: {gap_usd} USD
- **Bridge TVL at risk**: {bridge_tvl} USD
- **Estimated drain rate**: {drain_rate} USD/block

### Recommended Actions
1. ⚠️ **PAUSE BRIDGE IMMEDIATELY** - Every block increases loss
2. Verify guardian/validator key status
3. Check for unauthorized message submissions
4. Prepare incident response communication
""",
        
        "TVL_VELOCITY": """
## ⚠️ HIGH: Abnormal TVL Drain Detected

### What Happened
Bridge TVL decreased by {drain_percent}% ({drain_usd} USD) in the last hour.

### Evidence
- **TVL 1 hour ago**: {tvl_before} USD
- **TVL now**: {tvl_now} USD
- **Drain rate**: {drain_rate_per_block} USD/block

### Why This Is Dangerous
Rapid TVL drain typically indicates:
1. **Active exploit**: Attacker draining funds
2. **Panic withdrawal**: Users front-running suspected exploit
3. **Liquidity attack**: Coordinated drain for arbitrage

### Blast Radius
- **Current loss**: {drain_usd} USD
- **Remaining TVL**: {tvl_now} USD
- **Time to full drain at current rate**: {time_to_drain}

### Recommended Actions
1. Investigate largest withdrawals in last hour
2. Check for unusual transaction patterns
3. Monitor for exploit signatures
4. Consider temporary pause if pattern continues
"""
    }
    
    def explain(self, incident: Incident) -> Explanation:
        """
        Generate explanation for incident.
        """
        # Get primary violation type
        primary_violation = max(
            incident.violations,
            key=lambda v: v.invariant.severity.value
        )
        
        template = self.TEMPLATES.get(primary_violation.invariant.name)
        if not template:
            template = self._generate_generic_template(primary_violation)
        
        # Fill template with evidence
        explanation_text = template.format(
            **self._extract_template_vars(incident, primary_violation)
        )
        
        return Explanation(
            incident_id=incident.id,
            text=explanation_text,
            severity=incident.severity,
            confidence=self._calculate_confidence(incident),
            evidence=self._compile_evidence(incident),
            recommended_actions=self._get_recommended_actions(incident)
        )
    
    def _extract_template_vars(
        self,
        incident: Incident,
        violation: InvariantResult
    ) -> dict:
        """
        Extract variables for template from incident data.
        """
        evidence = violation.evidence
        
        return {
            "minted_amount": evidence.get("total_minted", "Unknown"),
            "locked_amount": evidence.get("total_locked", "Unknown"),
            "gap_amount": evidence.get("delta", "Unknown"),
            "gap_usd": self._format_usd(violation.violation_amount),
            "mint_count": len(evidence.get("mints", [])),
            "lock_count": len(evidence.get("locks", [])),
            "source_chain": incident.affected_chains[0] if incident.affected_chains else "Unknown",
            "dest_chain": incident.affected_chains[1] if len(incident.affected_chains) > 1 else "Unknown",
            "asset": evidence.get("asset", "tokens"),
            "bridge_tvl": self._format_usd(evidence.get("bridge_tvl", 0)),
            "drain_rate": self._format_usd(evidence.get("drain_rate", 0)),
            # ... more variables
        }
```

### Confidence Scoring

```python
class ConfidenceScorer:
    """
    Calculates confidence score for detections.
    
    High confidence = take action
    Low confidence = investigate further
    """
    
    def score(self, incident: Incident) -> float:
        """
        Returns confidence score 0.0 - 1.0
        """
        score = 0.0
        
        # Multiple invariants violated = higher confidence
        violation_count = len(incident.violations)
        score += min(0.3, violation_count * 0.1)
        
        # Critical invariants = higher confidence
        if any(v.invariant.severity == Severity.CRITICAL for v in incident.violations):
            score += 0.3
        
        # Economic loss quantified = higher confidence
        if incident.total_loss_usd > 0:
            score += 0.2
        
        # Cross-chain correlation = higher confidence
        if len(incident.affected_chains) > 1:
            score += 0.2
        
        # Known attack pattern matched
        if incident.matched_pattern:
            score += 0.2
        
        return min(1.0, score)
```

---

## Layer 6: Response Layer

### Alert Routing

```python
class AlertRouter:
    """
    Routes alerts based on severity and configuration.
    """
    
    async def route(self, incident: Incident, explanation: Explanation):
        severity = incident.severity
        
        # Critical = immediate pager + all channels
        if severity == Severity.CRITICAL:
            await asyncio.gather(
                self.pagerduty.trigger(incident, explanation),
                self.telegram.send_critical(incident, explanation),
                self.slack.send_critical(incident, explanation),
            )
        
        # High = Slack + Telegram
        elif severity == Severity.HIGH:
            await asyncio.gather(
                self.telegram.send_high(incident, explanation),
                self.slack.send_high(incident, explanation),
            )
        
        # Medium/Low = Slack only
        else:
            await self.slack.send_info(incident, explanation)
```

### Telegram Alert Format

```python
class TelegramAlerter:
    """
    Sends formatted alerts to Telegram.
    """
    
    async def send_critical(self, incident: Incident, explanation: Explanation):
        message = f"""
🚨🚨🚨 CRITICAL ALERT 🚨🚨🚨

{explanation.text[:500]}...

📊 Quick Stats:
• Severity: {incident.severity.name}
• Loss: ${incident.total_loss_usd:,.2f}
• Chains: {', '.join(incident.affected_chains)}
• Confidence: {explanation.confidence:.0%}

🔗 Full incident: {self.dashboard_url}/incidents/{incident.id}

⚡ Immediate actions:
{self._format_actions(explanation.recommended_actions[:3])}
"""
        await self.bot.send_message(
            chat_id=self.critical_channel,
            text=message,
            parse_mode="Markdown"
        )
```

---

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         KUBERNETES CLUSTER                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │ Chain Listener  │  │ Chain Listener  │  │ Chain Listener  │     │
│  │   (Ethereum)    │  │    (Solana)     │  │   (Polygon)     │     │
│  │   Deployment    │  │   Deployment    │  │   Deployment    │     │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘     │
│           │                    │                    │               │
│           └────────────────────┼────────────────────┘               │
│                                │                                    │
│                                ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      Redis Streams                           │   │
│  │                   (Event Queue)                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                │                                    │
│                                ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                  XDR Core Service                            │   │
│  │         (Normalization + Invariants + Correlation)          │   │
│  │                     Deployment (3 replicas)                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                │                                    │
│                                ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      PostgreSQL                              │   │
│  │              (Events, Incidents, State)                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Performance Requirements

| Metric | Target | Measurement |
|--------|--------|-------------|
| Event ingestion latency | < 200ms | P99 from block finality |
| Invariant evaluation | < 50ms | P99 per event |
| Incident correlation | < 100ms | P99 per violation |
| End-to-end detection | < 3 blocks | From first exploit tx |
| Alert delivery | < 10 seconds | From incident creation |
| Uptime | 99.9% | Monthly |

---

## Why This Architecture Works

1. **No trust in messages**: We verify on-chain state, not bridge messages
2. **Economic truth**: Invariants are mathematical facts, not heuristics
3. **Cross-chain correlation**: We see what no single chain can see
4. **Deterministic detection**: Same input = same output, always
5. **Explainable output**: Humans can verify our reasoning
6. **Fast enough**: Detection within blocks, not hours

