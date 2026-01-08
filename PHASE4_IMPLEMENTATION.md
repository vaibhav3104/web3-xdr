# Phase 4: Explainability Engine & Incident Clustering - Implementation Summary

## Overview

Phase 4 transforms Sentinel3 from a "Noise Generator" (alerting on every event) into an "Analyst" (grouping events into cohesive, explainable incidents).

**Status**: ✅ **COMPLETE**

---

## Components Implemented

### 1. Incident Builder Engine ✅

**File**: `src/correlation/incident_builder.py`

**Features:**
- ✅ **Stateful Deduplication**: Upsert logic (update existing or create new)
- ✅ **Cluster Key**: `(protocol_id, violation_type, source_chain, target_chain, time_window_bucket_1h)`
- ✅ **Idempotency**: Event-to-incident mapping prevents duplicates
- ✅ **Lifecycle Management**:
  - Auto-resolution after 6 hours of inactivity
  - Severity escalation (Medium → Critical)
  - Status tracking (OPEN_PENDING, OPEN_CONFIRMED, RESOLVED, STALE, FALSE_POSITIVE)
- ✅ **Event Aggregation**: Appends events to existing incidents
- ✅ **Timeline Building**: Chronological event timeline

**Key Methods:**
- `upsert_incident()`: Create or update incident
- `auto_resolve_stale_incidents()`: Auto-resolve inactive incidents
- `get_open_incidents()`: Get all active incidents

**Example:**
```python
builder = IncidentBuilder()
incident = builder.upsert_incident(violation, event)
# If matching incident exists, event is appended
# Otherwise, new incident is created
```

### 2. Explainability Engine 2.0 ✅

**Files**: 
- `src/explainability/engine.py` - Main engine
- `src/explainability/templates.py` - Template system

**Features:**
- ✅ **Structured Explanation Object**:
  - `summary`: One-sentence natural language description
  - `timeline`: List of timeline entries
  - `technical_context`: Function name, protocol version, detected pattern
  - `evidence`: Correlation keys, message IDs, amounts
  - `recommended_action`: PAUSE, INVESTIGATE, CONTACT_TEAM, MONITOR, IGNORE
- ✅ **Template System**: F-string templates for different violation types
- ✅ **Evidence Extraction**: Extracts correlation keys, amounts, message IDs

**Example Output:**
```
"Detected Mint-Without-Lock on Wormhole. Source chain Ethereum shows NO lock for sequence #123, but Solana minted 50,000 USDC."
```

**Template Types:**
- Mint-Without-Lock
- Fill-Without-Deposit
- Amount Mismatch
- Sequence Violation
- Generic

### 3. Confidence Scoring ✅

**File**: `src/detection/confidence.py`

**Heuristic Scorer (0.0 to 1.0):**
- ✅ **+0.4**: Block Finality (all events CONFIRMED)
- ✅ **+0.3**: Correlation Key Match (exact cryptographic match)
- ✅ **+0.2**: Amount Match (perfect or within tolerance)
- ✅ **+0.1**: Multi-Chain Trace (complete path confirmation)
- ✅ **-0.5**: Price Oracle Staleness (missing/stale data)

**Scoring Logic:**
```python
score = 0.0
score += finality_score * 0.4
score += correlation_score * 0.3
score += amount_score * 0.2
score += trace_score * 0.1
if oracle_stale:
    score -= 0.5
score = max(0.0, min(1.0, score))  # Clamp to [0.0, 1.0]
```

### 4. Database Model Updates ✅

**File**: `src/database/models.py`

**Added Fields to `IncidentModel`:**
- ✅ `cluster_key`: String(64), indexed - Deduplication key
- ✅ `event_count`: Integer, default=0 - Number of events in incident
- ✅ `explanation_json`: JSONB - Structured explanation (already existed, now used)

**Index Added:**
- ✅ `ix_incidents_cluster_key` - For fast deduplication lookups

### 5. API Updates ✅

**File**: `src/api/routes.py`

**Updated Endpoints:**
- ✅ `GET /api/incidents`: Added `event_count` to `IncidentSummary`
- ✅ `GET /api/incidents/{incident_id}`: New endpoint returning full details
  - Timeline entries
  - Structured explanation
  - All incident metadata

**New Models:**
- ✅ `TimelineEntry`: Timeline entry model
- ✅ `IncidentDetail`: Full incident details model

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              ViolationResult + SecurityEvent            │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   IncidentBuilder     │
         │   (Clustering)        │
         └───────────┬───────────┘
                     │
         ┌───────────┴───────────┐
         │  Generate Cluster Key │
         │  (protocol, type,     │
         │   chains, time_bucket) │
         └───────────┬───────────┘
                     │
         ┌───────────┴───────────┐
         │  Upsert Logic         │
         │  - Match existing?    │
         │  - Append event       │
         │  - Or create new      │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │      Incident         │
         │  - Aggregated events  │
         │  - Timeline           │
         │  - Value at risk      │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │ ExplainabilityEngine  │
         │  - Generate summary   │
         │  - Build timeline     │
         │  - Extract evidence   │
         │  - Recommend action  │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   ConfidenceScorer    │
         │  - Calculate score    │
         │  - Check finality     │
         │  - Verify correlation │
         └───────────────────────┘
```

---

## Key Features

### Intelligent Clustering

**Before Phase 4:**
- 100 transactions → 100 separate "Critical" alerts
- No grouping or context
- Alert fatigue

**After Phase 4:**
- 100 transactions → 1 clustered incident
- Timeline of all events
- Structured explanation
- Value at risk aggregation

### Deduplication Key

```
cluster_key = hash(
    protocol_id + ":" +
    violation_type + ":" +
    source_chain + ":" +
    target_chain + ":" +
    time_bucket_1h
)
```

**Example:**
- Protocol: `wormhole`
- Violation: `MINT_WITHOUT_LOCK`
- Source: `ethereum`
- Target: `solana`
- Time: `2026-01-08T21:00:00Z` (rounded to hour)

### Lifecycle Management

1. **OPEN_PENDING**: New incident, not yet confirmed
2. **OPEN_CONFIRMED**: Confirmed, actively being investigated
3. **RESOLVED**: Auto-resolved after 6h of inactivity
4. **STALE**: Unresolved but inactive
5. **FALSE_POSITIVE**: Manually marked

### Severity Escalation

- If incident is "MEDIUM" and receives "CRITICAL" event → Escalate to "CRITICAL"
- Updates confidence (weighted average)
- Updates value at risk (cumulative)

---

## Usage

### Creating Incidents

```python
from src.correlation.incident_builder import IncidentBuilder
from src.models.invariants import InvariantResult
from src.models.events import SecurityEvent

builder = IncidentBuilder()

# Process violation
incident = builder.upsert_incident(violation, event)

# If matching incident exists, event is appended
# Otherwise, new incident is created
```

### Generating Explanations

```python
from src.explainability import ExplainabilityEngine

engine = ExplainabilityEngine()
explanation = engine.explain_incident(
    incident=incident,
    violations=violations,
    events=events
)

print(explanation.summary)
# "Detected Mint-Without-Lock on Wormhole. Source chain Ethereum shows NO lock for sequence #123, but Solana minted 50,000 USDC."

print(explanation.recommended_action)
# RecommendedAction.PAUSE
```

### Scoring Confidence

```python
from src.detection.confidence import ConfidenceScorer

scorer = ConfidenceScorer()
confidence = scorer.score_incident(
    incident=incident,
    violations=violations,
    events=events,
    oracle_stale=False
)

print(f"Confidence: {confidence:.2f}")
# Confidence: 0.85
```

### Auto-Resolution

```python
# Auto-resolve stale incidents (runs periodically)
resolved = builder.auto_resolve_stale_incidents(max_idle_hours=6)

for incident in resolved:
    print(f"Resolved: {incident.incident_id}")
```

---

## API Endpoints

### GET /api/incidents

Returns list of incidents with `event_count`:

```json
[
  {
    "id": "inc_abc123",
    "title": "Mint-Without-Lock on Wormhole",
    "severity": "critical",
    "status": "open",
    "event_count": 15,
    "confidence": 0.85,
    "total_loss_usd": 50000.0
  }
]
```

### GET /api/incidents/{incident_id}

Returns full incident details:

```json
{
  "id": "inc_abc123",
  "cluster_key": "abc123...",
  "title": "Mint-Without-Lock on Wormhole",
  "summary": "Detected Mint-Without-Lock on Wormhole...",
  "timeline": [
    {
      "timestamp": "2026-01-08T21:00:00Z",
      "chain": "ethereum",
      "tx_hash": "0x...",
      "description": "Mint without lock detected: 50000 USDC on solana",
      "severity": "critical"
    }
  ],
  "explanation": {
    "summary": "Detected Mint-Without-Lock...",
    "recommended_action": "PAUSE",
    "confidence": 0.85,
    "evidence": [...]
  }
}
```

---

## Performance Considerations

### In-Memory Clustering

- Incidents stored in memory (`Dict[str, Incident]`)
- Fast lookups by cluster key
- No database locking during clustering

### Idempotency

- Event-to-incident mapping prevents duplicates
- Re-processing same event returns existing incident
- No duplicate evidence

### Efficient Queries

- Cluster key indexed in database
- Fast deduplication lookups
- Time-windowed buckets for efficient grouping

---

## Testing

```python
# Test clustering
builder = IncidentBuilder()
incident1 = builder.upsert_incident(violation1, event1)
incident2 = builder.upsert_incident(violation2, event2)  # Same cluster key

assert incident1.incident_id == incident2.incident_id  # Same incident
assert incident1.event_count == 2  # Two events aggregated

# Test explanation
engine = ExplainabilityEngine()
explanation = engine.explain_incident(incident1, [violation1, violation2], [event1, event2])
assert explanation.summary.startswith("Detected")
assert explanation.recommended_action in RecommendedAction

# Test confidence
scorer = ConfidenceScorer()
confidence = scorer.score_incident(incident1, [violation1], [event1])
assert 0.0 <= confidence <= 1.0
```

---

## Summary

**Phase 4 is complete and production-ready:**

- ✅ Intelligent incident clustering (100 events → 1 incident)
- ✅ Structured explanations with templates
- ✅ Confidence scoring (0.0-1.0)
- ✅ Lifecycle management (auto-resolution, escalation)
- ✅ API endpoints for full incident details
- ✅ Database model updates (cluster_key, event_count)

The system now groups related violations into cohesive incidents with human-readable explanations, transforming from a "Noise Generator" into an "Analyst".

