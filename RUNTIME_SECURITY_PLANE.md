# Runtime Security Plane - Implementation Summary

## Overview

The Runtime Security Plane transforms Sentinel3 from a reactive system (detecting confirmed incidents) into a proactive system that predicts incidents before they are confirmed on-chain, using transaction simulation.

## Architecture

### Key Components

1. **Intent Sources** (`src/runtime/intent_sources/`)
   - `PendingTxSource`: Abstract interface for pending transaction feeds
   - `PseudoIntentBlockSource`: Treats new blocks as "near-real-time" intents (works without mempool)

2. **Simulator** (`src/runtime/simulator/`)
   - `Simulator`: Abstract interface for transaction simulators
   - `AnvilSimulator`: Foundry Anvil-backed simulator with worker pool
   - `CalibrationHarness`: Replay calibration for simulator fidelity measurement

3. **Risk Router** (`src/runtime/risk_router.py`)
   - Routes transactions to appropriate analysis depth (IGNORE/HOT_ONLY/SIM_FAST/SIM_FULL)
   - Implements budgets to prevent system overload
   - Considers: protected contracts, dangerous selectors, value thresholds, address reputation

4. **Runtime Engine** (`src/runtime/runtime_engine.py`)
   - Orchestrates: intent → routing → simulation → predicted incident
   - Coordinates all components

5. **Policy Extension** (`src/response/policy.py`)
   - `evaluate_predicted()`: Stricter requirements for predicted incidents
   - Default: NO auto-pause (safe by default)
   - Requires explicit enable + allowlist + high confidence + multiple signals

6. **Data Models** (`src/models/predicted_incidents.py`)
   - `PredictedIncident`: Simulation-based pre-incident
   - `SimulationRun`: Audit record of simulation execution
   - `StateDiffFingerprint`: Compact state change fingerprint
   - `ConfidenceReasons`: Structured confidence scoring

7. **Database Models** (`src/database/models.py`)
   - `SimulationRunModel`: Stores simulation runs
   - `PredictedIncidentModel`: Stores predicted incidents

8. **API Routes** (`src/api/runtime_routes.py`)
   - `GET /api/runtime/predicted-incidents`: List predicted incidents
   - `GET /api/runtime/predicted-incidents/{id}`: Get predicted incident
   - `GET /api/runtime/simulations/{id}`: Get simulation run
   - `POST /api/runtime/simulate`: Manual simulation (admin/operator)
   - `POST /api/runtime/predicted-incidents/{id}/dismiss`: Dismiss predicted incident

9. **Metrics** (`src/telemetry/metrics.py`)
   - `runtime_simulations_total`: Total simulations by chain/mode/result
   - `runtime_simulation_duration_ms`: Simulation duration
   - `runtime_risk_router_decisions_total`: Router decisions
   - `runtime_budget_drops_total`: Budget limit drops
   - `predicted_incidents_total`: Predicted incidents by severity/status
   - `predicted_to_confirmed_match_rate`: Match rate gauge

## Key Features

### 1. Pseudo-Intent Mode (No Mempool Required)

The `PseudoIntentBlockSource` treats transactions in newly arrived blocks as "near-real-time" intents. This:
- Works without mempool access
- Reduces reaction latency significantly
- Applies risk routing and simulation selectively

### 2. Risk Router + Budgets

The risk router implements efficient gating:
- **HOT path**: Cheap checks only (no simulation)
- **DEEP path**: Simulation (FAST or FULL)
- Budgets prevent overload:
  - Per-chain simulation budget (default: 60/min)
  - Per-protocol simulation budget (default: 20/min)

### 3. Safe Defaults

Predicted incidents:
- **Do NOT** trigger auto-pause by default
- Require explicit enable (`RUNTIME_AUTO_ACTION_ENABLED=true`)
- Require allowlisting (protocol or contract)
- Require high confidence (default: 0.95)
- Require multiple independent signals (>= 2)

### 4. Explainability

Every predicted incident includes:
- "SIMULATION-BASED PREDICTION" banner
- Block reference used for fork
- Transaction details (hash, from, to, selector)
- Triggered invariants with formulas and deltas
- State-diff fingerprint summary
- Confidence score + reasons
- Assumptions (simulated alone vs bundle, missing context)
- Recommended actions

### 5. Calibration Harness

The calibration harness:
- Simulates historical transactions at prior state
- Compares predicted vs actual receipts/logs
- Produces calibration scores per chain/protocol
- Incorporates calibration into confidence scoring

## Configuration

### Environment Variables

```bash
# Enable Runtime Security Plane
RUNTIME_ENABLED=true

# Enable auto-action (default: false - safe)
RUNTIME_AUTO_ACTION_ENABLED=false

# Minimum confidence for auto-action (default: 0.95)
RUNTIME_AUTO_ACTION_MIN_CONFIDENCE=0.95

# Action cooldown (default: 3600 seconds)
RUNTIME_ACTION_COOLDOWN_SECONDS=3600

# Budgets
RUNTIME_PER_CHAIN_SIM_BUDGET=60  # simulations per minute
RUNTIME_PER_PROTOCOL_SIM_BUDGET=20

# Critical contracts (comma-separated)
RUNTIME_CRITICAL_CONTRACTS=0x123...,0x456...
```

## Usage

### Starting Runtime Engine

The runtime engine can be integrated into the worker process:

```python
from src.runtime.runtime_engine import RuntimeEngine
from src.runtime.intent_sources.pseudo_block import PseudoIntentBlockSource
from src.runtime.risk_router import RiskRouter
from src.runtime.simulator.anvil import AnvilSimulator

# Initialize components
intent_source = PseudoIntentBlockSource(chain_id, rpc_provider)
risk_router = RiskRouter()
simulator = AnvilSimulator(chain_id, rpc_url)
runtime_engine = RuntimeEngine(chain_id, intent_source, risk_router, simulator, invariant_engine, rpc_provider)

# Start runtime engine
await runtime_engine.start()

# Process cycle (call periodically)
predicted_incidents = await runtime_engine.process_cycle()
```

### API Usage

```bash
# List predicted incidents
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/runtime/predicted-incidents?chain_id=ethereum&status=OPEN

# Get predicted incident details
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/runtime/predicted-incidents/{id}

# Dismiss predicted incident
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "False positive"}' \
  http://localhost:8080/api/runtime/predicted-incidents/{id}/dismiss
```

## Safety Guarantees

1. **On-chain truth is authoritative**: Simulation outputs are labeled as "predicted"
2. **Efficiency**: Risk router + budgets prevent overload
3. **Safety**: Predicted incidents do NOT auto-pause unless:
   - Explicitly enabled
   - Allowlisted
   - High confidence (>= 0.95)
   - Multiple independent signals (>= 2)
   - Not in cooldown
4. **Explainability**: Complete explainability fields with assumptions

## Future Enhancements

1. **Mempool Integration**: Direct mempool feed (when available)
2. **Builder Stream Integration**: MEV builder stream support
3. **Full State Diff Extraction**: Complete trace-based state diff
4. **REVM Simulator**: Pure Python simulator option
5. **Frontend Integration**: UI for predicted incidents
6. **Tests**: Unit and integration tests

## Files Created

- `src/runtime/__init__.py`
- `src/runtime/intent_sources/__init__.py`
- `src/runtime/intent_sources/base.py`
- `src/runtime/intent_sources/pseudo_block.py`
- `src/runtime/simulator/__init__.py`
- `src/runtime/simulator/base.py`
- `src/runtime/simulator/anvil.py`
- `src/runtime/simulator/calibration.py`
- `src/runtime/risk_router.py`
- `src/runtime/runtime_engine.py`
- `src/models/predicted_incidents.py`
- `src/models/simulations.py`
- `src/api/runtime_routes.py`

## Files Modified

- `src/database/models.py` (added SimulationRunModel, PredictedIncidentModel)
- `src/response/policy.py` (added evaluate_predicted method)
- `src/telemetry/metrics.py` (added runtime metrics)
- `src/api/server.py` (registered runtime routes)

## Next Steps

1. **Database Migration**: Run Alembic migration to create new tables
2. **Worker Integration**: Integrate RuntimeEngine into worker process
3. **Frontend**: Add UI for predicted incidents
4. **Tests**: Add unit and integration tests
5. **Documentation**: Update README with runtime mode description

