# Phase 7: Runtime Engine Integration - Complete

## Summary

Successfully integrated the Runtime Security Plane into the Sentinel3 Worker and API services.

## Deliverables Completed

### 1. Database Migration ✅

**File:** `scripts/migrate_runtime_tables.py`

- Creates `simulation_runs` and `predicted_incidents` tables
- Includes all necessary indexes
- Can be run standalone: `python scripts/migrate_runtime_tables.py`

**Note:** Tables are also auto-created via `DatabaseManager.create_tables()` if models are imported.

### 2. Worker Integration ✅

**File:** `src/worker/main.py`

**Changes:**
- Added Runtime Security Plane imports (with graceful fallback if not available)
- Added `runtime_engines` dictionary to track engines per chain
- Added `_initialize_runtime_engines()` method:
  - Creates `PseudoIntentBlockSource` for each EVM chain
  - Creates `RiskRouter` and `AnvilSimulator`
  - Initializes `RuntimeEngine` with all components
  - Handles Anvil unavailability gracefully (logs warning, skips chain)
- Added **Loop C (Runtime)** - `runtime_loop()`:
  - Processes each runtime engine cycle
  - Stores predicted incidents to database
  - Publishes predicted incidents to event bus with `PREDICTED` flag
  - Updates Prometheus metrics
- Added graceful shutdown:
  - Stops all runtime engines on SIGTERM
  - Shuts down Anvil simulator pools

**Configuration:**
- Controlled by `RUNTIME_ENABLED` environment variable (default: `false`)
- Only initializes for EVM chains (non-EVM not supported yet)

### 3. API Routes ✅

**File:** `src/api/runtime_routes.py` (already created in Phase 6)

**Endpoints:**
- `GET /api/runtime/predicted-incidents` - List predicted incidents
- `GET /api/runtime/predicted-incidents/{id}` - Get predicted incident details
- `GET /api/runtime/simulations/{id}` - Get simulation run details
- `POST /api/runtime/simulate` - Manual simulation (admin/operator only)
- `POST /api/runtime/predicted-incidents/{id}/dismiss` - Dismiss predicted incident

**Integration:** Routes are registered in `src/api/server.py`

### 4. Frontend Updates ✅

**File:** `frontend/index.html`

**Changes:**
- Updated `loadIncidents()` to fetch both confirmed and predicted incidents
- Merges incidents and sorts by `created_at`
- Added purple badge styling for predicted incidents (`.severity-predicted`)
- Updated incident list to show "PREDICTED" badge instead of severity for predicted incidents
- Predicted incidents display with `[PREDICTED]` prefix in title

**Visual:**
- **Red Badge**: CRITICAL (confirmed)
- **Orange Badge**: HIGH (confirmed)
- **Yellow Badge**: MEDIUM (confirmed)
- **Green Badge**: LOW (confirmed)
- **Purple Badge**: PREDICTED (simulation-based)

## Architecture Flow

```
Worker Process
├── Loop A (Ingestion): Poll chains → Publish events to bus
├── Loop B (Detection): Consume events → Process incidents
└── Loop C (Runtime): [NEW]
    ├── Get pending txs from PseudoIntentBlockSource
    ├── Route through RiskRouter
    ├── Simulate high-risk txs via AnvilSimulator
    ├── Evaluate invariants on simulation results
    ├── Create PredictedIncident if violations found
    ├── Store to database
    └── Publish to event bus (with PREDICTED flag)
```

## Configuration

### Environment Variables

```bash
# Enable Runtime Security Plane
RUNTIME_ENABLED=true

# Runtime auto-action (default: false - safe)
RUNTIME_AUTO_ACTION_ENABLED=false

# Minimum confidence for auto-action
RUNTIME_AUTO_ACTION_MIN_CONFIDENCE=0.95

# Budgets
RUNTIME_PER_CHAIN_SIM_BUDGET=60  # simulations per minute
RUNTIME_PER_PROTOCOL_SIM_BUDGET=20

# Critical contracts (comma-separated)
RUNTIME_CRITICAL_CONTRACTS=0x123...,0x456...
```

### Prerequisites

1. **Foundry Anvil** (for simulation):
   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. **Database Migration**:
   ```bash
   python scripts/migrate_runtime_tables.py
   ```

## Testing

### 1. Verify Database Tables

```sql
SELECT COUNT(*) FROM simulation_runs;
SELECT COUNT(*) FROM predicted_incidents;
```

### 2. Check Worker Logs

Look for:
- `runtime_engine_initialized` - Runtime engine started
- `runtime_loop_started` - Loop C is running
- `predicted_incident_created` - Predicted incidents being created
- `predicted_incident_stored` - Stored to database

### 3. Check API Endpoints

```bash
# List predicted incidents
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/runtime/predicted-incidents

# Get specific predicted incident
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/runtime/predicted-incidents/{id}
```

### 4. Check Frontend

- Open `http://localhost:8080/frontend/index.html`
- Look for incidents with **Purple "PREDICTED"** badge
- Predicted incidents should show `[PREDICTED]` prefix in title

## Safety Features

1. **Graceful Degradation**: If Anvil is not installed, runtime engine is disabled for that chain (logs warning, continues)
2. **Budget Enforcement**: Risk router enforces per-chain and per-protocol budgets
3. **Safe Defaults**: Predicted incidents do NOT trigger auto-pause unless explicitly enabled
4. **Non-Blocking**: Anvil simulator uses worker pool, doesn't block main event loop

## Known Limitations

1. **Anvil Dependency**: Requires Foundry Anvil to be installed. If not available, runtime plane is disabled.
2. **EVM Only**: Currently only supports EVM chains (non-EVM simulation not implemented)
3. **State Diff Extraction**: Simplified implementation - full trace-based extraction would require debug_traceCall
4. **Simulation Run Storage**: Placeholder - simulation runs are not yet stored to database (only predicted incidents)

## Next Steps

1. **Store Simulation Runs**: Implement `_store_simulation_run()` to persist simulation results
2. **Frontend Detail Page**: Add detail view for predicted incidents showing simulation results
3. **Metrics Dashboard**: Add Grafana dashboard for runtime metrics
4. **Tests**: Add unit and integration tests for runtime engine
5. **Non-EVM Support**: Extend to Cosmos/Aptos chains

## Files Modified

- `src/worker/main.py` - Added runtime engine integration
- `frontend/index.html` - Added predicted incidents display
- `scripts/migrate_runtime_tables.py` - Created migration script

## Files Created (from Phase 6)

- `src/runtime/` - All runtime security plane modules
- `src/models/predicted_incidents.py` - Data models
- `src/api/runtime_routes.py` - API routes
- `src/database/models.py` - Database models (SimulationRunModel, PredictedIncidentModel)

## Deployment Checklist

- [ ] Run database migration: `python scripts/migrate_runtime_tables.py`
- [ ] Set `RUNTIME_ENABLED=true` in environment
- [ ] Install Foundry Anvil on worker nodes
- [ ] Configure `RUNTIME_CRITICAL_CONTRACTS` if needed
- [ ] Monitor worker logs for runtime engine initialization
- [ ] Verify predicted incidents appear in frontend
- [ ] Check Prometheus metrics for runtime operations

