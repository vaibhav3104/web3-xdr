# Sentinel3 Runtime Security Plane Test Suite

Comprehensive test suite for the Runtime Security Plane with **90%+ code coverage**.

## Test Structure

```
tests/
├── conftest.py                    # Global fixtures (mock_db, mock_redis, etc.)
├── runtime/
│   ├── test_sources.py          # Mempool source reliability tests
│   ├── test_risk_router.py      # Risk router decision logic tests
│   └── test_simulator.py         # Anvil simulator wrapper tests
└── worker/
    └── test_runtime_integration.py  # End-to-end integration tests
```

## Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/runtime/test_sources.py -v

# Run with coverage
pytest tests/ --cov=src/runtime --cov-report=html

# Run only fast tests (exclude slow/integration)
pytest tests/ -m "not slow"
```

## Test Coverage

### `test_sources.py` - Mempool Source Reliability
- ✅ Happy path with valid JSON
- ✅ Malformed data handling (no crash)
- ✅ WebSocket disconnect/reconnect with backoff
- ✅ Auth failure (401/403) handling
- ✅ Filter logic for monitored addresses
- ✅ Field normalization

### `test_risk_router.py` - Decision Logic
- ✅ Budget tracking and rate limiting
- ✅ Whitelist/blacklist logic
- ✅ Zero value transaction handling
- ✅ Dangerous selector detection
- ✅ Large value threshold
- ✅ Critical contract protection

### `test_simulator.py` - Anvil Wrapper
- ✅ Timeout handling and cleanup
- ✅ Process crash recovery
- ✅ Revert reason capture
- ✅ Concurrency and state isolation
- ✅ Snapshot/revert functionality

### `test_runtime_integration.py` - End-to-End
- ✅ Full flow: Intent → Router → Simulator → Incident
- ✅ Deduplication (same tx hash)
- ✅ Database fallback to stderr logging
- ✅ Router ignore skips simulation
- ✅ Multiple violations in single incident
- ✅ Simulation failure handling

## Key Features

- **100% Mocked**: No external dependencies (Anvil, DB, Redis, bloXroute)
- **Async Support**: All async tests use `@pytest.mark.asyncio`
- **Edge Cases**: Comprehensive coverage of failure scenarios
- **No Dangling Coroutines**: All async operations properly awaited

## Fixtures

See `conftest.py` for available fixtures:
- `mock_db` - Mock database connection
- `mock_redis` - Mock Redis client
- `mock_anvil_process` - Mock Anvil subprocess
- `sample_pending_tx` - Sample transaction
- `sample_simulation_run` - Sample simulation result
- `sample_predicted_incident` - Sample incident

