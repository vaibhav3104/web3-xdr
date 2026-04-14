"""
Pytest Configuration and Fixtures
==================================

Global fixtures for Sentinel3 Runtime Security Plane tests.
All external dependencies are mocked to ensure tests run without external services.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone
from typing import Dict, Any

from src.runtime.intent_sources.base import PendingTx
from src.models.predicted_incidents import (
    SimulationRun,
    SimulationMode,
    SimulationStatus,
    StateDiffFingerprint,
    PredictedIncident,
    PredictedIncidentStatus,
)
from src.models.invariants import InvariantResult, Severity


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_db():
    """Mock database connection and session."""
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None)))
    mock_session.commit = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.close = AsyncMock()
    
    mock_db_manager = MagicMock()
    mock_db_manager.get_session = MagicMock(return_value=mock_session)
    mock_db_manager.initialize = AsyncMock()
    
    return {
        "session": mock_session,
        "manager": mock_db_manager,
    }


@pytest.fixture
def mock_redis():
    """Mock Redis client and Pub/Sub."""
    mock_redis_client = AsyncMock()
    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.listen = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_redis_client.pubsub = MagicMock(return_value=mock_pubsub)
    
    return {
        "client": mock_redis_client,
        "pubsub": mock_pubsub,
    }


@pytest.fixture
def mock_anvil_process():
    """Mock Anvil subprocess."""
    mock_process = MagicMock()
    mock_process.poll = MagicMock(return_value=None)  # Process running
    mock_process.terminate = MagicMock()
    mock_process.kill = MagicMock()
    mock_process.stderr = MagicMock(read=MagicMock(return_value=b""))
    mock_process.stdout = MagicMock(read=MagicMock(return_value=b""))
    return mock_process


@pytest.fixture
def sample_pending_tx():
    """Sample pending transaction for testing."""
    return PendingTx(
        tx_hash="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        chain_id="ethereum",
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=1000000000000000000,  # 1 ETH
        data="0x8456cb59000000000000000000000000000000000000000000000000000000",  # pause()
        block_number=18000000,
        block_hash="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        gas_limit=50000,
        gas_price=20000000000,  # 20 gwei
    )


@pytest.fixture
def sample_simulation_run():
    """Sample simulation run result."""
    return SimulationRun(
        id="test-sim-123",
        chain_id="ethereum",
        block_number=18000000,
        block_hash="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        tx_hash="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        tx_from="0x1111111111111111111111111111111111111111",
        tx_to="0x2222222222222222222222222222222222222222",
        tx_selector="0x8456cb59",
        mode=SimulationMode.FAST,
        status=SimulationStatus.SUCCESS,
        created_at=datetime.now(timezone.utc),
        duration_ms=150,
        rpc_calls=5,
        state_diff_fingerprint=StateDiffFingerprint(),
        invariant_results=[],
        confidence=0.8,
        assumptions={"simulated_alone": True},
    )


@pytest.fixture
def sample_predicted_incident():
    """Sample predicted incident."""
    return PredictedIncident(
        id="test-incident-123",
        chain_id="ethereum",
        tx_hash="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        protocol_id="test-protocol",
        predicted_type="MINT_WITHOUT_LOCK",
        severity="HIGH",
        confidence=0.85,
        status=PredictedIncidentStatus.OPEN,
        dedupe_key="test-dedupe-key",
        explanation_json={"summary": "Test incident"},
        evidence_json={"violations": []},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def mock_invariant_result():
    """Mock invariant violation result."""
    return InvariantResult(
        invariant_name="MINT_LOCK_PARITY",
        violated=True,
        severity=Severity.HIGH,
        confidence=0.9,
        details={"mint_amount": "1000000", "lock_amount": "0"},
    )


@pytest.fixture
def mock_websocket():
    """Mock WebSocket connection."""
    ws = AsyncMock()
    ws.send = AsyncMock()
    ws.recv = AsyncMock()
    ws.close = AsyncMock()
    ws.__aenter__ = AsyncMock(return_value=ws)
    ws.__aexit__ = AsyncMock(return_value=None)
    return ws


@pytest.fixture(autouse=True)
def reset_mocks():
    """Reset all mocks before each test."""
    yield
    # Cleanup if needed


@pytest.fixture(autouse=True)
def _reset_singletons_and_prometheus():
    """
    Reset module-level singletons and suppress Prometheus metric
    re-registration errors between tests.

    Several modules (feedback_loop, entity_registry, confidence,
    invariants, patterns, enricher) use global singletons that
    accumulate state across tests.  Additionally, FeedbackLoop.__init__
    registers Prometheus Counter/Gauge metrics; creating a second
    instance raises ValueError (duplicated timeseries).

    This fixture:
    1. Disables Prometheus registration in FeedbackLoop for the
       duration of each test (patching PROM_AVAILABLE to False).
    2. Resets every known singleton to None after each test so the
       next test starts with a clean slate.
    """
    import src.rules.feedback_loop as _fl_mod

    # Disable Prometheus metric registration during tests to avoid
    # "Duplicated timeseries" errors when FeedbackLoop is instantiated
    # multiple times across different test classes.
    original_prom = _fl_mod.PROM_AVAILABLE
    _fl_mod.PROM_AVAILABLE = False

    yield

    # Restore original value
    _fl_mod.PROM_AVAILABLE = original_prom

    # Reset feedback_loop singleton
    _fl_mod._feedback_loop = None

    # Reset entity_registry singleton
    try:
        import src.enrichment.entity_registry as _er_mod
        _er_mod._entity_registry = None
    except (ImportError, AttributeError):
        pass

    # Reset confidence calculator singleton
    try:
        import src.rules.confidence as _cc_mod
        _cc_mod._calculator = None
    except (ImportError, AttributeError):
        pass

    # Reset invariant engine singleton
    try:
        import src.rules.invariants as _inv_mod
        _inv_mod._invariant_engine = None
    except (ImportError, AttributeError):
        pass

    # Reset pattern matcher singleton
    try:
        import src.rules.patterns as _pm_mod
        _pm_mod._pattern_matcher = None
    except (ImportError, AttributeError):
        pass

    # Reset enricher singleton
    try:
        import src.enrichment.enricher as _en_mod
        _en_mod._enricher = None
    except (ImportError, AttributeError):
        pass

