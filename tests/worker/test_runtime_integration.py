"""
End-to-End Runtime Security Plane Integration Tests
===================================================

Tests covering the full flow:
- Intent -> Source -> Router -> Simulator -> Incident
- Deduplication
- Database fallback
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
import sys
import io

# Mock pubsub before importing runtime_engine
import sys
from unittest.mock import MagicMock

# Mock the pubsub module to avoid import errors
mock_pubsub = MagicMock()
mock_pubsub_instance = AsyncMock()
mock_pubsub_instance.publish_intent = AsyncMock()
mock_pubsub_instance.publish_simulation = AsyncMock()
mock_pubsub_instance.publish_threat = AsyncMock()
mock_pubsub_instance.publish_predicted_incident = AsyncMock()
mock_pubsub.get_runtime_pubsub = AsyncMock(return_value=mock_pubsub_instance)
sys.modules['src.runtime.pubsub'] = mock_pubsub

from src.runtime.runtime_engine import RuntimeEngine
from src.runtime.intent_sources.base import PendingTx, PendingTxSource
from src.runtime.risk_router import RiskRouter, RouterDecision
from src.runtime.simulator.base import Simulator
from src.invariants.engine import InvariantEngine
from src.models.predicted_incidents import (
    PredictedIncident,
    PredictedIncidentStatus,
    SimulationRun,
    SimulationMode,
    SimulationStatus,
    StateDiffFingerprint,
)
from src.models.invariants import InvariantResult, Severity
from src.telemetry.rpc_client import MultiRpcProvider


class MockIntentSource(PendingTxSource):
    """Mock intent source for testing."""
    
    def __init__(self, chain_id: str, txs: list = None):
        super().__init__(chain_id)
        self.txs = txs or []
        self._running = False
    
    async def start(self):
        self._running = True
    
    async def stop(self):
        self._running = False
    
    async def get_pending_txs(self, limit: int = 100):
        return self.txs[:limit]


class MockSimulator(Simulator):
    """Mock simulator for testing."""
    
    def __init__(self, chain_id: str, rpc_url: str):
        super().__init__(chain_id, rpc_url)
        self.simulations_run = []
        self._initialized = False
    
    async def initialize(self):
        self._initialized = True
    
    async def shutdown(self):
        self._initialized = False
    
    async def simulate(self, pending_tx, mode=None, fork_block=None, fork_block_hash=None, timeout_seconds=30):
        # Track simulation
        self.simulations_run.append(pending_tx.tx_hash)
        
        return SimulationRun(
            id=f"sim-{pending_tx.tx_hash[:8]}",
            chain_id=self.chain_id,
            block_number=fork_block or 0,
            block_hash=fork_block_hash or "",
            tx_hash=pending_tx.tx_hash,
            tx_from=pending_tx.from_address,
            tx_to=pending_tx.to_address,
            tx_selector=pending_tx.selector,
            mode=mode or SimulationMode.FAST,
            status=SimulationStatus.SUCCESS,
            created_at=datetime.now(timezone.utc),
            duration_ms=100,
            rpc_calls=1,
            state_diff_fingerprint=StateDiffFingerprint(),
            invariant_results=[],
            confidence=0.8,
            assumptions={},
        )
    
    async def extract_state_diff(self, simulation_result, protected_addresses, watched_tokens, watched_pools):
        # Async method to match runtime_engine expectations
        return StateDiffFingerprint()


@pytest.mark.asyncio
class TestRuntimeIntegration:
    """End-to-end integration tests."""
    
    @pytest.fixture
    def malicious_tx(self):
        """Malicious transaction for testing."""
        return PendingTx(
            tx_hash="0xmalicious1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            chain_id="ethereum",
            from_address="0x9999999999999999999999999999999999999999",
            to_address="0x2222222222222222222222222222222222222222",
            value=1000000000000000000,  # 1 ETH
            data="0x8456cb59",  # pause() - dangerous selector
            block_number=18000000,
        )
    
    @pytest.fixture
    def mock_invariant_engine(self):
        """Mock invariant engine that returns violations."""
        engine = AsyncMock(spec=InvariantEngine)
        
        async def mock_evaluate(events):
            # Return a violation for malicious transactions
            return [
                InvariantResult(
                    invariant_name="DANGEROUS_SELECTOR",
                    violated=True,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    details={"selector": "0x8456cb59"},
                )
            ]
        
        engine.evaluate = AsyncMock(side_effect=mock_evaluate)
        engine.initialize = AsyncMock()
        engine.shutdown = AsyncMock()
        return engine
    
    @pytest.fixture
    def mock_rpc_provider(self):
        """Mock RPC provider."""
        provider = AsyncMock(spec=MultiRpcProvider)
        provider.get_block_number = AsyncMock(return_value=18000000)
        provider.get_block = AsyncMock(return_value={"hash": "0xblockhash"})
        provider.initialize = AsyncMock()
        provider.shutdown = AsyncMock()
        return provider
    
    @pytest.fixture
    def runtime_engine(self, malicious_tx, mock_invariant_engine, mock_rpc_provider):
        """Create RuntimeEngine with mocked dependencies."""
        intent_source = MockIntentSource("ethereum", [malicious_tx])
        risk_router = RiskRouter()
        simulator = MockSimulator("ethereum", "http://localhost:8545")
        
        engine = RuntimeEngine(
            chain_id="ethereum",
            intent_source=intent_source,
            risk_router=risk_router,
            simulator=simulator,
            invariant_engine=mock_invariant_engine,
            rpc_provider=mock_rpc_provider,
        )
        
        return engine
    
    @pytest.mark.asyncio
    async def test_full_flow_malicious_intent_to_incident(self, runtime_engine, malicious_tx, mock_invariant_engine):
        """Test: Inject a 'Malicious Intent' -> Source -> Router -> Simulator -> Incident."""
        # Initialize engine
        await runtime_engine.initialize()
        runtime_engine._running = True
        
        # Process cycle
        incidents = await runtime_engine.process_cycle()
        
        # Verify incident was created
        assert len(incidents) > 0
        incident = incidents[0]
        
        assert isinstance(incident, PredictedIncident)
        assert incident.tx_hash == malicious_tx.tx_hash
        assert incident.status == PredictedIncidentStatus.OPEN
        assert incident.confidence > 0
        
        # Verify simulation was run
        assert malicious_tx.tx_hash in runtime_engine.simulator.simulations_run
        
        await runtime_engine.shutdown()
    
    @pytest.mark.asyncio
    async def test_deduplication_same_tx_hash_once(self, runtime_engine, malicious_tx):
        """Test: Inject the SAME transaction hash twice. Verify only ONE simulation runs."""
        # Add same transaction twice
        runtime_engine.intent_source.txs = [malicious_tx, malicious_tx]
        
        await runtime_engine.initialize()
        runtime_engine._running = True
        
        # Process cycle
        incidents = await runtime_engine.process_cycle()
        
        # Verify only one simulation was run (deduplication)
        assert runtime_engine.simulator.simulations_run.count(malicious_tx.tx_hash) == 1
        
        # Verify only one incident was created
        assert len(incidents) == 1
        
        await runtime_engine.shutdown()
    
    
    @pytest.mark.asyncio
    async def test_router_ignore_skips_simulation(self, runtime_engine):
        """Test: Transactions that router ignores don't trigger simulation."""
        # Create safe transaction (should be ignored)
        safe_tx = PendingTx(
            tx_hash="0xsafe123",
            chain_id="ethereum",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=1000,  # Very small value
            data="0xa9059cbb",  # Safe selector
        )
        
        runtime_engine.intent_source.txs = [safe_tx]
        
        await runtime_engine.initialize()
        runtime_engine._running = True
        
        # Process cycle
        incidents = await runtime_engine.process_cycle()
        
        # Verify no simulation was run
        assert safe_tx.tx_hash not in runtime_engine.simulator.simulations_run
        
        # Verify no incidents created
        assert len(incidents) == 0
        
        await runtime_engine.shutdown()
    
    @pytest.mark.asyncio
    async def test_multiple_violations_create_single_incident(self, runtime_engine, malicious_tx, mock_invariant_engine):
        """Test: Multiple invariant violations create single incident with all violations."""
        # Mock engine to return multiple violations
        async def mock_evaluate(events):
            return [
                InvariantResult(
                    invariant_name="DANGEROUS_SELECTOR",
                    violated=True,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    details={},
                ),
                InvariantResult(
                    invariant_name="LARGE_VALUE",
                    violated=True,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    details={},
                ),
            ]
        
        mock_invariant_engine.evaluate = AsyncMock(side_effect=mock_evaluate)
        
        await runtime_engine.initialize()
        runtime_engine._running = True
        
        incidents = await runtime_engine.process_cycle()
        
        # Verify incident contains all violations
        assert len(incidents) > 0
        incident = incidents[0]
        assert len(incident.evidence_json.get("invariant_violations", [])) >= 2
        
        await runtime_engine.shutdown()
    
    @pytest.mark.asyncio
    async def test_simulation_failure_handles_gracefully(self, runtime_engine, malicious_tx):
        """Test: If simulation fails, system continues without crashing."""
        # Mock simulator to raise error
        async def mock_simulate(*args, **kwargs):
            raise RuntimeError("Simulation failed")
        
        runtime_engine.simulator.simulate = mock_simulate
        
        await runtime_engine.initialize()
        runtime_engine._running = True
        
        # Should not crash
        incidents = await runtime_engine.process_cycle()
        
        # May or may not create incidents, but shouldn't crash
        assert isinstance(incidents, list)
        
        await runtime_engine.shutdown()
    
    @pytest.mark.asyncio
    async def test_empty_intent_source_no_crash(self, runtime_engine):
        """Test: Empty intent source doesn't cause errors."""
        runtime_engine.intent_source.txs = []
        
        await runtime_engine.initialize()
        runtime_engine._running = True
        
        incidents = await runtime_engine.process_cycle()
        
        # Should return empty list, not crash
        assert incidents == []
        
        await runtime_engine.shutdown()

