"""
Simulator Interface
===================

Abstract base class for transaction simulators.
Implementations can use Anvil, REVM, or other simulation engines.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import structlog

from ...models.predicted_incidents import (
    SimulationRun,
    SimulationMode,
    StateDiffFingerprint,
)
from ...runtime.intent_sources.base import PendingTx

logger = structlog.get_logger(__name__)


class Simulator(ABC):
    """
    Abstract base class for transaction simulators.
    
    Implementations:
    - AnvilSimulator: Uses Foundry Anvil for forking and simulation
    - RevmSimulator: (Future) Pure Python REVM-based simulator
    """
    
    def __init__(self, chain_id: str, rpc_url: str):
        self.chain_id = chain_id
        self.rpc_url = rpc_url
        self._initialized = False
        logger.info("simulator_initialized", chain_id=chain_id, simulator_type=type(self).__name__)
    
    @abstractmethod
    async def initialize(self):
        """Initialize the simulator (e.g., start Anvil process)."""
        pass
    
    @abstractmethod
    async def shutdown(self):
        """Shutdown the simulator and clean up resources."""
        pass
    
    @abstractmethod
    async def simulate(
        self,
        pending_tx: PendingTx,
        mode: SimulationMode = SimulationMode.FAST,
        fork_block: Optional[int] = None,
        fork_block_hash: Optional[str] = None,
        timeout_seconds: int = 30
    ) -> SimulationRun:
        """
        Simulate a pending transaction.
        
        Args:
            pending_tx: The transaction to simulate
            mode: Simulation mode (FAST/FULL/BUNDLE)
            fork_block: Block number to fork at (None = latest)
            fork_block_hash: Block hash to fork at (for reorg safety)
            timeout_seconds: Maximum time to wait for simulation
        
        Returns:
            SimulationRun with results
        """
        pass
    
    @abstractmethod
    async def extract_state_diff(
        self,
        simulation_result: Dict[str, Any],
        protected_addresses: List[str],
        watched_tokens: List[str],
        watched_pools: List[str]
    ) -> StateDiffFingerprint:
        """
        Extract state diff fingerprint from simulation result.
        
        Args:
            simulation_result: Raw simulation result from simulator
            protected_addresses: Addresses to track balance changes for
            watched_tokens: Token addresses to track supply changes for
            watched_pools: Pool addresses to track reserve changes for
        
        Returns:
            StateDiffFingerprint with compact state changes
        """
        pass
    
    @property
    def is_initialized(self) -> bool:
        """Check if simulator is initialized."""
        return self._initialized

