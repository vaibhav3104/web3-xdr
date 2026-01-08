"""
Anvil Simulator - Foundry Anvil-backed transaction simulator
============================================================

Uses Foundry Anvil for forking and simulating transactions.
Manages a pool of Anvil instances for concurrent simulations.
"""

import asyncio
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Dict, List, Optional, Any, Tuple
import structlog
import aiohttp

from web3 import Web3, AsyncWeb3
from web3.types import TxParams

from .base import Simulator
from ...models.predicted_incidents import (
    SimulationRun,
    SimulationMode,
    SimulationStatus,
    StateDiffFingerprint,
    ConfidenceReasons,
)
from ...runtime.intent_sources.base import PendingTx

logger = structlog.get_logger(__name__)


class AnvilSimulator(Simulator):
    """
    Anvil-backed simulator with worker pool management.
    
    Features:
    - Fork at specific block numbers/hashes
    - Simulate transactions with timeout handling
    - Extract state diffs from simulation results
    - Worker pool for concurrent simulations
    """
    
    def __init__(
        self,
        chain_id: str,
        rpc_url: str,
        pool_size: int = 3,
        anvil_port_start: int = 8545,
        anvil_timeout_seconds: int = 30
    ):
        super().__init__(chain_id, rpc_url)
        self.pool_size = pool_size
        self.anvil_port_start = anvil_port_start
        self.anvil_timeout_seconds = anvil_timeout_seconds
        
        self._anvil_processes: Dict[int, subprocess.Popen] = {}  # port -> process
        self._anvil_web3: Dict[int, AsyncWeb3] = {}  # port -> Web3 instance
        self._anvil_lock = asyncio.Lock()
        self._available_ports: asyncio.Queue = asyncio.Queue()
        
        # Track fork states
        self._fork_states: Dict[int, Tuple[int, str]] = {}  # port -> (block_number, block_hash)
        
        logger.info(
            "anvil_simulator_initialized",
            chain_id=chain_id,
            pool_size=pool_size,
            anvil_port_start=anvil_port_start
        )
    
    async def initialize(self):
        """Initialize Anvil worker pool."""
        async with self._anvil_lock:
            if self._initialized:
                return
            
            logger.info("initializing_anvil_pool", pool_size=self.pool_size)
            
            # Check if anvil is available
            try:
                result = subprocess.run(
                    ["anvil", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode != 0:
                    raise RuntimeError("Anvil not found or not working")
                logger.info("anvil_found", version=result.stdout.strip())
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                logger.error("anvil_not_available", error=str(e))
                raise RuntimeError(
                    "Foundry Anvil is required but not found. "
                    "Install with: curl -L https://foundry.paradigm.xyz | bash && foundryup"
                )
            
            # Start Anvil instances
            for i in range(self.pool_size):
                port = self.anvil_port_start + i
                try:
                    await self._start_anvil_instance(port)
                    await self._available_ports.put(port)
                except Exception as e:
                    logger.error("failed_to_start_anvil_instance", port=port, error=str(e))
                    # Continue with fewer instances
            
            self._initialized = len(self._anvil_processes) > 0
            
            if not self._initialized:
                raise RuntimeError("Failed to start any Anvil instances")
            
            logger.info(
                "anvil_pool_initialized",
                instances=len(self._anvil_processes),
                ports=list(self._anvil_processes.keys())
            )
    
    async def _start_anvil_instance(self, port: int):
        """Start a single Anvil instance."""
        # Start Anvil with fork
        cmd = [
            "anvil",
            "--port", str(port),
            "--fork-url", self.rpc_url,
            "--fork-block-number", "latest",  # Will be updated per simulation
            "--host", "127.0.0.1",
            "--no-rate-limit",
            "--silent",  # Reduce noise
        ]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "ANVIL_PORT": str(port)}
        )
        
        # Wait for Anvil to be ready
        await asyncio.sleep(2)
        
        # Check if process is still running
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(f"Anvil process died: {stderr.decode()}")
        
        self._anvil_processes[port] = process
        
        # Create Web3 connection
        web3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(f"http://127.0.0.1:{port}"))
        self._anvil_web3[port] = web3
        
        logger.info("anvil_instance_started", port=port)
    
    async def shutdown(self):
        """Shutdown all Anvil instances."""
        async with self._anvil_lock:
            logger.info("shutting_down_anvil_pool", instances=len(self._anvil_processes))
            
            for port, process in self._anvil_processes.items():
                try:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    logger.info("anvil_instance_stopped", port=port)
                except Exception as e:
                    logger.warning("error_stopping_anvil", port=port, error=str(e))
            
            self._anvil_processes.clear()
            self._anvil_web3.clear()
            self._fork_states.clear()
            
            # Clear queue
            while not self._available_ports.empty():
                try:
                    self._available_ports.get_nowait()
                except:
                    pass
            
            self._initialized = False
            logger.info("anvil_pool_shutdown_complete")
    
    async def simulate(
        self,
        pending_tx: PendingTx,
        mode: SimulationMode = SimulationMode.FAST,
        fork_block: Optional[int] = None,
        fork_block_hash: Optional[str] = None,
        timeout_seconds: int = 30
    ) -> SimulationRun:
        """
        Simulate a pending transaction using Anvil.
        """
        start_time = time.time()
        simulation_id = f"sim_{int(start_time * 1000)}"
        
        # Get available Anvil instance
        port = await self._available_ports.get()
        
        try:
            web3 = self._anvil_web3[port]
            
            # Fork at specified block if needed
            if fork_block is not None:
                await self._fork_at_block(port, fork_block, fork_block_hash)
            
            # Prepare transaction
            tx_params: TxParams = {
                "from": pending_tx.from_address,
                "to": pending_tx.to_address,
                "value": pending_tx.value,
                "data": pending_tx.data,
                "gas": pending_tx.gas_limit or 5000000,
            }
            
            if pending_tx.gas_price:
                tx_params["gasPrice"] = pending_tx.gas_price
            elif pending_tx.max_fee_per_gas:
                tx_params["maxFeePerGas"] = pending_tx.max_fee_per_gas
            
            # Simulate transaction
            try:
                # Step 1: Take snapshot for loss estimation (Phase 9)
                snapshot_id = None
                try:
                    snapshot_result = await web3.provider.make_request("evm_snapshot", [])
                    if snapshot_result and isinstance(snapshot_result, int):
                        snapshot_id = snapshot_result
                        logger.debug("snapshot_taken", snapshot_id=snapshot_id, port=port)
                except Exception as e:
                    logger.warning("snapshot_failed", error=str(e))
                
                # Step 2: Use eth_call for simulation (doesn't actually execute)
                result = await asyncio.wait_for(
                    web3.eth.call(tx_params, block_identifier=fork_block or "latest"),
                    timeout=timeout_seconds
                )
                
                # Get transaction receipt (if it would succeed)
                # For state diff, we need to trace the execution
                # This is a simplified version - full implementation would use debug_traceCall
                
                duration_ms = int((time.time() - start_time) * 1000)
                
                # Extract state diff (simplified - would need trace for full diff)
                state_diff = StateDiffFingerprint()  # Empty for now, will be populated by extract_state_diff
                
                # Step 3: Revert snapshot (cleanup)
                if snapshot_id is not None:
                    try:
                        await web3.provider.make_request("evm_revert", [snapshot_id])
                        logger.debug("snapshot_reverted", snapshot_id=snapshot_id, port=port)
                    except Exception as e:
                        logger.warning("revert_snapshot_failed", snapshot_id=snapshot_id, error=str(e))
                
                simulation_run = SimulationRun(
                    id=simulation_id,
                    chain_id=self.chain_id,
                    block_number=fork_block or 0,
                    block_hash=fork_block_hash or "",
                    tx_hash=pending_tx.tx_hash,
                    tx_from=pending_tx.from_address,
                    tx_to=pending_tx.to_address,
                    tx_selector=pending_tx.selector,
                    mode=mode,
                    status=SimulationStatus.SUCCESS,
                    duration_ms=duration_ms,
                    rpc_calls=1,  # Simplified
                    state_diff_fingerprint=state_diff,
                    invariant_results=[],
                    confidence=0.5,  # Default, will be computed by risk router
                    assumptions={"simulated_alone": True, "missing_context": ["pending_txs"]},
                )
                
                logger.info(
                    "simulation_completed",
                    simulation_id=simulation_id,
                    tx_hash=pending_tx.tx_hash[:16],
                    duration_ms=duration_ms,
                    status="SUCCESS"
                )
                
                return simulation_run
                
            except asyncio.TimeoutError:
                duration_ms = int((time.time() - start_time) * 1000)
                logger.warning(
                    "simulation_timeout",
                    simulation_id=simulation_id,
                    tx_hash=pending_tx.tx_hash[:16],
                    timeout_seconds=timeout_seconds
                )
                
                return SimulationRun(
                    id=simulation_id,
                    chain_id=self.chain_id,
                    block_number=fork_block or 0,
                    block_hash=fork_block_hash or "",
                    tx_hash=pending_tx.tx_hash,
                    tx_from=pending_tx.from_address,
                    tx_to=pending_tx.to_address,
                    tx_selector=pending_tx.selector,
                    mode=mode,
                    status=SimulationStatus.TIMEOUT,
                    duration_ms=duration_ms,
                    rpc_calls=0,
                    confidence=0.0,
                )
                
            except Exception as e:
                duration_ms = int((time.time() - start_time) * 1000)
                logger.error(
                    "simulation_failed",
                    simulation_id=simulation_id,
                    tx_hash=pending_tx.tx_hash[:16],
                    error=str(e)
                )
                
                return SimulationRun(
                    id=simulation_id,
                    chain_id=self.chain_id,
                    block_number=fork_block or 0,
                    block_hash=fork_block_hash or "",
                    tx_hash=pending_tx.tx_hash,
                    tx_from=pending_tx.from_address,
                    tx_to=pending_tx.to_address,
                    tx_selector=pending_tx.selector,
                    mode=mode,
                    status=SimulationStatus.FAILED,
                    duration_ms=duration_ms,
                    rpc_calls=0,
                    confidence=0.0,
                )
        
        finally:
            # Return port to pool
            await self._available_ports.put(port)
    
    async def _fork_at_block(self, port: int, block_number: int, block_hash: Optional[str] = None):
        """Fork Anvil instance at a specific block."""
        # Check if already forked at this block
        if port in self._fork_states:
            current_block, current_hash = self._fork_states[port]
            if current_block == block_number:
                return  # Already forked at this block
        
        # Restart Anvil with new fork block
        # Note: Anvil doesn't support dynamic fork block changes easily
        # For production, we'd restart the instance or use a different approach
        # This is a simplified version
        
        web3 = self._anvil_web3[port]
        
        # Reset to fork block (simplified - would need Anvil restart for true fork)
        # For now, we'll just record the fork state
        self._fork_states[port] = (block_number, block_hash or "")
        
        logger.debug(
            "anvil_forked_at_block",
            port=port,
            block_number=block_number,
            block_hash=block_hash
        )
    
    async def extract_state_diff(
        self,
        simulation_result: Dict[str, Any],
        protected_addresses: List[str],
        watched_tokens: List[str],
        watched_pools: List[str]
    ) -> StateDiffFingerprint:
        """
        Extract state diff fingerprint from simulation result.
        
        This is a simplified implementation. A full implementation would:
        1. Use debug_traceCall to get full state diff
        2. Parse storage slots for tokens/pools
        3. Extract balance changes, supply changes, etc.
        """
        fingerprint = StateDiffFingerprint()
        
        # TODO: Implement full state diff extraction using trace
        # For now, return empty fingerprint
        # In production, this would:
        # - Call debug_traceCall on the simulation
        # - Parse the trace for storage changes
        # - Extract balance deltas for protected addresses
        # - Extract totalSupply deltas for watched tokens
        # - Extract reserve deltas for watched pools
        
        logger.debug(
            "state_diff_extracted",
            protected_addresses=len(protected_addresses),
            watched_tokens=len(watched_tokens),
            watched_pools=len(watched_pools)
        )
        
        return fingerprint

