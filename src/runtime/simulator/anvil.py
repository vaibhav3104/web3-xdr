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
        # Start Anvil with fork (uses latest block by default)
        cmd = [
            "anvil",
            "--port", str(port),
            "--fork-url", self.rpc_url,
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

                # Extract state diff via debug_traceCall (prestateTracer)
                state_diff = StateDiffFingerprint()
                try:
                    state_diff = await self.extract_state_diff(
                        simulation_result={"tx_params": tx_params, "port": port},
                        protected_addresses=[pending_tx.to_address] if pending_tx.to_address else [],
                        watched_tokens=[pending_tx.to_address] if pending_tx.to_address else [],
                        watched_pools=[],
                    )
                    if state_diff.token_balance_deltas or state_diff.total_supply_deltas or state_diff.reserve_deltas:
                        logger.info(
                            "state_diff_extracted",
                            tx_hash=pending_tx.tx_hash[:16],
                            balance_deltas=len(state_diff.token_balance_deltas),
                            supply_deltas=len(state_diff.total_supply_deltas),
                            reserve_deltas=len(state_diff.reserve_deltas),
                        )
                except Exception as diff_err:
                    logger.debug("state_diff_extraction_failed", error=str(diff_err))

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
    
    # Well-known ERC-20 storage slot patterns for balanceOf(address)
    # slot = keccak256(abi.encode(address, BALANCE_MAPPING_SLOT))
    COMMON_BALANCE_SLOTS = [0, 1, 2, 3, 5, 9, 51]  # OZ, Vyper, custom patterns
    # Well-known ERC-20 totalSupply slots
    COMMON_SUPPLY_SLOTS = [0, 2, 3]

    async def extract_state_diff(
        self,
        simulation_result: Dict[str, Any],
        protected_addresses: List[str],
        watched_tokens: List[str],
        watched_pools: List[str],
    ) -> StateDiffFingerprint:
        """
        Extract state diff fingerprint from simulation using debug_traceCall.

        Uses Anvil's prestateTracer to capture storage-level changes, then
        maps known storage slot patterns to semantic fields (balances,
        totalSupply, pool reserves).
        """
        fingerprint = StateDiffFingerprint()

        tx_params = simulation_result.get("tx_params")
        port = simulation_result.get("port")
        if not tx_params or not port:
            logger.debug("state_diff_skipped_no_params")
            return fingerprint

        web3 = self._anvil_web3.get(port)
        if not web3:
            return fingerprint

        try:
            # Call debug_traceCall with prestateTracer (Anvil supports this)
            trace = await web3.provider.make_request(
                "debug_traceCall",
                [
                    tx_params,
                    "latest",
                    {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}},
                ],
            )

            if not trace or not isinstance(trace, dict):
                logger.debug("state_diff_empty_trace")
                return fingerprint

            # trace has {"pre": {addr: {storage, balance, ...}}, "post": {addr: ...}}
            pre_state = trace.get("pre", trace.get("result", {}).get("pre", {}))
            post_state = trace.get("post", trace.get("result", {}).get("post", {}))

            if not pre_state and not post_state:
                # Try flat format (some Anvil versions)
                pre_state = trace.get("result", {})
                post_state = {}

            # --- 1. Token balance deltas for protected addresses ---
            protected_set = {a.lower() for a in protected_addresses}
            watched_token_set = {t.lower() for t in watched_tokens}
            watched_pool_set = {p.lower() for p in watched_pools}

            for token_addr in watched_token_set:
                token_pre = pre_state.get(token_addr, {}).get("storage", {})
                token_post = post_state.get(token_addr, {}).get("storage", {})

                if not token_post:
                    continue

                # Find changed storage slots
                changed_slots = set(token_post.keys())

                for addr in protected_set:
                    # Compute expected balance slots (keccak of packed addr + mapping slot)
                    for mapping_slot in self.COMMON_BALANCE_SLOTS:
                        slot_key = Web3.keccak(
                            bytes.fromhex(addr[2:].zfill(64))
                            + mapping_slot.to_bytes(32, "big")
                        ).hex()
                        slot_key_prefixed = "0x" + slot_key

                        if slot_key_prefixed in changed_slots:
                            pre_val = int(token_pre.get(slot_key_prefixed, "0x0"), 16)
                            post_val = int(token_post[slot_key_prefixed], 16)
                            delta = Decimal(post_val - pre_val)

                            if delta != 0:
                                if addr not in fingerprint.token_balance_deltas:
                                    fingerprint.token_balance_deltas[addr] = {}
                                fingerprint.token_balance_deltas[addr][token_addr] = delta

                # --- 2. totalSupply deltas ---
                for supply_slot in self.COMMON_SUPPLY_SLOTS:
                    slot_hex = "0x" + supply_slot.to_bytes(32, "big").hex()
                    if slot_hex in changed_slots:
                        pre_val = int(token_pre.get(slot_hex, "0x0"), 16)
                        post_val = int(token_post[slot_hex], 16)
                        delta = Decimal(post_val - pre_val)
                        if delta != 0:
                            fingerprint.total_supply_deltas[token_addr] = delta

            # --- 3. Reserve deltas for watched pools ---
            for pool_addr in watched_pool_set:
                pool_pre = pre_state.get(pool_addr, {}).get("storage", {})
                pool_post = post_state.get(pool_addr, {}).get("storage", {})

                if not pool_post:
                    continue

                # Uniswap V2 reserves: slot 8 packs reserve0 + reserve1 + blockTimestampLast
                reserve_slot = "0x" + (8).to_bytes(32, "big").hex()
                if reserve_slot in pool_post:
                    pre_packed = int(pool_pre.get(reserve_slot, "0x0"), 16)
                    post_packed = int(pool_post[reserve_slot], 16)

                    # Unpack: reserve0 = lower 112 bits, reserve1 = next 112 bits
                    mask_112 = (1 << 112) - 1
                    pre_r0, pre_r1 = pre_packed & mask_112, (pre_packed >> 112) & mask_112
                    post_r0, post_r1 = post_packed & mask_112, (post_packed >> 112) & mask_112

                    deltas = {}
                    if post_r0 - pre_r0 != 0:
                        deltas["reserve0"] = Decimal(post_r0 - pre_r0)
                    if post_r1 - pre_r1 != 0:
                        deltas["reserve1"] = Decimal(post_r1 - pre_r1)
                    if deltas:
                        fingerprint.reserve_deltas[pool_addr] = deltas

                # Check all changed slots for potential reserve changes (V3 pools)
                for slot_key in pool_post:
                    if slot_key == reserve_slot:
                        continue
                    pre_val = int(pool_pre.get(slot_key, "0x0"), 16)
                    post_val = int(pool_post[slot_key], 16)
                    # Large changes in pool storage are suspicious
                    if abs(post_val - pre_val) > 10**18:  # > 1 token unit
                        if pool_addr not in fingerprint.reserve_deltas:
                            fingerprint.reserve_deltas[pool_addr] = {}
                        fingerprint.reserve_deltas[pool_addr][slot_key[:10]] = Decimal(post_val - pre_val)

            # --- 4. Admin/proxy slot changes ---
            # EIP-1967 slots
            ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
            IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

            for addr in {**pre_state, **post_state}:
                addr_post = post_state.get(addr, {}).get("storage", {})
                addr_pre = pre_state.get(addr, {}).get("storage", {})

                for slot_name, slot_key in [("admin", ADMIN_SLOT), ("implementation", IMPL_SLOT)]:
                    if slot_key in addr_post:
                        old_val = addr_pre.get(slot_key, "0x0")
                        new_val = addr_post[slot_key]
                        if old_val != new_val:
                            fingerprint.admin_changes.append({
                                "contract": addr,
                                "slot": slot_name,
                                "old": old_val,
                                "new": new_val,
                            })

            logger.info(
                "state_diff_extracted",
                balance_deltas=len(fingerprint.token_balance_deltas),
                supply_deltas=len(fingerprint.total_supply_deltas),
                reserve_deltas=len(fingerprint.reserve_deltas),
                admin_changes=len(fingerprint.admin_changes),
            )

        except Exception as e:
            logger.warning("state_diff_extraction_failed", error=str(e))

        return fingerprint

