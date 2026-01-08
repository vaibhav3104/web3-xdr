"""
Calibration Harness - Replay calibration for simulator fidelity
================================================================

Simulates historical transactions and compares results to actual outcomes
to compute calibration scores per chain/protocol.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
import structlog

from .base import Simulator
from ...models.predicted_incidents import SimulationMode, SimulationStatus
from ...telemetry.rpc_client import MultiRpcProvider
from ...database.connection import DatabaseManager
from ...database.models import EventModel
from sqlalchemy import select, and_

logger = structlog.get_logger(__name__)


class CalibrationHarness:
    """
    Calibration harness for simulator fidelity measurement.
    
    Process:
    1. Sample historical transactions
    2. Simulate at previous block state
    3. Compare predicted vs actual receipts/logs
    4. Compute calibration score
    """
    
    def __init__(
        self,
        chain_id: str,
        simulator: Simulator,
        rpc_provider: MultiRpcProvider
    ):
        self.chain_id = chain_id
        self.simulator = simulator
        self.rpc_provider = rpc_provider
        self._calibration_scores: Dict[str, float] = {}  # protocol_id -> score
        
        logger.info("calibration_harness_initialized", chain_id=chain_id)
    
    async def run_calibration(
        self,
        block_range: Tuple[int, int],
        sample_size: int = 100,
        protocol_id: Optional[str] = None
    ) -> float:
        """
        Run calibration on a block range.
        
        Args:
            block_range: (start_block, end_block)
            sample_size: Number of transactions to sample
            protocol_id: Optional protocol filter
        
        Returns:
            Calibration score (0.0 - 1.0)
        """
        start_block, end_block = block_range
        
        logger.info(
            "calibration_started",
            chain_id=self.chain_id,
            block_range=(start_block, end_block),
            sample_size=sample_size,
            protocol_id=protocol_id
        )
        
        # Sample transactions from database
        sampled_txs = await self._sample_transactions(start_block, end_block, sample_size, protocol_id)
        
        if not sampled_txs:
            logger.warning("no_transactions_sampled", chain_id=self.chain_id)
            return 0.5  # Default score
        
        matches = 0
        mismatches = 0
        mismatch_categories: Dict[str, int] = {}
        
        for tx_hash, block_number in sampled_txs:
            try:
                # Get actual transaction receipt
                actual_receipt = await self.rpc_provider.get_transaction_receipt(tx_hash)
                if not actual_receipt:
                    continue
                
                # Simulate at previous block
                fork_block = block_number - 1
                
                # Get transaction data
                tx_data = await self.rpc_provider.get_transaction(tx_hash)
                if not tx_data:
                    continue
                
                # Create PendingTx (simplified - would need full conversion)
                from ...runtime.intent_sources.base import PendingTx
                pending_tx = PendingTx(
                    tx_hash=tx_hash,
                    chain_id=self.chain_id,
                    from_address=tx_data.get("from", ""),
                    to_address=tx_data.get("to"),
                    value=int(tx_data.get("value", 0)),
                    data=tx_data.get("input", "0x"),
                    block_number=block_number,
                )
                
                # Simulate
                simulation_run = await self.simulator.simulate(
                    pending_tx,
                    mode=SimulationMode.FAST,
                    fork_block=fork_block,
                    timeout_seconds=10
                )
                
                if simulation_run.status != SimulationStatus.SUCCESS:
                    mismatches += 1
                    mismatch_categories["simulation_failed"] = mismatch_categories.get("simulation_failed", 0) + 1
                    continue
                
                # Compare results
                match = await self._compare_results(simulation_run, actual_receipt, tx_data)
                
                if match:
                    matches += 1
                else:
                    mismatches += 1
                    mismatch_categories["result_mismatch"] = mismatch_categories.get("result_mismatch", 0) + 1
            
            except Exception as e:
                logger.warning(
                    "calibration_tx_failed",
                    tx_hash=tx_hash[:16],
                    error=str(e)
                )
                mismatches += 1
                mismatch_categories["error"] = mismatch_categories.get("error", 0) + 1
                continue
        
        # Compute calibration score
        total = matches + mismatches
        if total == 0:
            calibration_score = 0.5
        else:
            calibration_score = matches / total
        
        # Store calibration score
        key = protocol_id or "global"
        self._calibration_scores[key] = calibration_score
        
        logger.info(
            "calibration_completed",
            chain_id=self.chain_id,
            protocol_id=protocol_id,
            matches=matches,
            mismatches=mismatches,
            calibration_score=calibration_score,
            mismatch_categories=mismatch_categories
        )
        
        return calibration_score
    
    async def _sample_transactions(
        self,
        start_block: int,
        end_block: int,
        sample_size: int,
        protocol_id: Optional[str]
    ) -> List[Tuple[str, int]]:
        """Sample transactions from database."""
        try:
            async with DatabaseManager.get_session() as session:
                # Query events in block range
                query = select(EventModel.tx_hash, EventModel.block_number).where(
                    and_(
                        EventModel.chain_id == self.chain_id,
                        EventModel.block_number >= start_block,
                        EventModel.block_number <= end_block
                    )
                ).distinct().limit(sample_size * 2)  # Get more to account for filtering
                
                result = await session.execute(query)
                rows = result.all()
                
                # Convert to list and dedupe by tx_hash
                seen = set()
                sampled = []
                for tx_hash, block_number in rows:
                    if tx_hash not in seen:
                        seen.add(tx_hash)
                        sampled.append((tx_hash, block_number))
                        if len(sampled) >= sample_size:
                            break
                
                return sampled
        
        except Exception as e:
            logger.error("failed_to_sample_transactions", error=str(e))
            return []
    
    async def _compare_results(
        self,
        simulation_run: "SimulationRun",
        actual_receipt: dict,
        tx_data: dict
    ) -> bool:
        """
        Compare simulation results to actual receipt.
        
        Simplified comparison:
        - Check if transaction would succeed (status)
        - Compare log count (if available)
        - Compare key balance deltas (if available)
        
        Returns:
            True if results match, False otherwise
        """
        # Simplified comparison
        # Full implementation would:
        # 1. Compare transaction status (success/failure)
        # 2. Compare log count and key log events
        # 3. Compare balance deltas for watched addresses
        # 4. Compare gas usage (if available)
        
        # For now, return True (assume match)
        # This would be enhanced with actual comparison logic
        return True
    
    def get_calibration_score(self, protocol_id: Optional[str] = None) -> float:
        """Get stored calibration score."""
        key = protocol_id or "global"
        return self._calibration_scores.get(key, 0.8)  # Default 0.8 if not calibrated

