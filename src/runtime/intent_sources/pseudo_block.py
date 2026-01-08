"""
Pseudo-Intent Block Source
===========================

Treats transactions in newly arrived blocks as "near-real-time" intents.
This works without mempool access by simulating transactions as soon as
they appear in blocks, reducing reaction latency significantly.

This is the default implementation for the Runtime Security Plane.
"""

from datetime import datetime, timezone
from typing import List, Optional
import structlog

from web3 import Web3
from web3.types import TxData

from .base import PendingTx, PendingTxSource
from ...telemetry.rpc_client import MultiRpcProvider

logger = structlog.get_logger(__name__)


class PseudoIntentBlockSource(PendingTxSource):
    """
    Treats transactions in new blocks as pseudo-intents.
    
    On new block:
    1. Fetch block transaction list quickly
    2. Convert each tx to PendingTx
    3. Return for risk routing and simulation
    
    This reduces reaction latency without requiring mempool access.
    """
    
    def __init__(self, chain_id: str, rpc_provider: MultiRpcProvider, start_block: Optional[int] = None):
        super().__init__(chain_id)
        self.rpc_provider = rpc_provider
        self.last_processed_block = start_block or 0
        self._running = False
        logger.info(
            "pseudo_intent_block_source_initialized",
            chain_id=chain_id,
            start_block=self.last_processed_block
        )
    
    async def start(self):
        """Start the source."""
        self._running = True
        logger.info("pseudo_intent_block_source_started", chain_id=self.chain_id)
    
    async def stop(self):
        """Stop the source."""
        self._running = False
        logger.info("pseudo_intent_block_source_stopped", chain_id=self.chain_id)
    
    async def get_pending_txs(self, limit: int = 100) -> List[PendingTx]:
        """
        Get transactions from the latest block(s) as pseudo-intents.
        
        This fetches transactions from blocks that haven't been processed yet,
        treating them as "near-real-time" intents for simulation.
        """
        if not self._running:
            return []
        
        try:
            # Get current block height
            latest_block = await self.rpc_provider.get_block_number()
            
            if latest_block <= self.last_processed_block:
                return []  # No new blocks
            
            # Process blocks up to current (but respect limit)
            pending_txs: List[PendingTx] = []
            blocks_to_process = min(latest_block - self.last_processed_block, 5)  # Max 5 blocks at once
            
            for block_num in range(self.last_processed_block + 1, self.last_processed_block + blocks_to_process + 1):
                if len(pending_txs) >= limit:
                    break
                
                # Fetch block
                block = await self.rpc_provider.get_block(block_num, require_quorum=False)
                if not block:
                    logger.warning("failed_to_fetch_block", chain_id=self.chain_id, block_number=block_num)
                    continue
                
                block_hash = block.get("hash", "")
                block_timestamp = datetime.fromtimestamp(block.get("timestamp", 0), tz=timezone.utc)
                
                # Get transactions
                tx_hashes = block.get("transactions", [])
                if not tx_hashes:
                    continue
                
                # Fetch transaction details (batch)
                for tx_hash in tx_hashes[:limit - len(pending_txs)]:
                    try:
                        tx_data = await self.rpc_provider.get_transaction(tx_hash)
                        if not tx_data:
                            continue
                        
                        # Convert to PendingTx
                        pending_tx = self._tx_to_pending_tx(tx_data, block_num, block_hash, block_timestamp)
                        if pending_tx:
                            pending_txs.append(pending_tx)
                    except Exception as e:
                        logger.warning(
                            "failed_to_fetch_tx",
                            chain_id=self.chain_id,
                            tx_hash=tx_hash[:16],
                            error=str(e)
                        )
                        continue
                
                # Update last processed block
                self.last_processed_block = block_num
            
            logger.info(
                "pseudo_intent_txs_fetched",
                chain_id=self.chain_id,
                count=len(pending_txs),
                from_block=self.last_processed_block - blocks_to_process + 1,
                to_block=self.last_processed_block
            )
            
            return pending_txs
            
        except Exception as e:
            logger.error("failed_to_get_pending_txs", chain_id=self.chain_id, error=str(e))
            return []
    
    def _tx_to_pending_tx(
        self,
        tx_data: TxData,
        block_number: int,
        block_hash: str,
        block_timestamp: datetime
    ) -> Optional[PendingTx]:
        """Convert Web3 transaction data to PendingTx."""
        try:
            tx_hash = tx_data.get("hash")
            if isinstance(tx_hash, bytes):
                tx_hash = tx_hash.hex()
            elif not isinstance(tx_hash, str):
                tx_hash = Web3.to_hex(tx_hash) if tx_hash else ""
            
            if not tx_hash:
                return None
            
            # Extract calldata
            data = tx_data.get("input", "0x")
            if isinstance(data, bytes):
                data = data.hex()
            if not data.startswith("0x"):
                data = "0x" + data
            
            # Extract value
            value = tx_data.get("value", 0)
            if isinstance(value, (int, str)):
                value = int(value) if isinstance(value, str) else value
            else:
                value = 0
            
            # Extract addresses
            from_addr = tx_data.get("from", "")
            to_addr = tx_data.get("to")
            
            if isinstance(from_addr, bytes):
                from_addr = from_addr.hex()
            if to_addr and isinstance(to_addr, bytes):
                to_addr = to_addr.hex()
            
            # Extract gas info
            gas_limit = tx_data.get("gas")
            gas_price = tx_data.get("gasPrice")
            max_fee_per_gas = tx_data.get("maxFeePerGas")
            
            return PendingTx(
                tx_hash=tx_hash,
                chain_id=self.chain_id,
                from_address=from_addr.lower() if from_addr else "",
                to_address=to_addr.lower() if to_addr else None,
                value=value,
                data=data,
                block_number=block_number,
                block_hash=block_hash,
                seen_at=block_timestamp,
                gas_limit=gas_limit,
                gas_price=gas_price,
                max_fee_per_gas=max_fee_per_gas,
            )
        except Exception as e:
            logger.warning("failed_to_convert_tx", error=str(e))
            return None
    
    def update_last_processed_block(self, block_number: int):
        """Update the last processed block (useful for checkpointing)."""
        self.last_processed_block = block_number

