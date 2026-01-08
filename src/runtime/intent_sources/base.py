"""
Pending Transaction Source Interface
====================================

Abstract base class for sources of pending transactions (intents).
Future implementations can include mempool feeds, builder streams, etc.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class PendingTx:
    """
    Represents a pending transaction (intent) that can be simulated.
    """
    # Transaction identification
    tx_hash: str
    chain_id: str
    
    # Transaction details
    from_address: str
    to_address: Optional[str]
    value: int  # Wei/native units
    data: str  # Hex-encoded calldata
    
    # Block context (if available)
    block_number: Optional[int] = None
    block_hash: Optional[str] = None
    
    # Timestamp
    seen_at: datetime = None
    
    # Function selector (first 4 bytes of data)
    selector: Optional[str] = None
    
    # Gas info (if available)
    gas_limit: Optional[int] = None
    gas_price: Optional[int] = None
    max_fee_per_gas: Optional[int] = None
    
    def __post_init__(self):
        if self.seen_at is None:
            self.seen_at = datetime.now(timezone.utc)
        
        # Extract selector from data if not provided
        if self.selector is None and self.data and len(self.data) >= 10:
            self.selector = self.data[:10]  # 0x + 4 bytes
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "tx_hash": self.tx_hash,
            "chain_id": self.chain_id,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "value": self.value,
            "data": self.data,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "seen_at": self.seen_at.isoformat() if self.seen_at else None,
            "selector": self.selector,
            "gas_limit": self.gas_limit,
            "gas_price": self.gas_price,
            "max_fee_per_gas": self.max_fee_per_gas,
        }


class PendingTxSource(ABC):
    """
    Abstract base class for pending transaction sources.
    
    Implementations:
    - PseudoIntentBlockSource: Treats new blocks as "near-real-time" intents
    - MempoolSource: (Future) Direct mempool feed
    - BuilderStreamSource: (Future) MEV builder stream
    """
    
    def __init__(self, chain_id: str):
        self.chain_id = chain_id
        self._running = False
        logger.info("pending_tx_source_initialized", chain_id=chain_id, source_type=type(self).__name__)
    
    @abstractmethod
    async def start(self):
        """Start the source (if it needs background tasks)."""
        pass
    
    @abstractmethod
    async def stop(self):
        """Stop the source and clean up resources."""
        pass
    
    @abstractmethod
    async def get_pending_txs(self, limit: int = 100) -> List[PendingTx]:
        """
        Get pending transactions from this source.
        
        Args:
            limit: Maximum number of transactions to return
        
        Returns:
            List of pending transactions
        """
        pass
    
    @property
    def is_running(self) -> bool:
        """Check if source is running."""
        return self._running

