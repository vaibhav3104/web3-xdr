"""
Non-EVM Listener Base (Passive)
===============================

Phase 6: Passive interface for non-EVM listeners.
No threading, no loops - just poll_logs(block_number) -> List[SecurityEvent].
"""

from abc import ABC, abstractmethod
from typing import List, Optional
import structlog

from .base import ChainListener, ListenerConfig
from ..models.events import SecurityEvent

logger = structlog.get_logger(__name__)


class PassiveNonEVMListener(ChainListener):
    """
    Base class for passive non-EVM listeners.
    
    Phase 6: Listeners are passive - they don't run their own loops.
    The Worker calls poll_logs(block_number) to get events for a specific block.
    
    This ensures:
    - No threading issues in Cloud Run
    - Worker controls the polling loop
    - Checkpointing works correctly
    - Graceful shutdown
    """
    
    def __init__(self, config: ListenerConfig):
        super().__init__(config)
        self.last_processed_block = config.start_block or 0
    
    @abstractmethod
    async def poll_logs(self, block_number: int) -> List[SecurityEvent]:
        """
        Poll logs for a specific block number.
        
        This is the ONLY method the Worker calls.
        No internal loops, no threading, no asyncio.create_task.
        
        Args:
            block_number: Block number to poll
        
        Returns:
            List of SecurityEvent objects extracted from the block
        
        Raises:
            Exception: If polling fails (Worker will handle retries)
        """
        pass
    
    @abstractmethod
    async def get_latest_block(self) -> int:
        """
        Get the latest block height from the chain.
        
        Returns:
            Latest block height
        """
        pass
    
    async def get_block_info(self, block_number: int) -> Optional[dict]:
        """
        Get block metadata (optional, for debugging).
        
        Args:
            block_number: Block number
        
        Returns:
            Block metadata dict or None
        """
        return None

