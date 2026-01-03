"""
Base Chain Listener - Abstract base for all blockchain listeners.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncIterator, Callable, Dict, List, Optional, Set
import asyncio
import structlog

from ..models.events import SecurityEvent

logger = structlog.get_logger()


@dataclass
class ListenerConfig:
    """Configuration for a chain listener."""
    
    chain_id: str
    chain_name: str
    
    # RPC configuration
    rpc_url: str
    ws_url: Optional[str] = None
    
    # Contracts to monitor
    bridge_contracts: List[str] = field(default_factory=list)
    token_contracts: List[str] = field(default_factory=list)
    governance_contracts: List[str] = field(default_factory=list)
    
    # Polling configuration (for chains without WebSocket)
    poll_interval_seconds: float = 1.0
    
    # Block confirmation
    confirmations_required: int = 1
    
    # Recovery
    start_block: Optional[int] = None  # None = latest
    max_blocks_per_batch: int = 100
    
    # Retry configuration
    max_retries: int = 5
    retry_delay_seconds: float = 2.0


@dataclass
class BlockMetadata:
    """Metadata about a processed block."""
    
    chain_id: str
    block_number: int
    block_hash: str
    timestamp: datetime
    tx_count: int
    events_extracted: int


class ChainListener(ABC):
    """
    Abstract base class for blockchain listeners.
    
    Implementations must provide chain-specific logic for:
    - Connecting to nodes
    - Subscribing to events
    - Parsing raw events
    """
    
    def __init__(self, config: ListenerConfig):
        self.config = config
        self.chain_id = config.chain_id
        self.is_running = False
        self.last_processed_block: int = 0
        self.event_handlers: List[Callable[[SecurityEvent], asyncio.coroutine]] = []
        self._processed_tx_hashes: Set[str] = set()  # Dedup within window
        self._lock = asyncio.Lock()
    
    def add_event_handler(self, handler: Callable[[SecurityEvent], asyncio.coroutine]):
        """Add a handler to be called for each security event."""
        self.event_handlers.append(handler)
    
    async def emit_event(self, event: SecurityEvent):
        """Emit an event to all registered handlers."""
        # Deduplicate events
        event_key = f"{event.tx_hash}:{event.log_index}"
        if event_key in self._processed_tx_hashes:
            return
        self._processed_tx_hashes.add(event_key)
        
        # Limit dedup cache size
        if len(self._processed_tx_hashes) > 10000:
            # Remove oldest entries (simple approach)
            self._processed_tx_hashes = set(list(self._processed_tx_hashes)[-5000:])
        
        # Call all handlers concurrently
        await asyncio.gather(
            *[handler(event) for handler in self.event_handlers],
            return_exceptions=True
        )
    
    @abstractmethod
    async def connect(self):
        """Establish connection to blockchain node."""
        pass
    
    @abstractmethod
    async def disconnect(self):
        """Close connection to blockchain node."""
        pass
    
    @abstractmethod
    async def get_latest_block(self) -> int:
        """Get the latest block number."""
        pass
    
    @abstractmethod
    async def process_block(self, block_number: int) -> BlockMetadata:
        """Process a single block and emit security events."""
        pass
    
    @abstractmethod
    async def subscribe_to_events(self) -> AsyncIterator[SecurityEvent]:
        """Subscribe to real-time events via WebSocket."""
        pass
    
    async def start(self):
        """Start the listener."""
        self.is_running = True
        await self.connect()
        
        # Determine starting block
        if self.config.start_block:
            self.last_processed_block = self.config.start_block - 1
        else:
            self.last_processed_block = await self.get_latest_block()
        
        logger.info(
            "chain_listener_started",
            chain_id=self.chain_id,
            start_block=self.last_processed_block + 1
        )
        
        # Start processing loop
        await self._run_loop()
    
    async def stop(self):
        """Stop the listener."""
        self.is_running = False
        await self.disconnect()
        logger.info("chain_listener_stopped", chain_id=self.chain_id)
    
    async def _run_loop(self):
        """Main processing loop."""
        if self.config.ws_url:
            # Use WebSocket subscription
            await self._run_websocket_loop()
        else:
            # Fall back to polling
            await self._run_polling_loop()
    
    async def _run_websocket_loop(self):
        """Process events via WebSocket subscription."""
        retry_count = 0
        
        while self.is_running:
            try:
                async for event in self.subscribe_to_events():
                    if not self.is_running:
                        break
                    await self.emit_event(event)
                    retry_count = 0  # Reset on success
                    
            except Exception as e:
                logger.error(
                    "websocket_error",
                    chain_id=self.chain_id,
                    error=str(e),
                    retry_count=retry_count
                )
                
                if retry_count >= self.config.max_retries:
                    logger.error("max_retries_exceeded", chain_id=self.chain_id)
                    # Fall back to polling
                    await self._run_polling_loop()
                    return
                
                retry_count += 1
                await asyncio.sleep(self.config.retry_delay_seconds * retry_count)
                await self.connect()
    
    async def _run_polling_loop(self):
        """Process blocks via polling."""
        while self.is_running:
            try:
                latest_block = await self.get_latest_block()
                confirmed_block = latest_block - self.config.confirmations_required
                
                # Process any blocks we missed
                while self.last_processed_block < confirmed_block and self.is_running:
                    next_block = self.last_processed_block + 1
                    
                    # Batch processing for catch-up
                    blocks_to_process = min(
                        confirmed_block - self.last_processed_block,
                        self.config.max_blocks_per_batch
                    )
                    
                    for _ in range(blocks_to_process):
                        if not self.is_running:
                            break
                            
                        metadata = await self.process_block(next_block)
                        
                        async with self._lock:
                            self.last_processed_block = next_block
                        
                        logger.debug(
                            "block_processed",
                            chain_id=self.chain_id,
                            block_number=next_block,
                            events=metadata.events_extracted
                        )
                        
                        next_block += 1
                
                await asyncio.sleep(self.config.poll_interval_seconds)
                
            except Exception as e:
                logger.error(
                    "polling_error",
                    chain_id=self.chain_id,
                    error=str(e)
                )
                await asyncio.sleep(self.config.retry_delay_seconds)
    
    def get_status(self) -> dict:
        """Get current listener status."""
        return {
            "chain_id": self.chain_id,
            "is_running": self.is_running,
            "last_processed_block": self.last_processed_block,
            "handler_count": len(self.event_handlers),
        }

