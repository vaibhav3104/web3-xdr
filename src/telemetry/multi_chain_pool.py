"""
Multi-Chain Listener Pool
=========================

Unified management for all blockchain listeners:
- EVM chains (Ethereum, Polygon, Arbitrum, etc.)
- Cosmos chains (Cosmos Hub, Osmosis, etc.)
- Move chains (Aptos, Sui)
- Near Protocol

This is the main entry point for multi-chain monitoring.
"""

import asyncio
from typing import Dict, List, Optional, Callable, Any, Awaitable
from dataclasses import dataclass
from datetime import datetime, timezone
import yaml
import structlog

from .base import ChainListener, ListenerConfig
from .evm_listener import EVMListener
from .cosmos_listener import CosmosListener, CosmosConfig
from .aptos_listener import AptosListener, AptosConfig
from .near_listener import NearListener, NearConfig
from ..models.events import SecurityEvent
from ..correlation.cross_chain import (
    CrossChainCorrelator,
    BridgeEventParser,
    CrossChainEvent,
    CrossChainEventType,
    cross_chain_correlator
)

logger = structlog.get_logger(__name__)


@dataclass
class ChainStats:
    """Statistics for a single chain."""
    chain_id: str
    chain_type: str
    connected: bool
    events_processed: int
    last_event_time: Optional[datetime]
    last_block: int
    errors: int


class MultiChainListenerPool:
    """
    Manages listeners for all supported blockchain types.
    
    Features:
    - Unified event handling
    - Cross-chain correlation
    - Automatic reconnection
    - Health monitoring
    - Event routing
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.listeners: Dict[str, ChainListener] = {}
        self.chain_stats: Dict[str, ChainStats] = {}
        self.event_handlers: List[Callable[[SecurityEvent], Awaitable[Any]]] = []
        self._running = False
        self._tasks: List[asyncio.Task] = []
        
        # Cross-chain correlation
        self.cross_chain_correlator = cross_chain_correlator
        
        # Load config if provided
        if config_path:
            self.load_config(config_path)
    
    def load_config(self, config_path: str):
        """Load chain configurations from YAML file."""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        chains = config.get('chains', [])
        
        for chain_config in chains:
            chain_id = chain_config.get('chain_id', '')
            chain_type = chain_config.get('chain_type', 'evm')
            
            try:
                listener = self._create_listener(chain_config)
                if listener:
                    self.add_listener(chain_id, listener, chain_type)
            except Exception as e:
                logger.error(
                    "failed_to_create_listener",
                    chain_id=chain_id,
                    error=str(e)
                )
    
    def _create_listener(self, chain_config: dict) -> Optional[ChainListener]:
        """Create appropriate listener based on chain type."""
        chain_type = chain_config.get('chain_type', 'evm')
        chain_id = chain_config.get('chain_id', '')
        rpc_url = chain_config.get('rpc_url', '')
        
        if chain_type == 'cosmos':
            return CosmosListener(CosmosConfig(
                chain_id=chain_id,
                rpc_url=rpc_url,
                ws_url=chain_config.get('ws_url', ''),
                tendermint_rpc=rpc_url,
                ibc_channels=chain_config.get('ibc_channels', []),
                bridge_contracts=chain_config.get('bridge_contracts', [])
            ))
        
        elif chain_type == 'aptos':
            return AptosListener(AptosConfig(
                chain_id=chain_id,
                rpc_url=rpc_url,
                rest_api=rpc_url,
                chain_type='aptos',
                bridge_modules=chain_config.get('bridge_contracts', [])
            ))
        
        elif chain_type == 'sui':
            return AptosListener(AptosConfig(
                chain_id=chain_id,
                rpc_url=rpc_url,
                rest_api=rpc_url,
                chain_type='sui',
                bridge_modules=chain_config.get('bridge_contracts', [])
            ))
        
        elif chain_type == 'near':
            return NearListener(NearConfig(
                chain_id=chain_id,
                rpc_url=rpc_url,
                bridge_accounts=chain_config.get('bridge_contracts', [])
            ))
        
        elif chain_type == 'solana':
            # Solana uses similar REST API approach
            # For now, return None - would need Solana-specific listener
            logger.warning("solana_listener_not_implemented", chain_id=chain_id)
            return None
        
        else:
            # Default to EVM listener
            return EVMListener(ListenerConfig(
                chain_id=chain_id,
                rpc_url=rpc_url,
                ws_url=chain_config.get('ws_url', ''),
                bridge_contracts=chain_config.get('bridge_contracts', []),
                poll_interval=chain_config.get('poll_interval_seconds', 12)
            ))
    
    def add_listener(
        self,
        chain_id: str,
        listener: ChainListener,
        chain_type: str = "evm"
    ):
        """Add a listener to the pool."""
        self.listeners[chain_id] = listener
        self.chain_stats[chain_id] = ChainStats(
            chain_id=chain_id,
            chain_type=chain_type,
            connected=False,
            events_processed=0,
            last_event_time=None,
            last_block=0,
            errors=0
        )
        
        logger.info(
            "listener_added",
            chain_id=chain_id,
            chain_type=chain_type
        )
    
    def add_event_handler(self, handler: Callable[[SecurityEvent], Awaitable[Any]]):
        """Add a handler for security events."""
        self.event_handlers.append(handler)
    
    async def start(self):
        """Start all listeners and begin processing events."""
        self._running = True
        
        # Connect all listeners
        for chain_id, listener in self.listeners.items():
            try:
                connected = await listener.connect()
                self.chain_stats[chain_id].connected = connected
                
                if connected:
                    logger.info("chain_connected", chain_id=chain_id)
                else:
                    logger.warning("chain_connection_failed", chain_id=chain_id)
                    
            except Exception as e:
                logger.error(
                    "chain_connection_error",
                    chain_id=chain_id,
                    error=str(e)
                )
        
        # Start listening tasks
        for chain_id, listener in self.listeners.items():
            if self.chain_stats[chain_id].connected:
                task = asyncio.create_task(
                    self._listen_chain(chain_id, listener)
                )
                self._tasks.append(task)
        
        # Start correlation check task
        correlation_task = asyncio.create_task(self._correlation_check_loop())
        self._tasks.append(correlation_task)
        
        logger.info(
            "multi_chain_pool_started",
            chains=len(self.listeners),
            connected=sum(1 for s in self.chain_stats.values() if s.connected)
        )
    
    async def stop(self):
        """Stop all listeners and tasks."""
        self._running = False
        
        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        # Disconnect all listeners
        for chain_id, listener in self.listeners.items():
            try:
                await listener.disconnect()
                self.chain_stats[chain_id].connected = False
            except Exception as e:
                logger.error(
                    "chain_disconnect_error",
                    chain_id=chain_id,
                    error=str(e)
                )
        
        logger.info("multi_chain_pool_stopped")
    
    async def _listen_chain(self, chain_id: str, listener: ChainListener):
        """Listen for events from a single chain."""
        stats = self.chain_stats[chain_id]
        
        while self._running:
            try:
                async for event in listener.listen_events():
                    # Update stats
                    stats.events_processed += 1
                    stats.last_event_time = datetime.now(timezone.utc)
                    stats.last_block = event.block_number
                    
                    # Process for cross-chain correlation
                    await self._process_for_correlation(event)
                    
                    # Notify handlers
                    await self._notify_handlers(event)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                stats.errors += 1
                logger.error(
                    "chain_listen_error",
                    chain_id=chain_id,
                    error=str(e)
                )
                
                # Attempt reconnection
                if self._running:
                    await asyncio.sleep(5)
                    try:
                        await listener.disconnect()
                        connected = await listener.connect()
                        stats.connected = connected
                    except:
                        pass
    
    async def _process_for_correlation(self, event: SecurityEvent):
        """Process event for cross-chain correlation."""
        # Try to parse as bridge event
        cross_chain_event = BridgeEventParser.parse_event(
            event_data=event.raw_data,
            chain_id=event.chain_id,
            block_timestamp=event.block_timestamp
        )
        
        if cross_chain_event:
            # Add to cross-chain correlator
            violation = await self.cross_chain_correlator.process_event(cross_chain_event)
            
            if violation:
                logger.critical(
                    "cross_chain_violation_detected",
                    violation_type=violation.violation_type.value,
                    bridge=violation.bridge_id,
                    estimated_loss=violation.estimated_loss_usd
                )
    
    async def _notify_handlers(self, event: SecurityEvent):
        """Notify all event handlers."""
        for handler in self.event_handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error("handler_error", error=str(e))
    
    async def _correlation_check_loop(self):
        """Periodically check for expired correlations."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self.cross_chain_correlator.check_expired_correlations()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("correlation_check_error", error=str(e))
    
    def get_stats(self) -> Dict:
        """Get pool statistics."""
        return {
            "total_chains": len(self.listeners),
            "connected_chains": sum(1 for s in self.chain_stats.values() if s.connected),
            "total_events": sum(s.events_processed for s in self.chain_stats.values()),
            "total_errors": sum(s.errors for s in self.chain_stats.values()),
            "chain_stats": {
                chain_id: {
                    "type": stats.chain_type,
                    "connected": stats.connected,
                    "events": stats.events_processed,
                    "last_event": stats.last_event_time.isoformat() if stats.last_event_time else None,
                    "last_block": stats.last_block,
                    "errors": stats.errors
                }
                for chain_id, stats in self.chain_stats.items()
            },
            "correlation": self.cross_chain_correlator.get_stats()
        }
    
    def get_connected_chains(self) -> List[str]:
        """Get list of connected chains."""
        return [
            chain_id
            for chain_id, stats in self.chain_stats.items()
            if stats.connected
        ]
    
    def get_chain_health(self, chain_id: str) -> Optional[Dict]:
        """Get health status for a specific chain."""
        stats = self.chain_stats.get(chain_id)
        if not stats:
            return None
        
        # Calculate health score
        health_score = 100
        if not stats.connected:
            health_score = 0
        elif stats.errors > 10:
            health_score -= 30
        elif stats.errors > 5:
            health_score -= 15
        
        # Check for stale events
        if stats.last_event_time:
            age = (datetime.now(timezone.utc) - stats.last_event_time).total_seconds()
            if age > 300:  # 5 minutes
                health_score -= 20
            elif age > 120:  # 2 minutes
                health_score -= 10
        
        return {
            "chain_id": chain_id,
            "chain_type": stats.chain_type,
            "connected": stats.connected,
            "health_score": max(0, health_score),
            "events_processed": stats.events_processed,
            "last_event": stats.last_event_time.isoformat() if stats.last_event_time else None,
            "last_block": stats.last_block,
            "errors": stats.errors
        }


# Global pool instance
multi_chain_pool = MultiChainListenerPool()


# =============================================================================
# Factory Functions
# =============================================================================

def create_production_pool(config_path: str = "config/chains.yaml") -> MultiChainListenerPool:
    """Create a production-ready multi-chain pool."""
    pool = MultiChainListenerPool(config_path)
    
    # Add cross-chain violation handler
    async def handle_violation(violation):
        logger.critical(
            "CROSS_CHAIN_ATTACK_DETECTED",
            type=violation.violation_type.value,
            bridge=violation.bridge_id,
            source=violation.source_chain,
            dest=violation.dest_chain,
            loss_usd=violation.estimated_loss_usd
        )
        # Here you would:
        # 1. Send alerts (Telegram, Slack)
        # 2. Trigger Guardian system
        # 3. Create incident
    
    pool.cross_chain_correlator.add_violation_handler(handle_violation)
    
    return pool

