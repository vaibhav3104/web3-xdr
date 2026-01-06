"""
Listener Pool - Manages multiple chain listeners.

Supports:
- EVM chains (Ethereum, Polygon, Arbitrum, etc.)
- Solana
- Cosmos/IBC chains
- Aptos/Sui (Move-based)
- Near Protocol
"""

from typing import Awaitable, Any, Callable, Dict, List, Optional
import asyncio
import structlog

from .base import ChainListener, ListenerConfig
from .evm_listener import EVMListener
from .solana_listener import SolanaListener
from .cosmos_listener import CosmosListener, CosmosConfig
from .aptos_listener import AptosListener, AptosConfig
from .near_listener import NearListener, NearConfig
from ..models.events import SecurityEvent

logger = structlog.get_logger()


class ListenerPool:
    """
    Manages a pool of chain listeners for multi-chain monitoring.
    
    Features:
    - Unified event handling across chains
    - Health monitoring
    - Graceful startup/shutdown
    """
    
    def __init__(self):
        self.listeners: Dict[str, ChainListener] = {}
        self._event_handlers: List[Callable[[SecurityEvent], Awaitable[Any]]] = []
        self._tasks: Dict[str, asyncio.Task] = {}
        self._is_running = False
    
    def add_listener(self, config: ListenerConfig):
        """
        Add a chain listener based on configuration.
        """
        # Determine listener type based on chain
        chain_type = self._get_chain_type(config.chain_id)
        
        if chain_type == "evm":
            listener = EVMListener(config)
        elif chain_type == "solana":
            listener = SolanaListener(config)
        elif chain_type == "cosmos":
            # Convert to CosmosConfig
            cosmos_config = CosmosConfig(
                chain_id=config.chain_id,
                chain_name=config.chain_name,
                rpc_url=config.rpc_url,
                ws_url=config.ws_url,
                tendermint_rpc=config.rpc_url,
                bridge_contracts=config.bridge_contracts,
            )
            listener = CosmosListener(cosmos_config)
        elif chain_type == "aptos":
            # Convert to AptosConfig
            aptos_config = AptosConfig(
                chain_id=config.chain_id,
                chain_name=config.chain_name,
                rpc_url=config.rpc_url,
                rest_api=config.rpc_url,
                chain_type="aptos",
                bridge_modules=config.bridge_contracts,
            )
            listener = AptosListener(aptos_config)
        elif chain_type == "sui":
            # Convert to AptosConfig (Sui uses same listener)
            sui_config = AptosConfig(
                chain_id=config.chain_id,
                chain_name=config.chain_name,
                rpc_url=config.rpc_url,
                rest_api=config.rpc_url,
                chain_type="sui",
                bridge_modules=config.bridge_contracts,
            )
            listener = AptosListener(sui_config)
        elif chain_type == "near":
            # Convert to NearConfig
            near_config = NearConfig(
                chain_id=config.chain_id,
                chain_name=config.chain_name,
                rpc_url=config.rpc_url,
                bridge_accounts=config.bridge_contracts,
            )
            listener = NearListener(near_config)
        else:
            raise ValueError(f"Unknown chain type for {config.chain_id}")
        
        # Add event handlers
        for handler in self._event_handlers:
            listener.add_event_handler(handler)
        
        self.listeners[config.chain_id] = listener
        
        logger.info(
            "listener_added",
            chain_id=config.chain_id,
            listener_type=chain_type
        )
    
    def add_event_handler(self, handler: Callable[[SecurityEvent], Awaitable[Any]]):
        """
        Add a handler for all chain events.
        """
        self._event_handlers.append(handler)
        
        # Add to existing listeners
        for listener in self.listeners.values():
            listener.add_event_handler(handler)
    
    def _get_chain_type(self, chain_id: str) -> str:
        """
        Determine chain type from chain ID.
        """
        evm_chains = [
            "ethereum", "polygon", "arbitrum", "optimism",
            "bsc", "avalanche", "fantom", "base", "zksync",
            "linea", "scroll", "mantle", "blast"
        ]
        solana_chains = ["solana"]
        cosmos_chains = [
            "cosmos", "osmosis", "injective", "sei", "celestia",
            "dydx", "neutron", "kava", "evmos", "axelar"
        ]
        aptos_chains = ["aptos", "movement"]
        sui_chains = ["sui"]
        near_chains = ["near", "aurora"]
        
        chain_lower = chain_id.lower()
        
        if chain_lower in evm_chains or chain_lower.startswith("evm_"):
            return "evm"
        elif chain_lower in solana_chains:
            return "solana"
        elif chain_lower in cosmos_chains or chain_lower.startswith("cosmos_"):
            return "cosmos"
        elif chain_lower in aptos_chains:
            return "aptos"
        elif chain_lower in sui_chains:
            return "sui"
        elif chain_lower in near_chains:
            return "near"
        
        # Default to EVM for unknown chains with "0x" prefix in addresses
        return "evm"
    
    async def start(self):
        """
        Start all listeners.
        """
        if self._is_running:
            logger.warning("listener_pool_already_running")
            return
        
        self._is_running = True
        
        logger.info(
            "listener_pool_starting",
            listener_count=len(self.listeners)
        )
        
        # Start each listener as a task
        for chain_id, listener in self.listeners.items():
            task = asyncio.create_task(
                self._run_listener(chain_id, listener),
                name=f"listener_{chain_id}"
            )
            self._tasks[chain_id] = task
        
        logger.info("listener_pool_started")
    
    async def _run_listener(self, chain_id: str, listener: ChainListener):
        """
        Run a single listener with error handling.
        """
        while self._is_running:
            try:
                await listener.start()
            except Exception as e:
                logger.error(
                    "listener_crashed",
                    chain_id=chain_id,
                    error=str(e)
                )
                
                # Wait before restart
                await asyncio.sleep(10)
                
                if self._is_running:
                    logger.info("listener_restarting", chain_id=chain_id)
    
    async def stop(self):
        """
        Stop all listeners gracefully.
        """
        self._is_running = False
        
        logger.info("listener_pool_stopping")
        
        # Stop all listeners
        for listener in self.listeners.values():
            try:
                await listener.stop()
            except Exception as e:
                logger.error(
                    "listener_stop_error",
                    chain_id=listener.chain_id,
                    error=str(e)
                )
        
        # Cancel all tasks
        for task in self._tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        
        self._tasks.clear()
        
        logger.info("listener_pool_stopped")
    
    def get_status(self) -> dict:
        """
        Get status of all listeners.
        """
        return {
            "is_running": self._is_running,
            "listener_count": len(self.listeners),
            "listeners": {
                chain_id: listener.get_status()
                for chain_id, listener in self.listeners.items()
            }
        }
    
    def get_listener(self, chain_id: str) -> Optional[ChainListener]:
        """
        Get a specific listener by chain ID.
        """
        return self.listeners.get(chain_id)


async def create_listener_pool_from_config(config: dict) -> ListenerPool:
    """
    Factory function to create a listener pool from configuration.
    
    Config format:
    {
        "chains": [
            {
                "chain_id": "ethereum",
                "rpc_url": "https://...",
                "ws_url": "wss://...",
                "bridge_contracts": ["0x..."],
                "token_contracts": ["0x..."]
            }
        ]
    }
    """
    pool = ListenerPool()
    
    for chain_config in config.get("chains", []):
        listener_config = ListenerConfig(
            chain_id=chain_config["chain_id"],
            chain_name=chain_config.get("chain_name", chain_config["chain_id"]),
            rpc_url=chain_config["rpc_url"],
            ws_url=chain_config.get("ws_url"),
            bridge_contracts=chain_config.get("bridge_contracts", []),
            token_contracts=chain_config.get("token_contracts", []),
            governance_contracts=chain_config.get("governance_contracts", []),
            poll_interval_seconds=chain_config.get("poll_interval_seconds", 1.0),
            confirmations_required=chain_config.get("confirmations_required", 1),
            start_block=chain_config.get("start_block"),
        )
        
        pool.add_listener(listener_config)
    
    return pool

