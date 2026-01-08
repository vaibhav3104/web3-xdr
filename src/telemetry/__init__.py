"""
Blockchain Telemetry Collection Layer.

Responsible for:
- Connecting to blockchain nodes via RPC/WebSocket
- Subscribing to relevant events
- Parsing and normalizing raw blockchain data
- Ensuring no missed blocks

Supported Chain Types:
- EVM: Ethereum, Polygon, Arbitrum, Optimism, BSC, Avalanche, Base, etc.
- Solana: Solana mainnet/devnet
- Cosmos: Cosmos Hub, Osmosis, Injective, Sei, dYdX (IBC-enabled)
- Aptos/Sui: Move-based chains
- Near: Near Protocol with Rainbow Bridge support

Features:
- Robust RPC failover with health tracking
- Automatic provider rotation on errors
- Exponential backoff for resilience
"""

from .base import ChainListener, ListenerConfig
from .evm_listener import EVMListener
from .solana_listener import SolanaListener
from .cosmos_listener import CosmosListener, CosmosConfig
from .aptos_listener import AptosListener, AptosConfig
from .near_listener import NearListener, NearConfig
from .listener_pool import ListenerPool
from .robust_provider import (
    RobustHTTPProvider,
    RobustAsyncHTTPProvider,
    RobustProviderManager,
    ProviderStats,
    ProviderHealth,
    create_robust_provider,
)
from .robust_non_evm import (
    RobustNonEVMListener,
    NonEVMConfig,
    EndpointHealth,
    EndpointStats,
)

__all__ = [
    # Base
    "ChainListener",
    "ListenerConfig", 
    # Listeners
    "EVMListener",
    "SolanaListener",
    "CosmosListener",
    "CosmosConfig",
    "AptosListener",
    "AptosConfig",
    "NearListener",
    "NearConfig",
    "ListenerPool",
    # Robust EVM Provider
    "RobustHTTPProvider",
    "RobustAsyncHTTPProvider",
    "RobustProviderManager",
    "ProviderStats",
    "ProviderHealth",
    "create_robust_provider",
    # Robust Non-EVM Base
    "RobustNonEVMListener",
    "NonEVMConfig",
    "EndpointHealth",
    "EndpointStats",
]

