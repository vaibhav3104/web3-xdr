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
"""

from .base import ChainListener, ListenerConfig
from .evm_listener import EVMListener
from .solana_listener import SolanaListener
from .cosmos_listener import CosmosListener, CosmosConfig
from .aptos_listener import AptosListener, AptosConfig
from .near_listener import NearListener, NearConfig
from .listener_pool import ListenerPool

__all__ = [
    "ChainListener",
    "ListenerConfig", 
    "EVMListener",
    "SolanaListener",
    "CosmosListener",
    "CosmosConfig",
    "AptosListener",
    "AptosConfig",
    "NearListener",
    "NearConfig",
    "ListenerPool",
]

