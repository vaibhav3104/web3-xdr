"""
Security Graph Schema
=====================

Defines the node types, relationship types, and schema for the 
Neo4j security graph - the foundation of Wiz-for-Web3.

Node Types:
- Contract: Smart contracts with bytecode analysis
- Wallet: EOA wallets and their risk profiles
- Token: ERC20/721/1155 tokens
- Protocol: DeFi protocols (Aave, Uniswap, etc.)
- Oracle: Price oracles (Chainlink, Band, etc.)
- Bridge: Cross-chain bridges
- Pool: Liquidity pools

Relationship Types:
- OWNS: Wallet owns/deployed contract
- CALLS: Contract calls another contract
- TRANSFERS_TO: Token transfer between addresses
- USES_ORACLE: Protocol depends on oracle
- HAS_ADMIN_ACCESS: Admin/owner relationship
- BRIDGES_TO: Cross-chain bridge connection
- PROVIDES_LIQUIDITY: LP position
- BORROWED_FROM: Lending relationship
- FLASH_LOANED: Flash loan relationship
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


class NodeType(Enum):
    """Types of nodes in the security graph."""
    
    # Core entities
    CONTRACT = "Contract"
    WALLET = "Wallet"
    TOKEN = "Token"
    
    # DeFi entities
    PROTOCOL = "Protocol"
    ORACLE = "Oracle"
    BRIDGE = "Bridge"
    POOL = "Pool"
    VAULT = "Vault"
    
    # Governance
    MULTISIG = "Multisig"
    TIMELOCK = "Timelock"
    GOVERNOR = "Governor"
    
    # Risk entities
    MIXER = "Mixer"
    SANCTIONED = "Sanctioned"
    HACKER = "Hacker"


class RelationType(Enum):
    """Types of relationships in the security graph."""
    
    # Ownership & Control
    OWNS = "OWNS"
    DEPLOYED = "DEPLOYED"
    HAS_ADMIN_ACCESS = "HAS_ADMIN_ACCESS"
    CAN_UPGRADE = "CAN_UPGRADE"
    
    # Interactions
    CALLS = "CALLS"
    DELEGATES_TO = "DELEGATES_TO"
    
    # Token movements
    TRANSFERS_TO = "TRANSFERS_TO"
    APPROVED_SPENDER = "APPROVED_SPENDER"
    
    # DeFi relationships
    USES_ORACLE = "USES_ORACLE"
    PROVIDES_LIQUIDITY = "PROVIDES_LIQUIDITY"
    BORROWED_FROM = "BORROWED_FROM"
    LENT_TO = "LENT_TO"
    FLASH_LOANED = "FLASH_LOANED"
    STAKED_IN = "STAKED_IN"
    
    # Bridge relationships
    BRIDGES_TO = "BRIDGES_TO"
    LOCKED_IN = "LOCKED_IN"
    MINTED_FROM = "MINTED_FROM"
    
    # Risk relationships
    CONNECTED_TO_HACKER = "CONNECTED_TO_HACKER"
    RECEIVED_FROM_MIXER = "RECEIVED_FROM_MIXER"
    SENT_TO_MIXER = "SENT_TO_MIXER"


@dataclass
class NodeProperties:
    """Base properties for all nodes."""
    address: str
    chain_id: str
    first_seen: datetime
    last_seen: datetime
    risk_score: float = 0.0
    labels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContractNode(NodeProperties):
    """Properties specific to Contract nodes."""
    node_type: NodeType = NodeType.CONTRACT
    
    # Contract info
    name: Optional[str] = None
    symbol: Optional[str] = None
    is_verified: bool = False
    is_proxy: bool = False
    implementation_address: Optional[str] = None
    
    # Bytecode analysis
    bytecode_hash: Optional[str] = None
    has_selfdestruct: bool = False
    has_delegatecall: bool = False
    is_upgradeable: bool = False
    
    # Risk indicators
    similar_to_exploit: bool = False
    exploit_similarity_score: float = 0.0
    vulnerability_types: List[str] = field(default_factory=list)
    
    # Audit info
    is_audited: bool = False
    auditor: Optional[str] = None
    audit_date: Optional[datetime] = None


@dataclass
class WalletNode(NodeProperties):
    """Properties specific to Wallet nodes."""
    node_type: NodeType = NodeType.WALLET
    
    # Wallet type
    is_eoa: bool = True
    is_contract: bool = False
    is_multisig: bool = False
    
    # Labels
    is_exchange: bool = False
    is_mixer: bool = False
    is_sanctioned: bool = False
    is_known_hacker: bool = False
    entity_name: Optional[str] = None
    
    # Activity
    transaction_count: int = 0
    total_value_transferred_usd: float = 0.0
    
    # Risk
    connected_to_hacks: int = 0
    mixer_interactions: int = 0


@dataclass
class TokenNode(NodeProperties):
    """Properties specific to Token nodes."""
    node_type: NodeType = NodeType.TOKEN
    
    # Token info
    name: str = ""
    symbol: str = ""
    decimals: int = 18
    total_supply: float = 0.0
    
    # Token type
    is_erc20: bool = True
    is_erc721: bool = False
    is_erc1155: bool = False
    
    # Market data
    price_usd: float = 0.0
    market_cap_usd: float = 0.0
    holder_count: int = 0
    
    # Risk indicators
    is_honeypot: bool = False
    has_transfer_tax: bool = False
    has_blacklist: bool = False


@dataclass
class ProtocolNode(NodeProperties):
    """Properties specific to Protocol nodes."""
    node_type: NodeType = NodeType.PROTOCOL
    
    # Protocol info
    name: str = ""
    category: str = ""  # lending, dex, bridge, etc.
    website: Optional[str] = None
    
    # TVL
    tvl_usd: float = 0.0
    tvl_change_24h: float = 0.0
    
    # Contracts
    contract_addresses: List[str] = field(default_factory=list)
    
    # Security
    is_audited: bool = False
    has_bug_bounty: bool = False
    bug_bounty_max_usd: float = 0.0
    
    # Risk
    previous_exploits: int = 0
    total_lost_usd: float = 0.0


@dataclass
class OracleNode(NodeProperties):
    """Properties specific to Oracle nodes."""
    node_type: NodeType = NodeType.ORACLE
    
    # Oracle info
    name: str = ""
    oracle_type: str = ""  # chainlink, band, uniswap_twap, etc.
    
    # Feed info
    base_asset: str = ""
    quote_asset: str = ""
    heartbeat_seconds: int = 3600
    deviation_threshold: float = 0.01
    
    # Reliability
    uptime_30d: float = 100.0
    avg_update_delay_seconds: float = 0.0
    
    # Risk
    is_manipulable: bool = False
    manipulation_cost_usd: float = 0.0


@dataclass
class BridgeNode(NodeProperties):
    """Properties specific to Bridge nodes."""
    node_type: NodeType = NodeType.BRIDGE
    
    # Bridge info
    name: str = ""
    bridge_type: str = ""  # lock_mint, liquidity, message_passing
    
    # Chains
    source_chains: List[str] = field(default_factory=list)
    dest_chains: List[str] = field(default_factory=list)
    
    # Volume
    total_volume_usd: float = 0.0
    volume_24h_usd: float = 0.0
    
    # Security
    validator_count: int = 0
    threshold: int = 0
    
    # Risk
    previous_exploits: int = 0
    total_lost_usd: float = 0.0


@dataclass
class RelationshipProperties:
    """Properties for relationships between nodes."""
    
    # Timing
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1
    
    # Value
    total_value_usd: float = 0.0
    last_value_usd: float = 0.0
    
    # Transaction info
    last_tx_hash: Optional[str] = None
    last_block_number: Optional[int] = None
    
    # Risk
    risk_score: float = 0.0
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class GraphSchema:
    """
    Schema definition for the security graph.
    Provides methods to create and validate graph structures.
    """
    
    # Node type to properties mapping
    NODE_PROPERTIES = {
        NodeType.CONTRACT: ContractNode,
        NodeType.WALLET: WalletNode,
        NodeType.TOKEN: TokenNode,
        NodeType.PROTOCOL: ProtocolNode,
        NodeType.ORACLE: OracleNode,
        NodeType.BRIDGE: BridgeNode,
    }
    
    # Valid relationships between node types
    VALID_RELATIONSHIPS = {
        # Wallet relationships
        (NodeType.WALLET, RelationType.OWNS, NodeType.CONTRACT),
        (NodeType.WALLET, RelationType.DEPLOYED, NodeType.CONTRACT),
        (NodeType.WALLET, RelationType.TRANSFERS_TO, NodeType.WALLET),
        (NodeType.WALLET, RelationType.TRANSFERS_TO, NodeType.CONTRACT),
        (NodeType.WALLET, RelationType.HAS_ADMIN_ACCESS, NodeType.CONTRACT),
        (NodeType.WALLET, RelationType.PROVIDES_LIQUIDITY, NodeType.POOL),
        (NodeType.WALLET, RelationType.BORROWED_FROM, NodeType.PROTOCOL),
        (NodeType.WALLET, RelationType.STAKED_IN, NodeType.PROTOCOL),
        
        # Contract relationships
        (NodeType.CONTRACT, RelationType.CALLS, NodeType.CONTRACT),
        (NodeType.CONTRACT, RelationType.DELEGATES_TO, NodeType.CONTRACT),
        (NodeType.CONTRACT, RelationType.USES_ORACLE, NodeType.ORACLE),
        
        # Protocol relationships
        (NodeType.PROTOCOL, RelationType.USES_ORACLE, NodeType.ORACLE),
        (NodeType.PROTOCOL, RelationType.BRIDGES_TO, NodeType.BRIDGE),
        
        # Bridge relationships
        (NodeType.BRIDGE, RelationType.LOCKED_IN, NodeType.TOKEN),
        (NodeType.BRIDGE, RelationType.MINTED_FROM, NodeType.TOKEN),
        
        # Risk relationships
        (NodeType.WALLET, RelationType.CONNECTED_TO_HACKER, NodeType.HACKER),
        (NodeType.WALLET, RelationType.SENT_TO_MIXER, NodeType.MIXER),
        (NodeType.WALLET, RelationType.RECEIVED_FROM_MIXER, NodeType.MIXER),
    }
    
    # Neo4j Cypher schema creation queries
    SCHEMA_QUERIES = [
        # Indexes for fast lookups
        "CREATE INDEX IF NOT EXISTS FOR (n:Contract) ON (n.address)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Wallet) ON (n.address)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Token) ON (n.address)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Protocol) ON (n.name)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Oracle) ON (n.address)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Bridge) ON (n.name)",
        
        # Composite indexes
        "CREATE INDEX IF NOT EXISTS FOR (n:Contract) ON (n.chain_id, n.address)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Wallet) ON (n.chain_id, n.address)",
        
        # Risk score indexes for fast risk queries
        "CREATE INDEX IF NOT EXISTS FOR (n:Contract) ON (n.risk_score)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Wallet) ON (n.risk_score)",
        
        # Full-text search indexes
        "CREATE FULLTEXT INDEX entity_search IF NOT EXISTS FOR (n:Contract|Wallet|Token|Protocol) ON EACH [n.name, n.address]",
    ]
    
    @classmethod
    def get_node_properties(cls, node_type: NodeType) -> type:
        """Get the properties class for a node type."""
        return cls.NODE_PROPERTIES.get(node_type, NodeProperties)
    
    @classmethod
    def is_valid_relationship(
        cls, 
        from_type: NodeType, 
        rel_type: RelationType, 
        to_type: NodeType
    ) -> bool:
        """Check if a relationship is valid according to schema."""
        return (from_type, rel_type, to_type) in cls.VALID_RELATIONSHIPS
    
    @classmethod
    def get_schema_queries(cls) -> List[str]:
        """Get Neo4j queries to create schema."""
        return cls.SCHEMA_QUERIES
