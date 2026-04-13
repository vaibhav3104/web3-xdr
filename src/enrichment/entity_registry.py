"""
Entity Registry
===============

Classifies blockchain addresses into known entities:
- Exchanges (CEX/DEX)
- Mixers/Tumblers
- Known hackers
- Sanctioned addresses
- Smart money wallets
- Team/Project wallets
- Bridge contracts
"""

from typing import Dict, Optional, Set, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)


class EntityType(Enum):
    """Entity classification types."""
    UNKNOWN = "unknown"

    # Exchanges
    CEX = "cex"  # Centralized exchange
    DEX = "dex"  # Decentralized exchange

    # Privacy/Mixing
    MIXER = "mixer"
    TUMBLER = "tumbler"
    TORNADO = "tornado_cash"

    # Risk entities
    HACKER = "known_hacker"
    SANCTIONED = "sanctioned"
    PHISHER = "phisher"
    SCAMMER = "scammer"

    # Smart money
    SMART_MONEY = "smart_money"
    WHALE = "whale"
    VC = "vc"

    # Project entities
    TEAM_WALLET = "team_wallet"
    TREASURY = "treasury"
    DEPLOYER = "deployer"

    # Infrastructure
    BRIDGE = "bridge"
    PROTOCOL = "protocol"
    ORACLE = "oracle"

    # Contracts
    CONTRACT = "contract"
    EOA = "eoa"


class ReputationTier(Enum):
    """Reputation tier determines alert suppression and threshold behavior."""
    TRUSTED = "trusted"      # Major CEX, DEX routers, bridges — suppress below CRITICAL
    KNOWN = "known"          # Known protocols, VCs, smart money — suppress below HIGH
    NEUTRAL = "neutral"      # Unknown addresses — no suppression
    SUSPICIOUS = "suspicious"  # Mixers, new contracts — lower thresholds
    MALICIOUS = "malicious"  # Hackers, sanctioned — never suppress, always alert


# Map EntityType → ReputationTier
ENTITY_REPUTATION_MAP: Dict[EntityType, ReputationTier] = {
    EntityType.CEX: ReputationTier.TRUSTED,
    EntityType.DEX: ReputationTier.TRUSTED,
    EntityType.BRIDGE: ReputationTier.TRUSTED,
    EntityType.PROTOCOL: ReputationTier.TRUSTED,
    EntityType.ORACLE: ReputationTier.KNOWN,
    EntityType.SMART_MONEY: ReputationTier.KNOWN,
    EntityType.VC: ReputationTier.KNOWN,
    EntityType.WHALE: ReputationTier.KNOWN,
    EntityType.TEAM_WALLET: ReputationTier.KNOWN,
    EntityType.TREASURY: ReputationTier.KNOWN,
    EntityType.DEPLOYER: ReputationTier.NEUTRAL,
    EntityType.CONTRACT: ReputationTier.NEUTRAL,
    EntityType.EOA: ReputationTier.NEUTRAL,
    EntityType.UNKNOWN: ReputationTier.NEUTRAL,
    EntityType.MIXER: ReputationTier.SUSPICIOUS,
    EntityType.TUMBLER: ReputationTier.SUSPICIOUS,
    EntityType.TORNADO: ReputationTier.SUSPICIOUS,
    EntityType.PHISHER: ReputationTier.MALICIOUS,
    EntityType.SCAMMER: ReputationTier.MALICIOUS,
    EntityType.HACKER: ReputationTier.MALICIOUS,
    EntityType.SANCTIONED: ReputationTier.MALICIOUS,
}


@dataclass
class Entity:
    """Entity information."""
    address: str
    entity_type: EntityType
    name: Optional[str] = None
    labels: List[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0-100
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict = field(default_factory=dict)


class EntityRegistry:
    """
    Registry of known blockchain entities.
    
    Provides classification for:
    - Risk assessment (is this a known hacker?)
    - Flow analysis (is this an exchange?)
    - Smart money tracking
    """
    
    # Known centralized exchanges (lowercase addresses)
    CEX_ADDRESSES: Dict[str, str] = {
        # Binance
        "0x28c6c06298d514db089934071355e5743bf21d60": "Binance",
        "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance",
        "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance",
        "0x56eddb7aa87536c09ccc2793473599fd21a8b17f": "Binance",
        "0x9696f59e4d72e237be84ffd425dcad154bf96976": "Binance",
        "0xf977814e90da44bfa03b6295a0616a897441acec": "Binance",
        
        # Coinbase
        "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": "Coinbase",
        "0x503828976d22510aad0201ac7ec88293211d23da": "Coinbase",
        "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740": "Coinbase",
        "0x3cd751e6b0078be393132286c442345e5dc49699": "Coinbase",
        "0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511": "Coinbase",
        
        # Kraken
        "0x2910543af39aba0cd09dbb2d50200b3e800a63d2": "Kraken",
        "0x0a869d79a7052c7f1b55a8ebabbea3420f0d1e13": "Kraken",
        
        # FTX (historical)
        "0x2faf487a4414fe77e2327f0bf4ae2a264a776ad2": "FTX",
        
        # Gemini
        "0xd24400ae8bfebb18ca49be86258a3c749cf46853": "Gemini",
        
        # Huobi
        "0xab5c66752a9e8167967685f1450532fb96d5d24f": "Huobi",
        "0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b": "Huobi",
        
        # OKX
        "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": "OKX",
        "0x236f9f97e0e62388479bf9e5ba4889e46b0273c3": "OKX",
        
        # Bitfinex
        "0x876eabf441b2ee5b5b0554fd502a8e0600950cfa": "Bitfinex",
        "0x742d35cc6634c0532925a3b844bc454e4438f44e": "Bitfinex",
        
        # KuCoin
        "0xd6216fc19db775df9774a6e33526131da7d19a2c": "KuCoin",
        "0xf16e9b0d03470827a95cdfd0cb8a8a3b46969b91": "KuCoin",
    }
    
    # Known DEX routers and aggregators
    DEX_ADDRESSES: Dict[str, str] = {
        # Uniswap
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
        "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router 2",
        "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap Universal Router",
        
        # SushiSwap
        "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
        
        # 1inch
        "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch V4",
        "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
        
        # Curve
        "0x99a58482bd75cbab83b27ec03ca68ff489b5788f": "Curve Router",
        
        # 0x
        "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
        
        # Paraswap
        "0xdef171fe48cf0115b1d80b88dc8eab59176fee57": "Paraswap V5",
        
        # CoW Protocol
        "0x9008d19f58aabd9ed0d60971565aa8510560ab41": "CoW Protocol",
    }
    
    # Known mixers and privacy protocols
    MIXER_ADDRESSES: Dict[str, str] = {
        # Tornado Cash
        "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 0.1 ETH",
        "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 10 ETH",
        "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 100 ETH",
        "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash 1 ETH",
        "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash DAI",
        "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": "Tornado Cash cDAI",
        "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash Proxy",
        
        # Railgun
        "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9": "Railgun",
    }
    
    # Known hacker/exploit addresses
    HACKER_ADDRESSES: Dict[str, str] = {
        # Ronin Bridge Hacker
        "0x098b716b8aaf21512996dc57eb0615e2383e2f96": "Ronin Bridge Hacker",
        
        # Wormhole Hacker
        "0x629e7da20197a5429d30da36e77d06cdf796b71a": "Wormhole Hacker",
        
        # Euler Finance Hacker
        "0xb66cd966670d962c227b3eaba30a872dbfb995db": "Euler Hacker",
        
        # Curve Finance Hacker (2023)
        "0xdce5d6b41c32f578f875efffc0d422c57a75d7d8": "Curve Hacker 2023",
    }
    
    # OFAC Sanctioned addresses
    SANCTIONED_ADDRESSES: Set[str] = {
        # Tornado Cash related (OFAC sanctioned)
        "0x8589427373d6d84e98730d7795d8f6f8731fda16",
        "0x722122df12d4e14e13ac3b6895a86e84145b6967",
        "0xdd4c48c0b24039969fc16d1cdf626eab821d3384",
        "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
        "0xd96f2b1c14db8458374d9aca76e26c3d18364307",
        "0x4736dcf1b7a3d580672cce6e7c65cd5cc9cfba9d",
        
        # Lazarus Group
        "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
    }
    
    # Known smart money / VC wallets
    SMART_MONEY_ADDRESSES: Dict[str, str] = {
        # Paradigm
        "0x9b9647431632af44be02ddd22477ed94d14aacaa": "Paradigm",
        
        # a16z
        "0x05e793ce0c6027323ac150f6d45c2344d28b6019": "a16z",
        
        # Polychain
        "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf": "Polychain",
        
        # Three Arrows Capital (historical)
        "0x4862733b5fddfd35f35ea8ccf08f5045e57388b3": "Three Arrows Capital",
    }
    
    # Bridge contracts
    BRIDGE_ADDRESSES: Dict[str, str] = {
        # Wormhole
        "0x98f3c9e6e3face36baad05fe09d375ef1464288b": "Wormhole Token Bridge",

        # Multichain (Anyswap)
        "0x6b7a87899490ece95443e979ca9485cbe7e71522": "Multichain Router",

        # Stargate
        "0x8731d54e9d02c286767d56ac03e8037c07e01e98": "Stargate Router",

        # Hop Protocol
        "0xb8901acb165ed027e32754e0ffe830802919727f": "Hop Bridge",

        # Across
        "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5": "Across Bridge",

        # LayerZero
        "0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675": "LayerZero Endpoint",
    }

    # Major DeFi protocol contracts (routers, vaults, pools)
    PROTOCOL_ADDRESSES: Dict[str, str] = {
        # Aave V3
        "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "Aave V3 Pool",
        "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": "Aave V2 Lending Pool",

        # Compound V3
        "0xc3d688b66703497daa19211eedff47f25384cdc3": "Compound V3 cUSDCv3",
        "0xa17581a9e3356d9a858b789d68b4d866e593ae94": "Compound V3 cWETHv3",

        # Lido
        "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": "Lido stETH",
        "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": "Lido wstETH",

        # MakerDAO
        "0x9759a6ac90977b93b58547b4a71c78317f391a28": "MakerDAO DSR Manager",
        "0x5a15566417e6c1c9546523066500bddbc53f88c7": "MakerDAO PSM USDC",

        # Morpho
        "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb": "Morpho",

        # EigenLayer
        "0x858646372cc42e1a627fce94aa7a7033e7cf075a": "EigenLayer StrategyManager",

        # Rocket Pool
        "0xae78736cd615f374d3085123a210448e74fc6393": "Rocket Pool rETH",

        # Ethena
        "0x4c9edd5852cd905f086c759e8383e09bff1e68b3": "Ethena USDe",

        # Pendle
        "0x0000000001e4ef00d069e71d6ba041b0a16f7ea0": "Pendle Router V4",

        # Convex
        "0xf403c135812408bfbe8713b5a23a04b3d48aae31": "Convex Booster",

        # Yearn
        "0x5a6a4d54456819380173272a5e8e9b9904bdf41b": "Yearn DAI Vault",
    }
    
    def __init__(self):
        """Initialize the entity registry."""
        self._custom_entities: Dict[str, Entity] = {}
        self._cache: Dict[str, Entity] = {}
        logger.info("entity_registry_initialized")
    
    def classify(self, address: str) -> Entity:
        """
        Classify an address and return entity information.
        
        Args:
            address: Blockchain address (any case)
            
        Returns:
            Entity object with classification
        """
        address = address.lower()
        
        # Check cache
        if address in self._cache:
            return self._cache[address]
        
        # Check custom entities
        if address in self._custom_entities:
            return self._custom_entities[address]
        
        # Check known lists
        entity = self._lookup_known_entity(address)
        
        # Cache and return
        self._cache[address] = entity
        return entity
    
    def _lookup_known_entity(self, address: str) -> Entity:
        """Look up address in known entity lists."""
        
        # Check sanctioned first (highest risk)
        if address in self.SANCTIONED_ADDRESSES:
            return Entity(
                address=address,
                entity_type=EntityType.SANCTIONED,
                name="OFAC Sanctioned",
                risk_score=100.0,
                labels=["sanctioned", "high_risk"],
            )
        
        # Check hackers
        if address in self.HACKER_ADDRESSES:
            return Entity(
                address=address,
                entity_type=EntityType.HACKER,
                name=self.HACKER_ADDRESSES[address],
                risk_score=95.0,
                labels=["hacker", "high_risk"],
            )
        
        # Check mixers
        if address in self.MIXER_ADDRESSES:
            return Entity(
                address=address,
                entity_type=EntityType.MIXER,
                name=self.MIXER_ADDRESSES[address],
                risk_score=80.0,
                labels=["mixer", "privacy"],
            )
        
        # Check CEX
        if address in self.CEX_ADDRESSES:
            return Entity(
                address=address,
                entity_type=EntityType.CEX,
                name=self.CEX_ADDRESSES[address],
                risk_score=10.0,
                labels=["exchange", "cex"],
            )
        
        # Check DEX
        if address in self.DEX_ADDRESSES:
            return Entity(
                address=address,
                entity_type=EntityType.DEX,
                name=self.DEX_ADDRESSES[address],
                risk_score=5.0,
                labels=["exchange", "dex"],
            )
        
        # Check bridges
        if address in self.BRIDGE_ADDRESSES:
            return Entity(
                address=address,
                entity_type=EntityType.BRIDGE,
                name=self.BRIDGE_ADDRESSES[address],
                risk_score=15.0,
                labels=["bridge", "infrastructure"],
            )
        
        # Check smart money
        if address in self.SMART_MONEY_ADDRESSES:
            return Entity(
                address=address,
                entity_type=EntityType.SMART_MONEY,
                name=self.SMART_MONEY_ADDRESSES[address],
                risk_score=5.0,
                labels=["smart_money", "vc"],
            )

        # Check DeFi protocol contracts
        if address in self.PROTOCOL_ADDRESSES:
            return Entity(
                address=address,
                entity_type=EntityType.PROTOCOL,
                name=self.PROTOCOL_ADDRESSES[address],
                risk_score=5.0,
                labels=["protocol", "defi"],
            )

        # Unknown
        return Entity(
            address=address,
            entity_type=EntityType.UNKNOWN,
            risk_score=0.0,
        )
    
    def is_exchange(self, address: str) -> bool:
        """Check if address is a known exchange."""
        entity = self.classify(address)
        return entity.entity_type in (EntityType.CEX, EntityType.DEX)
    
    def is_mixer(self, address: str) -> bool:
        """Check if address is a known mixer."""
        entity = self.classify(address)
        return entity.entity_type in (EntityType.MIXER, EntityType.TUMBLER, EntityType.TORNADO)
    
    def is_high_risk(self, address: str) -> bool:
        """Check if address is high risk."""
        entity = self.classify(address)
        return entity.risk_score >= 80.0
    
    def is_sanctioned(self, address: str) -> bool:
        """Check if address is OFAC sanctioned."""
        entity = self.classify(address)
        return entity.entity_type == EntityType.SANCTIONED
    
    def is_known_hacker(self, address: str) -> bool:
        """Check if address is a known hacker."""
        entity = self.classify(address)
        return entity.entity_type == EntityType.HACKER
    
    def is_smart_money(self, address: str) -> bool:
        """Check if address is smart money."""
        entity = self.classify(address)
        return entity.entity_type in (EntityType.SMART_MONEY, EntityType.VC, EntityType.WHALE)
    
    def get_reputation_tier(self, address: str) -> ReputationTier:
        """Get the reputation tier for an address."""
        entity = self.classify(address)
        return ENTITY_REPUTATION_MAP.get(entity.entity_type, ReputationTier.NEUTRAL)

    def is_trusted(self, address: str) -> bool:
        """Check if address belongs to TRUSTED tier (CEX, DEX, bridge, protocol)."""
        return self.get_reputation_tier(address) == ReputationTier.TRUSTED

    def is_known(self, address: str) -> bool:
        """Check if address belongs to KNOWN tier (VCs, smart money, oracles)."""
        return self.get_reputation_tier(address) == ReputationTier.KNOWN

    def should_suppress_severity(self, address: str, severity: str) -> bool:
        """
        Check if alerts of the given severity should be suppressed for this address.

        TRUSTED addresses suppress everything below CRITICAL.
        KNOWN addresses suppress everything below HIGH.
        """
        tier = self.get_reputation_tier(address)
        severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        sev_val = severity_rank.get(severity, 1)

        if tier == ReputationTier.TRUSTED:
            return sev_val < severity_rank["critical"]  # suppress low/medium/high
        if tier == ReputationTier.KNOWN:
            return sev_val < severity_rank["high"]  # suppress low/medium
        return False

    def add_entity(self, entity: Entity):
        """Add a custom entity to the registry."""
        self._custom_entities[entity.address.lower()] = entity
        # Clear cache for this address
        if entity.address.lower() in self._cache:
            del self._cache[entity.address.lower()]


# Global singleton
_entity_registry: Optional[EntityRegistry] = None


def get_entity_registry() -> EntityRegistry:
    """Get global entity registry instance."""
    global _entity_registry
    if _entity_registry is None:
        _entity_registry = EntityRegistry()
    return _entity_registry
