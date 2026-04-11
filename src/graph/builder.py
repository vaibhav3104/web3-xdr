"""
Security Graph Builder
======================

Builds and maintains the security graph from blockchain events.
Converts raw events into graph nodes and relationships.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, Set
import structlog

from .schema import NodeType, RelationType, GraphSchema
from .connection import Neo4jConnection

logger = structlog.get_logger(__name__)


# Known entity classifications
KNOWN_EXCHANGES = {
    "0x28c6c06298d514db089934071355e5743bf21d60": ("Binance", "cex"),
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": ("Binance", "cex"),
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": ("Binance", "cex"),
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f": ("Binance", "cex"),
    "0xf89d7b9c864f589bbf53a82105107622b35eaa40": ("Bybit", "cex"),
    "0x1ab4973a48dc892cd9971ece8e01dcc7688f8f23": ("Coinbase", "cex"),
    "0x503828976d22510aad0201ac7ec88293211d23da": ("Coinbase", "cex"),
    "0xeb2629a2734e272bcc07bda959863f316f4bd4cf": ("Coinbase", "cex"),
    "0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852": ("Uniswap V2", "dex"),
    "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640": ("Uniswap V3", "dex"),
}

KNOWN_MIXERS = {
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": "Tornado Cash",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash",
}

KNOWN_HACKERS = {
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": "Ronin Hacker",
    "0x8d1b1d2a0e8b4e4f7b6c9e5d3a2f1c0b9a8e7d6c": "Example Hacker",
}

SANCTIONED_ADDRESSES = {
    "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c": "OFAC Sanctioned",
    "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b": "OFAC Sanctioned",
}

# Protocol contract mappings
PROTOCOL_CONTRACTS = {
    # Aave V3
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": ("Aave V3", "Pool"),
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": ("Aave V2", "Pool"),
    
    # Uniswap
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": ("Uniswap", "Router"),
    "0xe592427a0aece92de3edee1f18e0157c05861564": ("Uniswap V3", "Router"),
    
    # Compound
    "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b": ("Compound", "Comptroller"),
    
    # Curve
    "0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7": ("Curve", "3Pool"),
    
    # MakerDAO
    "0x5ef30b9986345249bc32d8928b7ee64de9435e39": ("MakerDAO", "DSR"),
}


class GraphBuilder:
    """
    Builds the security graph from blockchain events.
    
    Responsibilities:
    - Create nodes for contracts, wallets, tokens
    - Create relationships from transactions
    - Classify entities (exchange, mixer, hacker, etc.)
    - Update node properties over time
    """
    
    def __init__(self, connection: Neo4jConnection):
        """
        Initialize graph builder.
        
        Args:
            connection: Neo4j connection instance
        """
        self.conn = connection
        self._entity_cache: Dict[str, Dict[str, Any]] = {}
        self._processed_txs: Set[str] = set()
    
    async def initialize(self):
        """Initialize the graph schema."""
        await self.conn.create_schema(GraphSchema.get_schema_queries())
        logger.info("graph_schema_initialized")
    
    async def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a security event and update the graph.
        
        Args:
            event: Security event dictionary
            
        Returns:
            Summary of graph updates
        """
        tx_hash = event.get("tx_hash", "")
        if tx_hash in self._processed_txs:
            return {"status": "skipped", "reason": "already_processed"}
        
        event_type = event.get("event_type", "unknown")
        event.get("chain_id", "ethereum")
        
        updates = {
            "nodes_created": 0,
            "relationships_created": 0,
            "properties_updated": 0
        }
        
        try:
            # Process based on event type
            if event_type == "Transfer":
                updates = await self._process_transfer(event)
            elif event_type == "ContractDeployed":
                updates = await self._process_contract_deployment(event)
            elif event_type == "Swap":
                updates = await self._process_swap(event)
            elif event_type == "FlashLoan":
                updates = await self._process_flash_loan(event)
            elif event_type == "Liquidation":
                updates = await self._process_liquidation(event)
            elif event_type == "AdminAction":
                updates = await self._process_admin_action(event)
            else:
                # Generic event processing
                updates = await self._process_generic_event(event)
            
            self._processed_txs.add(tx_hash)
            
            logger.debug(
                "event_processed",
                event_type=event_type,
                tx_hash=tx_hash[:10] if tx_hash else "none",
                updates=updates
            )
            
        except Exception as e:
            logger.error(
                "event_processing_failed",
                event_type=event_type,
                error=str(e)
            )
        
        return updates
    
    async def _process_transfer(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a Transfer event."""
        from_addr = event.get("source_address", "").lower()
        to_addr = event.get("dest_address", "").lower()
        token_addr = event.get("asset_address", event.get("contract_address", "")).lower()
        chain_id = event.get("chain_id", "ethereum")
        amount_usd = float(event.get("amount_usd", 0))
        timestamp = event.get("block_timestamp", datetime.now(timezone.utc))
        tx_hash = event.get("tx_hash", "")
        
        if not from_addr or not to_addr:
            return {"nodes_created": 0, "relationships_created": 0}
        
        # Create/update wallet nodes
        await self._ensure_wallet_node(from_addr, chain_id, timestamp)
        await self._ensure_wallet_node(to_addr, chain_id, timestamp)
        
        # Create/update token node
        if token_addr:
            await self._ensure_token_node(token_addr, chain_id, timestamp)
        
        # Create TRANSFERS_TO relationship
        await self._create_transfer_relationship(
            from_addr, to_addr, chain_id, amount_usd, timestamp, tx_hash
        )
        
        # Check for risk relationships
        await self._check_risk_relationships(from_addr, to_addr, chain_id)
        
        return {"nodes_created": 2, "relationships_created": 1}
    
    async def _process_contract_deployment(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a contract deployment event."""
        deployer = event.get("source_address", "").lower()
        contract_addr = event.get("contract_address", "").lower()
        chain_id = event.get("chain_id", "ethereum")
        timestamp = event.get("block_timestamp", datetime.now(timezone.utc))
        
        # Get bytecode analysis if available
        bytecode_analysis = event.get("raw_event", {}).get("bytecode_analysis", {})
        
        # Create deployer wallet node
        await self._ensure_wallet_node(deployer, chain_id, timestamp)
        
        # Create contract node with analysis
        await self._create_contract_node(
            contract_addr, 
            chain_id, 
            timestamp,
            deployer=deployer,
            bytecode_analysis=bytecode_analysis
        )
        
        # Create DEPLOYED relationship
        await self._create_relationship(
            from_addr=deployer,
            from_type=NodeType.WALLET,
            to_addr=contract_addr,
            to_type=NodeType.CONTRACT,
            rel_type=RelationType.DEPLOYED,
            chain_id=chain_id,
            timestamp=timestamp,
            tx_hash=event.get("tx_hash", "")
        )
        
        return {"nodes_created": 2, "relationships_created": 1}
    
    async def _process_swap(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a swap event."""
        sender = event.get("source_address", "").lower()
        pool_addr = event.get("contract_address", "").lower()
        chain_id = event.get("chain_id", "ethereum")
        timestamp = event.get("block_timestamp", datetime.now(timezone.utc))
        amount_usd = float(event.get("amount_usd", 0))
        
        # Create wallet and pool nodes
        await self._ensure_wallet_node(sender, chain_id, timestamp)
        await self._ensure_pool_node(pool_addr, chain_id, timestamp)
        
        # Create relationship
        await self._create_relationship(
            from_addr=sender,
            from_type=NodeType.WALLET,
            to_addr=pool_addr,
            to_type=NodeType.POOL,
            rel_type=RelationType.CALLS,
            chain_id=chain_id,
            timestamp=timestamp,
            amount_usd=amount_usd,
            tx_hash=event.get("tx_hash", "")
        )
        
        return {"nodes_created": 2, "relationships_created": 1}
    
    async def _process_flash_loan(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a flash loan event."""
        borrower = event.get("source_address", "").lower()
        protocol_addr = event.get("contract_address", "").lower()
        chain_id = event.get("chain_id", "ethereum")
        timestamp = event.get("block_timestamp", datetime.now(timezone.utc))
        amount_usd = float(event.get("amount_usd", 0))
        
        # Create nodes
        await self._ensure_wallet_node(borrower, chain_id, timestamp)
        await self._ensure_protocol_node(protocol_addr, chain_id, timestamp)
        
        # Create FLASH_LOANED relationship
        await self._create_relationship(
            from_addr=borrower,
            from_type=NodeType.WALLET,
            to_addr=protocol_addr,
            to_type=NodeType.PROTOCOL,
            rel_type=RelationType.FLASH_LOANED,
            chain_id=chain_id,
            timestamp=timestamp,
            amount_usd=amount_usd,
            tx_hash=event.get("tx_hash", "")
        )
        
        return {"nodes_created": 2, "relationships_created": 1}
    
    async def _process_liquidation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a liquidation event."""
        liquidator = event.get("source_address", "").lower()
        protocol_addr = event.get("contract_address", "").lower()
        chain_id = event.get("chain_id", "ethereum")
        timestamp = event.get("block_timestamp", datetime.now(timezone.utc))
        float(event.get("amount_usd", 0))
        
        # Create nodes
        await self._ensure_wallet_node(liquidator, chain_id, timestamp)
        await self._ensure_protocol_node(protocol_addr, chain_id, timestamp)
        
        return {"nodes_created": 2, "relationships_created": 1}
    
    async def _process_admin_action(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process an admin action event."""
        admin = event.get("source_address", "").lower()
        contract_addr = event.get("contract_address", "").lower()
        chain_id = event.get("chain_id", "ethereum")
        timestamp = event.get("block_timestamp", datetime.now(timezone.utc))
        
        # Create nodes
        await self._ensure_wallet_node(admin, chain_id, timestamp)
        await self._ensure_contract_node(contract_addr, chain_id, timestamp)
        
        # Create HAS_ADMIN_ACCESS relationship
        await self._create_relationship(
            from_addr=admin,
            from_type=NodeType.WALLET,
            to_addr=contract_addr,
            to_type=NodeType.CONTRACT,
            rel_type=RelationType.HAS_ADMIN_ACCESS,
            chain_id=chain_id,
            timestamp=timestamp,
            tx_hash=event.get("tx_hash", "")
        )
        
        return {"nodes_created": 2, "relationships_created": 1}
    
    async def _process_generic_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a generic event."""
        source = event.get("source_address", "").lower()
        contract = event.get("contract_address", "").lower()
        chain_id = event.get("chain_id", "ethereum")
        timestamp = event.get("block_timestamp", datetime.now(timezone.utc))
        
        if source:
            await self._ensure_wallet_node(source, chain_id, timestamp)
        if contract:
            await self._ensure_contract_node(contract, chain_id, timestamp)
        
        return {"nodes_created": 2 if source and contract else 1}
    
    async def _ensure_wallet_node(
        self, 
        address: str, 
        chain_id: str, 
        timestamp: datetime
    ):
        """Create or update a wallet node."""
        if not address or address == "0x" + "0" * 40:
            return
        
        # Check cache first
        cache_key = f"{chain_id}:{address}"
        if cache_key in self._entity_cache:
            return
        
        # Classify wallet
        labels = ["Wallet"]
        entity_name = None
        is_exchange = False
        is_mixer = False
        is_hacker = False
        is_sanctioned = False
        
        if address in KNOWN_EXCHANGES:
            entity_name, entity_type = KNOWN_EXCHANGES[address]
            labels.append("Exchange")
            is_exchange = True
        
        if address in KNOWN_MIXERS:
            entity_name = KNOWN_MIXERS[address]
            labels.append("Mixer")
            is_mixer = True
        
        if address in KNOWN_HACKERS:
            entity_name = KNOWN_HACKERS[address]
            labels.append("Hacker")
            is_hacker = True
        
        if address in SANCTIONED_ADDRESSES:
            entity_name = SANCTIONED_ADDRESSES[address]
            labels.append("Sanctioned")
            is_sanctioned = True
        
        # Calculate initial risk score
        risk_score = 0.0
        if is_mixer:
            risk_score = 80.0
        elif is_hacker:
            risk_score = 100.0
        elif is_sanctioned:
            risk_score = 100.0
        
        # Create node in Neo4j
        query = """
        MERGE (w:Wallet {address: $address, chain_id: $chain_id})
        ON CREATE SET
            w.first_seen = $timestamp,
            w.last_seen = $timestamp,
            w.entity_name = $entity_name,
            w.is_exchange = $is_exchange,
            w.is_mixer = $is_mixer,
            w.is_hacker = $is_hacker,
            w.is_sanctioned = $is_sanctioned,
            w.risk_score = $risk_score,
            w.transaction_count = 0
        ON MATCH SET
            w.last_seen = $timestamp,
            w.transaction_count = w.transaction_count + 1
        """
        
        # Add additional labels
        for label in labels[1:]:  # Skip "Wallet" as it's in MERGE
            query += f"\nSET w:{label}"
        
        await self.conn.execute(query, {
            "address": address,
            "chain_id": chain_id,
            "timestamp": timestamp.isoformat(),
            "entity_name": entity_name,
            "is_exchange": is_exchange,
            "is_mixer": is_mixer,
            "is_hacker": is_hacker,
            "is_sanctioned": is_sanctioned,
            "risk_score": risk_score
        })
        
        # Cache
        self._entity_cache[cache_key] = {
            "type": "wallet",
            "labels": labels,
            "risk_score": risk_score
        }
    
    async def _ensure_contract_node(
        self,
        address: str,
        chain_id: str,
        timestamp: datetime,
        deployer: Optional[str] = None,
        bytecode_analysis: Optional[Dict[str, Any]] = None
    ):
        """Create or update a contract node."""
        if not address:
            return
        
        cache_key = f"{chain_id}:{address}"
        if cache_key in self._entity_cache:
            return
        
        # Check if this is a known protocol contract
        labels = ["Contract"]
        protocol_name = None
        contract_type = None
        
        if address in PROTOCOL_CONTRACTS:
            protocol_name, contract_type = PROTOCOL_CONTRACTS[address]
            labels.append("Protocol")
        
        # Extract bytecode analysis
        has_selfdestruct = False
        has_delegatecall = False
        is_upgradeable = False
        risk_score = 0.0
        vulnerability_types = []
        
        if bytecode_analysis:
            has_selfdestruct = bytecode_analysis.get("has_selfdestruct", False)
            has_delegatecall = bytecode_analysis.get("has_delegatecall", False)
            is_upgradeable = bytecode_analysis.get("is_upgradeable", False)
            risk_score = bytecode_analysis.get("risk_score", 0.0)
            vulnerability_types = bytecode_analysis.get("vulnerability_types", [])
            
            if has_selfdestruct:
                risk_score += 20
            if has_delegatecall and not is_upgradeable:
                risk_score += 15
        
        query = """
        MERGE (c:Contract {address: $address, chain_id: $chain_id})
        ON CREATE SET
            c.first_seen = $timestamp,
            c.last_seen = $timestamp,
            c.deployer = $deployer,
            c.protocol_name = $protocol_name,
            c.contract_type = $contract_type,
            c.has_selfdestruct = $has_selfdestruct,
            c.has_delegatecall = $has_delegatecall,
            c.is_upgradeable = $is_upgradeable,
            c.risk_score = $risk_score,
            c.vulnerability_types = $vulnerability_types
        ON MATCH SET
            c.last_seen = $timestamp
        """
        
        for label in labels[1:]:
            query += f"\nSET c:{label}"
        
        await self.conn.execute(query, {
            "address": address,
            "chain_id": chain_id,
            "timestamp": timestamp.isoformat(),
            "deployer": deployer,
            "protocol_name": protocol_name,
            "contract_type": contract_type,
            "has_selfdestruct": has_selfdestruct,
            "has_delegatecall": has_delegatecall,
            "is_upgradeable": is_upgradeable,
            "risk_score": risk_score,
            "vulnerability_types": vulnerability_types
        })
        
        self._entity_cache[cache_key] = {
            "type": "contract",
            "labels": labels,
            "risk_score": risk_score
        }
    
    async def _ensure_token_node(
        self,
        address: str,
        chain_id: str,
        timestamp: datetime
    ):
        """Create or update a token node."""
        if not address:
            return
        
        cache_key = f"token:{chain_id}:{address}"
        if cache_key in self._entity_cache:
            return
        
        query = """
        MERGE (t:Token {address: $address, chain_id: $chain_id})
        ON CREATE SET
            t.first_seen = $timestamp,
            t.last_seen = $timestamp,
            t.transfer_count = 1
        ON MATCH SET
            t.last_seen = $timestamp,
            t.transfer_count = t.transfer_count + 1
        """
        
        await self.conn.execute(query, {
            "address": address,
            "chain_id": chain_id,
            "timestamp": timestamp.isoformat()
        })
        
        self._entity_cache[cache_key] = {"type": "token"}
    
    async def _ensure_pool_node(
        self,
        address: str,
        chain_id: str,
        timestamp: datetime
    ):
        """Create or update a pool node."""
        if not address:
            return
        
        query = """
        MERGE (p:Pool {address: $address, chain_id: $chain_id})
        ON CREATE SET
            p.first_seen = $timestamp,
            p.last_seen = $timestamp,
            p.swap_count = 1
        ON MATCH SET
            p.last_seen = $timestamp,
            p.swap_count = p.swap_count + 1
        """
        
        await self.conn.execute(query, {
            "address": address,
            "chain_id": chain_id,
            "timestamp": timestamp.isoformat()
        })
    
    async def _ensure_protocol_node(
        self,
        address: str,
        chain_id: str,
        timestamp: datetime
    ):
        """Create or update a protocol node."""
        if not address:
            return
        
        # Check if known protocol
        protocol_name = None
        if address in PROTOCOL_CONTRACTS:
            protocol_name, _ = PROTOCOL_CONTRACTS[address]
        
        query = """
        MERGE (p:Protocol {address: $address, chain_id: $chain_id})
        ON CREATE SET
            p.first_seen = $timestamp,
            p.last_seen = $timestamp,
            p.name = $protocol_name
        ON MATCH SET
            p.last_seen = $timestamp
        """
        
        await self.conn.execute(query, {
            "address": address,
            "chain_id": chain_id,
            "timestamp": timestamp.isoformat(),
            "protocol_name": protocol_name
        })
    
    async def _create_transfer_relationship(
        self,
        from_addr: str,
        to_addr: str,
        chain_id: str,
        amount_usd: float,
        timestamp: datetime,
        tx_hash: str
    ):
        """Create a TRANSFERS_TO relationship."""
        query = """
        MATCH (from:Wallet {address: $from_addr, chain_id: $chain_id})
        MATCH (to:Wallet {address: $to_addr, chain_id: $chain_id})
        MERGE (from)-[r:TRANSFERS_TO]->(to)
        ON CREATE SET
            r.first_seen = $timestamp,
            r.last_seen = $timestamp,
            r.total_value_usd = $amount_usd,
            r.occurrence_count = 1,
            r.last_tx_hash = $tx_hash
        ON MATCH SET
            r.last_seen = $timestamp,
            r.total_value_usd = r.total_value_usd + $amount_usd,
            r.occurrence_count = r.occurrence_count + 1,
            r.last_tx_hash = $tx_hash
        """
        
        await self.conn.execute(query, {
            "from_addr": from_addr,
            "to_addr": to_addr,
            "chain_id": chain_id,
            "amount_usd": amount_usd,
            "timestamp": timestamp.isoformat(),
            "tx_hash": tx_hash
        })
    
    async def _create_relationship(
        self,
        from_addr: str,
        from_type: NodeType,
        to_addr: str,
        to_type: NodeType,
        rel_type: RelationType,
        chain_id: str,
        timestamp: datetime,
        amount_usd: float = 0.0,
        tx_hash: str = ""
    ):
        """Create a generic relationship."""
        query = f"""
        MATCH (from:{from_type.value} {{address: $from_addr, chain_id: $chain_id}})
        MATCH (to:{to_type.value} {{address: $to_addr, chain_id: $chain_id}})
        MERGE (from)-[r:{rel_type.value}]->(to)
        ON CREATE SET
            r.first_seen = $timestamp,
            r.last_seen = $timestamp,
            r.total_value_usd = $amount_usd,
            r.occurrence_count = 1,
            r.last_tx_hash = $tx_hash
        ON MATCH SET
            r.last_seen = $timestamp,
            r.total_value_usd = r.total_value_usd + $amount_usd,
            r.occurrence_count = r.occurrence_count + 1,
            r.last_tx_hash = $tx_hash
        """
        
        await self.conn.execute(query, {
            "from_addr": from_addr,
            "to_addr": to_addr,
            "chain_id": chain_id,
            "amount_usd": amount_usd,
            "timestamp": timestamp.isoformat(),
            "tx_hash": tx_hash
        })
    
    async def _check_risk_relationships(
        self,
        from_addr: str,
        to_addr: str,
        chain_id: str
    ):
        """Check and create risk-related relationships."""
        # Check if receiving from or sending to mixer
        if from_addr in KNOWN_MIXERS:
            query = """
            MATCH (w:Wallet {address: $wallet, chain_id: $chain_id})
            MATCH (m:Mixer {address: $mixer, chain_id: $chain_id})
            MERGE (w)-[r:RECEIVED_FROM_MIXER]->(m)
            SET r.last_seen = datetime()
            SET w.mixer_interactions = coalesce(w.mixer_interactions, 0) + 1
            SET w.risk_score = CASE 
                WHEN w.risk_score < 50 THEN w.risk_score + 10
                ELSE w.risk_score
            END
            """
            await self.conn.execute(query, {
                "wallet": to_addr,
                "mixer": from_addr,
                "chain_id": chain_id
            })
        
        if to_addr in KNOWN_MIXERS:
            query = """
            MATCH (w:Wallet {address: $wallet, chain_id: $chain_id})
            MATCH (m:Mixer {address: $mixer, chain_id: $chain_id})
            MERGE (w)-[r:SENT_TO_MIXER]->(m)
            SET r.last_seen = datetime()
            SET w.mixer_interactions = coalesce(w.mixer_interactions, 0) + 1
            SET w.risk_score = CASE 
                WHEN w.risk_score < 50 THEN w.risk_score + 10
                ELSE w.risk_score
            END
            """
            await self.conn.execute(query, {
                "wallet": from_addr,
                "mixer": to_addr,
                "chain_id": chain_id
            })
    
    async def get_graph_stats(self) -> Dict[str, Any]:
        """Get statistics about the graph."""
        return await self.conn.health_check()
    
    async def clear_cache(self):
        """Clear the entity cache."""
        self._entity_cache.clear()
        self._processed_txs.clear()
