"""
Transaction Graph Analysis
==========================

Advanced ML features for transaction pattern analysis:
1. Transaction graph construction and analysis
2. Wallet clustering by behavior
3. Anomaly detection on gas patterns
4. Deployer wallet risk scoring
"""

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import structlog

logger = structlog.get_logger(__name__)


class WalletRole(Enum):
    """Roles a wallet can have in the graph."""
    UNKNOWN = "unknown"
    DEPLOYER = "deployer"
    WHALE = "whale"
    MEV_BOT = "mev_bot"
    EXCHANGE = "exchange"
    BRIDGE = "bridge"
    MIXER = "mixer"
    ATTACKER = "attacker"
    VICTIM = "victim"
    INTERMEDIARY = "intermediary"


class ClusterType(Enum):
    """Types of wallet clusters."""
    EXCHANGE_CLUSTER = "exchange_cluster"
    WHALE_CLUSTER = "whale_cluster"
    BOT_CLUSTER = "bot_cluster"
    ATTACK_CLUSTER = "attack_cluster"
    MIXER_CLUSTER = "mixer_cluster"
    UNKNOWN = "unknown"


@dataclass
class WalletNode:
    """Node representing a wallet in the transaction graph."""
    address: str
    chain_id: str
    
    # Transaction metrics
    tx_count: int = 0
    total_value_in_usd: float = 0.0
    total_value_out_usd: float = 0.0
    unique_counterparties: int = 0
    
    # Timing metrics
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    avg_tx_interval_seconds: float = 0.0
    
    # Gas metrics
    avg_gas_price_gwei: float = 0.0
    max_gas_price_gwei: float = 0.0
    gas_usage_pattern: str = "normal"  # normal, high, erratic
    
    # Classification
    role: WalletRole = WalletRole.UNKNOWN
    cluster_id: Optional[str] = None
    risk_score: float = 0.0
    
    # Flags
    is_contract: bool = False
    is_labeled: bool = False
    label: Optional[str] = None
    
    # Connections
    connected_addresses: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": self.address,
            "chain_id": self.chain_id,
            "tx_count": self.tx_count,
            "total_value_in_usd": self.total_value_in_usd,
            "total_value_out_usd": self.total_value_out_usd,
            "unique_counterparties": self.unique_counterparties,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "avg_gas_price_gwei": self.avg_gas_price_gwei,
            "role": self.role.value,
            "cluster_id": self.cluster_id,
            "risk_score": self.risk_score,
            "is_contract": self.is_contract,
            "label": self.label,
        }


@dataclass
class TransactionEdge:
    """Edge representing a transaction between wallets."""
    tx_hash: str
    from_address: str
    to_address: str
    chain_id: str
    
    value_usd: float = 0.0
    gas_price_gwei: float = 0.0
    gas_used: int = 0
    timestamp: Optional[datetime] = None
    block_number: int = 0
    
    # Classification
    tx_type: str = "transfer"  # transfer, swap, bridge, contract_call
    is_suspicious: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tx_hash": self.tx_hash,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "chain_id": self.chain_id,
            "value_usd": self.value_usd,
            "gas_price_gwei": self.gas_price_gwei,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "tx_type": self.tx_type,
            "is_suspicious": self.is_suspicious,
        }


@dataclass
class WalletCluster:
    """A cluster of related wallets."""
    cluster_id: str
    cluster_type: ClusterType
    
    addresses: Set[str] = field(default_factory=set)
    
    # Aggregate metrics
    total_value_usd: float = 0.0
    total_tx_count: int = 0
    
    # Risk assessment
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cluster_id": self.cluster_id,
            "cluster_type": self.cluster_type.value,
            "address_count": len(self.addresses),
            "addresses": list(self.addresses)[:10],  # Limit for display
            "total_value_usd": self.total_value_usd,
            "total_tx_count": self.total_tx_count,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
        }


class TransactionGraphAnalyzer:
    """
    Analyzes transaction graphs for suspicious patterns.
    
    Features:
    1. Build and maintain transaction graph
    2. Detect wallet clusters
    3. Identify suspicious patterns
    4. Score wallet risk
    """
    
    def __init__(self):
        # Graph storage
        self._nodes: Dict[str, WalletNode] = {}  # address -> node
        self._edges: List[TransactionEdge] = []
        self._clusters: Dict[str, WalletCluster] = {}  # cluster_id -> cluster
        
        # Address lookups
        self._address_to_cluster: Dict[str, str] = {}  # address -> cluster_id
        
        # Known addresses (would be loaded from database)
        self._known_exchanges: Set[str] = {
            "0x28c6c06298d514db089934071355e5743bf21d60",  # Binance
            "0x21a31ee1afc51d94c2efccaa2092ad1028285549",  # Binance
            "0xdfd5293d8e347dfe59e90efd55b2956a1343963d",  # Binance
            "0x56eddb7aa87536c09ccc2793473599fd21a8b17f",  # Binance
            "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be",  # Binance
            "0xd24400ae8bfebb18ca49be86258a3c749cf46853",  # Gemini
            "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b",  # OKX
            "0x98c3d3183c4b8a650614ad179a1a98be0a8d6b8e",  # OKX
            "0x503828976d22510aad0201ac7ec88293211d23da",  # Coinbase
            "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740",  # Coinbase
            "0x3cd751e6b0078be393132286c442345e5dc49699",  # Coinbase
        }
        
        self._known_bridges: Set[str] = {
            "0x3ee18b2214aff97000d974cf647e7c347e8fa585",  # Wormhole
            "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f",  # Arbitrum Bridge
            "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1",  # Optimism Bridge
            "0x8ed95d1746bf1e4dab58d8ed4724f1ef95b20db0",  # Polygon Bridge
        }
        
        self._known_mixers: Set[str] = {
            "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",  # Tornado Cash
            "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc",  # Tornado Cash
            "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",  # Tornado Cash
        }
        
        # Statistics
        self._stats = {
            "nodes_created": 0,
            "edges_created": 0,
            "clusters_detected": 0,
            "suspicious_patterns": 0,
        }
        
        logger.info("transaction_graph_analyzer_initialized")
    
    def add_transaction(
        self,
        tx_hash: str,
        from_address: str,
        to_address: str,
        chain_id: str,
        value_usd: float = 0.0,
        gas_price_gwei: float = 0.0,
        gas_used: int = 0,
        timestamp: Optional[datetime] = None,
        block_number: int = 0,
        tx_type: str = "transfer"
    ) -> TransactionEdge:
        """Add a transaction to the graph."""
        # Normalize addresses
        from_address = from_address.lower() if from_address else ""
        to_address = to_address.lower() if to_address else ""
        
        if not from_address or not to_address:
            return None
        
        # Create or update nodes
        from_node = self._get_or_create_node(from_address, chain_id)
        to_node = self._get_or_create_node(to_address, chain_id)
        
        # Update node metrics
        from_node.tx_count += 1
        from_node.total_value_out_usd += value_usd
        from_node.connected_addresses.add(to_address)
        from_node.unique_counterparties = len(from_node.connected_addresses)
        
        to_node.tx_count += 1
        to_node.total_value_in_usd += value_usd
        to_node.connected_addresses.add(from_address)
        to_node.unique_counterparties = len(to_node.connected_addresses)
        
        # Update timestamps
        if timestamp:
            if from_node.first_seen is None or timestamp < from_node.first_seen:
                from_node.first_seen = timestamp
            if from_node.last_seen is None or timestamp > from_node.last_seen:
                from_node.last_seen = timestamp
            
            if to_node.first_seen is None or timestamp < to_node.first_seen:
                to_node.first_seen = timestamp
            if to_node.last_seen is None or timestamp > to_node.last_seen:
                to_node.last_seen = timestamp
        
        # Update gas metrics
        if gas_price_gwei > 0:
            # Running average
            from_node.avg_gas_price_gwei = (
                (from_node.avg_gas_price_gwei * (from_node.tx_count - 1) + gas_price_gwei)
                / from_node.tx_count
            )
            if gas_price_gwei > from_node.max_gas_price_gwei:
                from_node.max_gas_price_gwei = gas_price_gwei
        
        # Create edge
        edge = TransactionEdge(
            tx_hash=tx_hash,
            from_address=from_address,
            to_address=to_address,
            chain_id=chain_id,
            value_usd=value_usd,
            gas_price_gwei=gas_price_gwei,
            gas_used=gas_used,
            timestamp=timestamp,
            block_number=block_number,
            tx_type=tx_type,
        )
        
        self._edges.append(edge)
        self._stats["edges_created"] += 1
        
        # Keep edges limited
        if len(self._edges) > 100000:
            self._edges = self._edges[-50000:]
        
        # Classify nodes if enough data
        self._classify_node(from_node)
        self._classify_node(to_node)
        
        return edge
    
    def _get_or_create_node(self, address: str, chain_id: str) -> WalletNode:
        """Get existing node or create new one."""
        if address not in self._nodes:
            node = WalletNode(address=address, chain_id=chain_id)
            
            # Check known addresses
            if address in self._known_exchanges:
                node.role = WalletRole.EXCHANGE
                node.is_labeled = True
                node.label = "Exchange"
            elif address in self._known_bridges:
                node.role = WalletRole.BRIDGE
                node.is_labeled = True
                node.label = "Bridge"
            elif address in self._known_mixers:
                node.role = WalletRole.MIXER
                node.is_labeled = True
                node.label = "Mixer"
                node.risk_score = 0.8  # High risk for mixers
            
            self._nodes[address] = node
            self._stats["nodes_created"] += 1
        
        return self._nodes[address]
    
    def _classify_node(self, node: WalletNode):
        """Classify a node based on behavior patterns."""
        if node.is_labeled:
            return  # Already classified
        
        # MEV Bot detection
        if (
            node.tx_count > 100 and
            node.avg_gas_price_gwei > 50 and
            node.max_gas_price_gwei > 200
        ):
            node.role = WalletRole.MEV_BOT
            node.risk_score = max(node.risk_score, 0.5)
        
        # Whale detection
        elif node.total_value_out_usd > 1000000 or node.total_value_in_usd > 1000000:
            node.role = WalletRole.WHALE
        
        # Deployer detection (would need contract creation data)
        # For now, mark as deployer if they've created contracts
    
    def analyze_wallet(self, address: str) -> Dict[str, Any]:
        """
        Comprehensive wallet analysis.
        
        Returns risk score and detailed analysis.
        """
        address = address.lower()
        
        if address not in self._nodes:
            return {
                "address": address,
                "found": False,
                "risk_score": 0.5,  # Unknown = medium risk
                "analysis": "Address not found in transaction graph",
            }
        
        node = self._nodes[address]
        
        # Calculate risk score based on multiple factors
        risk_factors = []
        risk_score = 0.0
        
        # Factor 1: Mixer interaction
        mixer_interactions = sum(
            1 for addr in node.connected_addresses
            if addr in self._known_mixers
        )
        if mixer_interactions > 0:
            risk_score += 0.3
            risk_factors.append(f"Interacted with {mixer_interactions} known mixer(s)")
        
        # Factor 2: High gas usage (MEV/front-running)
        if node.max_gas_price_gwei > 200:
            risk_score += 0.15
            risk_factors.append(f"High gas usage detected (max: {node.max_gas_price_gwei:.0f} gwei)")
        
        # Factor 3: Rapid transactions (bot behavior)
        if node.tx_count > 100:
            time_span = (node.last_seen - node.first_seen).total_seconds() if node.first_seen and node.last_seen else 1
            if time_span > 0 and node.tx_count / time_span > 0.1:  # More than 1 tx per 10 seconds average
                risk_score += 0.2
                risk_factors.append("Bot-like transaction frequency detected")
        
        # Factor 4: Large value movements
        if node.total_value_out_usd > 1000000:
            risk_score += 0.1
            risk_factors.append(f"Large value movements: ${node.total_value_out_usd:,.0f}")
        
        # Factor 5: Few counterparties but high volume (concentration)
        if node.unique_counterparties < 5 and node.total_value_out_usd > 100000:
            risk_score += 0.15
            risk_factors.append("Concentrated transaction pattern")
        
        # Cap risk score
        risk_score = min(1.0, risk_score)
        node.risk_score = risk_score
        
        return {
            "address": address,
            "found": True,
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "risk_factors": risk_factors,
            "role": node.role.value,
            "metrics": {
                "tx_count": node.tx_count,
                "total_value_in_usd": node.total_value_in_usd,
                "total_value_out_usd": node.total_value_out_usd,
                "unique_counterparties": node.unique_counterparties,
                "avg_gas_price_gwei": node.avg_gas_price_gwei,
            },
            "cluster_id": node.cluster_id,
            "label": node.label,
        }
    
    def _risk_level(self, score: float) -> str:
        """Convert risk score to level."""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        return "minimal"
    
    def detect_clusters(self) -> List[WalletCluster]:
        """
        Detect wallet clusters using graph analysis.
        
        Uses simple connected component analysis.
        """
        # Build adjacency list
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        
        for edge in self._edges[-10000:]:  # Analyze recent transactions
            adjacency[edge.from_address].add(edge.to_address)
            adjacency[edge.to_address].add(edge.from_address)
        
        # Find connected components
        visited = set()
        clusters = []
        
        for address in adjacency:
            if address in visited:
                continue
            
            # BFS to find component
            component = set()
            queue = [address]
            
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                
                visited.add(current)
                component.add(current)
                
                for neighbor in adjacency[current]:
                    if neighbor not in visited:
                        queue.append(neighbor)
            
            # Only keep significant clusters (3+ addresses)
            if len(component) >= 3:
                cluster = self._create_cluster(component)
                clusters.append(cluster)
        
        self._stats["clusters_detected"] = len(clusters)
        
        return clusters
    
    def _create_cluster(self, addresses: Set[str]) -> WalletCluster:
        """Create a cluster from a set of addresses."""
        cluster_id = hashlib.sha256(
            ":".join(sorted(addresses)[:5]).encode()
        ).hexdigest()[:16]
        
        # Determine cluster type
        has_mixer = any(addr in self._known_mixers for addr in addresses)
        has_exchange = any(addr in self._known_exchanges for addr in addresses)
        
        if has_mixer:
            cluster_type = ClusterType.MIXER_CLUSTER
        elif has_exchange:
            cluster_type = ClusterType.EXCHANGE_CLUSTER
        else:
            cluster_type = ClusterType.UNKNOWN
        
        # Calculate aggregate metrics
        total_value = 0.0
        total_tx = 0
        risk_factors = []
        
        for addr in addresses:
            if addr in self._nodes:
                node = self._nodes[addr]
                total_value += node.total_value_out_usd
                total_tx += node.tx_count
        
        # Risk assessment
        risk_score = 0.0
        if has_mixer:
            risk_score = 0.8
            risk_factors.append("Contains known mixer address")
        elif len(addresses) > 10:
            risk_score = 0.4
            risk_factors.append("Large cluster size")
        
        cluster = WalletCluster(
            cluster_id=cluster_id,
            cluster_type=cluster_type,
            addresses=addresses,
            total_value_usd=total_value,
            total_tx_count=total_tx,
            risk_score=risk_score,
            risk_factors=risk_factors,
        )
        
        # Update address mappings
        for addr in addresses:
            self._address_to_cluster[addr] = cluster_id
            if addr in self._nodes:
                self._nodes[addr].cluster_id = cluster_id
        
        self._clusters[cluster_id] = cluster
        
        return cluster
    
    def detect_gas_anomalies(self, lookback_hours: int = 24) -> List[Dict[str, Any]]:
        """
        Detect anomalous gas usage patterns.
        
        Returns list of suspicious addresses with gas anomalies.
        """
        anomalies = []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        
        # Calculate average gas price
        recent_edges = [e for e in self._edges if e.timestamp and e.timestamp > cutoff]
        if not recent_edges:
            return []
        
        avg_gas = sum(e.gas_price_gwei for e in recent_edges) / len(recent_edges)
        std_dev = (
            sum((e.gas_price_gwei - avg_gas) ** 2 for e in recent_edges) / len(recent_edges)
        ) ** 0.5
        
        # Find addresses with anomalous gas usage
        for address, node in self._nodes.items():
            if node.max_gas_price_gwei > avg_gas + 3 * std_dev:
                anomalies.append({
                    "address": address,
                    "anomaly_type": "high_gas",
                    "max_gas_gwei": node.max_gas_price_gwei,
                    "avg_gas_gwei": node.avg_gas_price_gwei,
                    "network_avg_gwei": avg_gas,
                    "deviation_factor": (node.max_gas_price_gwei - avg_gas) / std_dev if std_dev > 0 else 0,
                    "risk_score": min(1.0, (node.max_gas_price_gwei - avg_gas) / (avg_gas + 1) * 0.5),
                })
        
        self._stats["suspicious_patterns"] += len(anomalies)
        
        return sorted(anomalies, key=lambda x: x["risk_score"], reverse=True)[:50]
    
    def get_deployer_risk_score(self, deployer_address: str) -> Dict[str, Any]:
        """
        Calculate risk score for a contract deployer.
        
        Considers:
        - Previous deployment history
        - Funding sources
        - Interaction with known bad actors
        """
        deployer_address = deployer_address.lower()
        
        analysis = self.analyze_wallet(deployer_address)
        
        # Additional deployer-specific factors
        risk_factors = analysis.get("risk_factors", [])
        risk_score = analysis.get("risk_score", 0.5)
        
        if deployer_address in self._nodes:
            node = self._nodes[deployer_address]
            
            # Check if funded by mixer
            for connected in node.connected_addresses:
                if connected in self._known_mixers:
                    risk_score = min(1.0, risk_score + 0.3)
                    risk_factors.append("Funded by known mixer")
                    break
            
            # Check if new wallet (created recently for deployment)
            if node.first_seen and node.tx_count < 10:
                time_active = (datetime.now(timezone.utc) - node.first_seen).days
                if time_active < 7:
                    risk_score = min(1.0, risk_score + 0.2)
                    risk_factors.append(f"New wallet (active {time_active} days)")
        
        return {
            "deployer_address": deployer_address,
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "risk_factors": risk_factors,
            "recommendation": self._get_recommendation(risk_score),
        }
    
    def _get_recommendation(self, risk_score: float) -> str:
        """Get recommendation based on risk score."""
        if risk_score >= 0.8:
            return "HIGH RISK: Manual review required before interaction"
        elif risk_score >= 0.6:
            return "ELEVATED RISK: Proceed with caution, consider additional verification"
        elif risk_score >= 0.4:
            return "MODERATE RISK: Standard precautions recommended"
        elif risk_score >= 0.2:
            return "LOW RISK: Normal interaction acceptable"
        return "MINIMAL RISK: No concerns detected"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return {
            **self._stats,
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "total_clusters": len(self._clusters),
        }


# Global instance
graph_analyzer = TransactionGraphAnalyzer()
