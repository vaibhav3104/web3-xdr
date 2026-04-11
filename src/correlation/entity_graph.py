"""
Entity Graph - Tracks relationships between blockchain entities.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple
import structlog

from ..models.events import SecurityEvent, EventType
from ..models.entities import Entity, EntityType
from ..models.incidents import AttackGraph, AttackGraphNode, AttackGraphEdge

logger = structlog.get_logger()


@dataclass
class GraphEdge:
    """Edge in the entity graph."""
    source_id: str
    dest_id: str
    event_ids: List[str] = field(default_factory=list)
    total_volume_usd: float = 0.0
    tx_count: int = 0
    first_interaction: Optional[datetime] = None
    last_interaction: Optional[datetime] = None
    chains: Set[str] = field(default_factory=set)


class EntityGraph:
    """
    Graph of entities and their relationships.
    
    Used for:
    - Tracing fund flows
    - Identifying attacker patterns
    - Building attack narratives
    """
    
    def __init__(self):
        # Entity storage
        self.entities: Dict[str, Entity] = {}
        
        # Adjacency lists (bidirectional)
        self.outgoing_edges: Dict[str, Dict[str, GraphEdge]] = {}  # from -> to -> edge
        self.incoming_edges: Dict[str, Dict[str, GraphEdge]] = {}  # to -> from -> edge
        
        # Index by address (for cross-chain lookup)
        self.address_index: Dict[str, Set[str]] = {}  # address -> entity_ids
        
        # Known entity labels
        self._known_entities: Dict[Tuple[str, str], Entity] = {}  # (chain, address) -> entity
    
    def get_or_create_entity(
        self,
        address: str,
        chain_id: str,
        entity_type: EntityType = EntityType.UNKNOWN
    ) -> Entity:
        """Get existing entity or create new one."""
        key = (chain_id, address.lower())
        
        if key in self._known_entities:
            return self._known_entities[key]
        
        # Create new entity
        entity = Entity(
            address=address.lower(),
            chain_id=chain_id,
            entity_type=entity_type,
            first_seen=datetime.now(timezone.utc)
        )
        
        self._known_entities[key] = entity
        self.entities[entity.id] = entity
        
        # Index by address
        addr_lower = address.lower()
        if addr_lower not in self.address_index:
            self.address_index[addr_lower] = set()
        self.address_index[addr_lower].add(entity.id)
        
        return entity
    
    def add_event(self, event: SecurityEvent):
        """
        Add an event to the graph.
        
        Creates/updates entities and edges.
        """
        # Get/create entities
        source_entity = None
        dest_entity = None
        
        if event.source_address:
            source_entity = self.get_or_create_entity(
                event.source_address,
                event.chain_id
            )
            source_entity.tx_count += 1
            source_entity.total_volume_usd += float(event.amount_usd)
            source_entity.last_seen = event.block_timestamp
        
        if event.dest_address:
            dest_entity = self.get_or_create_entity(
                event.dest_address,
                event.chain_id
            )
            dest_entity.tx_count += 1
            dest_entity.total_volume_usd += float(event.amount_usd)
            dest_entity.last_seen = event.block_timestamp
        
        # Create/update edge
        if source_entity and dest_entity:
            self._add_edge(source_entity.id, dest_entity.id, event)
        
        # Detect entity type from behavior
        if event.event_type == EventType.MINT and dest_entity:
            if dest_entity.entity_type == EntityType.UNKNOWN:
                dest_entity.entity_type = EntityType.CONTRACT
        
        if event.bridge_id:
            contract_entity = self.get_or_create_entity(
                event.contract_address,
                event.chain_id,
                EntityType.BRIDGE
            )
            contract_entity.labels.append(f"bridge:{event.bridge_id}")
    
    def _add_edge(self, source_id: str, dest_id: str, event: SecurityEvent):
        """Add or update an edge."""
        # Initialize adjacency if needed
        if source_id not in self.outgoing_edges:
            self.outgoing_edges[source_id] = {}
        if dest_id not in self.incoming_edges:
            self.incoming_edges[dest_id] = {}
        
        # Get or create edge
        if dest_id not in self.outgoing_edges[source_id]:
            edge = GraphEdge(source_id=source_id, dest_id=dest_id)
            self.outgoing_edges[source_id][dest_id] = edge
            self.incoming_edges[dest_id][source_id] = edge
        else:
            edge = self.outgoing_edges[source_id][dest_id]
        
        # Update edge
        edge.event_ids.append(event.event_id)
        edge.total_volume_usd += float(event.amount_usd)
        edge.tx_count += 1
        edge.chains.add(event.chain_id)
        
        if edge.first_interaction is None:
            edge.first_interaction = event.block_timestamp
        edge.last_interaction = event.block_timestamp
    
    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """Get entity by ID."""
        return self.entities.get(entity_id)
    
    def get_entity_by_address(
        self,
        address: str,
        chain_id: Optional[str] = None
    ) -> Optional[Entity]:
        """Get entity by address, optionally filtered by chain."""
        entity_ids = self.address_index.get(address.lower(), set())
        
        for entity_id in entity_ids:
            entity = self.entities.get(entity_id)
            if entity and (chain_id is None or entity.chain_id == chain_id):
                return entity
        
        return None
    
    def get_connected_entities(
        self,
        entity_id: str,
        direction: str = "both",  # "outgoing", "incoming", "both"
        max_hops: int = 2,
        min_volume_usd: float = 0
    ) -> List[Entity]:
        """
        Get entities connected to the given entity.
        """
        visited = set()
        result = []
        queue = [(entity_id, 0)]
        
        while queue:
            current_id, depth = queue.pop(0)
            
            if current_id in visited or depth > max_hops:
                continue
            visited.add(current_id)
            
            entity = self.entities.get(current_id)
            if entity and current_id != entity_id:
                result.append(entity)
            
            # Get neighbors
            neighbors = set()
            
            if direction in ("outgoing", "both"):
                for dest_id, edge in self.outgoing_edges.get(current_id, {}).items():
                    if edge.total_volume_usd >= min_volume_usd:
                        neighbors.add(dest_id)
            
            if direction in ("incoming", "both"):
                for source_id, edge in self.incoming_edges.get(current_id, {}).items():
                    if edge.total_volume_usd >= min_volume_usd:
                        neighbors.add(source_id)
            
            for neighbor_id in neighbors:
                if neighbor_id not in visited:
                    queue.append((neighbor_id, depth + 1))
        
        return result
    
    def trace_funds(
        self,
        source_entity_id: str,
        time_window: Optional[timedelta] = None,
        min_amount_usd: float = 0
    ) -> List[List[Tuple[str, float]]]:
        """
        Trace fund flows from source entity.
        
        Returns list of paths, each path is list of (entity_id, amount) tuples.
        """
        paths = []
        cutoff = datetime.now(timezone.utc) - time_window if time_window else None
        
        def dfs(current_id: str, path: List[Tuple[str, float]], visited: Set[str]):
            if current_id in visited:
                return
            
            visited.add(current_id)
            
            # Get outgoing edges
            for dest_id, edge in self.outgoing_edges.get(current_id, {}).items():
                if edge.total_volume_usd < min_amount_usd:
                    continue
                if cutoff and edge.last_interaction and edge.last_interaction < cutoff:
                    continue
                
                new_path = path + [(dest_id, edge.total_volume_usd)]
                paths.append(new_path)
                
                # Continue tracing
                dfs(dest_id, new_path, visited.copy())
        
        dfs(source_entity_id, [(source_entity_id, 0)], set())
        return paths
    
    def build_attack_graph(
        self,
        violation_events: List[SecurityEvent],
        time_window: timedelta = timedelta(hours=1)
    ) -> AttackGraph:
        """
        Build an attack graph from violation-related events.
        """
        attack_graph = AttackGraph()
        node_map: Dict[str, AttackGraphNode] = {}
        
        # Find all entities involved
        for event in violation_events:
            # Add source
            if event.source_address:
                entity = self.get_entity_by_address(
                    event.source_address,
                    event.chain_id
                )
                if entity and entity.id not in node_map:
                    node = AttackGraphNode(
                        entity_id=entity.id,
                        address=entity.address,
                        chain_id=entity.chain_id,
                        role="unknown",
                        first_seen_in_attack=event.block_timestamp
                    )
                    node_map[entity.id] = node
                    attack_graph.nodes.append(node)
            
            # Add dest
            if event.dest_address:
                entity = self.get_entity_by_address(
                    event.dest_address,
                    event.chain_id
                )
                if entity and entity.id not in node_map:
                    node = AttackGraphNode(
                        entity_id=entity.id,
                        address=entity.address,
                        chain_id=entity.chain_id,
                        role="unknown",
                        first_seen_in_attack=event.block_timestamp
                    )
                    node_map[entity.id] = node
                    attack_graph.nodes.append(node)
            
            # Add edge
            if event.source_address and event.dest_address:
                source_entity = self.get_entity_by_address(event.source_address, event.chain_id)
                dest_entity = self.get_entity_by_address(event.dest_address, event.chain_id)
                
                if source_entity and dest_entity:
                    edge = AttackGraphEdge(
                        source_id=source_entity.id,
                        dest_id=dest_entity.id,
                        tx_hash=event.tx_hash,
                        chain_id=event.chain_id,
                        amount_usd=float(event.amount_usd),
                        timestamp=event.block_timestamp,
                        event_type=event.event_type.value
                    )
                    attack_graph.edges.append(edge)
        
        # Classify roles based on fund flow
        self._classify_attack_roles(attack_graph)
        
        return attack_graph
    
    def _classify_attack_roles(self, attack_graph: AttackGraph):
        """
        Classify node roles in attack graph.
        
        Attacker: Net receiver of funds with no legitimate source
        Victim: Net sender (usually bridge/protocol)
        Intermediary: Pass-through
        """
        # Calculate net flow for each node
        net_flow: Dict[str, float] = {}
        
        for node in attack_graph.nodes:
            net_flow[node.entity_id] = 0
        
        for edge in attack_graph.edges:
            if edge.source_id in net_flow:
                net_flow[edge.source_id] -= edge.amount_usd
            if edge.dest_id in net_flow:
                net_flow[edge.dest_id] += edge.amount_usd
        
        # Assign roles
        for node in attack_graph.nodes:
            entity = self.entities.get(node.entity_id)
            flow = net_flow.get(node.entity_id, 0)
            
            # Bridge/protocol = victim
            if entity and entity.entity_type in (EntityType.BRIDGE, EntityType.PROTOCOL):
                node.role = "victim"
                node.funds_sent_usd = abs(min(0, flow))
            
            # Net receiver with significant amount = potential attacker
            elif flow > 10000:  # > $10k received
                node.role = "attacker"
                node.funds_received_usd = flow
            
            # Net sender = either victim or intermediary
            elif flow < -10000:
                node.role = "victim"
                node.funds_sent_usd = abs(flow)
            
            else:
                node.role = "intermediary"


class EntityGraphBuilder:
    """
    Builds and maintains the entity graph from event stream.
    """
    
    def __init__(self):
        self.graph = EntityGraph()
        self._event_count = 0
    
    async def process_event(self, event: SecurityEvent):
        """Process an event and update the graph."""
        self.graph.add_event(event)
        self._event_count += 1
    
    def get_graph(self) -> EntityGraph:
        """Get the current graph."""
        return self.graph
    
    def get_stats(self) -> dict:
        """Get graph statistics."""
        return {
            "entity_count": len(self.graph.entities),
            "edge_count": sum(
                len(edges) for edges in self.graph.outgoing_edges.values()
            ),
            "events_processed": self._event_count,
        }

