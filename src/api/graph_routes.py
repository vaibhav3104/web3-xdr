"""
Security Graph API Routes
=========================

REST API endpoints for the Security Graph, Attack Path Analysis,
and Risk Scoring - the core of Wiz-for-Web3.
"""

import asyncio

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import structlog

# Import graph components
from src.graph.connection import get_neo4j_connection, Neo4jConnection
from src.graph.builder import GraphBuilder
from src.graph.analyzer import AttackPathAnalyzer
from src.graph.risk import GraphRiskScorer

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/graph", tags=["Security Graph"])

# Global instances (initialized on startup)
_neo4j_conn: Optional[Neo4jConnection] = None
_graph_builder: Optional[GraphBuilder] = None
_attack_analyzer: Optional[AttackPathAnalyzer] = None
_risk_scorer: Optional[GraphRiskScorer] = None


# ============================================================================
# Request/Response Models
# ============================================================================

class EntityRiskRequest(BaseModel):
    """Request for entity risk assessment."""
    address: str = Field(..., description="Entity address")
    chain_id: str = Field(default="ethereum", description="Chain ID")


class AttackPathRequest(BaseModel):
    """Request for attack path analysis."""
    target_address: Optional[str] = Field(None, description="Target to analyze")
    chain_id: str = Field(default="ethereum", description="Chain ID")
    max_depth: int = Field(default=5, ge=1, le=10, description="Max path depth")
    min_tvl_usd: float = Field(default=100000, description="Min TVL filter")


class GraphStatsResponse(BaseModel):
    """Graph statistics response."""
    status: str
    node_counts: Dict[str, int]
    relationship_counts: Dict[str, int]
    database: Optional[Dict[str, Any]] = None


class RiskScoreResponse(BaseModel):
    """Risk score response."""
    address: str
    chain_id: str
    total_score: float
    risk_level: str
    intrinsic_risk: float
    behavioral_risk: float
    association_risk: float
    temporal_risk: float
    factors: List[Dict[str, Any]]
    confidence: float


class AttackPathResponse(BaseModel):
    """Attack path response."""
    id: str
    attack_vector: str
    entry_point: str
    target: str
    severity: str
    total_risk_score: float
    capital_required_usd: float
    potential_loss_usd: float
    likelihood: float
    steps: List[Dict[str, Any]]
    mitigations: List[str]
    blast_radius: Dict[str, Any]


class HighRiskEntityResponse(BaseModel):
    """High risk entity response."""
    address: str
    labels: List[str]
    risk_score: float
    risk_level: str
    name: Optional[str]


# ============================================================================
# Initialization
# ============================================================================

async def initialize_graph():
    """Initialize graph components."""
    global _neo4j_conn, _graph_builder, _attack_analyzer, _risk_scorer
    
    import os
    
    try:
        # Use real Neo4j if URI is configured, otherwise mock
        neo4j_uri = os.getenv("NEO4J_URI")
        use_mock = not neo4j_uri
        
        logger.info("graph_init_starting", use_mock=use_mock, has_uri=bool(neo4j_uri))
        
        _neo4j_conn = get_neo4j_connection(use_mock=use_mock)
        await _neo4j_conn.connect()
        
        _graph_builder = GraphBuilder(_neo4j_conn)
        await _graph_builder.initialize()
        
        _attack_analyzer = AttackPathAnalyzer(_neo4j_conn)
        _risk_scorer = GraphRiskScorer(_neo4j_conn)
        
        logger.info("graph_components_initialized")
        
    except Exception as e:
        logger.error("graph_initialization_failed", error=str(e))
        # Continue with mock/fallback


# ============================================================================
# Graph Health & Stats
# ============================================================================

@router.get("/health", response_model=GraphStatsResponse)
async def get_graph_health():
    """
    Get graph database health and statistics.
    
    Returns node counts, relationship counts, and database info.
    """
    if not _neo4j_conn:
        await initialize_graph()
    
    try:
        health = await _neo4j_conn.health_check()
        return GraphStatsResponse(
            status=health.get("status", "unknown"),
            node_counts=health.get("node_counts", {}),
            relationship_counts=health.get("relationship_counts", {}),
            database=health.get("database")
        )
    except Exception as e:
        logger.error("graph_health_check_failed", error=str(e))
        return GraphStatsResponse(
            status="error",
            node_counts={},
            relationship_counts={},
            database={"error": str(e)}
        )


@router.get("/stats")
async def get_graph_stats():
    """
    Get detailed graph statistics.
    """
    if not _graph_builder:
        await initialize_graph()
    
    try:
        stats = await _graph_builder.get_graph_stats()
        return {
            "success": True,
            "stats": stats,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


# ============================================================================
# Risk Scoring
# ============================================================================

@router.post("/risk/score", response_model=RiskScoreResponse)
async def calculate_entity_risk(request: EntityRiskRequest):
    """
    Calculate comprehensive risk score for an entity.
    
    Risk is calculated from:
    - Intrinsic properties (bytecode, audit status)
    - Behavioral patterns (transaction history)
    - Graph associations (connections to hackers, mixers)
    - Temporal factors (entity age, activity patterns)
    """
    if not _risk_scorer:
        await initialize_graph()
    
    try:
        risk_score = await _risk_scorer.calculate_risk_score(
            address=request.address.lower(),
            chain_id=request.chain_id,
            include_details=True
        )

        # Propagate risk through graph after each calculation so connected
        # entities inherit risk from newly scored high-risk nodes.
        if risk_score.total_score >= 80:
            asyncio.ensure_future(
                _risk_scorer.propagate_risk(chain_id=request.chain_id, max_hops=3)
            )

        return RiskScoreResponse(
            address=risk_score.address,
            chain_id=risk_score.chain_id,
            total_score=risk_score.total_score,
            risk_level=risk_score.risk_level,
            intrinsic_risk=risk_score.intrinsic_risk,
            behavioral_risk=risk_score.behavioral_risk,
            association_risk=risk_score.association_risk,
            temporal_risk=risk_score.temporal_risk,
            factors=risk_score.factors,
            confidence=risk_score.confidence
        )
        
    except Exception as e:
        logger.error("risk_calculation_failed", address=request.address[:10], error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/risk/high-risk-entities")
async def get_high_risk_entities(
    chain_id: str = Query(default="ethereum"),
    limit: int = Query(default=20, ge=1, le=100),
    entity_type: Optional[str] = Query(default=None, description="Filter by type: Wallet, Contract")
):
    """
    Get entities with highest risk scores.
    """
    if not _risk_scorer:
        await initialize_graph()
    
    try:
        entities = await _risk_scorer.get_highest_risk_entities(
            chain_id=chain_id,
            limit=limit,
            entity_type=entity_type
        )
        
        return {
            "success": True,
            "chain_id": chain_id,
            "count": len(entities),
            "entities": entities
        }
        
    except Exception as e:
        logger.error("high_risk_entities_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/risk/batch")
async def batch_calculate_risk(addresses: List[EntityRiskRequest]):
    """
    Calculate risk scores for multiple entities.
    """
    if not _risk_scorer:
        await initialize_graph()
    
    try:
        address_tuples = [(req.address.lower(), req.chain_id) for req in addresses]
        scores = await _risk_scorer.batch_calculate_risk(address_tuples)
        
        return {
            "success": True,
            "count": len(scores),
            "scores": [
                {
                    "address": s.address,
                    "chain_id": s.chain_id,
                    "total_score": s.total_score,
                    "risk_level": s.risk_level
                }
                for s in scores
            ]
        }
        
    except Exception as e:
        logger.error("batch_risk_calculation_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/entities")
async def get_entities_by_label(
    label: str = Query(..., description="Entity label: Hacker, Mixer, Exchange, Protocol, Bridge, Oracle, FlashLoanProvider, Sanctioned"),
    chain_id: str = Query(default="ethereum"),
    limit: int = Query(default=30, ge=1, le=100)
):
    """
    Get entities by label type.
    
    Labels:
    - Hacker: Known exploit addresses
    - Mixer: Tornado Cash, etc.
    - Exchange: CEX hot wallets (Binance, Coinbase, etc.)
    - Protocol: DeFi protocols (Aave, Uniswap, etc.)
    - Bridge: Cross-chain bridges
    - Oracle: Price oracles (Chainlink, etc.)
    - FlashLoanProvider: Flash loan sources
    - Sanctioned: OFAC sanctioned addresses
    """
    if not _neo4j_conn:
        await initialize_graph()
    
    try:
        # Query Neo4j for entities with the specified label
        # Don't filter by chain_id since many entities have 'ethereum' or NULL
        cypher = f"""
        MATCH (n:{label})
        RETURN n.address as address, 
               labels(n) as labels,
               n.entity_name as entity_name,
               n.name as name,
               n.risk_score as risk_score,
               n.exploit as exploit,
               n.exchange as exchange,
               n.category as category
        ORDER BY n.risk_score DESC
        LIMIT $limit
        """
        
        # Use query() which returns a list of dicts
        records = await _neo4j_conn.query(cypher, {
            "limit": limit
        })
        
        entities = []
        for record in records:
            entity = {
                "address": record.get("address"),
                "labels": record.get("labels", [label]),
                "entity_name": record.get("entity_name") or record.get("name"),
                "name": record.get("name") or record.get("entity_name"),
                "risk_score": record.get("risk_score") or 50,
            }
            
            # Add extra fields based on type
            if record.get("exploit"):
                entity["exploit"] = record["exploit"]
            if record.get("exchange"):
                entity["exchange"] = record["exchange"]
            if record.get("category"):
                entity["category"] = record["category"]
                
            entities.append(entity)
        
        return {
            "success": True,
            "label": label,
            "chain_id": chain_id,
            "count": len(entities),
            "entities": entities
        }
        
    except Exception as e:
        logger.error("get_entities_failed", label=label, error=str(e))
        # Return empty list on error (mock fallback)
        return {
            "success": False,
            "label": label,
            "chain_id": chain_id,
            "count": 0,
            "entities": [],
            "error": str(e)
        }


# ============================================================================
# Attack Path Analysis
# ============================================================================

@router.post("/attack-paths", response_model=List[AttackPathResponse])
async def find_attack_paths(request: AttackPathRequest):
    """
    Find potential attack paths to a target.
    
    Analyzes the security graph to identify:
    - Admin key compromise paths
    - Oracle manipulation paths
    - Flash loan attack paths
    - Bridge exploit paths
    - Governance attack paths
    
    Returns paths sorted by risk score.
    """
    if not _attack_analyzer:
        await initialize_graph()
    
    try:
        paths = await _attack_analyzer.find_attack_paths(
            target_address=request.target_address.lower() if request.target_address else None,
            chain_id=request.chain_id,
            max_depth=request.max_depth,
            min_tvl_usd=request.min_tvl_usd
        )
        
        return [
            AttackPathResponse(
                id=p.id,
                attack_vector=p.attack_vector.value,
                entry_point=p.entry_point,
                target=p.target,
                severity=p.severity,
                total_risk_score=p.total_risk_score,
                capital_required_usd=p.capital_required_usd,
                potential_loss_usd=p.potential_loss_usd,
                likelihood=p.likelihood,
                steps=[
                    {
                        "step": s.step_number,
                        "action": s.action,
                        "from": s.from_entity,
                        "to": s.to_entity,
                        "relationship": s.relationship,
                        "risk_contribution": s.risk_contribution,
                        "description": s.description
                    }
                    for s in p.steps
                ],
                mitigations=p.mitigations,
                blast_radius=p.blast_radius
            )
            for p in paths
        ]
        
    except Exception as e:
        logger.error("attack_path_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-paths/summary")
async def get_attack_path_summary(chain_id: str = Query(default="ethereum")):
    """
    Get summary of attack paths by type.
    """
    if not _attack_analyzer:
        await initialize_graph()
    
    try:
        paths = await _attack_analyzer.find_attack_paths(
            chain_id=chain_id,
            max_depth=3
        )
        
        # Summarize by attack vector
        summary = {}
        for path in paths:
            vector = path.attack_vector.value
            if vector not in summary:
                summary[vector] = {
                    "count": 0,
                    "critical": 0,
                    "high": 0,
                    "total_potential_loss": 0
                }
            
            summary[vector]["count"] += 1
            if path.severity == "CRITICAL":
                summary[vector]["critical"] += 1
            elif path.severity == "HIGH":
                summary[vector]["high"] += 1
            summary[vector]["total_potential_loss"] += path.potential_loss_usd
        
        return {
            "success": True,
            "chain_id": chain_id,
            "total_paths": len(paths),
            "by_attack_vector": summary
        }
        
    except Exception as e:
        logger.error("attack_path_summary_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/entity/{address}/risk-profile")
async def get_entity_risk_profile(
    address: str,
    chain_id: str = Query(default="ethereum")
):
    """
    Get comprehensive risk profile for an entity.
    
    Includes:
    - Risk score breakdown
    - Risk factors
    - Recommendations
    - Connected entities
    """
    if not _attack_analyzer:
        await initialize_graph()
    
    try:
        profile = await _attack_analyzer.get_entity_risk_profile(
            address=address.lower(),
            chain_id=chain_id
        )
        
        return {
            "success": True,
            "profile": profile
        }
        
    except Exception as e:
        logger.error("entity_profile_failed", address=address[:10], error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Graph Building
# ============================================================================

@router.post("/ingest")
async def ingest_event(event: Dict[str, Any], background_tasks: BackgroundTasks):
    """
    Ingest an event into the security graph.
    
    This endpoint processes security events and updates the graph
    with new nodes and relationships.
    """
    if not _graph_builder:
        await initialize_graph()
    
    # Process in background to not block response
    background_tasks.add_task(_graph_builder.process_event, event)
    
    return {
        "success": True,
        "message": "Event queued for processing",
        "event_type": event.get("event_type"),
        "tx_hash": event.get("tx_hash", "")[:10]
    }


@router.post("/ingest/batch")
async def ingest_events_batch(
    events: List[Dict[str, Any]],
    background_tasks: BackgroundTasks
):
    """
    Ingest multiple events into the security graph.
    """
    if not _graph_builder:
        await initialize_graph()
    
    # Process each event in background
    for event in events:
        background_tasks.add_task(_graph_builder.process_event, event)
    
    return {
        "success": True,
        "message": f"Queued {len(events)} events for processing"
    }


# ============================================================================
# Graph Visualization Data
# ============================================================================

@router.get("/visualization/{address}")
async def get_visualization_data(
    address: str,
    chain_id: str = Query(default="ethereum"),
    depth: int = Query(default=2, ge=1, le=4)
):
    """
    Get graph data for visualization.
    
    Returns nodes and edges centered on the given address,
    formatted for graph visualization libraries (D3, vis.js, etc.)
    """
    if not _neo4j_conn:
        await initialize_graph()
    
    try:
        # Query for connected nodes
        query = f"""
        MATCH path = (center {{address: $address, chain_id: $chain_id}})-[*1..{depth}]-(connected)
        WITH nodes(path) AS nodes, relationships(path) AS rels
        UNWIND nodes AS n
        WITH DISTINCT n, rels
        RETURN 
            collect(DISTINCT {{
                id: n.address,
                label: labels(n)[0],
                risk_score: n.risk_score,
                name: n.entity_name
            }}) AS nodes,
            [r IN rels | {{
                source: startNode(r).address,
                target: endNode(r).address,
                type: type(r),
                value: r.total_value_usd
            }}] AS edges
        """
        
        results = await _neo4j_conn.query(query, {
            "address": address.lower(),
            "chain_id": chain_id
        })
        
        if not results:
            return {
                "nodes": [{"id": address, "label": "Unknown", "risk_score": 0}],
                "edges": []
            }
        
        return {
            "nodes": results[0].get("nodes", []),
            "edges": results[0].get("edges", [])
        }
        
    except Exception as e:
        logger.error("visualization_data_failed", error=str(e))
        return {
            "nodes": [{"id": address, "label": "Unknown", "risk_score": 0}],
            "edges": []
        }
