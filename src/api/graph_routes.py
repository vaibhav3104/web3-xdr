"""
Security Graph API Routes
=========================

REST API endpoints for the Security Graph, Attack Path Analysis,
and Risk Scoring - the core of Wiz-for-Web3.

Built on PostgreSQL (events + incidents tables) instead of Neo4j.
Graph nodes/edges are derived from event addresses and incident
associations, cached in-memory and rebuilt periodically.
"""

import hashlib
import time as _time

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import structlog
from sqlalchemy import text

from src.database.connection import DatabaseManager

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/graph", tags=["Security Graph"])


# ============================================================================
# Helpers
# ============================================================================

def _utcnow_naive() -> datetime:
    """Return current UTC time as a naive datetime (asyncpg tz-naive compat)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============================================================================
# Request/Response Models  (kept identical for frontend compatibility)
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
# In-memory graph cache
# ============================================================================

# Known high-volume / labelled address patterns
_KNOWN_LABELS: Dict[str, List[str]] = {
    "0x0000000000000000000000000000000000000000": ["NullAddress"],
}

# Exchange hot-wallet prefixes or addresses (simplified heuristic)
_EXCHANGE_KEYWORDS = {"binance", "coinbase", "kraken", "ftx", "okx", "huobi"}
_BRIDGE_KEYWORDS = {"bridge", "wormhole", "multichain", "stargate", "layerzero"}


class _GraphCache:
    """In-memory graph built from PostgreSQL data.

    Attributes:
        nodes: dict[address] -> node dict
        edges: list of edge dicts
        built_at: epoch seconds of last rebuild
        ttl: seconds before the cache is considered stale
    """

    def __init__(self, ttl: int = 120):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self.built_at: float = 0.0
        self.ttl = ttl

    @property
    def is_stale(self) -> bool:
        return (_time.time() - self.built_at) > self.ttl

    # ------------------------------------------------------------------
    # Build from PostgreSQL
    # ------------------------------------------------------------------

    async def rebuild(self) -> None:
        """Rebuild the full graph from events + incidents tables."""
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []
        edge_dedup: set = set()

        try:
            async with DatabaseManager.get_session() as session:
                # ---- events ----
                rows = await session.execute(text("""
                    SELECT from_address, to_address, contract_address,
                           chain_id, event_type, severity,
                           COALESCE(amount_usd, 0) AS amount_usd,
                           tx_hash
                    FROM events
                    ORDER BY block_timestamp DESC
                    LIMIT 10000
                """))
                events = rows.mappings().all()

                for ev in events:
                    from_addr = (ev["from_address"] or "").lower()
                    to_addr = (ev["to_address"] or "").lower()
                    contract = (ev["contract_address"] or "").lower()
                    chain = ev["chain_id"] or "ethereum"
                    sev = ev["severity"] or "LOW"
                    amount = float(ev["amount_usd"] or 0)
                    # ---- nodes ----
                    for addr, etype_label in [
                        (from_addr, "Wallet"),
                        (to_addr, "Wallet"),
                        (contract, "Contract"),
                    ]:
                        if not addr:
                            continue
                        if addr not in nodes:
                            labels = _classify_address(addr, etype_label)
                            nodes[addr] = {
                                "id": addr,
                                "labels": labels,
                                "name": _address_name(addr),
                                "risk_score": 0.0,
                                "chain_id": chain,
                                "volume": 0.0,
                                "tx_count": 0,
                                "entity_type": labels[0] if labels else "Wallet",
                                "_severities": [],
                                "_incident_count": 0,
                            }
                        node = nodes[addr]
                        node["volume"] += amount
                        node["tx_count"] += 1
                        node["_severities"].append(sev)

                    # ---- edges ----
                    if from_addr and to_addr:
                        ekey = (from_addr, to_addr, "TRANSFER")
                        if ekey not in edge_dedup:
                            edge_dedup.add(ekey)
                            edges.append({
                                "source": from_addr,
                                "target": to_addr,
                                "type": "TRANSFER",
                                "value": amount,
                            })
                        else:
                            # accumulate value on existing edge
                            for edge in edges:
                                if (
                                    edge["source"] == from_addr
                                    and edge["target"] == to_addr
                                    and edge["type"] == "TRANSFER"
                                ):
                                    edge["value"] += amount
                                    break

                    if from_addr and contract:
                        ekey2 = (from_addr, contract, "INTERACTS_WITH")
                        if ekey2 not in edge_dedup:
                            edge_dedup.add(ekey2)
                            edges.append({
                                "source": from_addr,
                                "target": contract,
                                "type": "INTERACTS_WITH",
                                "value": amount,
                            })

                # ---- incidents ----
                inc_rows = await session.execute(text("""
                    SELECT incident_id, attack_type, severity, confidence,
                           COALESCE(total_loss_usd, 0) AS total_loss_usd,
                           affected_chains, affected_contracts, affected_addresses,
                           created_at
                    FROM incidents
                    ORDER BY created_at DESC
                    LIMIT 5000
                """))
                incidents = inc_rows.mappings().all()

                for inc in incidents:
                    sev = inc["severity"] or "MEDIUM"
                    contracts = inc["affected_contracts"] or []
                    addresses = inc["affected_addresses"] or []
                    all_addrs = [a.lower() for a in contracts + addresses if a]

                    for addr in all_addrs:
                        if addr in nodes:
                            nodes[addr]["_incident_count"] += 1
                            nodes[addr]["_severities"].append(sev)
                        else:
                            labels = _classify_address(addr, "Wallet")
                            nodes[addr] = {
                                "id": addr,
                                "labels": labels,
                                "name": _address_name(addr),
                                "risk_score": 0.0,
                                "chain_id": "ethereum",
                                "volume": 0.0,
                                "tx_count": 0,
                                "entity_type": labels[0] if labels else "Wallet",
                                "_severities": [sev],
                                "_incident_count": 1,
                            }

                    # Edges between all incident-related addresses (INVOLVED_IN)
                    for i, a in enumerate(all_addrs):
                        for b in all_addrs[i + 1:]:
                            ekey3 = (a, b, "INVOLVED_IN_INCIDENT")
                            if ekey3 not in edge_dedup:
                                edge_dedup.add(ekey3)
                                edges.append({
                                    "source": a,
                                    "target": b,
                                    "type": "INVOLVED_IN_INCIDENT",
                                    "value": float(inc["total_loss_usd"] or 0),
                                })

        except Exception as e:
            logger.error("graph_cache_rebuild_failed", error=str(e))
            # Keep whatever we have — may be empty on first run
            self.nodes = nodes
            self.edges = edges
            self.built_at = _time.time()
            return

        # ---- compute risk scores ----
        for node in nodes.values():
            node["risk_score"] = _compute_risk_score(node)
            # Clean up internal fields
            del node["_severities"]
            del node["_incident_count"]

        self.nodes = nodes
        self.edges = edges
        self.built_at = _time.time()
        logger.info(
            "graph_cache_rebuilt",
            node_count=len(nodes),
            edge_count=len(edges),
        )

    async def ensure_fresh(self) -> None:
        """Rebuild if the cache is stale."""
        if self.is_stale:
            await self.rebuild()


_graph = _GraphCache(ttl=120)


# ============================================================================
# Classification / scoring helpers
# ============================================================================

def _classify_address(addr: str, default: str = "Wallet") -> List[str]:
    """Return label list for an address based on heuristics."""
    if addr in _KNOWN_LABELS:
        return list(_KNOWN_LABELS[addr])

    labels: List[str] = []

    # Very simple heuristic: if address was passed as a contract, keep that
    if default == "Contract":
        labels.append("Contract")
    else:
        labels.append("Wallet")

    # Check known keyword patterns in the address name mapping (future: could
    # use an external label DB)
    name = _address_name(addr)
    if name:
        nl = name.lower()
        if any(k in nl for k in _EXCHANGE_KEYWORDS):
            labels.insert(0, "Exchange")
        elif any(k in nl for k in _BRIDGE_KEYWORDS):
            labels.insert(0, "Bridge")
        elif "protocol" in nl or "aave" in nl or "uniswap" in nl or "compound" in nl:
            labels.insert(0, "Protocol")
        elif "mixer" in nl or "tornado" in nl:
            labels.insert(0, "Mixer")
        elif "oracle" in nl or "chainlink" in nl:
            labels.insert(0, "Oracle")

    return labels


def _address_name(addr: str) -> Optional[str]:
    """Return a human-friendly name if known, else None."""
    return _KNOWN_LABELS.get(addr, [None])[0] if addr in _KNOWN_LABELS else None


def _risk_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _compute_risk_score(node: Dict[str, Any]) -> float:
    """Compute a 0-100 risk score from internal node metadata."""
    score = 0.0
    sevs = node.get("_severities", [])
    inc_count = node.get("_incident_count", 0)
    volume = node.get("volume", 0)
    tx_count = node.get("tx_count", 0)

    # Severity-based component (max 40 pts)
    sev_weights = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}
    sev_score = sum(sev_weights.get(s.upper(), 1) for s in sevs)
    score += min(sev_score, 40)

    # Incident involvement (max 30 pts)
    score += min(inc_count * 10, 30)

    # Volume heuristic (max 15 pts)
    if volume > 1_000_000:
        score += 15
    elif volume > 100_000:
        score += 10
    elif volume > 10_000:
        score += 5

    # Transaction count (max 15 pts)
    if tx_count > 100:
        score += 15
    elif tx_count > 20:
        score += 10
    elif tx_count > 5:
        score += 5

    return min(round(score, 1), 100.0)


def _compute_detailed_risk(
    address: str,
    chain_id: str,
    node: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return a full RiskScoreResponse-compatible dict for an address."""
    if node is None:
        return {
            "address": address,
            "chain_id": chain_id,
            "total_score": 0.0,
            "risk_level": "LOW",
            "intrinsic_risk": 0.0,
            "behavioral_risk": 0.0,
            "association_risk": 0.0,
            "temporal_risk": 0.0,
            "factors": [],
            "confidence": 0.1,
        }

    risk_score = node.get("risk_score", 0.0)
    volume = node.get("volume", 0)
    tx_count = node.get("tx_count", 0)

    # Decompose into sub-scores (approximate)
    intrinsic = min(risk_score * 0.25, 25)
    behavioral = min(risk_score * 0.35, 35)
    association = min(risk_score * 0.25, 25)
    temporal = min(risk_score * 0.15, 15)

    factors: List[Dict[str, Any]] = []
    if volume > 100_000:
        factors.append({
            "factor": "high_volume",
            "description": f"Total volume ${volume:,.0f}",
            "contribution": min(volume / 100_000, 10),
        })
    if tx_count > 20:
        factors.append({
            "factor": "high_tx_count",
            "description": f"{tx_count} transactions observed",
            "contribution": min(tx_count / 10, 10),
        })
    if "Contract" in node.get("labels", []):
        factors.append({
            "factor": "contract_interaction",
            "description": "Address is a smart contract",
            "contribution": 5.0,
        })
    if risk_score >= 60:
        factors.append({
            "factor": "incident_involvement",
            "description": "Involved in security incidents",
            "contribution": 15.0,
        })

    confidence = 0.3
    if tx_count > 10:
        confidence = 0.6
    if tx_count > 50:
        confidence = 0.8

    return {
        "address": address,
        "chain_id": chain_id,
        "total_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "intrinsic_risk": round(intrinsic, 2),
        "behavioral_risk": round(behavioral, 2),
        "association_risk": round(association, 2),
        "temporal_risk": round(temporal, 2),
        "factors": factors,
        "confidence": confidence,
    }


# ============================================================================
# Graph Health & Stats
# ============================================================================

@router.get("/health", response_model=GraphStatsResponse)
async def get_graph_health():
    """Get graph database health and statistics."""
    await _graph.ensure_fresh()

    node_counts: Dict[str, int] = {}
    for n in _graph.nodes.values():
        for lbl in n.get("labels", []):
            node_counts[lbl] = node_counts.get(lbl, 0) + 1

    rel_counts: Dict[str, int] = {}
    for e in _graph.edges:
        rtype = e.get("type", "TRANSFER")
        rel_counts[rtype] = rel_counts.get(rtype, 0) + 1

    db_healthy = await DatabaseManager.health_check()

    return GraphStatsResponse(
        status="healthy" if db_healthy else "degraded",
        node_counts=node_counts,
        relationship_counts=rel_counts,
        database={
            "type": "postgresql",
            "healthy": db_healthy,
            "pool": DatabaseManager.get_pool_stats(),
        },
    )


@router.get("/stats")
async def get_graph_stats():
    """Get detailed graph statistics."""
    await _graph.ensure_fresh()

    node_counts: Dict[str, int] = {}
    for n in _graph.nodes.values():
        for lbl in n.get("labels", []):
            node_counts[lbl] = node_counts.get(lbl, 0) + 1

    rel_counts: Dict[str, int] = {}
    for e in _graph.edges:
        rtype = e.get("type", "TRANSFER")
        rel_counts[rtype] = rel_counts.get(rtype, 0) + 1

    total_volume = sum(n.get("volume", 0) for n in _graph.nodes.values())

    return {
        "success": True,
        "stats": {
            "total_nodes": len(_graph.nodes),
            "total_edges": len(_graph.edges),
            "node_counts": node_counts,
            "relationship_counts": rel_counts,
            "total_volume_usd": total_volume,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# Risk Scoring
# ============================================================================

@router.post("/risk/score", response_model=RiskScoreResponse)
async def calculate_entity_risk(request: EntityRiskRequest):
    """Calculate comprehensive risk score for an entity."""
    await _graph.ensure_fresh()

    addr = request.address.lower()
    node = _graph.nodes.get(addr)

    # If the address is not in cache, do a direct DB lookup
    if node is None:
        node = await _lookup_address(addr, request.chain_id)

    result = _compute_detailed_risk(addr, request.chain_id, node)
    return RiskScoreResponse(**result)


@router.get("/risk/high-risk-entities")
async def get_high_risk_entities(
    chain_id: str = Query(default="ethereum"),
    limit: int = Query(default=20, ge=1, le=100),
    entity_type: Optional[str] = Query(
        default=None, description="Filter by type: Wallet, Contract"
    ),
):
    """Get entities with highest risk scores."""
    await _graph.ensure_fresh()

    candidates = list(_graph.nodes.values())

    # Filter by chain
    if chain_id:
        candidates = [
            n for n in candidates
            if n.get("chain_id", "ethereum") == chain_id
        ]

    # Filter by entity type
    if entity_type:
        candidates = [
            n for n in candidates
            if entity_type in n.get("labels", [])
        ]

    # Sort descending by risk
    candidates.sort(key=lambda n: n.get("risk_score", 0), reverse=True)
    candidates = candidates[:limit]

    entities = [
        {
            "address": n["id"],
            "labels": n.get("labels", []),
            "risk_score": n.get("risk_score", 0),
            "risk_level": _risk_level(n.get("risk_score", 0)),
            "name": n.get("name"),
        }
        for n in candidates
    ]

    return {
        "success": True,
        "chain_id": chain_id,
        "count": len(entities),
        "entities": entities,
    }


@router.post("/risk/batch")
async def batch_calculate_risk(addresses: List[EntityRiskRequest]):
    """Calculate risk scores for multiple entities."""
    await _graph.ensure_fresh()

    scores = []
    for req in addresses:
        addr = req.address.lower()
        node = _graph.nodes.get(addr)
        result = _compute_detailed_risk(addr, req.chain_id, node)
        scores.append({
            "address": result["address"],
            "chain_id": result["chain_id"],
            "total_score": result["total_score"],
            "risk_level": result["risk_level"],
        })

    return {
        "success": True,
        "count": len(scores),
        "scores": scores,
    }


@router.get("/entities")
async def get_entities_by_label(
    label: str = Query(
        ...,
        description="Entity label: Hacker, Mixer, Exchange, Protocol, "
        "Bridge, Oracle, FlashLoanProvider, Sanctioned",
    ),
    chain_id: str = Query(default="ethereum"),
    limit: int = Query(default=30, ge=1, le=100),
):
    """Get entities by label type."""
    await _graph.ensure_fresh()

    candidates = [
        n for n in _graph.nodes.values()
        if label in n.get("labels", [])
    ]

    # Sort by risk_score descending
    candidates.sort(key=lambda n: n.get("risk_score", 0), reverse=True)
    candidates = candidates[:limit]

    entities = []
    for n in candidates:
        entity: Dict[str, Any] = {
            "address": n["id"],
            "labels": n.get("labels", []),
            "entity_name": n.get("name"),
            "name": n.get("name"),
            "risk_score": n.get("risk_score", 50),
        }
        entities.append(entity)

    return {
        "success": True,
        "label": label,
        "chain_id": chain_id,
        "count": len(entities),
        "entities": entities,
    }


# ============================================================================
# Attack Path Analysis
# ============================================================================

@router.post("/attack-paths", response_model=List[AttackPathResponse])
async def find_attack_paths(request: AttackPathRequest):
    """Find potential attack paths to a target.

    Derives simplified attack paths from incident data rather than
    a full graph traversal (Neo4j replacement).
    """
    await _graph.ensure_fresh()

    paths: List[AttackPathResponse] = []

    try:
        async with DatabaseManager.get_session() as session:
            q = text("""
                SELECT incident_id, attack_type, severity, confidence,
                       COALESCE(total_loss_usd, 0) AS total_loss_usd,
                       affected_contracts, affected_addresses
                FROM incidents
                WHERE :chain = ANY(affected_chains)
                ORDER BY total_loss_usd DESC NULLS LAST
                LIMIT 20
            """)
            rows = await session.execute(q, {"chain": request.chain_id})
            incidents = rows.mappings().all()

        for inc in incidents:
            contracts = inc["affected_contracts"] or []
            addresses = inc["affected_addresses"] or []
            all_addrs = contracts + addresses
            if not all_addrs:
                continue

            entry = all_addrs[0] if all_addrs else "unknown"
            target_addr = (
                request.target_address.lower()
                if request.target_address
                else (all_addrs[-1] if len(all_addrs) > 1 else entry)
            )

            # If caller specified a target, only include relevant incidents
            if request.target_address:
                lower_addrs = [a.lower() for a in all_addrs]
                if request.target_address.lower() not in lower_addrs:
                    continue

            loss = float(inc["total_loss_usd"] or 0)
            sev = inc["severity"] or "MEDIUM"
            conf = float(inc["confidence"] or 0.5)

            steps = []
            for idx, addr in enumerate(all_addrs[:request.max_depth]):
                steps.append({
                    "step": idx + 1,
                    "action": inc["attack_type"] or "unknown",
                    "from": all_addrs[max(0, idx - 1)],
                    "to": addr,
                    "relationship": "EXPLOITS" if idx == 0 else "PROPAGATES",
                    "risk_contribution": round(conf * 20, 1),
                    "description": f"Step {idx + 1} of {inc['attack_type']} attack",
                })

            path_id = hashlib.md5(
                (inc["incident_id"] + target_addr).encode()
            ).hexdigest()[:16]

            paths.append(AttackPathResponse(
                id=path_id,
                attack_vector=inc["attack_type"] or "unknown",
                entry_point=entry,
                target=target_addr,
                severity=sev,
                total_risk_score=round(conf * 100, 1),
                capital_required_usd=loss * 0.1,
                potential_loss_usd=loss,
                likelihood=conf,
                steps=steps,
                mitigations=_generate_mitigations(inc["attack_type"]),
                blast_radius={
                    "affected_contracts": len(contracts),
                    "affected_addresses": len(addresses),
                    "total_loss_usd": loss,
                },
            ))

    except Exception as e:
        logger.error("attack_path_analysis_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

    return paths


@router.get("/attack-paths/summary")
async def get_attack_path_summary(
    chain_id: str = Query(default="ethereum"),
):
    """Get summary of attack paths by type."""
    try:
        async with DatabaseManager.get_session() as session:
            q = text("""
                SELECT attack_type, severity,
                       COUNT(*) AS cnt,
                       COALESCE(SUM(total_loss_usd), 0) AS total_loss
                FROM incidents
                WHERE :chain = ANY(affected_chains)
                GROUP BY attack_type, severity
            """)
            rows = await session.execute(q, {"chain": chain_id})
            agg = rows.mappings().all()

        summary: Dict[str, Dict[str, Any]] = {}
        total_paths = 0
        for r in agg:
            vector = r["attack_type"]
            if vector not in summary:
                summary[vector] = {
                    "count": 0,
                    "critical": 0,
                    "high": 0,
                    "total_potential_loss": 0,
                }
            cnt = int(r["cnt"])
            summary[vector]["count"] += cnt
            total_paths += cnt
            if r["severity"] == "CRITICAL":
                summary[vector]["critical"] += cnt
            elif r["severity"] == "HIGH":
                summary[vector]["high"] += cnt
            summary[vector]["total_potential_loss"] += float(r["total_loss"])

        return {
            "success": True,
            "chain_id": chain_id,
            "total_paths": total_paths,
            "by_attack_vector": summary,
        }

    except Exception as e:
        logger.error("attack_path_summary_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/entity/{address}/risk-profile")
async def get_entity_risk_profile(
    address: str,
    chain_id: str = Query(default="ethereum"),
):
    """Get comprehensive risk profile for an entity."""
    await _graph.ensure_fresh()

    addr = address.lower()
    node = _graph.nodes.get(addr)

    if node is None:
        node = await _lookup_address(addr, chain_id)

    risk = _compute_detailed_risk(addr, chain_id, node)

    # Find connected entities
    connected = []
    for e in _graph.edges:
        peer = None
        if e["source"] == addr:
            peer = e["target"]
        elif e["target"] == addr:
            peer = e["source"]
        if peer and peer in _graph.nodes:
            pn = _graph.nodes[peer]
            connected.append({
                "address": peer,
                "labels": pn.get("labels", []),
                "risk_score": pn.get("risk_score", 0),
                "relationship": e["type"],
            })

    # Recommendations
    recommendations = []
    if risk["total_score"] >= 80:
        recommendations.append("Immediately investigate this entity")
        recommendations.append("Consider blocking transactions from this address")
    elif risk["total_score"] >= 60:
        recommendations.append("Monitor this entity closely")
        recommendations.append("Review associated transactions")
    elif risk["total_score"] >= 30:
        recommendations.append("Standard monitoring recommended")
    else:
        recommendations.append("No immediate action required")

    return {
        "success": True,
        "profile": {
            "address": addr,
            "chain_id": chain_id,
            "labels": (node or {}).get("labels", ["Unknown"]),
            "risk_score": risk["total_score"],
            "risk_level": risk["risk_level"],
            "risk_breakdown": {
                "intrinsic_risk": risk["intrinsic_risk"],
                "behavioral_risk": risk["behavioral_risk"],
                "association_risk": risk["association_risk"],
                "temporal_risk": risk["temporal_risk"],
            },
            "factors": risk["factors"],
            "confidence": risk["confidence"],
            "connected_entities": connected[:20],
            "recommendations": recommendations,
            "volume_usd": (node or {}).get("volume", 0),
            "tx_count": (node or {}).get("tx_count", 0),
        },
    }


# ============================================================================
# Graph Building  (ingest endpoints — store to PG, invalidate cache)
# ============================================================================

@router.post("/ingest")
async def ingest_event(
    event: Dict[str, Any],
    background_tasks: BackgroundTasks,
):
    """Ingest an event into the security graph.

    Events are already persisted to PostgreSQL by the main pipeline;
    this endpoint simply invalidates the graph cache so the next read
    will pick up the new data.
    """
    # Mark cache stale so next read triggers a rebuild
    _graph.built_at = 0.0

    return {
        "success": True,
        "message": "Event queued for processing",
        "event_type": event.get("event_type"),
        "tx_hash": (event.get("tx_hash", "") or "")[:10],
    }


@router.post("/ingest/batch")
async def ingest_events_batch(
    events: List[Dict[str, Any]],
    background_tasks: BackgroundTasks,
):
    """Ingest multiple events into the security graph."""
    _graph.built_at = 0.0

    return {
        "success": True,
        "message": f"Queued {len(events)} events for processing",
    }


# ============================================================================
# Graph Visualization Data
# ============================================================================

@router.get("/visualization/full")
async def get_full_visualization(
    chain_id: Optional[str] = Query(
        default=None, description="Filter by chain"
    ),
    risk_level: Optional[str] = Query(
        default=None, description="Filter by risk: critical, high, medium, low"
    ),
    entity_type: Optional[str] = Query(
        default=None,
        description="Filter by type: Wallet, Contract, Bridge, Exchange, etc.",
    ),
    limit: int = Query(default=200, ge=1, le=500),
):
    """Get full graph data for the Security Graph visualization page.

    Returns all nodes and edges formatted for D3 force-directed layout.
    """
    await _graph.ensure_fresh()

    risk_thresholds = {
        "critical": (80, 100),
        "high": (60, 80),
        "medium": (30, 60),
        "low": (0, 30),
    }

    candidates = list(_graph.nodes.values())

    # ---- filters ----
    if chain_id:
        candidates = [
            n for n in candidates
            if n.get("chain_id") == chain_id
        ]

    if risk_level:
        lo, hi = risk_thresholds.get(risk_level.lower(), (0, 100))
        candidates = [
            n for n in candidates
            if lo <= n.get("risk_score", 0) <= hi
        ]

    if entity_type:
        candidates = [
            n for n in candidates
            if entity_type in n.get("labels", [])
        ]

    # Sort by risk_score desc, take top N
    candidates.sort(key=lambda n: n.get("risk_score", 0), reverse=True)
    candidates = candidates[:limit]

    addr_set = {n["id"] for n in candidates}

    nodes = [
        {
            "id": n["id"],
            "labels": n.get("labels", []),
            "name": n.get("name"),
            "risk_score": n.get("risk_score", 0),
            "chain_id": n.get("chain_id", "ethereum"),
            "volume": n.get("volume", 0),
            "tx_count": n.get("tx_count", 0),
            "entity_type": n.get("entity_type", "Wallet"),
        }
        for n in candidates
    ]

    edges = [
        e for e in _graph.edges
        if e["source"] in addr_set and e["target"] in addr_set
    ][:500]

    return {
        "success": True,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


@router.get("/visualization/{address}")
async def get_visualization_data(
    address: str,
    chain_id: str = Query(default="ethereum"),
    depth: int = Query(default=2, ge=1, le=4),
):
    """Get graph data for visualization centered on a given address."""
    await _graph.ensure_fresh()

    addr = address.lower()

    # BFS from the address up to `depth` hops
    visited: set = set()
    frontier: set = {addr}
    collected_nodes: Dict[str, Dict[str, Any]] = {}
    collected_edges: List[Dict[str, Any]] = []

    # Build adjacency index for fast lookup
    adj: Dict[str, List[Dict[str, Any]]] = {}
    for e in _graph.edges:
        adj.setdefault(e["source"], []).append(e)
        adj.setdefault(e["target"], []).append(e)

    for _d in range(depth):
        next_frontier: set = set()
        for node_id in frontier:
            if node_id in visited:
                continue
            visited.add(node_id)
            if node_id in _graph.nodes:
                collected_nodes[node_id] = _graph.nodes[node_id]
            for edge in adj.get(node_id, []):
                peer = (
                    edge["target"]
                    if edge["source"] == node_id
                    else edge["source"]
                )
                collected_edges.append(edge)
                if peer not in visited:
                    next_frontier.add(peer)
        frontier = next_frontier

    # Add remaining frontier nodes (leaf level)
    for node_id in frontier:
        if node_id in _graph.nodes:
            collected_nodes[node_id] = _graph.nodes[node_id]

    if not collected_nodes:
        # Address not in graph — return single stub node
        return {
            "nodes": [{"id": addr, "label": "Unknown", "risk_score": 0}],
            "edges": [],
        }

    # Deduplicate edges
    seen_edges: set = set()
    unique_edges = []
    for e in collected_edges:
        ekey = (e["source"], e["target"], e["type"])
        if ekey not in seen_edges:
            seen_edges.add(ekey)
            unique_edges.append(e)

    nodes_out = [
        {
            "id": n["id"],
            "labels": n.get("labels", []),
            "name": n.get("name"),
            "risk_score": n.get("risk_score", 0),
            "chain_id": n.get("chain_id", "ethereum"),
            "volume": n.get("volume", 0),
            "tx_count": n.get("tx_count", 0),
            "entity_type": n.get("entity_type", "Wallet"),
        }
        for n in collected_nodes.values()
    ]

    return {
        "nodes": nodes_out,
        "edges": unique_edges,
    }


# ============================================================================
# Helpers (private)
# ============================================================================

async def _lookup_address(
    address: str, chain_id: str
) -> Optional[Dict[str, Any]]:
    """Look up a single address from PG when it is not in the cache."""
    try:
        async with DatabaseManager.get_session() as session:
            q = text("""
                SELECT
                    COUNT(*) AS tx_count,
                    COALESCE(SUM(amount_usd), 0) AS total_volume,
                    MAX(severity) AS max_severity
                FROM events
                WHERE (from_address = :addr OR to_address = :addr
                       OR contract_address = :addr)
                  AND chain_id = :chain
            """)
            row = (
                await session.execute(q, {"addr": address, "chain": chain_id})
            ).mappings().first()

            if row is None or row["tx_count"] == 0:
                return None

            is_contract_q = text("""
                SELECT 1 FROM events
                WHERE contract_address = :addr AND chain_id = :chain
                LIMIT 1
            """)
            is_contract = (
                await session.execute(
                    is_contract_q, {"addr": address, "chain": chain_id}
                )
            ).first()

            default_label = "Contract" if is_contract else "Wallet"
            labels = _classify_address(address, default_label)

            return {
                "id": address,
                "labels": labels,
                "name": _address_name(address),
                "risk_score": 0.0,
                "chain_id": chain_id,
                "volume": float(row["total_volume"]),
                "tx_count": int(row["tx_count"]),
                "entity_type": labels[0] if labels else "Wallet",
            }

    except Exception as e:
        logger.error("address_lookup_failed", address=address[:10], error=str(e))
        return None


def _generate_mitigations(attack_type: Optional[str]) -> List[str]:
    """Return generic mitigation suggestions for a given attack type."""
    attack = (attack_type or "").lower()

    mitigations_map: Dict[str, List[str]] = {
        "flash_loan": [
            "Implement flash-loan-resistant oracle pricing",
            "Add minimum delay between large operations",
            "Use TWAP oracles instead of spot prices",
        ],
        "reentrancy": [
            "Apply checks-effects-interactions pattern",
            "Use reentrancy guards on all external calls",
            "Limit gas forwarded to external calls",
        ],
        "oracle_manipulation": [
            "Use decentralised price oracles with TWAP",
            "Implement price deviation circuit breakers",
            "Add multiple oracle fallback sources",
        ],
        "governance": [
            "Implement timelocks on governance proposals",
            "Require multi-sig for parameter changes",
            "Add proposal delay periods",
        ],
        "bridge": [
            "Implement withdrawal delays for large amounts",
            "Add fraud-proof verification windows",
            "Use multi-validator bridge consensus",
        ],
    }

    for key, mits in mitigations_map.items():
        if key in attack:
            return mits

    return [
        "Review smart contract audit reports",
        "Monitor for abnormal transaction patterns",
        "Implement rate limiting on high-value operations",
    ]
