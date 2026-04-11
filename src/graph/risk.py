"""
Graph-Based Risk Scoring Engine
===============================

Calculates risk scores based on graph topology and entity relationships.
This is the "brain" that combines graph analysis with ML predictions.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import math
import structlog

from .connection import Neo4jConnection
from .schema import NodeType, RelationType

logger = structlog.get_logger(__name__)


@dataclass
class RiskScore:
    """Comprehensive risk score for an entity."""
    address: str
    chain_id: str
    
    # Overall score
    total_score: float  # 0-100
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Component scores
    intrinsic_risk: float  # Based on entity properties
    behavioral_risk: float  # Based on transaction patterns
    association_risk: float  # Based on graph connections
    temporal_risk: float  # Based on time patterns
    
    # Contributing factors
    factors: List[Dict[str, Any]]
    
    # Confidence
    confidence: float  # 0-1
    data_points: int


class GraphRiskScorer:
    """
    Calculates risk scores using graph topology and entity relationships.
    
    Risk Components:
    1. Intrinsic Risk: Based on entity's own properties
       - Contract: bytecode analysis, audit status, age
       - Wallet: EOA vs contract, transaction history
       
    2. Behavioral Risk: Based on transaction patterns
       - Unusual transaction sizes
       - Timing patterns (night activity)
       - Velocity changes
       
    3. Association Risk: Based on graph connections
       - Distance to known hackers
       - Mixer interactions
       - Sanctioned address connections
       
    4. Temporal Risk: Based on time-based patterns
       - New entity (< 7 days)
       - Sudden activity spike
       - Dormant reactivation
    """
    
    # Risk weights
    WEIGHTS = {
        "intrinsic": 0.25,
        "behavioral": 0.25,
        "association": 0.35,  # Graph connections are most important
        "temporal": 0.15
    }
    
    # Association risk multipliers
    ASSOCIATION_RISKS = {
        "direct_hacker": 100,      # Direct transaction with hacker
        "1_hop_hacker": 60,        # 1 hop from hacker
        "2_hop_hacker": 30,        # 2 hops from hacker
        "3_hop_hacker": 15,        # 3 hops from hacker
        "direct_mixer": 50,        # Direct mixer interaction
        "1_hop_mixer": 25,         # 1 hop from mixer user
        "sanctioned": 100,         # Sanctioned address
        "1_hop_sanctioned": 70,    # 1 hop from sanctioned
    }
    
    def __init__(self, connection: Neo4jConnection):
        """
        Initialize risk scorer.
        
        Args:
            connection: Neo4j connection instance
        """
        self.conn = connection
    
    async def calculate_risk_score(
        self,
        address: str,
        chain_id: str,
        include_details: bool = True
    ) -> RiskScore:
        """
        Calculate comprehensive risk score for an entity.
        
        Args:
            address: Entity address
            chain_id: Chain ID
            include_details: Whether to include detailed factors
            
        Returns:
            RiskScore object with all components
        """
        # Calculate component scores in parallel
        intrinsic_task = self._calculate_intrinsic_risk(address, chain_id)
        behavioral_task = self._calculate_behavioral_risk(address, chain_id)
        association_task = self._calculate_association_risk(address, chain_id)
        temporal_task = self._calculate_temporal_risk(address, chain_id)
        
        (
            (intrinsic_score, intrinsic_factors),
            (behavioral_score, behavioral_factors),
            (association_score, association_factors),
            (temporal_score, temporal_factors)
        ) = await asyncio.gather(
            intrinsic_task,
            behavioral_task,
            association_task,
            temporal_task
        )
        
        # Calculate weighted total
        total_score = (
            intrinsic_score * self.WEIGHTS["intrinsic"] +
            behavioral_score * self.WEIGHTS["behavioral"] +
            association_score * self.WEIGHTS["association"] +
            temporal_score * self.WEIGHTS["temporal"]
        )
        
        # Determine risk level
        risk_level = self._get_risk_level(total_score)
        
        # Combine factors
        all_factors = []
        if include_details:
            all_factors = intrinsic_factors + behavioral_factors + association_factors + temporal_factors
            all_factors.sort(key=lambda f: f.get("contribution", 0), reverse=True)
        
        # Calculate confidence based on data points
        data_points = sum(len(f) for f in [intrinsic_factors, behavioral_factors, association_factors, temporal_factors])
        confidence = min(1.0, data_points / 10)  # More data = higher confidence
        
        return RiskScore(
            address=address,
            chain_id=chain_id,
            total_score=round(total_score, 2),
            risk_level=risk_level,
            intrinsic_risk=round(intrinsic_score, 2),
            behavioral_risk=round(behavioral_score, 2),
            association_risk=round(association_score, 2),
            temporal_risk=round(temporal_score, 2),
            factors=all_factors[:10],  # Top 10 factors
            confidence=round(confidence, 2),
            data_points=data_points
        )
    
    async def _calculate_intrinsic_risk(
        self,
        address: str,
        chain_id: str
    ) -> Tuple[float, List[Dict]]:
        """Calculate risk based on entity's own properties."""
        
        query = """
        MATCH (entity {address: $address, chain_id: $chain_id})
        
        RETURN
            labels(entity) AS labels,
            entity.risk_score AS existing_risk,
            entity.is_verified AS is_verified,
            entity.is_audited AS is_audited,
            entity.has_selfdestruct AS has_selfdestruct,
            entity.has_delegatecall AS has_delegatecall,
            entity.is_upgradeable AS is_upgradeable,
            entity.is_eoa AS is_eoa,
            entity.is_mixer AS is_mixer,
            entity.is_hacker AS is_hacker,
            entity.is_sanctioned AS is_sanctioned,
            entity.transaction_count AS tx_count
        """
        
        results = await self.conn.query(query, {
            "address": address,
            "chain_id": chain_id
        })
        
        if not results:
            return (50.0, [{"factor": "Unknown entity", "contribution": 50}])
        
        result = results[0]
        factors = []
        score = 0.0
        
        # Check labels
        labels = result.get("labels", [])
        
        if "Hacker" in labels or result.get("is_hacker"):
            score = 100
            factors.append({"factor": "Known hacker address", "contribution": 100, "severity": "CRITICAL"})
            return (score, factors)
        
        if "Sanctioned" in labels or result.get("is_sanctioned"):
            score = 100
            factors.append({"factor": "Sanctioned address", "contribution": 100, "severity": "CRITICAL"})
            return (score, factors)
        
        if "Mixer" in labels or result.get("is_mixer"):
            score = 80
            factors.append({"factor": "Known mixer address", "contribution": 80, "severity": "HIGH"})
            return (score, factors)
        
        # Contract-specific risks
        if "Contract" in labels:
            if result.get("has_selfdestruct"):
                score += 30
                factors.append({"factor": "Contract has selfdestruct", "contribution": 30, "severity": "HIGH"})
            
            if result.get("has_delegatecall") and not result.get("is_upgradeable"):
                score += 25
                factors.append({"factor": "Unprotected delegatecall", "contribution": 25, "severity": "HIGH"})
            
            if not result.get("is_verified"):
                score += 15
                factors.append({"factor": "Unverified contract", "contribution": 15, "severity": "MEDIUM"})
            
            if not result.get("is_audited"):
                score += 10
                factors.append({"factor": "No audit record", "contribution": 10, "severity": "LOW"})
        
        # Wallet-specific risks
        if "Wallet" in labels:
            tx_count = result.get("tx_count", 0)
            if tx_count < 5:
                score += 20
                factors.append({"factor": "New wallet (< 5 transactions)", "contribution": 20, "severity": "MEDIUM"})
        
        # Use existing risk score if available
        existing = result.get("existing_risk", 0)
        if existing > score:
            score = existing
        
        return (min(score, 100), factors)
    
    async def _calculate_behavioral_risk(
        self,
        address: str,
        chain_id: str
    ) -> Tuple[float, List[Dict]]:
        """Calculate risk based on transaction patterns."""
        
        query = """
        MATCH (entity {address: $address, chain_id: $chain_id})
        
        // Get outgoing transfers
        OPTIONAL MATCH (entity)-[r:TRANSFERS_TO]->()
        WITH entity, 
             collect(r.total_value_usd) AS transfer_values,
             count(r) AS transfer_count
        
        // Get incoming transfers
        OPTIONAL MATCH ()-[r2:TRANSFERS_TO]->(entity)
        
        WITH entity, transfer_values, transfer_count,
             collect(r2.total_value_usd) AS incoming_values,
             count(r2) AS incoming_count
        
        RETURN
            transfer_count,
            incoming_count,
            transfer_values,
            incoming_values,
            entity.total_value_transferred_usd AS total_value
        """
        
        results = await self.conn.query(query, {
            "address": address,
            "chain_id": chain_id
        })
        
        if not results:
            return (0.0, [])
        
        result = results[0]
        factors = []
        score = 0.0
        
        transfer_count = result.get("transfer_count", 0)
        incoming_count = result.get("incoming_count", 0)
        transfer_values = [v for v in (result.get("transfer_values") or []) if v]
        incoming_values = [v for v in (result.get("incoming_values") or []) if v]
        
        # Pattern 1: One-directional flow (only outgoing = drain pattern)
        if transfer_count > 0 and incoming_count == 0:
            score += 20
            factors.append({
                "factor": "Only outgoing transfers (potential drain)",
                "contribution": 20,
                "severity": "MEDIUM"
            })

        # Pattern 2: Statistical outlier detection (z-score) on transfer values
        if transfer_values and len(transfer_values) >= 3:
            avg_transfer = sum(transfer_values) / len(transfer_values)
            variance = sum((v - avg_transfer) ** 2 for v in transfer_values) / len(transfer_values)
            std_dev = variance ** 0.5 if variance > 0 else 0
            max_transfer = max(transfer_values)

            if std_dev > 0:
                z_score = (max_transfer - avg_transfer) / std_dev
                # z > 3 = 99.7th percentile outlier — highly anomalous
                if z_score > 3.0 and max_transfer > 50000:
                    contribution = min(30, int(z_score * 5))
                    score += contribution
                    factors.append({
                        "factor": f"Statistical outlier transfer ${max_transfer:,.0f} (z={z_score:.1f})",
                        "contribution": contribution,
                        "severity": "HIGH"
                    })
            elif max_transfer > avg_transfer * 10 and max_transfer > 100000:
                # Fallback: not enough variance data, use ratio heuristic
                score += 25
                factors.append({
                    "factor": f"Unusual large transfer (${max_transfer:,.0f})",
                    "contribution": 25,
                    "severity": "HIGH"
                })

        # Pattern 3: Outgoing/incoming ratio imbalance
        if transfer_count > 5 and incoming_count > 0:
            ratio = transfer_count / incoming_count
            if ratio > 10:
                score += 15
                factors.append({
                    "factor": f"Extreme out/in ratio ({ratio:.1f}:1)",
                    "contribution": 15,
                    "severity": "MEDIUM"
                })

        # Pattern 4: High velocity
        if transfer_count > 100:
            score += 15
            factors.append({
                "factor": f"High transaction velocity ({transfer_count} transfers)",
                "contribution": 15,
                "severity": "MEDIUM"
            })

        # Pattern 5: Value concentration (single transfer > 80% of total volume)
        if transfer_values and len(transfer_values) > 1:
            total_value = sum(transfer_values)
            if total_value > 0:
                max_transfer = max(transfer_values)
                concentration = max_transfer / total_value
                if concentration > 0.8 and max_transfer > 100000:
                    score += 15
                    factors.append({
                        "factor": f"Single transfer is {concentration:.0%} of total volume",
                        "contribution": 15,
                        "severity": "MEDIUM"
                    })

        return (min(score, 100), factors)
    
    async def _calculate_association_risk(
        self,
        address: str,
        chain_id: str
    ) -> Tuple[float, List[Dict]]:
        """
        Calculate risk based on graph connections.
        This is the most important component - leveraging graph topology.
        """
        
        # Query for connections to risky entities
        query = """
        MATCH (entity {address: $address, chain_id: $chain_id})
        
        // Direct connections to hackers
        OPTIONAL MATCH (entity)-[*1]-(hacker:Hacker)
        WITH entity, count(DISTINCT hacker) AS direct_hacker
        
        // 2-hop connections to hackers
        OPTIONAL MATCH (entity)-[*2]-(hacker2:Hacker)
        WITH entity, direct_hacker, count(DISTINCT hacker2) AS hop2_hacker
        
        // 3-hop connections to hackers
        OPTIONAL MATCH (entity)-[*3]-(hacker3:Hacker)
        WITH entity, direct_hacker, hop2_hacker, count(DISTINCT hacker3) AS hop3_hacker
        
        // Direct mixer connections
        OPTIONAL MATCH (entity)-[*1]-(mixer:Mixer)
        WITH entity, direct_hacker, hop2_hacker, hop3_hacker,
             count(DISTINCT mixer) AS direct_mixer
        
        // 2-hop mixer connections
        OPTIONAL MATCH (entity)-[*2]-(mixer2:Mixer)
        WITH entity, direct_hacker, hop2_hacker, hop3_hacker, direct_mixer,
             count(DISTINCT mixer2) AS hop2_mixer
        
        // Sanctioned connections
        OPTIONAL MATCH (entity)-[*1..2]-(sanctioned:Sanctioned)
        
        RETURN
            direct_hacker,
            hop2_hacker - direct_hacker AS hop2_only_hacker,
            hop3_hacker - hop2_hacker AS hop3_only_hacker,
            direct_mixer,
            hop2_mixer - direct_mixer AS hop2_only_mixer,
            count(DISTINCT sanctioned) AS sanctioned_connections
        """
        
        results = await self.conn.query(query, {
            "address": address,
            "chain_id": chain_id
        })
        
        if not results:
            return (0.0, [])
        
        result = results[0]
        factors = []
        score = 0.0
        
        # Direct hacker connection (CRITICAL)
        direct_hacker = result.get("direct_hacker", 0)
        if direct_hacker > 0:
            contribution = self.ASSOCIATION_RISKS["direct_hacker"]
            score += contribution
            factors.append({
                "factor": f"Direct connection to {direct_hacker} known hacker(s)",
                "contribution": contribution,
                "severity": "CRITICAL",
                "hops": 1
            })
        
        # 2-hop hacker connection
        hop2_hacker = result.get("hop2_only_hacker", 0)
        if hop2_hacker > 0 and direct_hacker == 0:
            contribution = self.ASSOCIATION_RISKS["2_hop_hacker"]
            score += contribution
            factors.append({
                "factor": f"2 hops from {hop2_hacker} known hacker(s)",
                "contribution": contribution,
                "severity": "HIGH",
                "hops": 2
            })
        
        # 3-hop hacker connection
        hop3_hacker = result.get("hop3_only_hacker", 0)
        if hop3_hacker > 0 and hop2_hacker == 0 and direct_hacker == 0:
            contribution = self.ASSOCIATION_RISKS["3_hop_hacker"]
            score += contribution
            factors.append({
                "factor": f"3 hops from {hop3_hacker} known hacker(s)",
                "contribution": contribution,
                "severity": "MEDIUM",
                "hops": 3
            })
        
        # Direct mixer connection
        direct_mixer = result.get("direct_mixer", 0)
        if direct_mixer > 0:
            contribution = self.ASSOCIATION_RISKS["direct_mixer"]
            score += contribution
            factors.append({
                "factor": f"Direct interaction with {direct_mixer} mixer(s)",
                "contribution": contribution,
                "severity": "HIGH",
                "hops": 1
            })
        
        # 2-hop mixer connection
        hop2_mixer = result.get("hop2_only_mixer", 0)
        if hop2_mixer > 0 and direct_mixer == 0:
            contribution = self.ASSOCIATION_RISKS["1_hop_mixer"]
            score += contribution
            factors.append({
                "factor": f"2 hops from {hop2_mixer} mixer user(s)",
                "contribution": contribution,
                "severity": "MEDIUM",
                "hops": 2
            })
        
        # Sanctioned connections
        sanctioned = result.get("sanctioned_connections", 0)
        if sanctioned > 0:
            contribution = self.ASSOCIATION_RISKS["1_hop_sanctioned"]
            score += contribution
            factors.append({
                "factor": f"Connected to {sanctioned} sanctioned address(es)",
                "contribution": contribution,
                "severity": "CRITICAL"
            })
        
        return (min(score, 100), factors)
    
    async def _calculate_temporal_risk(
        self,
        address: str,
        chain_id: str
    ) -> Tuple[float, List[Dict]]:
        """Calculate risk based on time patterns."""
        
        query = """
        MATCH (entity {address: $address, chain_id: $chain_id})
        
        RETURN
            entity.first_seen AS first_seen,
            entity.last_seen AS last_seen,
            entity.transaction_count AS tx_count
        """
        
        results = await self.conn.query(query, {
            "address": address,
            "chain_id": chain_id
        })
        
        if not results:
            return (0.0, [])
        
        result = results[0]
        factors = []
        score = 0.0
        
        first_seen = result.get("first_seen")
        last_seen = result.get("last_seen")
        
        if first_seen:
            try:
                # Parse ISO format
                if isinstance(first_seen, str):
                    first_seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                else:
                    first_seen_dt = first_seen
                
                age_days = (datetime.now(timezone.utc) - first_seen_dt.replace(tzinfo=None)).days
                
                if age_days < 1:
                    score += 40
                    factors.append({
                        "factor": "Entity created today",
                        "contribution": 40,
                        "severity": "HIGH"
                    })
                elif age_days < 7:
                    score += 25
                    factors.append({
                        "factor": f"New entity ({age_days} days old)",
                        "contribution": 25,
                        "severity": "MEDIUM"
                    })
                elif age_days < 30:
                    score += 10
                    factors.append({
                        "factor": f"Recent entity ({age_days} days old)",
                        "contribution": 10,
                        "severity": "LOW"
                    })
            except Exception as e:
                logger.debug("temporal_parse_error", error=str(e))

        # Dormant reactivation detection
        if first_seen and last_seen:
            try:
                if isinstance(last_seen, str):
                    last_seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                else:
                    last_seen_dt = last_seen

                if isinstance(first_seen, str):
                    first_seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                else:
                    first_seen_dt = first_seen

                now = datetime.now(timezone.utc)
                total_lifespan = (now - first_seen_dt.replace(tzinfo=None)).days
                days_since_last = (now - last_seen_dt.replace(tzinfo=None)).days

                # Dormant = existed for 90+ days but went silent for 60+ days
                # then reactivated recently (last seen within 7 days)
                if total_lifespan >= 90 and days_since_last <= 7:
                    # Check for a dormancy gap: active period vs total lifespan
                    active_span = (last_seen_dt.replace(tzinfo=None) - first_seen_dt.replace(tzinfo=None)).days
                    dormancy_gap = total_lifespan - active_span

                    if dormancy_gap >= 60:
                        score += 35
                        factors.append({
                            "factor": f"Dormant reactivation: {dormancy_gap}d silent after {active_span}d active, resumed within last {days_since_last}d",
                            "contribution": 35,
                            "severity": "HIGH"
                        })
                    elif dormancy_gap >= 30:
                        score += 20
                        factors.append({
                            "factor": f"Reactivated after {dormancy_gap}d dormancy",
                            "contribution": 20,
                            "severity": "MEDIUM"
                        })

                # Sudden burst: low tx count but very recent last_seen on old entity
                tx_count = result.get("tx_count", 0)
                if total_lifespan >= 180 and days_since_last <= 3 and tx_count and tx_count < 10:
                    score += 15
                    factors.append({
                        "factor": f"Old entity ({total_lifespan}d) with minimal activity ({tx_count} txs) suddenly active",
                        "contribution": 15,
                        "severity": "MEDIUM"
                    })

            except Exception as e:
                logger.debug("dormant_reactivation_parse_error", error=str(e))

        return (min(score, 100), factors)
    
    def _get_risk_level(self, score: float) -> str:
        """Convert numeric score to risk level."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    async def batch_calculate_risk(
        self,
        addresses: List[Tuple[str, str]]  # List of (address, chain_id)
    ) -> List[RiskScore]:
        """
        Calculate risk scores for multiple entities.
        
        Args:
            addresses: List of (address, chain_id) tuples
            
        Returns:
            List of RiskScore objects
        """
        tasks = [
            self.calculate_risk_score(addr, chain, include_details=False)
            for addr, chain in addresses
        ]
        return await asyncio.gather(*tasks)
    
    async def get_highest_risk_entities(
        self,
        chain_id: str,
        limit: int = 20,
        entity_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get entities with highest risk scores.
        
        Args:
            chain_id: Chain to query
            limit: Maximum results
            entity_type: Optional filter (Wallet, Contract, etc.)
            
        Returns:
            List of high-risk entities
        """
        type_filter = f"AND entity:{entity_type}" if entity_type else ""
        
        query = f"""
        MATCH (entity)
        WHERE entity.chain_id = $chain_id
        AND entity.risk_score > 0
        {type_filter}
        
        RETURN
            entity.address AS address,
            labels(entity) AS labels,
            entity.risk_score AS risk_score,
            entity.entity_name AS name,
            entity.first_seen AS first_seen,
            entity.last_seen AS last_seen
        ORDER BY entity.risk_score DESC
        LIMIT $limit
        """
        
        results = await self.conn.query(query, {
            "chain_id": chain_id,
            "limit": limit
        })
        
        return [
            {
                "address": r.get("address"),
                "labels": r.get("labels", []),
                "risk_score": r.get("risk_score", 0),
                "name": r.get("name"),
                "risk_level": self._get_risk_level(r.get("risk_score", 0)),
                "first_seen": r.get("first_seen"),
                "last_seen": r.get("last_seen")
            }
            for r in results
        ]
    
    async def propagate_risk(self, chain_id: str, max_hops: int = 3):
        """
        Propagate risk scores through the graph.
        Entities connected to high-risk entities inherit some risk.
        
        Args:
            chain_id: Chain to process
            max_hops: Maximum hops for risk propagation
        """
        # Start from highest risk entities and propagate outward
        query = """
        // Find high-risk entities
        MATCH (high_risk)
        WHERE high_risk.chain_id = $chain_id
        AND high_risk.risk_score >= 80
        
        // Find connected entities within max_hops
        MATCH path = (high_risk)-[*1..3]-(connected)
        WHERE connected.chain_id = $chain_id
        AND connected.risk_score < high_risk.risk_score
        
        // Calculate propagated risk (decreases with distance)
        WITH connected, high_risk, length(path) AS distance,
             high_risk.risk_score * (1.0 / (distance + 1)) AS propagated_risk
        
        // Update risk score (take max of current and propagated)
        SET connected.risk_score = CASE
            WHEN connected.risk_score < propagated_risk
            THEN propagated_risk
            ELSE connected.risk_score
        END
        
        RETURN count(connected) AS updated_count
        """
        
        result = await self.conn.execute(query, {
            "chain_id": chain_id
        })
        
        logger.info(
            "risk_propagated",
            chain_id=chain_id,
            updated=result.get("properties_set", 0)
        )
