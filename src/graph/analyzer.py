"""
Attack Path Analyzer
====================

Analyzes the security graph to find potential attack paths,
calculate blast radius, and identify vulnerable configurations.

This is the "killer feature" - similar to Wiz's attack path analysis
but for Web3/DeFi protocols.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import structlog

from .connection import Neo4jConnection
from .schema import NodeType, RelationType

logger = structlog.get_logger(__name__)


class AttackVectorType(Enum):
    """Types of attack vectors in Web3."""
    
    # Smart Contract
    REENTRANCY = "reentrancy"
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle_manipulation"
    PRICE_MANIPULATION = "price_manipulation"
    GOVERNANCE_ATTACK = "governance_attack"
    
    # Access Control
    ADMIN_KEY_COMPROMISE = "admin_key_compromise"
    MULTISIG_COMPROMISE = "multisig_compromise"
    TIMELOCK_BYPASS = "timelock_bypass"
    UPGRADE_ATTACK = "upgrade_attack"
    
    # Bridge
    BRIDGE_EXPLOIT = "bridge_exploit"
    VALIDATOR_COLLUSION = "validator_collusion"
    
    # Economic
    SANDWICH_ATTACK = "sandwich_attack"
    RUG_PULL = "rug_pull"
    LIQUIDITY_DRAIN = "liquidity_drain"


@dataclass
class AttackStep:
    """A single step in an attack path."""
    step_number: int
    action: str
    from_entity: str
    to_entity: str
    relationship: str
    risk_contribution: float
    capital_required_usd: float = 0.0
    description: str = ""


@dataclass
class AttackPath:
    """A complete attack path from entry to target."""
    id: str
    attack_vector: AttackVectorType
    entry_point: str
    target: str
    steps: List[AttackStep]
    total_risk_score: float
    capital_required_usd: float
    potential_loss_usd: float
    likelihood: float  # 0-1
    blast_radius: Dict[str, Any]
    mitigations: List[str]
    
    @property
    def severity(self) -> str:
        """Calculate severity based on risk and potential loss."""
        if self.potential_loss_usd > 10_000_000 or self.total_risk_score > 90:
            return "CRITICAL"
        elif self.potential_loss_usd > 1_000_000 or self.total_risk_score > 70:
            return "HIGH"
        elif self.potential_loss_usd > 100_000 or self.total_risk_score > 50:
            return "MEDIUM"
        else:
            return "LOW"


@dataclass
class BlastRadius:
    """Blast radius calculation for an attack."""
    affected_contracts: List[str]
    affected_wallets: int
    affected_protocols: List[str]
    total_tvl_at_risk_usd: float
    affected_tokens: List[str]
    downstream_impact: Dict[str, Any]


class AttackPathAnalyzer:
    """
    Analyzes the security graph to identify attack paths.
    
    Key capabilities:
    1. Find paths from risky entities to valuable targets
    2. Calculate blast radius of potential exploits
    3. Identify admin key risks
    4. Detect oracle dependency risks
    5. Find bridge vulnerabilities
    """
    
    def __init__(self, connection: Neo4jConnection):
        """
        Initialize the analyzer.
        
        Args:
            connection: Neo4j connection instance
        """
        self.conn = connection
    
    async def find_attack_paths(
        self,
        target_address: Optional[str] = None,
        chain_id: str = "ethereum",
        max_depth: int = 5,
        min_tvl_usd: float = 100_000
    ) -> List[AttackPath]:
        """
        Find all potential attack paths to a target or high-value targets.
        
        Args:
            target_address: Specific target to analyze (None for all high-value)
            chain_id: Chain to analyze
            max_depth: Maximum path depth
            min_tvl_usd: Minimum TVL to consider
            
        Returns:
            List of potential attack paths
        """
        attack_paths = []
        
        # 1. Admin Key Compromise Paths
        admin_paths = await self._find_admin_key_paths(target_address, chain_id, max_depth)
        attack_paths.extend(admin_paths)
        
        # 2. Oracle Manipulation Paths
        oracle_paths = await self._find_oracle_manipulation_paths(target_address, chain_id)
        attack_paths.extend(oracle_paths)
        
        # 3. Flash Loan Attack Paths
        flash_loan_paths = await self._find_flash_loan_paths(target_address, chain_id)
        attack_paths.extend(flash_loan_paths)
        
        # 4. Bridge Exploit Paths
        bridge_paths = await self._find_bridge_exploit_paths(chain_id)
        attack_paths.extend(bridge_paths)
        
        # 5. Governance Attack Paths
        governance_paths = await self._find_governance_attack_paths(target_address, chain_id)
        attack_paths.extend(governance_paths)
        
        # Sort by risk score
        attack_paths.sort(key=lambda p: p.total_risk_score, reverse=True)
        
        logger.info(
            "attack_paths_found",
            total=len(attack_paths),
            critical=len([p for p in attack_paths if p.severity == "CRITICAL"]),
            high=len([p for p in attack_paths if p.severity == "HIGH"])
        )
        
        return attack_paths
    
    async def _find_admin_key_paths(
        self,
        target_address: Optional[str],
        chain_id: str,
        max_depth: int
    ) -> List[AttackPath]:
        """Find attack paths through admin key compromise."""
        
        # Query: Find all admin relationships to high-value contracts
        query = """
        MATCH path = (admin:Wallet)-[:HAS_ADMIN_ACCESS*1..3]->(target:Contract)
        WHERE target.chain_id = $chain_id
        AND (target.risk_score > 0 OR target:Protocol)
        """ + (f"AND target.address = $target_address" if target_address else "") + """
        WITH admin, target, path,
             [n IN nodes(path) WHERE n:Wallet] AS wallets_in_path
        
        // Calculate risk based on admin wallet properties
        WITH admin, target, path, wallets_in_path,
             CASE
                 WHEN admin.is_eoa = true THEN 30  // EOA admins are riskier
                 WHEN admin:Multisig THEN 10      // Multisig is safer
                 ELSE 20
             END AS admin_risk,
             CASE
                 WHEN admin.transaction_count < 10 THEN 20  // New admin is risky
                 ELSE 0
             END AS activity_risk
        
        RETURN 
            admin.address AS admin_address,
            target.address AS target_address,
            target.protocol_name AS protocol_name,
            length(path) AS path_length,
            admin_risk + activity_risk AS risk_score,
            [rel IN relationships(path) | type(rel)] AS relationship_types,
            [node IN nodes(path) | node.address] AS path_addresses
        ORDER BY risk_score DESC
        LIMIT 20
        """
        
        results = await self.conn.query(query, {
            "chain_id": chain_id,
            "target_address": target_address
        })
        
        attack_paths = []
        for i, result in enumerate(results):
            steps = []
            path_addresses = result.get("path_addresses", [])
            rel_types = result.get("relationship_types", [])
            
            for j, (addr, rel) in enumerate(zip(path_addresses[:-1], rel_types)):
                steps.append(AttackStep(
                    step_number=j + 1,
                    action=f"Compromise {rel.lower().replace('_', ' ')}",
                    from_entity=addr,
                    to_entity=path_addresses[j + 1] if j + 1 < len(path_addresses) else "",
                    relationship=rel,
                    risk_contribution=result.get("risk_score", 0) / len(rel_types),
                    description=f"Attacker gains {rel.lower().replace('_', ' ')} access"
                ))
            
            # Calculate blast radius
            blast_radius = await self._calculate_blast_radius(
                result.get("target_address", ""),
                chain_id
            )
            
            attack_paths.append(AttackPath(
                id=f"admin-key-{i+1}",
                attack_vector=AttackVectorType.ADMIN_KEY_COMPROMISE,
                entry_point=result.get("admin_address", ""),
                target=result.get("target_address", ""),
                steps=steps,
                total_risk_score=result.get("risk_score", 0),
                capital_required_usd=0,  # Admin key compromise doesn't need capital
                potential_loss_usd=blast_radius.total_tvl_at_risk_usd,
                likelihood=0.3 if result.get("risk_score", 0) > 30 else 0.1,
                blast_radius={
                    "affected_contracts": blast_radius.affected_contracts,
                    "affected_wallets": blast_radius.affected_wallets,
                    "tvl_at_risk": blast_radius.total_tvl_at_risk_usd
                },
                mitigations=[
                    "Use multisig for admin functions",
                    "Implement timelock for sensitive operations",
                    "Regular key rotation",
                    "Hardware wallet for admin keys"
                ]
            ))
        
        return attack_paths
    
    async def _find_oracle_manipulation_paths(
        self,
        target_address: Optional[str],
        chain_id: str
    ) -> List[AttackPath]:
        """Find attack paths through oracle manipulation."""
        
        query = """
        MATCH (protocol:Protocol)-[:USES_ORACLE]->(oracle:Oracle)
        WHERE protocol.chain_id = $chain_id
        """ + (f"AND protocol.address = $target_address" if target_address else "") + """
        
        // Find protocols that depend on potentially manipulable oracles
        WITH protocol, oracle,
             CASE
                 WHEN oracle.oracle_type = 'uniswap_twap' THEN 40  // TWAP is manipulable
                 WHEN oracle.oracle_type = 'spot' THEN 60         // Spot price very manipulable
                 WHEN oracle.oracle_type = 'chainlink' THEN 10    // Chainlink is safer
                 ELSE 30
             END AS oracle_risk
        
        RETURN
            protocol.address AS protocol_address,
            protocol.name AS protocol_name,
            oracle.address AS oracle_address,
            oracle.oracle_type AS oracle_type,
            oracle.base_asset AS base_asset,
            oracle_risk AS risk_score
        ORDER BY oracle_risk DESC
        LIMIT 10
        """
        
        results = await self.conn.query(query, {
            "chain_id": chain_id,
            "target_address": target_address
        })
        
        attack_paths = []
        for i, result in enumerate(results):
            oracle_type = result.get("oracle_type", "unknown")
            
            steps = [
                AttackStep(
                    step_number=1,
                    action="Obtain flash loan for capital",
                    from_entity="flash_loan_provider",
                    to_entity="attacker",
                    relationship="FLASH_LOANED",
                    risk_contribution=10,
                    capital_required_usd=0,
                    description="Borrow large amount via flash loan"
                ),
                AttackStep(
                    step_number=2,
                    action=f"Manipulate {oracle_type} oracle",
                    from_entity="attacker",
                    to_entity=result.get("oracle_address", ""),
                    relationship="MANIPULATES",
                    risk_contribution=result.get("risk_score", 0),
                    description=f"Execute trades to move {result.get('base_asset', '')} price"
                ),
                AttackStep(
                    step_number=3,
                    action="Exploit price discrepancy",
                    from_entity="attacker",
                    to_entity=result.get("protocol_address", ""),
                    relationship="EXPLOITS",
                    risk_contribution=20,
                    description="Use manipulated price to borrow/liquidate"
                ),
                AttackStep(
                    step_number=4,
                    action="Repay flash loan and profit",
                    from_entity="attacker",
                    to_entity="flash_loan_provider",
                    relationship="REPAYS",
                    risk_contribution=0,
                    description="Return borrowed funds, keep profit"
                )
            ]
            
            # Estimate capital needed (varies by oracle type)
            capital_needed = {
                "spot": 100_000,
                "uniswap_twap": 1_000_000,
                "chainlink": 10_000_000  # Very hard to manipulate
            }.get(oracle_type, 500_000)
            
            attack_paths.append(AttackPath(
                id=f"oracle-manip-{i+1}",
                attack_vector=AttackVectorType.ORACLE_MANIPULATION,
                entry_point="flash_loan_provider",
                target=result.get("protocol_address", ""),
                steps=steps,
                total_risk_score=result.get("risk_score", 0),
                capital_required_usd=capital_needed,
                potential_loss_usd=capital_needed * 10,  # Typical leverage
                likelihood=0.4 if result.get("risk_score", 0) > 30 else 0.1,
                blast_radius={
                    "affected_contracts": [result.get("protocol_address", "")],
                    "affected_wallets": 0,
                    "tvl_at_risk": capital_needed * 10
                },
                mitigations=[
                    "Use Chainlink or other decentralized oracles",
                    "Implement TWAP with longer windows",
                    "Add price deviation checks",
                    "Use multiple oracle sources"
                ]
            ))
        
        return attack_paths
    
    async def _find_flash_loan_paths(
        self,
        target_address: Optional[str],
        chain_id: str
    ) -> List[AttackPath]:
        """Find protocols vulnerable to flash loan attacks."""
        
        query = """
        MATCH (protocol:Protocol)
        WHERE protocol.chain_id = $chain_id
        """ + (f"AND protocol.address = $target_address" if target_address else "") + """
        
        // Find protocols with flash loan interactions
        OPTIONAL MATCH (protocol)<-[:FLASH_LOANED]-(borrower:Wallet)
        
        WITH protocol, count(borrower) AS flash_loan_count
        WHERE flash_loan_count > 0
        
        RETURN
            protocol.address AS protocol_address,
            protocol.name AS protocol_name,
            flash_loan_count,
            CASE
                WHEN flash_loan_count > 100 THEN 50
                WHEN flash_loan_count > 10 THEN 30
                ELSE 10
            END AS risk_score
        ORDER BY risk_score DESC
        LIMIT 10
        """
        
        results = await self.conn.query(query, {
            "chain_id": chain_id,
            "target_address": target_address
        })
        
        attack_paths = []
        for i, result in enumerate(results):
            attack_paths.append(AttackPath(
                id=f"flash-loan-{i+1}",
                attack_vector=AttackVectorType.FLASH_LOAN,
                entry_point="aave_flash_loan",
                target=result.get("protocol_address", ""),
                steps=[
                    AttackStep(
                        step_number=1,
                        action="Initiate flash loan",
                        from_entity="attacker",
                        to_entity="aave",
                        relationship="FLASH_LOANED",
                        risk_contribution=10,
                        capital_required_usd=0,
                        description="Borrow funds via flash loan"
                    ),
                    AttackStep(
                        step_number=2,
                        action="Execute attack sequence",
                        from_entity="attacker",
                        to_entity=result.get("protocol_address", ""),
                        relationship="EXPLOITS",
                        risk_contribution=result.get("risk_score", 0),
                        description="Exploit vulnerability in target protocol"
                    )
                ],
                total_risk_score=result.get("risk_score", 0),
                capital_required_usd=0,  # Flash loans need no capital
                potential_loss_usd=1_000_000,  # Estimate
                likelihood=0.2,
                blast_radius={
                    "affected_contracts": [result.get("protocol_address", "")],
                    "affected_wallets": 0,
                    "tvl_at_risk": 1_000_000
                },
                mitigations=[
                    "Implement reentrancy guards",
                    "Use checks-effects-interactions pattern",
                    "Add flash loan detection",
                    "Implement rate limiting"
                ]
            ))
        
        return attack_paths
    
    async def _find_bridge_exploit_paths(self, chain_id: str) -> List[AttackPath]:
        """Find bridge vulnerabilities."""
        
        query = """
        MATCH (bridge:Bridge)
        WHERE bridge.chain_id = $chain_id OR $chain_id IN bridge.source_chains
        
        WITH bridge,
             CASE
                 WHEN bridge.validator_count < 5 THEN 60
                 WHEN bridge.validator_count < 10 THEN 40
                 ELSE 20
             END AS validator_risk,
             CASE
                 WHEN bridge.previous_exploits > 0 THEN 30
                 ELSE 0
             END AS history_risk
        
        RETURN
            bridge.address AS bridge_address,
            bridge.name AS bridge_name,
            bridge.validator_count AS validator_count,
            bridge.total_volume_usd AS total_volume,
            validator_risk + history_risk AS risk_score
        ORDER BY risk_score DESC
        LIMIT 5
        """
        
        results = await self.conn.query(query, {"chain_id": chain_id})
        
        attack_paths = []
        for i, result in enumerate(results):
            attack_paths.append(AttackPath(
                id=f"bridge-exploit-{i+1}",
                attack_vector=AttackVectorType.BRIDGE_EXPLOIT,
                entry_point="validator_set",
                target=result.get("bridge_address", ""),
                steps=[
                    AttackStep(
                        step_number=1,
                        action="Compromise validator keys",
                        from_entity="attacker",
                        to_entity="validators",
                        relationship="COMPROMISES",
                        risk_contribution=result.get("risk_score", 0) * 0.7,
                        description=f"Compromise {result.get('validator_count', 0)} validators"
                    ),
                    AttackStep(
                        step_number=2,
                        action="Submit fraudulent proof",
                        from_entity="validators",
                        to_entity=result.get("bridge_address", ""),
                        relationship="VALIDATES",
                        risk_contribution=result.get("risk_score", 0) * 0.3,
                        description="Approve fake cross-chain message"
                    )
                ],
                total_risk_score=result.get("risk_score", 0),
                capital_required_usd=0,
                potential_loss_usd=result.get("total_volume", 0) * 0.1,
                likelihood=0.1,
                blast_radius={
                    "affected_contracts": [result.get("bridge_address", "")],
                    "affected_wallets": 1000,  # Estimate
                    "tvl_at_risk": result.get("total_volume", 0) * 0.1
                },
                mitigations=[
                    "Increase validator count",
                    "Implement fraud proofs",
                    "Add withdrawal delays",
                    "Use optimistic rollup design"
                ]
            ))
        
        return attack_paths
    
    async def _find_governance_attack_paths(
        self,
        target_address: Optional[str],
        chain_id: str
    ) -> List[AttackPath]:
        """Find governance attack vulnerabilities."""
        
        query = """
        MATCH (gov:Governor)-[:CONTROLS]->(target:Contract)
        WHERE target.chain_id = $chain_id
        """ + (f"AND target.address = $target_address" if target_address else "") + """
        
        // Find governance with low quorum or short voting periods
        WITH gov, target,
             CASE
                 WHEN gov.quorum_percentage < 5 THEN 50
                 WHEN gov.quorum_percentage < 10 THEN 30
                 ELSE 10
             END AS quorum_risk
        
        RETURN
            gov.address AS gov_address,
            target.address AS target_address,
            gov.quorum_percentage AS quorum,
            quorum_risk AS risk_score
        ORDER BY risk_score DESC
        LIMIT 5
        """
        
        results = await self.conn.query(query, {
            "chain_id": chain_id,
            "target_address": target_address
        })
        
        attack_paths = []
        for i, result in enumerate(results):
            attack_paths.append(AttackPath(
                id=f"governance-{i+1}",
                attack_vector=AttackVectorType.GOVERNANCE_ATTACK,
                entry_point="token_market",
                target=result.get("target_address", ""),
                steps=[
                    AttackStep(
                        step_number=1,
                        action="Acquire governance tokens",
                        from_entity="attacker",
                        to_entity="token_market",
                        relationship="BUYS",
                        risk_contribution=10,
                        capital_required_usd=1_000_000,
                        description="Buy or borrow governance tokens"
                    ),
                    AttackStep(
                        step_number=2,
                        action="Submit malicious proposal",
                        from_entity="attacker",
                        to_entity=result.get("gov_address", ""),
                        relationship="PROPOSES",
                        risk_contribution=result.get("risk_score", 0),
                        description="Create proposal to drain funds"
                    ),
                    AttackStep(
                        step_number=3,
                        action="Vote and execute",
                        from_entity="attacker",
                        to_entity=result.get("target_address", ""),
                        relationship="EXECUTES",
                        risk_contribution=20,
                        description="Pass vote and execute malicious action"
                    )
                ],
                total_risk_score=result.get("risk_score", 0),
                capital_required_usd=1_000_000,  # Need tokens
                potential_loss_usd=10_000_000,  # Estimate
                likelihood=0.1,
                blast_radius={
                    "affected_contracts": [result.get("target_address", "")],
                    "affected_wallets": 0,
                    "tvl_at_risk": 10_000_000
                },
                mitigations=[
                    "Increase quorum requirements",
                    "Add timelock delays",
                    "Implement vote escrow",
                    "Add emergency pause mechanism"
                ]
            ))
        
        return attack_paths
    
    async def _calculate_blast_radius(
        self,
        target_address: str,
        chain_id: str
    ) -> BlastRadius:
        """Calculate the blast radius of an attack on a target."""
        
        # Find all connected entities
        query = """
        MATCH (target {address: $target_address, chain_id: $chain_id})
        
        // Find downstream contracts
        OPTIONAL MATCH (target)-[*1..3]->(downstream:Contract)
        WITH target, collect(DISTINCT downstream.address) AS downstream_contracts
        
        // Find affected wallets (users of the protocol)
        OPTIONAL MATCH (wallet:Wallet)-[*1..2]->(target)
        WITH target, downstream_contracts, count(DISTINCT wallet) AS affected_wallets
        
        // Find affected protocols
        OPTIONAL MATCH (target)-[*1..2]->(protocol:Protocol)
        WITH target, downstream_contracts, affected_wallets,
             collect(DISTINCT protocol.name) AS affected_protocols
        
        // Find affected tokens
        OPTIONAL MATCH (target)-[*1..2]->(token:Token)
        
        RETURN
            downstream_contracts,
            affected_wallets,
            affected_protocols,
            collect(DISTINCT token.address) AS affected_tokens
        """
        
        results = await self.conn.query(query, {
            "target_address": target_address,
            "chain_id": chain_id
        })
        
        if not results:
            return BlastRadius(
                affected_contracts=[target_address],
                affected_wallets=0,
                affected_protocols=[],
                total_tvl_at_risk_usd=0,
                affected_tokens=[],
                downstream_impact={}
            )
        
        result = results[0]
        
        return BlastRadius(
            affected_contracts=[target_address] + (result.get("downstream_contracts") or []),
            affected_wallets=result.get("affected_wallets", 0),
            affected_protocols=result.get("affected_protocols") or [],
            total_tvl_at_risk_usd=0,  # Would need TVL data
            affected_tokens=result.get("affected_tokens") or [],
            downstream_impact={
                "contracts": len(result.get("downstream_contracts") or []),
                "protocols": len(result.get("affected_protocols") or [])
            }
        )
    
    async def get_entity_risk_profile(
        self,
        address: str,
        chain_id: str
    ) -> Dict[str, Any]:
        """
        Get comprehensive risk profile for an entity.
        
        Returns:
            Risk profile including score, factors, and recommendations
        """
        query = """
        MATCH (entity {address: $address, chain_id: $chain_id})
        
        // Get direct risk factors
        OPTIONAL MATCH (entity)-[:CONNECTED_TO_HACKER]->(hacker:Hacker)
        OPTIONAL MATCH (entity)-[:SENT_TO_MIXER|RECEIVED_FROM_MIXER]->(mixer:Mixer)
        OPTIONAL MATCH (entity)-[:HAS_ADMIN_ACCESS]->(admin_target:Contract)
        
        // Get relationship counts
        OPTIONAL MATCH (entity)-[r]-()
        
        WITH entity,
             count(DISTINCT hacker) AS hacker_connections,
             count(DISTINCT mixer) AS mixer_interactions,
             count(DISTINCT admin_target) AS admin_access_count,
             count(r) AS total_relationships,
             labels(entity) AS entity_labels
        
        RETURN
            entity.address AS address,
            entity.risk_score AS current_risk_score,
            entity_labels,
            hacker_connections,
            mixer_interactions,
            admin_access_count,
            total_relationships,
            entity.first_seen AS first_seen,
            entity.last_seen AS last_seen
        """
        
        results = await self.conn.query(query, {
            "address": address,
            "chain_id": chain_id
        })
        
        if not results:
            return {"error": "Entity not found", "address": address}
        
        result = results[0]
        
        # Calculate risk factors
        risk_factors = []
        risk_score = result.get("current_risk_score", 0)
        
        if result.get("hacker_connections", 0) > 0:
            risk_factors.append({
                "factor": "Connected to known hackers",
                "severity": "CRITICAL",
                "contribution": 40
            })
            risk_score = max(risk_score, 80)
        
        if result.get("mixer_interactions", 0) > 0:
            risk_factors.append({
                "factor": "Mixer interactions detected",
                "severity": "HIGH",
                "contribution": 30
            })
            risk_score = max(risk_score, 60)
        
        if result.get("admin_access_count", 0) > 3:
            risk_factors.append({
                "factor": "Admin access to multiple contracts",
                "severity": "MEDIUM",
                "contribution": 20
            })
        
        return {
            "address": address,
            "chain_id": chain_id,
            "risk_score": min(risk_score, 100),
            "risk_level": "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW",
            "labels": result.get("entity_labels", []),
            "risk_factors": risk_factors,
            "statistics": {
                "hacker_connections": result.get("hacker_connections", 0),
                "mixer_interactions": result.get("mixer_interactions", 0),
                "admin_access_count": result.get("admin_access_count", 0),
                "total_relationships": result.get("total_relationships", 0)
            },
            "first_seen": result.get("first_seen"),
            "last_seen": result.get("last_seen"),
            "recommendations": self._get_recommendations(risk_factors)
        }
    
    def _get_recommendations(self, risk_factors: List[Dict]) -> List[str]:
        """Generate recommendations based on risk factors."""
        recommendations = []
        
        for factor in risk_factors:
            if "hacker" in factor["factor"].lower():
                recommendations.append("Investigate source of funds and consider blocking")
                recommendations.append("Report to relevant authorities if confirmed")
            
            if "mixer" in factor["factor"].lower():
                recommendations.append("Enhanced monitoring for this address")
                recommendations.append("Consider AML compliance review")
            
            if "admin" in factor["factor"].lower():
                recommendations.append("Review admin access permissions")
                recommendations.append("Consider implementing multisig")
        
        if not recommendations:
            recommendations.append("Continue standard monitoring")
        
        return list(set(recommendations))  # Deduplicate
