#!/usr/bin/env python3
"""
Build Attack Path Relationships in Security Graph
==================================================

Creates relationships between entities to enable attack path detection:
- TRANSFERRED_TO: Token/ETH transfers between wallets
- INTERACTED_WITH: Contract interactions
- BORROWED_FROM: Flash loan relationships
- BRIDGED_TO: Cross-chain bridge transfers
- MIXED_THROUGH: Mixer usage
- EXPLOITED: Hacker to protocol relationships
- FUNDED_BY: Funding chain relationships

Usage:
    python scripts/build_attack_paths.py --uri "neo4j+s://xxx" --password "xxx"
"""

import os
import sys
import asyncio
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog
from src.graph.connection import Neo4jConnection

logger = structlog.get_logger(__name__)


# ============================================================================
# KNOWN ATTACK PATTERNS
# ============================================================================

# Flash Loan Attack Pattern: Flash Loan Provider -> DEX -> Target Protocol -> Mixer
FLASH_LOAN_ATTACK_PATTERNS = [
    {
        "name": "Classic Flash Loan Attack",
        "steps": [
            {"from": "FlashLoanProvider", "to": "Protocol", "rel": "BORROWED_FROM"},
            {"from": "Protocol", "to": "Protocol", "rel": "MANIPULATED"},
            {"from": "Protocol", "to": "Mixer", "rel": "LAUNDERED_THROUGH"},
        ]
    },
    {
        "name": "Oracle Manipulation Attack",
        "steps": [
            {"from": "FlashLoanProvider", "to": "Protocol", "rel": "BORROWED_FROM"},
            {"from": "Protocol", "to": "Oracle", "rel": "MANIPULATED_ORACLE"},
            {"from": "Oracle", "to": "Protocol", "rel": "EXPLOITED_PROTOCOL"},
            {"from": "Protocol", "to": "Mixer", "rel": "LAUNDERED_THROUGH"},
        ]
    },
]

# Known exploit chains (from historical data)
KNOWN_EXPLOIT_CHAINS = [
    # Ronin Bridge Hack
    {
        "attacker": "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
        "steps": [
            ("0x098b716b8aaf21512996dc57eb0615e2383e2f96", "0x8407dc57739bcda7aa53ca6f12f82f9d51c2f21e", "EXPLOITED"),
            ("0x098b716b8aaf21512996dc57eb0615e2383e2f96", "0x8589427373d6d84e98730d7795d8f6f8731fda16", "LAUNDERED_THROUGH"),
        ]
    },
    # Euler Finance Hack
    {
        "attacker": "0xb4d24dacbdffa1bbf9a624044484b3feeb7fdf74",
        "steps": [
            ("0xb4d24dacbdffa1bbf9a624044484b3feeb7fdf74", "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2", "BORROWED_FROM"),
            ("0xb4d24dacbdffa1bbf9a624044484b3feeb7fdf74", "0x27182842e098f60e3d576794a5bffb0777e025d3", "EXPLOITED"),
        ]
    },
]


async def build_attack_paths(uri: str, username: str, password: str):
    """Build attack path relationships in the security graph."""
    
    print("\n" + "="*60)
    print("🔗 Building Attack Path Relationships")
    print("="*60)
    
    conn = Neo4jConnection(uri=uri, username=username, password=password)
    
    try:
        await conn.connect()
        print("✅ Connected to Neo4j")
        
        # ====================================================================
        # 1. Create Protocol Dependency Relationships
        # ====================================================================
        print("\n📊 Creating protocol dependency relationships...")
        
        # Lending protocols depend on oracles
        await conn.execute("""
            MATCH (p:Protocol), (o:Oracle)
            WHERE p.category = 'lending'
            MERGE (p)-[:DEPENDS_ON_ORACLE]->(o)
        """)
        print("   ✓ Linked lending protocols to oracles")
        
        # DEXes can be used for price manipulation
        await conn.execute("""
            MATCH (d:Protocol {category: 'dex'}), (o:Oracle)
            MERGE (d)-[:CAN_MANIPULATE]->(o)
        """)
        print("   ✓ Linked DEXes to oracles (manipulation vector)")
        
        # Flash loan providers can fund attacks
        await conn.execute("""
            MATCH (f:FlashLoanProvider), (p:Protocol)
            WHERE p.category IN ['lending', 'dex']
            MERGE (f)-[:CAN_FUND_ATTACK_ON]->(p)
        """)
        print("   ✓ Linked flash loan providers to protocols")
        
        # ====================================================================
        # 2. Create Hacker -> Target Relationships
        # ====================================================================
        print("\n🏴‍☠️ Creating hacker exploit relationships...")
        
        # Link hackers to protocols they exploited
        for chain in KNOWN_EXPLOIT_CHAINS:
            for from_addr, to_addr, rel_type in chain["steps"]:
                await conn.execute(f"""
                    MATCH (from {{address: $from_addr}})
                    MATCH (to {{address: $to_addr}})
                    MERGE (from)-[:{rel_type}]->(to)
                """, {"from_addr": from_addr.lower(), "to_addr": to_addr.lower()})
        print(f"   ✓ Created {len(KNOWN_EXPLOIT_CHAINS)} known exploit chains")
        
        # ====================================================================
        # 3. Create Bridge Relationships
        # ====================================================================
        print("\n🌉 Creating bridge relationships...")
        
        # Bridges connect to other bridges (cross-chain paths)
        await conn.execute("""
            MATCH (b1:Bridge), (b2:Bridge)
            WHERE b1 <> b2
            AND ANY(chain IN b1.supported_chains WHERE chain IN b2.supported_chains)
            MERGE (b1)-[:CONNECTS_TO]->(b2)
        """)
        print("   ✓ Linked bridges with shared chains")
        
        # ====================================================================
        # 4. Create Mixer Relationships
        # ====================================================================
        print("\n🌀 Creating mixer relationships...")
        
        # Hackers often use mixers
        await conn.execute("""
            MATCH (h:Hacker), (m:Mixer)
            MERGE (h)-[:LIKELY_USES]->(m)
        """)
        print("   ✓ Linked hackers to mixers")
        
        # Mixers connect to exchanges (exit points)
        await conn.execute("""
            MATCH (m:Mixer), (e:Exchange)
            MERGE (m)-[:EXITS_TO]->(e)
        """)
        print("   ✓ Linked mixers to exchanges")
        
        # ====================================================================
        # 5. Create Flash Loan Attack Paths
        # ====================================================================
        print("\n⚡ Creating flash loan attack paths...")
        
        # Flash loan -> DEX -> Lending (classic attack)
        await conn.execute("""
            MATCH (f:FlashLoanProvider), (d:Protocol {category: 'dex'}), (l:Protocol {category: 'lending'})
            MERGE (f)-[:ATTACK_STEP_1]->(d)
            MERGE (d)-[:ATTACK_STEP_2]->(l)
        """)
        print("   ✓ Created flash loan attack paths")
        
        # ====================================================================
        # 6. Create Risk Propagation Relationships
        # ====================================================================
        print("\n⚠️ Creating risk propagation relationships...")
        
        # High-risk entities propagate risk to connected entities
        await conn.execute("""
            MATCH (h:Hacker)-[r]->(target)
            SET target.associated_risk = COALESCE(target.associated_risk, 0) + 50
        """)
        
        await conn.execute("""
            MATCH (s:Sanctioned)-[r]->(target)
            SET target.associated_risk = COALESCE(target.associated_risk, 0) + 80
        """)
        
        await conn.execute("""
            MATCH (m:Mixer)<-[r]-(source)
            SET source.mixer_association = true
        """)
        print("   ✓ Propagated risk scores")
        
        # ====================================================================
        # 7. Create Attack Vector Templates
        # ====================================================================
        print("\n🎯 Creating attack vector templates...")
        
        # Create template nodes for common attack patterns
        attack_vectors = [
            {"name": "Flash Loan Attack", "severity": "CRITICAL", "steps": 4},
            {"name": "Oracle Manipulation", "severity": "CRITICAL", "steps": 3},
            {"name": "Reentrancy", "severity": "HIGH", "steps": 2},
            {"name": "Bridge Exploit", "severity": "CRITICAL", "steps": 3},
            {"name": "Admin Key Compromise", "severity": "CRITICAL", "steps": 2},
            {"name": "Governance Attack", "severity": "HIGH", "steps": 4},
            {"name": "Rug Pull", "severity": "HIGH", "steps": 2},
            {"name": "Sandwich Attack", "severity": "MEDIUM", "steps": 3},
        ]
        
        for vector in attack_vectors:
            await conn.execute("""
                MERGE (v:AttackVector {name: $name})
                SET v.severity = $severity,
                    v.typical_steps = $steps,
                    v.created_at = datetime()
            """, vector)
        print(f"   ✓ Created {len(attack_vectors)} attack vector templates")
        
        # Link attack vectors to relevant entities
        await conn.execute("""
            MATCH (v:AttackVector {name: 'Flash Loan Attack'}), (f:FlashLoanProvider)
            MERGE (v)-[:STARTS_WITH]->(f)
        """)
        
        await conn.execute("""
            MATCH (v:AttackVector {name: 'Oracle Manipulation'}), (o:Oracle)
            MERGE (v)-[:TARGETS]->(o)
        """)
        
        await conn.execute("""
            MATCH (v:AttackVector {name: 'Bridge Exploit'}), (b:Bridge)
            MERGE (v)-[:TARGETS]->(b)
        """)
        print("   ✓ Linked attack vectors to entities")
        
        # ====================================================================
        # 8. Create Index for Fast Path Queries
        # ====================================================================
        print("\n📈 Creating indexes for fast path queries...")
        
        indexes = [
            "CREATE INDEX IF NOT EXISTS FOR (w:Wallet) ON (w.risk_score)",
            "CREATE INDEX IF NOT EXISTS FOR (c:Contract) ON (c.risk_score)",
            "CREATE INDEX IF NOT EXISTS FOR (h:Hacker) ON (h.exploit_amount_usd)",
            "CREATE INDEX IF NOT EXISTS FOR (p:Protocol) ON (p.tvl_usd)",
        ]
        
        for idx in indexes:
            try:
                await conn.execute(idx)
            except:
                pass  # Index may already exist
        print("   ✓ Created performance indexes")
        
        # ====================================================================
        # Verify Results
        # ====================================================================
        print("\n🔍 Verifying attack path relationships...")
        
        # Count relationships
        result = await conn.execute("""
            MATCH ()-[r]->()
            RETURN type(r) as rel_type, count(*) as count
            ORDER BY count DESC
            LIMIT 20
        """)
        
        print("\n📊 Relationship Statistics:")
        records = await result.values()
        for record in records:
            print(f"   • {record[0]}: {record[1]} relationships")
        
        # Test a sample attack path query
        print("\n🧪 Testing attack path query...")
        result = await conn.execute("""
            MATCH path = (f:FlashLoanProvider)-[*1..3]->(m:Mixer)
            RETURN count(path) as path_count
        """)
        records = await result.values()
        path_count = records[0][0] if records else 0
        print(f"   Found {path_count} potential flash loan → mixer paths")
        
        # Get graph stats
        health = await conn.health_check()
        print(f"\n📊 Final Graph Statistics:")
        print(f"   Status: {health.get('status', 'unknown')}")
        node_counts = health.get('node_counts', {})
        for label, count in sorted(node_counts.items(), key=lambda x: -x[1]):
            print(f"   • {label}: {count} nodes")
        
        print("\n" + "="*60)
        print("✅ Attack Path Relationships Built!")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        raise
    finally:
        await conn.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build attack path relationships")
    parser.add_argument("--uri", help="Neo4j URI", default=os.getenv("NEO4J_URI"))
    parser.add_argument("--username", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", help="Neo4j password", default=os.getenv("NEO4J_PASSWORD"))
    
    args = parser.parse_args()
    
    if not args.uri or not args.password:
        print("❌ Error: NEO4J_URI and NEO4J_PASSWORD required")
        sys.exit(1)
    
    asyncio.run(build_attack_paths(args.uri, args.username, args.password))
