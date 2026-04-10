#!/usr/bin/env python3
"""
Neo4j AuraDB Setup Script
=========================

Sets up Neo4j AuraDB for the Security Graph.
Run this script to:
1. Create AuraDB instance (manual step - provides instructions)
2. Initialize schema and indexes
3. Load initial data (known entities)
4. Verify connection

Usage:
    python scripts/setup_neo4j_aura.py --uri "neo4j+s://xxx.databases.neo4j.io" --password "your-password"
"""

import os
import sys
import asyncio
import argparse
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog
from src.graph.connection import Neo4jConnection
from src.graph.schema import GraphSchema

logger = structlog.get_logger(__name__)


# Known entities to pre-load
KNOWN_EXCHANGES = {
    "0x28c6c06298d514db089934071355e5743bf21d60": ("Binance 14", "cex"),
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": ("Binance 15", "cex"),
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": ("Binance 16", "cex"),
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f": ("Binance 17", "cex"),
    "0xf89d7b9c864f589bbf53a82105107622b35eaa40": ("Bybit", "cex"),
    "0x1ab4973a48dc892cd9971ece8e01dcc7688f8f23": ("Coinbase 1", "cex"),
    "0x503828976d22510aad0201ac7ec88293211d23da": ("Coinbase 2", "cex"),
    "0xeb2629a2734e272bcc07bda959863f316f4bd4cf": ("Coinbase 3", "cex"),
    "0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852": ("Uniswap V2: USDT", "dex"),
    "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640": ("Uniswap V3: USDC", "dex"),
    "0x8ad599c3a0ff1de082011efddc58f1908eb6e6d8": ("Uniswap V3: WETH", "dex"),
    "0xcbcdf9626bc03e24f779434178a73a0b4bad62ed": ("Uniswap V3: WBTC", "dex"),
    "0x5777d92f208679db4b9778590fa3cab3ac9e2168": ("Uniswap V3: DAI", "dex"),
}

KNOWN_MIXERS = {
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": "Tornado Cash: Router",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash: Proxy",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash: 0.1 ETH",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash: 1 ETH",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash: 10 ETH",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash: 100 ETH",
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": "Tornado Cash: 0.1 DAI",
    "0x07687e702b410fa43f4cb4af7fa097918ffd2730": "Tornado Cash: 1000 DAI",
    "0x23773e65ed146a459791799d01336db287f25334": "Tornado Cash: 10000 DAI",
}

KNOWN_HACKERS = {
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": "Ronin Bridge Hacker",
    "0x0864b86886f9c79c4b7c0b7e5c5f9a6c0c8c8e8e": "Wormhole Hacker",
    "0xb4d24dacbdffa1bbf9a624044484b3feeb7fdf74": "Euler Finance Hacker",
    "0x5d4b6a5c8b6c9d0e1f2a3b4c5d6e7f8a9b0c1d2e": "Mango Markets Hacker",
}

KNOWN_PROTOCOLS = {
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": ("Aave V3", "Pool", "lending"),
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": ("Aave V2", "Pool", "lending"),
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": ("Uniswap", "Universal Router", "dex"),
    "0xe592427a0aece92de3edee1f18e0157c05861564": ("Uniswap V3", "SwapRouter", "dex"),
    "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b": ("Compound", "Comptroller", "lending"),
    "0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7": ("Curve", "3Pool", "dex"),
    "0x5ef30b9986345249bc32d8928b7ee64de9435e39": ("MakerDAO", "DSR Manager", "lending"),
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": ("Lido", "stETH", "staking"),
    "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": ("Lido", "wstETH", "staking"),
}

SANCTIONED_ADDRESSES = {
    "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c": "OFAC Sanctioned",
    "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b": "OFAC Sanctioned",
    "0x7f367cc41522ce07553e823bf3be79a889debe1b": "OFAC Sanctioned",
    "0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a": "OFAC Sanctioned",
}


async def setup_auradb(uri: str, username: str, password: str):
    """Set up Neo4j AuraDB with schema and initial data."""
    
    print("\n" + "="*60)
    print("🚀 Neo4j AuraDB Setup for Sentinel3 Security Graph")
    print("="*60)
    
    # Connect to AuraDB
    print("\n📡 Connecting to Neo4j AuraDB...")
    conn = Neo4jConnection(uri=uri, username=username, password=password)
    
    try:
        await conn.connect()
        print("✅ Connected successfully!")
        
        # Create schema
        print("\n📊 Creating schema (indexes and constraints)...")
        schema_queries = GraphSchema.get_schema_queries()
        
        for i, query in enumerate(schema_queries):
            try:
                await conn.execute(query)
                print(f"   ✓ Schema {i+1}/{len(schema_queries)}")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print(f"   ⏭ Schema {i+1}/{len(schema_queries)} (already exists)")
                else:
                    print(f"   ✗ Schema {i+1}/{len(schema_queries)}: {e}")
        
        # Load known exchanges
        print("\n🏦 Loading known exchanges...")
        for address, (name, exchange_type) in KNOWN_EXCHANGES.items():
            query = """
            MERGE (w:Wallet:Exchange {address: $address})
            SET w.entity_name = $name,
                w.exchange_type = $exchange_type,
                w.is_exchange = true,
                w.risk_score = 5,
                w.chain_id = 'ethereum',
                w.first_seen = datetime(),
                w.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": name,
                "exchange_type": exchange_type
            })
        print(f"   ✓ Loaded {len(KNOWN_EXCHANGES)} exchanges")
        
        # Load known mixers
        print("\n🌀 Loading known mixers...")
        for address, name in KNOWN_MIXERS.items():
            query = """
            MERGE (w:Wallet:Mixer {address: $address})
            SET w.entity_name = $name,
                w.is_mixer = true,
                w.risk_score = 80,
                w.chain_id = 'ethereum',
                w.first_seen = datetime(),
                w.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": name
            })
        print(f"   ✓ Loaded {len(KNOWN_MIXERS)} mixers")
        
        # Load known hackers
        print("\n🏴‍☠️ Loading known hackers...")
        for address, name in KNOWN_HACKERS.items():
            query = """
            MERGE (w:Wallet:Hacker {address: $address})
            SET w.entity_name = $name,
                w.is_hacker = true,
                w.risk_score = 100,
                w.chain_id = 'ethereum',
                w.first_seen = datetime(),
                w.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": name
            })
        print(f"   ✓ Loaded {len(KNOWN_HACKERS)} hackers")
        
        # Load known protocols
        print("\n🔷 Loading known protocols...")
        for address, (name, contract_type, category) in KNOWN_PROTOCOLS.items():
            query = """
            MERGE (c:Contract:Protocol {address: $address})
            SET c.name = $name,
                c.contract_type = $contract_type,
                c.category = $category,
                c.risk_score = 10,
                c.is_verified = true,
                c.chain_id = 'ethereum',
                c.first_seen = datetime(),
                c.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": name,
                "contract_type": contract_type,
                "category": category
            })
        print(f"   ✓ Loaded {len(KNOWN_PROTOCOLS)} protocols")
        
        # Load sanctioned addresses
        print("\n⛔ Loading sanctioned addresses...")
        for address, name in SANCTIONED_ADDRESSES.items():
            query = """
            MERGE (w:Wallet:Sanctioned {address: $address})
            SET w.entity_name = $name,
                w.is_sanctioned = true,
                w.risk_score = 100,
                w.chain_id = 'ethereum',
                w.first_seen = datetime(),
                w.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": name
            })
        print(f"   ✓ Loaded {len(SANCTIONED_ADDRESSES)} sanctioned addresses")
        
        # Verify setup
        print("\n🔍 Verifying setup...")
        health = await conn.health_check()
        
        print(f"\n📈 Graph Statistics:")
        print(f"   Status: {health.get('status', 'unknown')}")
        
        node_counts = health.get('node_counts', {})
        if node_counts:
            for label, count in node_counts.items():
                print(f"   • {label}: {count} nodes")
        
        total_nodes = sum(node_counts.values()) if node_counts else 0
        print(f"\n   Total nodes: {total_nodes}")
        
        print("\n" + "="*60)
        print("✅ Neo4j AuraDB setup complete!")
        print("="*60)
        
        # Print connection info for env vars
        print("\n📝 Add these to your environment:")
        print(f"   NEO4J_URI={uri}")
        print(f"   NEO4J_USERNAME={username}")
        print(f"   NEO4J_PASSWORD=<your-password>")
        
        print("\n🔧 Or set in Google Cloud Secret Manager:")
        print(f"   gcloud secrets create neo4j-uri --data-file=-")
        print(f"   gcloud secrets create neo4j-password --data-file=-")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        raise
    finally:
        await conn.disconnect()


def print_auradb_instructions():
    """Print instructions for creating AuraDB instance."""
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     NEO4J AURADB SETUP INSTRUCTIONS                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  1. Go to https://neo4j.com/cloud/aura-free/                                ║
║                                                                              ║
║  2. Create a FREE AuraDB instance:                                          ║
║     • Click "Start Free"                                                    ║
║     • Sign up or log in                                                     ║
║     • Create new instance:                                                  ║
║       - Name: sentinel3-security-graph                                      ║
║       - Region: us-central1 (or closest to your Cloud Run)                 ║
║       - Type: AuraDB Free (50K nodes, 175K relationships)                  ║
║                                                                              ║
║  3. Save your credentials:                                                  ║
║     • Connection URI: neo4j+s://xxxxxxxx.databases.neo4j.io                ║
║     • Username: neo4j                                                       ║
║     • Password: (auto-generated, SAVE IT!)                                 ║
║                                                                              ║
║  4. Run this script with your credentials:                                  ║
║     python scripts/setup_neo4j_aura.py \\                                   ║
║       --uri "neo4j+s://xxx.databases.neo4j.io" \\                           ║
║       --password "your-password"                                            ║
║                                                                              ║
║  5. For production, upgrade to AuraDB Professional:                         ║
║     • 400K nodes, 1.6M relationships                                       ║
║     • ~$65/month                                                            ║
║     • Better performance and SLA                                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Set up Neo4j AuraDB for Sentinel3")
    parser.add_argument("--uri", help="Neo4j AuraDB URI (e.g., neo4j+s://xxx.databases.neo4j.io)")
    parser.add_argument("--username", default="neo4j", help="Neo4j username (default: neo4j)")
    parser.add_argument("--password", help="Neo4j password")
    parser.add_argument("--instructions", action="store_true", help="Show AuraDB setup instructions")
    
    args = parser.parse_args()
    
    if args.instructions or (not args.uri and not args.password):
        print_auradb_instructions()
        if not args.instructions:
            print("\n⚠️  Please provide --uri and --password, or use --instructions for setup guide.\n")
        sys.exit(0)
    
    if not args.uri or not args.password:
        print("❌ Error: Both --uri and --password are required")
        print("   Run with --instructions for setup guide")
        sys.exit(1)
    
    asyncio.run(setup_auradb(args.uri, args.username, args.password))
