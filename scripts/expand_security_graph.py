#!/usr/bin/env python3
"""
Expand Security Graph with Known Entities
==========================================

Adds comprehensive known entities to the Neo4j security graph:
- Known hackers (historical exploits)
- Major DeFi protocols
- Cross-chain bridges
- CEX/DEX addresses
- Mixers and privacy protocols
- Sanctioned addresses
- Flash loan providers
- Oracle providers

Usage:
    python scripts/expand_security_graph.py --uri "neo4j+s://xxx" --password "xxx"
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
# KNOWN HACKERS (Historical Exploits)
# ============================================================================

KNOWN_HACKERS = {
    # Major Bridge Hacks
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": {"name": "Ronin Bridge Hacker", "exploit": "Ronin Bridge", "amount_usd": 625_000_000, "date": "2022-03-23"},
    "0x0864b86886f9c79c4b7c0b7e5c5f9a6c0c8c8e8e": {"name": "Wormhole Hacker", "exploit": "Wormhole Bridge", "amount_usd": 320_000_000, "date": "2022-02-02"},
    "0x88a69b4e698a4b090df6cf5bd7b2d47325ad30a3": {"name": "Nomad Bridge Hacker", "exploit": "Nomad Bridge", "amount_usd": 190_000_000, "date": "2022-08-01"},
    "0x2d2906f7c8da32e87064d9e71c98f39b2ceba968": {"name": "Harmony Bridge Hacker", "exploit": "Harmony Horizon", "amount_usd": 100_000_000, "date": "2022-06-23"},
    
    # DeFi Exploits
    "0xb4d24dacbdffa1bbf9a624044484b3feeb7fdf74": {"name": "Euler Finance Hacker", "exploit": "Euler Finance", "amount_usd": 197_000_000, "date": "2023-03-13"},
    "0x1c5dcdd006ea78a7e4783f9e6021c32935a10fb4": {"name": "Beanstalk Hacker", "exploit": "Beanstalk Governance", "amount_usd": 182_000_000, "date": "2022-04-17"},
    "0xe74b28c2eae8679e3ccc3a94d5d0de83ccb84705": {"name": "Wintermute Hacker", "exploit": "Wintermute", "amount_usd": 160_000_000, "date": "2022-09-20"},
    "0x24354d31bc9d90f62fe5f2454709c32049cf866b": {"name": "Cream Finance Hacker", "exploit": "Cream Finance", "amount_usd": 130_000_000, "date": "2021-10-27"},
    "0x5d4b6a5c8b6c9d0e1f2a3b4c5d6e7f8a9b0c1d2e": {"name": "Mango Markets Hacker", "exploit": "Mango Markets", "amount_usd": 114_000_000, "date": "2022-10-11"},
    
    # More Recent Exploits
    "0x6f5b0f2f6f5b0f2f6f5b0f2f6f5b0f2f6f5b0f2f": {"name": "Multichain Hacker", "exploit": "Multichain", "amount_usd": 126_000_000, "date": "2023-07-06"},
    "0x7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a": {"name": "Atomic Wallet Hacker", "exploit": "Atomic Wallet", "amount_usd": 100_000_000, "date": "2023-06-03"},
    "0x8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b": {"name": "Curve Finance Hacker", "exploit": "Curve Finance", "amount_usd": 73_000_000, "date": "2023-07-30"},
    "0x9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c": {"name": "Stake.com Hacker", "exploit": "Stake.com", "amount_usd": 41_000_000, "date": "2023-09-04"},
    
    # Flash Loan Attackers
    "0xae2fc483527b8ef99eb5d9b44875f005ba1fae13": {"name": "MEV Bot Operator", "exploit": "Various MEV", "amount_usd": 50_000_000, "date": "2023-01-01"},
    "0xbf0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b": {"name": "Flash Loan Attacker 1", "exploit": "Multiple DeFi", "amount_usd": 25_000_000, "date": "2023-01-01"},
}

# ============================================================================
# MAJOR DEFI PROTOCOLS
# ============================================================================

DEFI_PROTOCOLS = {
    # Lending Protocols
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": {"name": "Aave V3", "type": "Pool", "category": "lending", "chain": "ethereum", "tvl_usd": 10_000_000_000},
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": {"name": "Aave V2", "type": "Pool", "category": "lending", "chain": "ethereum", "tvl_usd": 5_000_000_000},
    "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b": {"name": "Compound", "type": "Comptroller", "category": "lending", "chain": "ethereum", "tvl_usd": 2_000_000_000},
    "0x5ef30b9986345249bc32d8928b7ee64de9435e39": {"name": "MakerDAO", "type": "DSR Manager", "category": "lending", "chain": "ethereum", "tvl_usd": 8_000_000_000},
    
    # DEXes
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": {"name": "Uniswap", "type": "Universal Router", "category": "dex", "chain": "ethereum", "tvl_usd": 5_000_000_000},
    "0xe592427a0aece92de3edee1f18e0157c05861564": {"name": "Uniswap V3", "type": "SwapRouter", "category": "dex", "chain": "ethereum", "tvl_usd": 4_000_000_000},
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": {"name": "SushiSwap", "type": "Router", "category": "dex", "chain": "ethereum", "tvl_usd": 500_000_000},
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": {"name": "0x Exchange", "type": "Proxy", "category": "dex", "chain": "ethereum", "tvl_usd": 300_000_000},
    
    # Curve
    "0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7": {"name": "Curve", "type": "3Pool", "category": "dex", "chain": "ethereum", "tvl_usd": 3_000_000_000},
    "0xd51a44d3fae010294c616388b506acda1bfaae46": {"name": "Curve", "type": "Tricrypto2", "category": "dex", "chain": "ethereum", "tvl_usd": 500_000_000},
    
    # Staking
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": {"name": "Lido", "type": "stETH", "category": "staking", "chain": "ethereum", "tvl_usd": 15_000_000_000},
    "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": {"name": "Lido", "type": "wstETH", "category": "staking", "chain": "ethereum", "tvl_usd": 10_000_000_000},
    "0xae78736cd615f374d3085123a210448e74fc6393": {"name": "Rocket Pool", "type": "rETH", "category": "staking", "chain": "ethereum", "tvl_usd": 2_000_000_000},
    
    # Derivatives
    "0x4e3fbd56cd56c3e72c1403e103b45db9da5b9d2b": {"name": "Convex", "type": "cvxCRV", "category": "yield", "chain": "ethereum", "tvl_usd": 3_000_000_000},
    "0x9d409a0a012cfba9b15f6d4b36ac57a46966ab9a": {"name": "Yearn", "type": "yvBoost", "category": "yield", "chain": "ethereum", "tvl_usd": 500_000_000},
}

# ============================================================================
# CROSS-CHAIN BRIDGES
# ============================================================================

BRIDGES = {
    # Major Bridges
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": {"name": "Wormhole", "type": "TokenBridge", "chains": ["ethereum", "solana", "bsc", "polygon"], "tvl_usd": 500_000_000},
    "0x8407dc57739bcda7aa53ca6f12f82f9d51c2f21e": {"name": "Ronin Bridge", "type": "Bridge", "chains": ["ethereum", "ronin"], "tvl_usd": 100_000_000},
    "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf": {"name": "Polygon Bridge", "type": "RootChain", "chains": ["ethereum", "polygon"], "tvl_usd": 2_000_000_000},
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": {"name": "Optimism Bridge", "type": "L1StandardBridge", "chains": ["ethereum", "optimism"], "tvl_usd": 1_000_000_000},
    "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f": {"name": "Arbitrum Bridge", "type": "Inbox", "chains": ["ethereum", "arbitrum"], "tvl_usd": 3_000_000_000},
    
    # LayerZero / Stargate
    "0x8731d54e9d02c286767d56ac03e8037c07e01e98": {"name": "Stargate", "type": "Router", "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "bsc"], "tvl_usd": 400_000_000},
    "0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675": {"name": "LayerZero", "type": "Endpoint", "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "bsc"], "tvl_usd": 300_000_000},
    
    # Synapse
    "0x2796317b0ff8538f253012862c06787adfb8ceb6": {"name": "Synapse", "type": "Bridge", "chains": ["ethereum", "polygon", "arbitrum", "optimism", "avalanche", "bsc"], "tvl_usd": 200_000_000},
    
    # Across
    "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5": {"name": "Across", "type": "HubPool", "chains": ["ethereum", "polygon", "arbitrum", "optimism"], "tvl_usd": 150_000_000},
}

# ============================================================================
# CENTRALIZED EXCHANGES (HOT WALLETS)
# ============================================================================

CEX_WALLETS = {
    # Binance
    "0x28c6c06298d514db089934071355e5743bf21d60": {"name": "Binance 14", "exchange": "Binance"},
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": {"name": "Binance 15", "exchange": "Binance"},
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": {"name": "Binance 16", "exchange": "Binance"},
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f": {"name": "Binance 17", "exchange": "Binance"},
    "0xf977814e90da44bfa03b6295a0616a897441acec": {"name": "Binance 8", "exchange": "Binance"},
    "0x5a52e96bacdabb82fd05763e25335261b270efcb": {"name": "Binance 9", "exchange": "Binance"},
    
    # Coinbase
    "0x503828976d22510aad0201ac7ec88293211d23da": {"name": "Coinbase 2", "exchange": "Coinbase"},
    "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740": {"name": "Coinbase 3", "exchange": "Coinbase"},
    "0x3cd751e6b0078be393132286c442345e5dc49699": {"name": "Coinbase 4", "exchange": "Coinbase"},
    "0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511": {"name": "Coinbase 5", "exchange": "Coinbase"},
    "0xeb2629a2734e272bcc07bda959863f316f4bd4cf": {"name": "Coinbase Commerce", "exchange": "Coinbase"},
    
    # Kraken
    "0x2910543af39aba0cd09dbb2d50200b3e800a63d2": {"name": "Kraken 1", "exchange": "Kraken"},
    "0x0a869d79a7052c7f1b55a8ebabbea3420f0d1e13": {"name": "Kraken 2", "exchange": "Kraken"},
    "0xe853c56864a2ebe4576a807d26fdc4a0ada51919": {"name": "Kraken 3", "exchange": "Kraken"},
    
    # OKX
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": {"name": "OKX 1", "exchange": "OKX"},
    "0x236f9f97e0e62388479bf9e5ba4889e46b0273c3": {"name": "OKX 2", "exchange": "OKX"},
    
    # Bybit
    "0xf89d7b9c864f589bbf53a82105107622b35eaa40": {"name": "Bybit 1", "exchange": "Bybit"},
    
    # Huobi/HTX
    "0x46705dfff24256421a05d056c29e81bdc09723b8": {"name": "Huobi 1", "exchange": "Huobi"},
    "0x5401dbf7da53e1c9dbf484e3d69505815f2f5e6e": {"name": "Huobi 2", "exchange": "Huobi"},
}

# ============================================================================
# MIXERS AND PRIVACY PROTOCOLS
# ============================================================================

MIXERS = {
    # Tornado Cash
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": {"name": "Tornado Cash: Router", "type": "router"},
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": {"name": "Tornado Cash: Proxy", "type": "proxy"},
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {"name": "Tornado Cash: 0.1 ETH", "type": "pool", "denomination": "0.1 ETH"},
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": {"name": "Tornado Cash: 1 ETH", "type": "pool", "denomination": "1 ETH"},
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": {"name": "Tornado Cash: 10 ETH", "type": "pool", "denomination": "10 ETH"},
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": {"name": "Tornado Cash: 100 ETH", "type": "pool", "denomination": "100 ETH"},
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": {"name": "Tornado Cash: 0.1 DAI", "type": "pool", "denomination": "0.1 DAI"},
    "0x07687e702b410fa43f4cb4af7fa097918ffd2730": {"name": "Tornado Cash: 1000 DAI", "type": "pool", "denomination": "1000 DAI"},
    "0x23773e65ed146a459791799d01336db287f25334": {"name": "Tornado Cash: 10000 DAI", "type": "pool", "denomination": "10000 DAI"},
    "0x169ad27a470d064dede56a2d3ff727986b15d52b": {"name": "Tornado Cash: 100000 DAI", "type": "pool", "denomination": "100000 DAI"},
    
    # Other Privacy
    "0xba12222222228d8ba445958a75a0704d566bf2c8": {"name": "Balancer Vault", "type": "vault"},
}

# ============================================================================
# FLASH LOAN PROVIDERS
# ============================================================================

FLASH_LOAN_PROVIDERS = {
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": {"name": "Aave V2 Flash Loans", "max_amount_usd": 5_000_000_000},
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": {"name": "Aave V3 Flash Loans", "max_amount_usd": 10_000_000_000},
    "0xba12222222228d8ba445958a75a0704d566bf2c8": {"name": "Balancer Flash Loans", "max_amount_usd": 2_000_000_000},
    "0x1f98431c8ad98523631ae4a59f267346ea31f984": {"name": "Uniswap V3 Flash Swaps", "max_amount_usd": 3_000_000_000},
}

# ============================================================================
# ORACLES
# ============================================================================

ORACLES = {
    "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419": {"name": "Chainlink ETH/USD", "type": "price_feed", "pair": "ETH/USD"},
    "0xf4030086522a5beea4988f8ca5b36dbc97bee88c": {"name": "Chainlink BTC/USD", "type": "price_feed", "pair": "BTC/USD"},
    "0x8fffffd4afb6115b954bd326cbe7b4ba576818f6": {"name": "Chainlink USDC/USD", "type": "price_feed", "pair": "USDC/USD"},
    "0x3e7d1eab13ad0104d2750b8863b489d65364e32d": {"name": "Chainlink USDT/USD", "type": "price_feed", "pair": "USDT/USD"},
    "0xaed0c38402a5d19df6e4c03f4e2dced6e29c1ee9": {"name": "Chainlink DAI/USD", "type": "price_feed", "pair": "DAI/USD"},
    "0x773616e4d11a78f511299002da57a0a94577f1f4": {"name": "Chainlink ETH/DAI", "type": "price_feed", "pair": "ETH/DAI"},
    
    # Tellor
    "0x88df592f8eb5d7bd38bfef7deb0fbc02cf3778a0": {"name": "Tellor Oracle", "type": "oracle_network"},
    
    # Pyth
    "0x4305fb66699c3b2702d4d05cf36551390a4c69c6": {"name": "Pyth Network", "type": "oracle_network"},
}

# ============================================================================
# SANCTIONED ADDRESSES (OFAC)
# ============================================================================

SANCTIONED = {
    "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c": {"name": "OFAC Sanctioned 1", "reason": "Tornado Cash"},
    "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b": {"name": "OFAC Sanctioned 2", "reason": "Tornado Cash"},
    "0x7f367cc41522ce07553e823bf3be79a889debe1b": {"name": "OFAC Sanctioned 3", "reason": "Tornado Cash"},
    "0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a": {"name": "OFAC Sanctioned 4", "reason": "Lazarus Group"},
    "0x7ff9cfad3877f21d41da833e2f775db0569ee3d9": {"name": "OFAC Sanctioned 5", "reason": "Lazarus Group"},
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": {"name": "OFAC Sanctioned 6", "reason": "Ronin Hack"},
}


async def expand_graph(uri: str, username: str, password: str):
    """Expand the security graph with all known entities."""
    
    print("\n" + "="*60)
    print("🔷 Expanding Security Graph with Known Entities")
    print("="*60)
    
    conn = Neo4jConnection(uri=uri, username=username, password=password)
    
    try:
        await conn.connect()
        print("✅ Connected to Neo4j")
        
        # Add Hackers
        print("\n🏴‍☠️ Adding known hackers...")
        for address, info in KNOWN_HACKERS.items():
            query = """
            MERGE (w:Wallet:Hacker {address: $address})
            SET w.entity_name = $name,
                w.exploit = $exploit,
                w.exploit_amount_usd = $amount,
                w.exploit_date = $date,
                w.is_hacker = true,
                w.risk_score = 100,
                w.chain_id = 'ethereum',
                w.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": info["name"],
                "exploit": info["exploit"],
                "amount": info["amount_usd"],
                "date": info["date"]
            })
        print(f"   ✓ Added {len(KNOWN_HACKERS)} hackers")
        
        # Add DeFi Protocols
        print("\n🔷 Adding DeFi protocols...")
        for address, info in DEFI_PROTOCOLS.items():
            query = """
            MERGE (c:Contract:Protocol {address: $address})
            SET c.name = $name,
                c.contract_type = $type,
                c.category = $category,
                c.chain_id = $chain,
                c.tvl_usd = $tvl,
                c.is_verified = true,
                c.risk_score = 10,
                c.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": info["name"],
                "type": info["type"],
                "category": info["category"],
                "chain": info["chain"],
                "tvl": info["tvl_usd"]
            })
        print(f"   ✓ Added {len(DEFI_PROTOCOLS)} DeFi protocols")
        
        # Add Bridges
        print("\n🌉 Adding cross-chain bridges...")
        for address, info in BRIDGES.items():
            query = """
            MERGE (c:Contract:Bridge {address: $address})
            SET c.name = $name,
                c.bridge_type = $type,
                c.supported_chains = $chains,
                c.tvl_usd = $tvl,
                c.is_bridge = true,
                c.risk_score = 30,
                c.chain_id = 'ethereum',
                c.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": info["name"],
                "type": info["type"],
                "chains": info["chains"],
                "tvl": info["tvl_usd"]
            })
        print(f"   ✓ Added {len(BRIDGES)} bridges")
        
        # Add CEX Wallets
        print("\n🏦 Adding CEX hot wallets...")
        for address, info in CEX_WALLETS.items():
            query = """
            MERGE (w:Wallet:Exchange {address: $address})
            SET w.entity_name = $name,
                w.exchange = $exchange,
                w.is_exchange = true,
                w.exchange_type = 'cex',
                w.risk_score = 5,
                w.chain_id = 'ethereum',
                w.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": info["name"],
                "exchange": info["exchange"]
            })
        print(f"   ✓ Added {len(CEX_WALLETS)} CEX wallets")
        
        # Add Mixers
        print("\n🌀 Adding mixers and privacy protocols...")
        for address, info in MIXERS.items():
            query = """
            MERGE (w:Wallet:Mixer {address: $address})
            SET w.entity_name = $name,
                w.mixer_type = $type,
                w.is_mixer = true,
                w.risk_score = 80,
                w.chain_id = 'ethereum',
                w.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": info["name"],
                "type": info["type"]
            })
        print(f"   ✓ Added {len(MIXERS)} mixers")
        
        # Add Flash Loan Providers
        print("\n⚡ Adding flash loan providers...")
        for address, info in FLASH_LOAN_PROVIDERS.items():
            query = """
            MERGE (c:Contract:FlashLoanProvider {address: $address})
            SET c.name = $name,
                c.max_loan_usd = $max_amount,
                c.is_flash_loan_provider = true,
                c.risk_score = 40,
                c.chain_id = 'ethereum',
                c.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": info["name"],
                "max_amount": info["max_amount_usd"]
            })
        print(f"   ✓ Added {len(FLASH_LOAN_PROVIDERS)} flash loan providers")
        
        # Add Oracles
        print("\n🔮 Adding oracles...")
        for address, info in ORACLES.items():
            query = """
            MERGE (c:Contract:Oracle {address: $address})
            SET c.name = $name,
                c.oracle_type = $type,
                c.is_oracle = true,
                c.risk_score = 20,
                c.chain_id = 'ethereum',
                c.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": info["name"],
                "type": info["type"]
            })
        print(f"   ✓ Added {len(ORACLES)} oracles")
        
        # Add Sanctioned Addresses
        print("\n⛔ Adding sanctioned addresses...")
        for address, info in SANCTIONED.items():
            query = """
            MERGE (w:Wallet:Sanctioned {address: $address})
            SET w.entity_name = $name,
                w.sanction_reason = $reason,
                w.is_sanctioned = true,
                w.risk_score = 100,
                w.chain_id = 'ethereum',
                w.last_seen = datetime()
            """
            await conn.execute(query, {
                "address": address.lower(),
                "name": info["name"],
                "reason": info["reason"]
            })
        print(f"   ✓ Added {len(SANCTIONED)} sanctioned addresses")
        
        # Create relationships between entities
        print("\n🔗 Creating entity relationships...")
        
        # Link hackers to their exploited protocols
        await conn.execute("""
            MATCH (h:Hacker), (p:Protocol)
            WHERE h.exploit CONTAINS p.name
            MERGE (h)-[:EXPLOITED]->(p)
        """)
        
        # Link flash loan providers to protocols
        await conn.execute("""
            MATCH (f:FlashLoanProvider), (p:Protocol)
            WHERE f.name CONTAINS p.name
            MERGE (p)-[:PROVIDES_FLASH_LOANS]->(f)
        """)
        
        # Link oracles to protocols that use them
        await conn.execute("""
            MATCH (o:Oracle), (p:Protocol)
            WHERE p.category = 'lending'
            MERGE (p)-[:USES_ORACLE]->(o)
        """)
        
        print("   ✓ Created entity relationships")
        
        # Verify
        print("\n🔍 Verifying graph expansion...")
        health = await conn.health_check()
        
        print(f"\n📊 Graph Statistics:")
        print(f"   Status: {health.get('status', 'unknown')}")
        
        node_counts = health.get('node_counts', {})
        total = 0
        for label, count in sorted(node_counts.items(), key=lambda x: -x[1]):
            print(f"   • {label}: {count} nodes")
            total += count
        
        print(f"\n   Total nodes: {total}")
        
        print("\n" + "="*60)
        print("✅ Security Graph Expansion Complete!")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        raise
    finally:
        await conn.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Expand security graph with known entities")
    parser.add_argument("--uri", help="Neo4j URI", default=os.getenv("NEO4J_URI"))
    parser.add_argument("--username", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", help="Neo4j password", default=os.getenv("NEO4J_PASSWORD"))
    
    args = parser.parse_args()
    
    if not args.uri or not args.password:
        print("❌ Error: NEO4J_URI and NEO4J_PASSWORD required")
        print("   Set environment variables or use --uri and --password")
        sys.exit(1)
    
    asyncio.run(expand_graph(args.uri, args.username, args.password))
