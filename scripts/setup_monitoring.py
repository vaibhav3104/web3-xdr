#!/usr/bin/env python3
"""
Sentinel3 - Setup Real Bridge Monitoring

This script helps you:
1. Test your RPC connections
2. Verify bridge contracts are accessible
3. Start monitoring real chains
"""

import asyncio
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def test_ethereum_connection(rpc_url: str):
    """Test Ethereum RPC connection."""
    try:
        from web3 import AsyncWeb3, AsyncHTTPProvider
        
        w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
        
        if not await w3.is_connected():
            return False, "Could not connect to RPC"
        
        block = await w3.eth.block_number
        chain_id = await w3.eth.chain_id
        
        return True, f"Connected! Block: {block:,}, Chain ID: {chain_id}"
        
    except Exception as e:
        return False, str(e)


async def test_bridge_contract(rpc_url: str, contract_address: str):
    """Test if bridge contract is accessible."""
    try:
        from web3 import AsyncWeb3, AsyncHTTPProvider
        
        w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
        
        # Get contract code
        code = await w3.eth.get_code(contract_address)
        
        if code == b'' or code == '0x':
            return False, "No contract at this address"
        
        return True, f"Contract found! Code size: {len(code)} bytes"
        
    except Exception as e:
        return False, str(e)


async def get_recent_events(rpc_url: str, contract_address: str, blocks: int = 100):
    """Get recent events from a contract."""
    try:
        from web3 import AsyncWeb3, AsyncHTTPProvider
        
        w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
        
        latest_block = await w3.eth.block_number
        from_block = latest_block - blocks
        
        logs = await w3.eth.get_logs({
            "fromBlock": from_block,
            "toBlock": "latest",
            "address": contract_address
        })
        
        return True, f"Found {len(logs)} events in last {blocks} blocks"
        
    except Exception as e:
        return False, str(e)


def print_banner():
    print()
    print("=" * 70)
    print("🛡️  Sentinel3 - Real Bridge Monitoring Setup")
    print("=" * 70)
    print()


def print_step(num: int, title: str):
    print(f"\n{'─' * 50}")
    print(f"📌 Step {num}: {title}")
    print(f"{'─' * 50}")


async def main():
    print_banner()
    
    # Check if API key is configured
    print_step(1, "Check Configuration")
    
    import yaml
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "chains.yaml")
    
    if not os.path.exists(config_path):
        print("❌ Config file not found!")
        print(f"   Expected: {config_path}")
        print("   Run: cp config/chains.example.yaml config/chains.yaml")
        return
    
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    # Check for placeholder API keys
    chains = config.get("chains", [])
    
    has_real_key = False
    for chain in chains:
        rpc_url = chain.get("rpc_url", "")
        if "YOUR_" in rpc_url or "YOUR_INFURA_KEY" in rpc_url:
            print(f"⚠️  {chain['chain_name']}: API key not configured")
            print(f"   Edit config/chains.yaml and replace YOUR_INFURA_KEY")
        else:
            has_real_key = True
            print(f"✅ {chain['chain_name']}: RPC URL configured")
    
    if not has_real_key:
        print()
        print("=" * 70)
        print("📋 HOW TO GET FREE INFURA API KEY:")
        print("=" * 70)
        print()
        print("1. Go to https://app.infura.io/register")
        print("2. Create a free account (email + password)")
        print("3. Click 'Create New API Key' → Select 'Web3 API'")
        print("4. Name it 'web3-xdr' and click Create")
        print("5. Copy your Project ID")
        print("6. Edit config/chains.yaml and replace YOUR_INFURA_KEY")
        print()
        print("Free tier: 100,000 requests/day")
        print()
        return
    
    # Test connections
    print_step(2, "Test RPC Connections")
    
    for chain in chains:
        rpc_url = chain.get("rpc_url", "")
        
        if "YOUR_" in rpc_url:
            continue
            
        print(f"\n🔗 Testing {chain['chain_name']}...")
        success, message = await test_ethereum_connection(rpc_url)
        
        if success:
            print(f"   ✅ {message}")
        else:
            print(f"   ❌ {message}")
    
    # Test bridge contracts
    print_step(3, "Test Bridge Contracts")
    
    for chain in chains:
        rpc_url = chain.get("rpc_url", "")
        
        if "YOUR_" in rpc_url:
            continue
        
        for contract in chain.get("bridge_contracts", [])[:2]:  # Test first 2
            print(f"\n📝 Testing {chain['chain_name']} contract {contract[:10]}...")
            success, message = await test_bridge_contract(rpc_url, contract)
            
            if success:
                print(f"   ✅ {message}")
                
                # Get recent events
                success2, message2 = await get_recent_events(rpc_url, contract)
                if success2:
                    print(f"   📊 {message2}")
            else:
                print(f"   ❌ {message}")
    
    # Summary
    print_step(4, "Ready to Monitor!")
    
    print()
    print("🚀 To start real-time monitoring, run:")
    print()
    print("   cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr")
    print("   ../venv/bin/python -m src.main --config config/chains.yaml")
    print()
    print("📊 Dashboard will be available at:")
    print("   http://localhost:8080/frontend/index.html")
    print()


if __name__ == "__main__":
    asyncio.run(main())

