#!/usr/bin/env python3
"""
Script to collect real bytecode from blockchain for ML training
Run this to build a high-quality training dataset from actual contracts

Usage:
    python scripts/collect_bytecode.py
    
    # With custom RPC endpoints:
    ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY python scripts/collect_bytecode.py
"""

import sys
import os
import asyncio

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ai.data.bytecode_collector import (
    BytecodeCollector,
    RealBytecodeFeatureExtractor,
    collect_training_bytecode,
    EXPLOIT_CONTRACTS,
    SAFE_CONTRACTS,
    SCAM_CONTRACTS
)


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██████╗    ║
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚════██╗   ║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      █████╔╝   ║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ╚═══██╗   ║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██████╔╝   ║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═════╝    ║
║                                                                              ║
║                    🔬 BYTECODE COLLECTOR FOR ML TRAINING                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


def print_dataset_summary():
    """Print summary of contracts we'll collect"""
    print("\n📋 Dataset Summary:")
    print("=" * 60)
    
    print("\n🔴 EXPLOIT CONTRACTS (Known Attack Contracts):")
    total_exploits = 0
    for chain, contracts in EXPLOIT_CONTRACTS.items():
        print(f"   {chain.upper()}: {len(contracts)} contracts")
        for c in contracts[:3]:
            print(f"      • {c['attack']} ({c['label']})")
        if len(contracts) > 3:
            print(f"      • ... and {len(contracts) - 3} more")
        total_exploits += len(contracts)
    
    print(f"\n   Total Exploit Contracts: {total_exploits}")
    
    print("\n🟢 SAFE CONTRACTS (Verified Protocols):")
    total_safe = 0
    for chain, contracts in SAFE_CONTRACTS.items():
        print(f"   {chain.upper()}: {len(contracts)} contracts")
        for c in contracts[:3]:
            print(f"      • {c['protocol']}")
        if len(contracts) > 3:
            print(f"      • ... and {len(contracts) - 3} more")
        total_safe += len(contracts)
    
    print(f"\n   Total Safe Contracts: {total_safe}")
    
    print("\n🟡 SCAM CONTRACTS (Honeypots, Rug Pulls):")
    total_scams = 0
    for chain, contracts in SCAM_CONTRACTS.items():
        print(f"   {chain.upper()}: {len(contracts)} contracts")
        total_scams += len(contracts)
    
    print(f"\n   Total Scam Contracts: {total_scams}")
    
    print("\n" + "=" * 60)
    print(f"📊 TOTAL CONTRACTS TO COLLECT: {total_exploits + total_safe + total_scams}")
    print("=" * 60)


async def main():
    print_banner()
    print_dataset_summary()
    
    print("\n⏳ Starting bytecode collection...")
    print("   This may take a few minutes depending on network speed.\n")
    
    # Check for RPC endpoints
    print("🔗 RPC Endpoints:")
    endpoints = {
        "ethereum": os.getenv("ETH_RPC_URL", "https://eth.llamarpc.com"),
        "arbitrum": os.getenv("ARB_RPC_URL", "https://arb1.arbitrum.io/rpc"),
        "polygon": os.getenv("POLYGON_RPC_URL", "https://polygon-rpc.com"),
        "bsc": os.getenv("BSC_RPC_URL", "https://bsc-dataseed.binance.org"),
    }
    for chain, url in endpoints.items():
        masked_url = url[:30] + "..." if len(url) > 30 else url
        print(f"   {chain}: {masked_url}")
    
    print("\n" + "-" * 60)
    
    # Run collection
    try:
        training_data = await collect_training_bytecode()
        
        print("\n" + "=" * 60)
        print("✅ COLLECTION COMPLETE!")
        print("=" * 60)
        
        # Print feature statistics
        if training_data:
            print("\n📊 Feature Statistics:")
            
            # Analyze collected features
            labels = {}
            for item in training_data:
                label = item["label"]
                labels[label] = labels.get(label, 0) + 1
            
            print("\n   Label Distribution:")
            for label, count in sorted(labels.items(), key=lambda x: -x[1]):
                bar = "█" * min(count, 30)
                print(f"      {label:25} {count:4} {bar}")
            
            # Show sample features
            print("\n   Sample Feature Vectors:")
            for item in training_data[:2]:
                print(f"\n   📍 {item['address'][:20]}... ({item['label']})")
                features = item.get("features_dict", {})
                print(f"      Bytecode Length: {features.get('bytecode_length', 'N/A')} bytes")
                print(f"      CALL count: {features.get('call_count', 'N/A')}")
                print(f"      DELEGATECALL count: {features.get('delegatecall_count', 'N/A')}")
                print(f"      Has Flash Loan: {features.get('has_flash_loan_callback', 'N/A')}")
                print(f"      Has Reentrancy: {features.get('has_reentrancy_pattern', 'N/A')}")
                print(f"      Risk Score: {features.get('risk_score', 'N/A'):.2f}")
        
        print("\n" + "=" * 60)
        print("📁 Output Files:")
        print("   • data/bytecode/training_data_real.json (Training data with features)")
        print("   • data/bytecode/bytecode_dataset_*.json (Raw bytecode)")
        print("   • data/bytecode/bytecode_summary.json (Summary without bytecode)")
        print("=" * 60)
        
        print("\n🚀 Next Steps:")
        print("   1. Run training: python -m src.ai.training.pipeline")
        print("   2. Or via API: POST /api/ml/train")
        print("\n")
        
    except Exception as e:
        print(f"\n❌ Error during collection: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

