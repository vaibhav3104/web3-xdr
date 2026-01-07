#!/usr/bin/env python3
"""
Test the Auto-Collector
Monitors blockchain for real contract deployments and analyzes them
"""

import sys
import os
import asyncio
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
║              🔍 AUTO-COLLECTOR TEST - REAL CONTRACT MONITORING               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


async def test_auto_collector():
    """Test the auto-collector with real blockchain data"""
    from src.ai.collectors.auto_collector import AutoContractCollector, ContractAnalysis
    
    print("\n🔍 Starting Auto-Collector Test...")
    print("=" * 60)
    print(f"⏰ Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    contracts_found = []
    threats_found = []
    
    async def on_analysis(analysis: ContractAnalysis):
        """Called when any contract is analyzed"""
        contracts_found.append(analysis)
        
        status = "🔴 THREAT" if analysis.is_threat else "🟢 SAFE"
        print(f"\n{status} Contract Detected!")
        print(f"   📍 Address:  {analysis.contract.address[:20]}...{analysis.contract.address[-8:]}")
        print(f"   ⛓️  Chain:    {analysis.contract.chain}")
        print(f"   👤 Deployer: {analysis.contract.deployer[:20]}...{analysis.contract.deployer[-8:]}")
        print(f"   📦 Size:     {analysis.contract.bytecode_length:,} bytes")
        print(f"   📊 Category: {analysis.threat_category}")
        print(f"   ⚠️  Risk:     {analysis.risk_score:.2%}")
        print(f"   🎯 Confidence: {analysis.confidence:.2%}")
        
        if analysis.alerts:
            print(f"   🚨 Alerts:")
            for alert in analysis.alerts:
                print(f"      • {alert}")
    
    async def on_threat(analysis: ContractAnalysis):
        """Called when a threat is detected"""
        threats_found.append(analysis)
        print(f"\n" + "🚨" * 30)
        print(f"   THREAT DETECTED!")
        print(f"   Contract: {analysis.contract.address}")
        print(f"   Category: {analysis.threat_category}")
        print(f"   Risk Score: {analysis.risk_score:.2%}")
        print("🚨" * 30)
    
    # Create collector - monitor Ethereum and Polygon (faster block times)
    collector = AutoContractCollector(
        chains=["ethereum", "polygon"],
        analysis_callback=on_analysis,
        threat_callback=on_threat,
        storage_path="./data/auto_collected"
    )
    
    print(f"\n📡 Monitoring chains: {collector.chains}")
    print(f"📂 Storage path: {collector.storage_path}")
    print("\n⏳ Waiting for new contract deployments...")
    print("   (Press Ctrl+C to stop)\n")
    print("-" * 60)
    
    # Run for a limited time (60 seconds for testing)
    try:
        # Start the collector in background
        collector_task = asyncio.create_task(collector.start())
        
        # Run for 45 seconds (enough to catch a few blocks)
        await asyncio.sleep(45)
        
        # Stop
        await collector.stop()
        collector_task.cancel()
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Stopping collector...")
        await collector.stop()
    except asyncio.CancelledError:
        pass
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 COLLECTION SUMMARY")
    print("=" * 60)
    
    stats = collector.get_stats()
    print(f"\n   Total Contracts Collected: {stats['contracts_collected']}")
    print(f"   Contracts Analyzed:        {stats['contracts_analyzed']}")
    print(f"   Threats Detected:          {stats['threats_detected']}")
    
    if stats.get('by_chain'):
        print(f"\n   By Chain:")
        for chain, count in stats['by_chain'].items():
            print(f"      {chain}: {count}")
    
    if stats.get('by_threat_type'):
        print(f"\n   By Threat Type:")
        for threat_type, count in stats['by_threat_type'].items():
            print(f"      {threat_type}: {count}")
    
    print("\n" + "=" * 60)
    
    # List collected contracts
    if contracts_found:
        print(f"\n📋 Contracts Found ({len(contracts_found)}):")
        for i, analysis in enumerate(contracts_found[:10], 1):
            status = "⚠️" if analysis.is_threat else "✅"
            print(f"   {i}. {status} {analysis.contract.address[:16]}... ({analysis.contract.chain}) - {analysis.threat_category}")
        
        if len(contracts_found) > 10:
            print(f"   ... and {len(contracts_found) - 10} more")
    
    if threats_found:
        print(f"\n🚨 THREATS FOUND ({len(threats_found)}):")
        for analysis in threats_found:
            print(f"\n   Contract: {analysis.contract.address}")
            print(f"   Chain:    {analysis.contract.chain}")
            print(f"   Type:     {analysis.threat_category}")
            print(f"   Risk:     {analysis.risk_score:.2%}")
            print(f"   Deployer: {analysis.contract.deployer}")
    
    return contracts_found, threats_found


async def main():
    print_banner()
    
    # Run test
    contracts, threats = await test_auto_collector()
    
    print("\n✅ Auto-collector test complete!")
    print(f"   Contracts monitored: {len(contracts)}")
    print(f"   Threats detected: {len(threats)}")
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(0)

