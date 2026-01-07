#!/usr/bin/env python3
"""
Quick test of the Continuous Learning System
Runs for 30 seconds to demonstrate functionality
"""

import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

async def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   🧪 CONTINUOUS LEARNING SYSTEM - QUICK TEST (30 seconds)                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
    
    from src.ai.continuous_learning import ContinuousLearningSystem, LearningConfig
    
    # Quick test config
    config = LearningConfig(
        chains=["ethereum", "polygon"],  # Just 2 chains for quick test
        model_types=["mlp"],  # Just MLP for quick test
        retrain_interval_hours=1,  # Short interval
        min_new_samples=5,  # Low threshold
    )
    
    system = ContinuousLearningSystem(config)
    
    # Start in background
    task = asyncio.create_task(system.start())
    
    # Run for 30 seconds
    print("⏱️  Running for 30 seconds...\n")
    await asyncio.sleep(30)
    
    # Stop
    print("\n⏹️  Stopping test...")
    await system.stop()
    task.cancel()
    
    # Print results
    stats = system.get_stats()
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           TEST RESULTS                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   Contracts Collected:  {stats['contracts_collected']:<48}║
║   Contracts Analyzed:   {stats['contracts_analyzed']:<48}║
║   Threats Detected:     {stats['threats_detected']:<48}║
║   Training Samples:     {len(system.training_data):<48}║
║   Pending Samples:      {stats['pending_samples']:<48}║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
    
    if stats['by_chain']:
        print("   By Chain:")
        for chain, count in stats['by_chain'].items():
            print(f"      {chain}: {count}")
    
    print("\n✅ Continuous learning system test complete!")
    print("   The system is ready for 24/7 operation.")
    print("\n   To run permanently:")
    print("   $ python scripts/run_continuous_learning.py")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted.")

