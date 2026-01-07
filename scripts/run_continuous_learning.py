#!/usr/bin/env python3
"""
Run Sentinel3 Continuous Learning System
24/7/365 contract collection and model training

Usage:
    python scripts/run_continuous_learning.py
    
    # With custom settings:
    python scripts/run_continuous_learning.py --retrain-hours 4 --chains ethereum,polygon
"""

import sys
import os
import argparse
import asyncio

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                      ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██████╗            ║
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚════██╗           ║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      █████╔╝           ║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ╚═══██╗           ║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██████╔╝           ║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═════╝            ║
║                                                                                      ║
║                    🧠 CONTINUOUS LEARNING SYSTEM 🧠                                  ║
║                        24/7/365 OPERATION MODE                                       ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
""")


async def main(args):
    print_banner()
    
    from src.ai.continuous_learning import ContinuousLearningSystem, LearningConfig
    
    # Parse chains
    chains = args.chains.split(',') if args.chains else [
        "ethereum", "polygon", "arbitrum", "bsc"
    ]
    
    # Parse model types
    model_types = args.models.split(',') if args.models else [
        "mlp", "random_forest"
    ]
    
    # Create config
    config = LearningConfig(
        chains=chains,
        model_types=model_types,
        retrain_interval_hours=args.retrain_hours,
        min_new_samples=args.min_samples,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        alert_on_threat=not args.no_alerts,
    )
    
    print(f"""
┌────────────────────────────────────────────────────────────────────────────┐
│ Configuration:                                                             │
├────────────────────────────────────────────────────────────────────────────┤
│ Chains:           {', '.join(config.chains):<52}│
│ Model Types:      {', '.join(config.model_types):<52}│
│ Retrain Interval: Every {config.retrain_interval_hours} hours{' ' * 45}│
│ Min Samples:      {config.min_new_samples} contracts before retraining{' ' * 30}│
│ Training Epochs:  {config.epochs:<52}│
│ Batch Size:       {config.batch_size:<52}│
│ Threat Alerts:    {'Enabled' if config.alert_on_threat else 'Disabled':<52}│
└────────────────────────────────────────────────────────────────────────────┘
""")
    
    # Create and start system
    system = ContinuousLearningSystem(config)
    
    # Add notification callback (placeholder)
    async def notify_threat(analysis):
        # TODO: Integrate with Telegram/Slack
        pass
    
    system.add_threat_callback(notify_threat)
    
    # Run forever
    await system.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel3 Continuous Learning System")
    
    parser.add_argument(
        "--chains",
        type=str,
        default="ethereum,polygon,arbitrum,bsc",
        help="Comma-separated list of chains to monitor"
    )
    
    parser.add_argument(
        "--models",
        type=str,
        default="mlp,random_forest",
        help="Comma-separated list of model types to train"
    )
    
    parser.add_argument(
        "--retrain-hours",
        type=int,
        default=6,
        help="Hours between model retraining (default: 6)"
    )
    
    parser.add_argument(
        "--min-samples",
        type=int,
        default=50,
        help="Minimum new samples before retraining (default: 50)"
    )
    
    parser.add_argument(
        "--epochs",
        type=int,
        default=50,
        help="Training epochs (default: 50)"
    )
    
    parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        help="Training batch size (default: 64)"
    )
    
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=0.0005,
        help="Learning rate (default: 0.0005)"
    )
    
    parser.add_argument(
        "--no-alerts",
        action="store_true",
        help="Disable threat alerts"
    )
    
    args = parser.parse_args()
    
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n\n👋 Continuous learning system stopped.")
        sys.exit(0)

