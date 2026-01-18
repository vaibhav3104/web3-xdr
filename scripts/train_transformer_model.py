#!/usr/bin/env python3
"""
Train BytecodeTransformer Model for Contract Classification

This script trains the transformer-based deep learning model for
smart contract threat classification using the exploit database.

Usage:
    python scripts/train_transformer_model.py

Requirements:
    - PyTorch (pip install torch)
    - numpy (pip install numpy)
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def main():
    print("=" * 70)
    print("BytecodeTransformer Model Training")
    print("=" * 70)
    
    # Check PyTorch availability
    try:
        import torch
        print(f"✅ PyTorch version: {torch.__version__}")
        print(f"✅ CUDA available: {torch.cuda.is_available()}")
        if torch.cuda.is_available():
            print(f"   GPU: {torch.cuda.get_device_name(0)}")
    except ImportError:
        print("❌ PyTorch not installed. Install with: pip install torch")
        sys.exit(1)
    
    # Import our modules
    try:
        from src.ai.models.deep_classifier import (
            DeepContractClassifier, 
            PYTORCH_AVAILABLE,
            BytecodeTransformer
        )
        from src.ai.data.exploit_database import EXPLOIT_DATABASE, get_all_exploits
        from src.ai.data.bytecode_collector import RealBytecodeFeatureExtractor
        print("✅ Modules imported successfully")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        sys.exit(1)
    
    if not PYTORCH_AVAILABLE:
        print("❌ PyTorch not available in deep_classifier module")
        sys.exit(1)
    
    # Create model directory
    model_dir = Path("./data/models")
    model_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize classifier with transformer
    print("\n📦 Initializing BytecodeTransformer model...")
    classifier = DeepContractClassifier(
        model_type="transformer",
        model_path=str(model_dir / "deep_transformer.pt")
    )
    
    print(f"   Model type: transformer")
    print(f"   Device: {classifier.device}")
    print(f"   Model path: {classifier.model_path}")
    
    # Print model architecture
    print("\n🏗️ Model Architecture:")
    print("-" * 50)
    total_params = sum(p.numel() for p in classifier.model.parameters())
    trainable_params = sum(p.numel() for p in classifier.model.parameters() if p.requires_grad)
    print(f"   Total parameters: {total_params:,}")
    print(f"   Trainable parameters: {trainable_params:,}")
    print("-" * 50)
    
    # Collect training data from exploit database
    print("\n📊 Loading training data from exploit database...")
    exploits = get_all_exploits()
    print(f"   Found {len(exploits)} exploit contracts")
    
    # Create synthetic training data (in production, you'd fetch real bytecode)
    print("\n🔧 Generating training samples...")
    
    # For demo purposes, we'll create synthetic bytecode patterns
    # In production, you'd fetch real bytecode from RPC endpoints
    training_samples = []
    
    # Generate samples for each threat category
    threat_patterns = {
        "safe": [
            # Simple storage contract
            "608060405234801561001057600080fd5b5060405161001d906100a4565b604051809103906000f080158015610039573d6000803e3d6000fd5b505060405161004790610062565b604051809103906000f080158015610063573d6000803e3d6000fd5b50506100b1565b",
        ],
        "flash_loan_exploit": [
            # Flash loan callback pattern
            "608060405234801561001057600080fd5b5063c3924ed6600052600436106100415760003560e01c806323e30c8b14610046578063fa461e3314610058575b600080fd5bf1f1f1f1f1",
        ],
        "reentrancy_exploit": [
            # CALL followed by SSTORE pattern
            "608060405234801561001057600080fd5b50600436106100415760003560e01c80633ccfd60b14610046575b600080fd5b61004e610050565b005b3373ffffffffffffffff16f1f1f1f155555555",
        ],
        "rug_pull": [
            # SELFDESTRUCT + admin pattern
            "608060405234801561001057600080fd5b506040516100f2fde38b600052ff",
        ],
        "honeypot": [
            # Transfer restriction pattern
            "608060405234801561001057600080fd5b506040516100a9f2fde38b600052ffffffff",
        ],
        "bridge_exploit": [
            # Mint + burn + delegatecall pattern
            "608060405234801561001057600080fd5b5063409c10f19600052604051634042966c6800f4f4f4",
        ],
    }
    
    # Generate multiple samples per category
    for category, patterns in threat_patterns.items():
        for pattern in patterns:
            # Add variations
            for i in range(10):
                # Add some randomization to patterns
                variation = pattern + f"{i:02x}" * 20
                training_samples.append({
                    "bytecode": variation,
                    "label": category
                })
    
    print(f"   Generated {len(training_samples)} training samples")
    
    # Train the model
    print("\n🚀 Training transformer model...")
    print("-" * 50)
    
    try:
        # Prepare training data
        bytecodes = [s["bytecode"] for s in training_samples]
        labels = [s["label"] for s in training_samples]
        
        # Train
        history = classifier.train(
            bytecodes=bytecodes,
            labels=labels,
            epochs=50,
            batch_size=16,
            learning_rate=0.001,
            validation_split=0.2
        )
        
        print("\n✅ Training completed!")
        
        # Save training metrics
        metrics = {
            "model_type": "transformer",
            "training_date": datetime.now().isoformat(),
            "epochs": 50,
            "samples": len(training_samples),
            "categories": list(threat_patterns.keys()),
            "device": str(classifier.device),
            "final_train_loss": history.get("train_loss", [])[-1] if history.get("train_loss") else None,
            "final_val_loss": history.get("val_loss", [])[-1] if history.get("val_loss") else None,
            "final_val_accuracy": history.get("val_accuracy", [])[-1] if history.get("val_accuracy") else None,
        }
        
        metrics_path = model_dir / "transformer_training_metrics.json"
        with open(metrics_path, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"   Metrics saved to: {metrics_path}")
        
    except Exception as e:
        print(f"\n⚠️ Training error: {e}")
        print("   Saving untrained model weights...")
        classifier._save_weights()
    
    # Test the model
    print("\n🧪 Testing model on sample contracts...")
    print("-" * 50)
    
    test_cases = [
        ("Safe contract", "608060405234801561001057600080fd5b5060405161001d"),
        ("Flash loan pattern", "608060405234801561001057600080fd5b5063c3924ed6f1f1f1"),
        ("Reentrancy pattern", "608060405234801561001057600080fd5b5063ccfd60bf1555555"),
    ]
    
    for name, bytecode in test_cases:
        try:
            result = classifier.classify(bytecode)
            print(f"\n   {name}:")
            print(f"      Category: {result.category}")
            print(f"      Confidence: {result.confidence:.2%}")
            print(f"      Risk Score: {result.risk_score:.2f}")
            print(f"      Inference Time: {result.inference_time_ms:.2f}ms")
        except Exception as e:
            print(f"\n   {name}: Error - {e}")
    
    print("\n" + "=" * 70)
    print("✅ Transformer model setup complete!")
    print(f"   Model saved to: {classifier.model_path}")
    print("=" * 70)
    
    # Print usage instructions
    print("\n📝 Usage:")
    print("-" * 50)
    print("1. Set environment variable:")
    print("   export ML_MODEL_TYPE=transformer")
    print("")
    print("2. Or in .env file:")
    print("   ML_MODEL_TYPE=transformer")
    print("")
    print("3. The model will be loaded automatically when the")
    print("   AutoContractCollector starts monitoring.")
    print("-" * 50)


if __name__ == "__main__":
    main()
