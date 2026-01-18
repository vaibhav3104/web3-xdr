#!/usr/bin/env python3
"""
Train Transformer Model on Cloud Run with GPU
Triggered via API endpoint
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

def train_transformer():
    """Train the transformer model"""
    print("=" * 70)
    print("BytecodeTransformer Model Training (Cloud GPU)")
    print("=" * 70)
    
    import torch
    print(f"✅ PyTorch version: {torch.__version__}")
    print(f"✅ CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"   GPU: {torch.cuda.get_device_name(0)}")
        print(f"   GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
    
    # Import modules
    from src.ai.models.deep_classifier import DeepContractClassifier
    from src.ai.data.bytecode_collector import RealBytecodeFeatureExtractor
    
    # Create model directory
    model_dir = Path("/app/data/models")
    model_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize classifier
    print("\n📦 Initializing BytecodeTransformer...")
    classifier = DeepContractClassifier(
        model_type="transformer",
        model_path=str(model_dir / "deep_transformer.pt"),
        device="cuda" if torch.cuda.is_available() else "cpu"
    )
    
    print(f"   Device: {classifier.device}")
    
    # Model info
    total_params = sum(p.numel() for p in classifier.model.parameters())
    print(f"   Parameters: {total_params:,}")
    
    # Generate training data
    print("\n📊 Generating training data...")
    
    threat_patterns = {
        "safe": [
            "608060405234801561001057600080fd5b5060405161001d906100a4565b604051809103906000f080158015610039573d6000803e3d6000fd5b505060405161004790610062565b604051809103906000f080158015610063573d6000803e3d6000fd5b50506100b1565b",
            "608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b",
        ],
        "flash_loan_exploit": [
            "608060405234801561001057600080fd5b5063c3924ed6600052600436106100415760003560e01c806323e30c8b14610046578063fa461e3314610058575b600080fd5bf1f1f1f1f1",
            "608060405234801561001057600080fd5b506040516370a0823160e01b81523060048201526000906001600160a01b0316906370a0823190602401602060405180830381865afa158015610067573d6000803e3d6000fd5bf1f1f1f1",
        ],
        "reentrancy_exploit": [
            "608060405234801561001057600080fd5b50600436106100415760003560e01c80633ccfd60b14610046575b600080fd5b61004e610050565b005b3373ffffffffffffffff16f1f1f1f155555555",
            "608060405234801561001057600080fd5b506040516000903373ffffffffffffffffffffffffffffffffffffffff1690620186a09060405160006040518083038185875af1158015610055573d6000803e3d6000fd5bf1f155",
        ],
        "rug_pull": [
            "608060405234801561001057600080fd5b506040516100f2fde38b600052ff",
            "608060405234801561001057600080fd5b5060405160008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff",
        ],
        "honeypot": [
            "608060405234801561001057600080fd5b506040516100a9f2fde38b600052ffffffff",
            "608060405234801561001057600080fd5b5060408051600481526024810182526020810180516001600160e01b03166370a0823160e01b1781529151600093849384939192909173ffffffffffffffffffffffffffffffffffffffff",
        ],
        "bridge_exploit": [
            "608060405234801561001057600080fd5b5063409c10f19600052604051634042966c6800f4f4f4",
            "608060405234801561001057600080fd5b5060405163a9059cbb60e01b8152336004820152602481018290526001600160a01b0384169063a9059cbb906044f4f4f4",
        ],
        "price_manipulation": [
            "608060405234801561001057600080fd5b506040516370a0823160e01b81523060048201526000906001600160a01b0316906370a082319060240160206040518083038186803b158015610053573d6000803e3d6000fd5b",
            "608060405234801561001057600080fd5b506040516315ab88c960e31b81526004810182905260009073ffffffffffffffffffffffffffffffffffffffff",
        ],
        "access_control_exploit": [
            "608060405234801561001057600080fd5b506040516370a0823160e01b81523060048201526000906001600160a01b031690638da5cb5b90602401602060405180830381865afa",
            "608060405234801561001057600080fd5b50604051636352211e60e01b815260048101829052339073ffffffffffffffffffffffffffffffffffffffff",
        ],
    }
    
    training_samples = []
    for category, patterns in threat_patterns.items():
        for pattern in patterns:
            # Generate variations
            for i in range(20):  # 20 variations per pattern
                variation = pattern + f"{i:02x}" * (10 + i % 10)
                training_samples.append({
                    "bytecode": variation,
                    "label": category
                })
    
    print(f"   Generated {len(training_samples)} training samples")
    
    # Prepare data
    extractor = classifier.extractor
    train_data = []
    
    for sample in training_samples:
        features = extractor.extract_features(sample["bytecode"])
        feature_vector = extractor.features_to_vector(features)
        train_data.append({
            "bytecode": sample["bytecode"],
            "features": feature_vector,
            "label": sample["label"]
        })
    
    # Split train/val
    import random
    random.shuffle(train_data)
    split_idx = int(len(train_data) * 0.8)
    train_set = train_data[:split_idx]
    val_set = train_data[split_idx:]
    
    print(f"   Training: {len(train_set)}, Validation: {len(val_set)}")
    
    # Train
    print("\n🚀 Training...")
    print("-" * 50)
    
    history = classifier.train(
        train_data=train_set,
        val_data=val_set,
        epochs=100,
        batch_size=32,
        learning_rate=0.0005,
        early_stopping_patience=15
    )
    
    print("\n✅ Training complete!")
    
    # Save metrics
    metrics = {
        "model_type": "transformer",
        "training_date": datetime.now().isoformat(),
        "device": str(classifier.device),
        "samples": len(training_samples),
        "categories": list(threat_patterns.keys()),
        "epochs_completed": len(history.get("train_loss", [])),
        "final_train_loss": history.get("train_loss", [None])[-1],
        "final_val_loss": history.get("val_loss", [None])[-1],
        "final_train_acc": history.get("train_acc", [None])[-1],
        "final_val_acc": history.get("val_acc", [None])[-1],
    }
    
    with open(model_dir / "training_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    
    # Test
    print("\n🧪 Testing...")
    test_cases = [
        ("Safe", "608060405234801561001057600080fd5b5060405161001d"),
        ("Flash loan", "608060405234801561001057600080fd5b5063c3924ed6f1f1f1"),
        ("Reentrancy", "608060405234801561001057600080fd5b5063ccfd60bf1555555"),
    ]
    
    for name, bytecode in test_cases:
        result = classifier.classify(bytecode)
        print(f"   {name}: {result.category} ({result.confidence:.1%})")
    
    print("\n" + "=" * 70)
    print("✅ Model saved to:", classifier.model_path)
    print("=" * 70)
    
    return metrics


if __name__ == "__main__":
    train_transformer()
