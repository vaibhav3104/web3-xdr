#!/usr/bin/env python3
"""
Train Deep Learning Models for Contract Classification
Uses PyTorch to train MLP, CNN, and Ensemble models
"""

import sys
import os
import json
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
║              🧠 DEEP LEARNING MODEL TRAINING                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


def check_pytorch():
    """Check if PyTorch is available"""
    try:
        import torch
        print(f"✅ PyTorch version: {torch.__version__}")
        print(f"   CUDA available: {torch.cuda.is_available()}")
        if torch.cuda.is_available():
            print(f"   CUDA device: {torch.cuda.get_device_name(0)}")
        return True
    except ImportError:
        print("❌ PyTorch not installed!")
        print("   Install with: pip install torch")
        return False


def load_training_data():
    """Load training data from collected bytecode"""
    data_path = "./data/bytecode/training_data_real.json"
    
    if os.path.exists(data_path):
        print(f"\n📂 Loading training data from: {data_path}")
        with open(data_path, 'r') as f:
            data = json.load(f)
        print(f"   Loaded {len(data)} samples")
        return data
    else:
        print(f"\n⚠️ Training data not found at {data_path}")
        print("   Running bytecode collection first...")
        
        # Run collection
        import asyncio
        from src.ai.data.bytecode_collector import collect_training_bytecode
        
        data = asyncio.run(collect_training_bytecode())
        return data


def prepare_data_with_synthetic(real_data):
    """Augment real data with synthetic samples for better training"""
    import random
    
    print("\n📊 Preparing training data with synthetic augmentation...")
    
    # Count labels
    labels = {}
    for item in real_data:
        label = item['label']
        labels[label] = labels.get(label, 0) + 1
    
    print(f"\n   Original distribution:")
    for label, count in sorted(labels.items(), key=lambda x: -x[1]):
        print(f"      {label}: {count}")
    
    # Augment with synthetic data
    augmented_data = list(real_data)
    
    # Add synthetic exploit samples to balance dataset
    exploit_patterns = {
        "flash_loan_exploit": {
            "features": [0.5, 0.4, 0.1, 0.1, 0.0, 0.3, 0.3, 0.1, 0.1, 0.2, 0.3, 1.0, 0.2, 0.1, 0.0, 0.1, 0.1, 0.0, 0.3, 0.75],
        },
        "reentrancy_exploit": {
            "features": [0.4, 0.5, 0.2, 0.1, 0.0, 0.4, 0.3, 0.1, 0.1, 0.3, 0.2, 0.3, 1.0, 0.1, 0.0, 0.1, 0.1, 0.0, 0.3, 0.70],
        },
        "governance_attack": {
            "features": [0.5, 0.3, 0.1, 0.1, 0.0, 0.2, 0.2, 0.0, 0.1, 0.2, 0.3, 1.0, 0.1, 0.1, 0.0, 0.1, 1.0, 0.0, 0.3, 0.65],
        },
        "bridge_exploit": {
            "features": [0.3, 0.3, 0.2, 0.1, 0.0, 0.2, 0.2, 0.1, 0.1, 0.2, 0.2, 0.2, 0.1, 0.0, 1.0, 0.1, 0.1, 0.0, 0.3, 0.80],
        },
        "oracle_manipulation": {
            "features": [0.4, 0.4, 0.1, 0.2, 0.0, 0.3, 0.4, 0.1, 0.2, 0.2, 0.3, 0.3, 0.1, 0.0, 0.0, 0.1, 0.1, 0.0, 0.3, 0.60],
        },
        "rug_pull": {
            "features": [0.3, 0.2, 0.1, 0.0, 1.0, 0.2, 0.1, 0.0, 0.0, 0.1, 0.2, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.2, 0.85],
        },
        "honeypot": {
            "features": [0.3, 0.3, 0.3, 0.1, 0.5, 0.2, 0.2, 0.0, 0.0, 0.2, 0.2, 0.0, 0.0, 0.0, 0.0, 1.0, 0.5, 0.5, 0.3, 0.80],
        },
        "unknown_threat": {
            "features": [0.4, 0.3, 0.2, 0.1, 0.1, 0.3, 0.3, 0.1, 0.1, 0.2, 0.3, 0.2, 0.2, 0.0, 0.0, 0.2, 0.2, 0.1, 0.3, 0.55],
        },
        "price_manipulation": {
            "features": [0.6, 0.5, 0.1, 0.2, 0.0, 0.3, 0.4, 0.1, 0.2, 0.3, 0.4, 0.4, 0.2, 0.0, 0.0, 0.1, 0.2, 0.0, 0.4, 0.70],
        },
    }
    
    # Add 50 synthetic samples per exploit type
    for exploit_type, pattern in exploit_patterns.items():
        for i in range(50):
            # Add variation
            features = [f + random.uniform(-0.15, 0.15) for f in pattern["features"]]
            features = [max(0, min(1, f)) for f in features]
            
            augmented_data.append({
                "address": f"0x{random.randbytes(20).hex()}",
                "chain": random.choice(["ethereum", "arbitrum", "polygon"]),
                "label": exploit_type,
                "source": "synthetic",
                "features": features,
            })
    
    # Add 200 synthetic safe samples
    safe_patterns = [
        [0.3, 0.1, 0.0, 0.1, 0.0, 0.2, 0.2, 0.0, 0.0, 0.1, 0.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.2, 0.15],  # Simple ERC20
        [0.5, 0.2, 0.0, 0.2, 0.0, 0.3, 0.3, 0.0, 0.1, 0.2, 0.3, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.0, 0.3, 0.20],  # DEX
        [0.6, 0.3, 0.1, 0.2, 0.0, 0.4, 0.4, 0.0, 0.1, 0.3, 0.4, 0.0, 0.0, 0.0, 0.0, 0.0, 0.3, 0.0, 0.4, 0.25],  # Lending
    ]
    
    for i in range(200):
        pattern = random.choice(safe_patterns)
        features = [f + random.uniform(-0.1, 0.1) for f in pattern]
        features = [max(0, min(1, f)) for f in features]
        
        augmented_data.append({
            "address": f"0x{random.randbytes(20).hex()}",
            "chain": random.choice(["ethereum", "arbitrum", "polygon", "bsc"]),
            "label": "safe",
            "source": "synthetic",
            "features": features,
        })
    
    # Final distribution
    final_labels = {}
    for item in augmented_data:
        label = item['label']
        final_labels[label] = final_labels.get(label, 0) + 1
    
    print(f"\n   Augmented distribution:")
    for label, count in sorted(final_labels.items(), key=lambda x: -x[1]):
        print(f"      {label}: {count}")
    
    print(f"\n   Total samples: {len(augmented_data)}")
    
    return augmented_data


def train_mlp_model(data):
    """Train MLP model"""
    print("\n" + "=" * 60)
    print("🧠 TRAINING MLP MODEL")
    print("=" * 60)
    
    try:
        from src.ai.models.deep_classifier import DeepContractClassifier
        from sklearn.model_selection import train_test_split
        
        # Stratified split to ensure all classes are represented
        labels = [d['label'] for d in data]
        
        train_data, val_data = train_test_split(
            data, 
            test_size=0.2, 
            stratify=labels,
            random_state=42
        )
        
        print(f"\n   Training samples: {len(train_data)}")
        print(f"   Validation samples: {len(val_data)}")
        
        # Show class distribution in train/val
        train_labels = {}
        for d in train_data:
            train_labels[d['label']] = train_labels.get(d['label'], 0) + 1
        val_labels = {}
        for d in val_data:
            val_labels[d['label']] = val_labels.get(d['label'], 0) + 1
        
        print("\n   Training distribution:")
        for label, count in sorted(train_labels.items()):
            print(f"      {label}: {count}")
        
        print("\n   Validation distribution:")
        for label, count in sorted(val_labels.items()):
            print(f"      {label}: {count}")
        
        # Create and train classifier
        classifier = DeepContractClassifier(
            model_type="mlp",
            model_path="./data/models/deep_mlp.pt"
        )
        
        history = classifier.train(
            train_data=train_data,
            val_data=val_data,
            epochs=50,
            batch_size=64,  # Larger batch size for stability
            learning_rate=0.0005,  # Lower learning rate
            early_stopping_patience=15  # More patience
        )
        
        print(f"\n✅ MLP Model trained successfully!")
        print(f"   Final Train Accuracy: {history['train_acc'][-1]:.2f}%")
        print(f"   Final Val Accuracy: {history['val_acc'][-1]:.2f}%")
        
        return history
        
    except Exception as e:
        print(f"❌ MLP training failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_model(model_type="mlp"):
    """Test the trained model"""
    print("\n" + "=" * 60)
    print(f"🧪 TESTING {model_type.upper()} MODEL")
    print("=" * 60)
    
    try:
        from src.ai.models.deep_classifier import DeepContractClassifier
        
        classifier = DeepContractClassifier(
            model_type=model_type,
            model_path=f"./data/models/deep_{model_type}.pt"
        )
        
        # Test bytecodes
        test_cases = [
            # Simple safe contract
            ("0x608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50", "Simple Contract"),
            # Contract with DELEGATECALL (suspicious)
            ("0x608060405234801561001057600080fd5b506040516101603803806101608339818101604052810190f4f400", "Delegatecall Contract"),
            # Contract with SELFDESTRUCT (risky)
            ("0x608060405234801561001057600080fd5b50ff00", "Selfdestruct Contract"),
        ]
        
        for bytecode, name in test_cases:
            result = classifier.classify(bytecode)
            print(f"\n   📋 {name}")
            print(f"      Category: {result.category}")
            print(f"      Risk Score: {result.risk_score:.2%}")
            print(f"      Confidence: {result.confidence:.2%}")
            print(f"      Inference Time: {result.inference_time_ms:.2f}ms")
        
        print(f"\n✅ Model testing complete!")
        
    except Exception as e:
        print(f"❌ Model testing failed: {e}")
        import traceback
        traceback.print_exc()


def main():
    print_banner()
    
    print(f"⏰ Training started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Check PyTorch
    if not check_pytorch():
        print("\n❌ Cannot proceed without PyTorch")
        return 1
    
    # Load training data
    real_data = load_training_data()
    
    if not real_data:
        print("❌ No training data available")
        return 1
    
    # Prepare data with synthetic augmentation
    training_data = prepare_data_with_synthetic(real_data)
    
    # Train MLP model
    mlp_history = train_mlp_model(training_data)
    
    # Test the model
    if mlp_history:
        test_model("mlp")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TRAINING SUMMARY")
    print("=" * 60)
    
    if mlp_history:
        print(f"\n   ✅ MLP Model:")
        print(f"      Path: ./data/models/deep_mlp.pt")
        print(f"      Final Accuracy: {mlp_history['val_acc'][-1]:.2f}%")
    
    print(f"\n⏰ Training completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

