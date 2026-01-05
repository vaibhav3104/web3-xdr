"""
ML Training Pipeline
Orchestrates the complete training workflow
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass, asdict

# ML imports
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    import pickle
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn not installed. ML training disabled.")

from ..data.attack_database import (
    HISTORICAL_ATTACKS, 
    get_bridge_attacks, 
    get_defi_attacks,
    AttackType
)
from ..data.bytecode_extractor import BytecodeExtractor, features_to_vector

@dataclass
class TrainingConfig:
    """Configuration for training pipeline"""
    # Data settings
    train_split: float = 0.8
    val_split: float = 0.1
    test_split: float = 0.1
    
    # Model settings
    model_type: str = "random_forest"  # random_forest, gradient_boosting
    n_estimators: int = 100
    max_depth: int = 10
    
    # Training settings
    random_seed: int = 42
    cross_validation_folds: int = 5
    
    # Output settings
    output_dir: str = "./models"
    model_name: str = "contract_classifier"

@dataclass
class TrainingResult:
    """Results from training run"""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_samples: int
    validation_samples: int
    test_samples: int
    cross_val_scores: List[float]
    confusion_matrix: List[List[int]]
    classification_report: str
    training_time_seconds: float
    timestamp: str

class TrainingPipeline:
    """
    Complete ML training pipeline for contract threat detection
    """
    
    def __init__(self, config: Optional[TrainingConfig] = None):
        self.config = config or TrainingConfig()
        self.extractor = BytecodeExtractor()
        self.training_data: List[Dict] = []
        self.model = None
        self.label_encoder: Dict[str, int] = {}
        self.label_decoder: Dict[int, str] = {}
    
    def collect_training_data(self) -> int:
        """
        Collect and prepare training data from various sources
        
        Returns:
            Number of samples collected
        """
        print("📊 Collecting training data...")
        
        # 1. Add historical attack data
        self._add_attack_data()
        
        # 2. Add synthetic safe contract data
        self._add_safe_contract_data()
        
        # 3. Add manually labeled data (if available)
        self._add_labeled_data()
        
        print(f"✅ Collected {len(self.training_data)} training samples")
        return len(self.training_data)
    
    def _add_attack_data(self):
        """Add historical attack data as training samples"""
        import random
        
        attack_type_mapping = {
            "signature_forgery": "bridge_exploit",
            "validator_compromise": "bridge_exploit",
            "message_replay": "bridge_exploit",
            "admin_key_theft": "bridge_exploit",
            "proof_forgery": "bridge_exploit",
            "mint_without_lock": "bridge_exploit",
            "flash_loan": "flash_loan_exploit",
            "reentrancy": "reentrancy_exploit",
            "oracle_manipulation": "oracle_manipulation",
            "governance_attack": "governance_attack",
            "price_manipulation": "oracle_manipulation",
            "sandwich_attack": "flash_loan_exploit",
            "liquidation_cascade": "oracle_manipulation",
            "rug_pull": "rug_pull",
            "honeypot": "honeypot",
            "access_control": "unknown_threat",
        }
        
        # Generate multiple samples per attack type to ensure enough data
        for attack in HISTORICAL_ATTACKS:
            label = attack_type_mapping.get(attack["attack_type"], "unknown_threat")
            
            # Generate 10 variations per historical attack
            for i in range(10):
                features = self._create_synthetic_features(attack)
                # Add some variation
                features = [f + random.uniform(-0.05, 0.05) for f in features]
                features = [max(0, min(1, f)) for f in features]
                
                self.training_data.append({
                    "features": features,
                    "label": label,
                    "source": "historical_attack",
                    "attack_name": attack["name"]
                })
        
        # Add extra samples for underrepresented attack types
        extra_attack_types = [
            ("governance_attack", {"flash_loan": 1.0, "admin": 1.0, "risk": 0.8}),
            ("rug_pull", {"selfdestruct": 1.0, "admin": 1.0, "risk": 0.95}),
            ("honeypot", {"selfdestruct": 0.5, "delegatecall": 1.0, "risk": 0.85}),
            ("unknown_threat", {"delegatecall": 1.0, "risk": 0.6}),
        ]
        
        for attack_type, pattern in extra_attack_types:
            for i in range(30):  # 30 extra samples per type
                features = [0.0] * 20
                features[0] = random.uniform(0.2, 0.5)  # bytecode_length
                features[2] = random.uniform(0.1, 0.4)  # call_count
                features[11] = pattern.get("flash_loan", 0.0) * random.uniform(0.8, 1.0)
                features[15] = pattern.get("admin", 0.0) * random.uniform(0.8, 1.0)
                features[17] = pattern.get("delegatecall", 0.0) * random.uniform(0.8, 1.0)
                features[18] = pattern.get("selfdestruct", 0.0) * random.uniform(0.8, 1.0)
                features[19] = pattern.get("risk", 0.5) * random.uniform(0.9, 1.1)
                features = [max(0, min(1, f)) for f in features]
                
                self.training_data.append({
                    "features": features,
                    "label": attack_type,
                    "source": "synthetic_attack"
                })
    
    def _create_synthetic_features(self, attack: Dict) -> List[float]:
        """Create synthetic feature vector based on attack characteristics"""
        # Base features
        features = [0.0] * 20
        
        attack_type = attack["attack_type"]
        
        # Set features based on attack type
        if attack_type in ["flash_loan", "reentrancy"]:
            features[0] = 0.5  # bytecode_length (normalized)
            features[2] = 0.4  # call_count
            features[11] = 1.0  # has_flash_loan_callback
            features[16] = 1.0 if attack_type == "reentrancy" else 0.0  # has_reentrancy
            features[19] = 0.85  # risk_score
        
        elif attack_type in ["signature_forgery", "validator_compromise", "bridge_exploit"]:
            features[0] = 0.3
            features[13] = 1.0  # has_mint
            features[14] = 1.0  # has_burn
            features[19] = 0.9
        
        elif attack_type == "oracle_manipulation":
            features[2] = 0.6  # High call count
            features[7] = 0.5  # sload count
            features[19] = 0.75
        
        elif attack_type == "governance_attack":
            features[11] = 1.0  # flash loan
            features[15] = 1.0  # admin functions
            features[19] = 0.8
        
        elif attack_type in ["rug_pull", "honeypot"]:
            features[9] = 1.0  # selfdestruct
            features[15] = 1.0  # admin
            features[18] = 1.0  # has selfdestruct
            features[19] = 0.95
        
        # Add some noise for variety
        import random
        features = [f + random.uniform(-0.1, 0.1) for f in features]
        features = [max(0, min(1, f)) for f in features]  # Clamp to [0, 1]
        
        return features
    
    def _add_safe_contract_data(self):
        """Add synthetic safe contract examples"""
        # Generate safe contract features
        import random
        
        safe_patterns = [
            # Simple ERC20
            {"bytecode_length": 0.2, "call_count": 0.1, "risk_score": 0.1},
            # Standard DEX
            {"bytecode_length": 0.4, "call_count": 0.3, "risk_score": 0.2},
            # Lending protocol
            {"bytecode_length": 0.5, "call_count": 0.4, "sload_count": 0.3, "risk_score": 0.25},
            # NFT contract
            {"bytecode_length": 0.3, "call_count": 0.2, "risk_score": 0.15},
            # Governance
            {"bytecode_length": 0.4, "admin_functions": 1.0, "risk_score": 0.3},
        ]
        
        # Generate 500 safe samples (balance with attack samples)
        for i in range(500):
            pattern = random.choice(safe_patterns)
            features = [0.0] * 20
            
            features[0] = pattern.get("bytecode_length", 0.3) + random.uniform(-0.1, 0.1)
            features[2] = pattern.get("call_count", 0.2) + random.uniform(-0.1, 0.1)
            features[7] = pattern.get("sload_count", 0.2) + random.uniform(-0.1, 0.1)
            features[15] = pattern.get("admin_functions", 0.0)
            features[19] = pattern.get("risk_score", 0.2) + random.uniform(-0.05, 0.05)
            
            features = [max(0, min(1, f)) for f in features]
            
            self.training_data.append({
                "features": features,
                "label": "safe",
                "source": "synthetic_safe"
            })
    
    def _add_labeled_data(self):
        """Load manually labeled data if available"""
        labeled_path = Path(self.config.output_dir) / "labeled_contracts.json"
        
        if labeled_path.exists():
            with open(labeled_path, 'r') as f:
                labeled = json.load(f)
                for item in labeled:
                    self.training_data.append({
                        "features": item["features"],
                        "label": item["label"],
                        "source": "manual_label"
                    })
    
    def prepare_data(self) -> tuple:
        """
        Prepare data for training
        
        Returns:
            (X_train, X_val, X_test, y_train, y_val, y_test)
        """
        if not self.training_data:
            raise ValueError("No training data. Call collect_training_data() first.")
        
        # Extract features and labels
        X = np.array([d["features"] for d in self.training_data])
        labels = [d["label"] for d in self.training_data]
        
        # Encode labels
        unique_labels = list(set(labels))
        self.label_encoder = {label: i for i, label in enumerate(unique_labels)}
        self.label_decoder = {i: label for label, i in self.label_encoder.items()}
        y = np.array([self.label_encoder[label] for label in labels])
        
        # Check for classes with too few samples
        from collections import Counter
        label_counts = Counter(y)
        min_count = min(label_counts.values())
        
        # Use stratify only if all classes have enough samples
        use_stratify = min_count >= 3
        
        # Split data
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, 
            test_size=self.config.test_split,
            random_state=self.config.random_seed,
            stratify=y if use_stratify else None
        )
        
        val_ratio = self.config.val_split / (self.config.train_split + self.config.val_split)
        
        # Check again for validation split
        val_label_counts = Counter(y_temp)
        val_min_count = min(val_label_counts.values())
        use_val_stratify = val_min_count >= 2
        
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp,
            test_size=val_ratio,
            random_state=self.config.random_seed,
            stratify=y_temp if use_val_stratify else None
        )
        
        print(f"📊 Data split:")
        print(f"   Training:   {len(X_train)} samples")
        print(f"   Validation: {len(X_val)} samples")
        print(f"   Test:       {len(X_test)} samples")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def train(self) -> TrainingResult:
        """
        Train the model
        
        Returns:
            TrainingResult with metrics
        """
        if not ML_AVAILABLE:
            raise RuntimeError("scikit-learn not installed")
        
        import time
        start_time = time.time()
        
        # Prepare data
        X_train, X_val, X_test, y_train, y_val, y_test = self.prepare_data()
        
        # Create model
        print(f"🔧 Training {self.config.model_type} model...")
        
        if self.config.model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=self.config.n_estimators,
                max_depth=self.config.max_depth,
                random_state=self.config.random_seed,
                class_weight='balanced'
            )
        elif self.config.model_type == "gradient_boosting":
            self.model = GradientBoostingClassifier(
                n_estimators=self.config.n_estimators,
                max_depth=self.config.max_depth,
                random_state=self.config.random_seed
            )
        
        # Train
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        
        # Cross-validation
        cv_scores = cross_val_score(
            self.model, X_train, y_train, 
            cv=self.config.cross_validation_folds
        )
        
        # Metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # Reports
        target_names = [self.label_decoder[i] for i in range(len(self.label_decoder))]
        report = classification_report(y_test, y_pred, target_names=target_names, zero_division=0)
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        training_time = time.time() - start_time
        
        print(f"\n📊 Training Results:")
        print(f"   Accuracy:  {accuracy:.2%}")
        print(f"   Precision: {precision:.2%}")
        print(f"   Recall:    {recall:.2%}")
        print(f"   F1 Score:  {f1:.2%}")
        print(f"   CV Scores: {cv_scores.mean():.2%} (+/- {cv_scores.std()*2:.2%})")
        print(f"\n{report}")
        
        result = TrainingResult(
            model_name=self.config.model_name,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            training_samples=len(X_train),
            validation_samples=len(X_val),
            test_samples=len(X_test),
            cross_val_scores=cv_scores.tolist(),
            confusion_matrix=cm,
            classification_report=report,
            training_time_seconds=training_time,
            timestamp=datetime.utcnow().isoformat()
        )
        
        return result
    
    def save_model(self, result: TrainingResult):
        """Save trained model and metadata"""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save model
        model_path = output_dir / f"{self.config.model_name}.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'label_encoder': self.label_encoder,
                'label_decoder': self.label_decoder,
                'config': asdict(self.config)
            }, f)
        
        # Save training results
        results_path = output_dir / f"{self.config.model_name}_results.json"
        with open(results_path, 'w') as f:
            json.dump(asdict(result), f, indent=2)
        
        print(f"\n💾 Model saved to: {model_path}")
        print(f"📊 Results saved to: {results_path}")
    
    def run(self) -> TrainingResult:
        """Run complete training pipeline"""
        print("=" * 60)
        print("🚀 STARTING ML TRAINING PIPELINE")
        print("=" * 60)
        
        # Collect data
        self.collect_training_data()
        
        # Train model
        result = self.train()
        
        # Save
        self.save_model(result)
        
        print("\n" + "=" * 60)
        print("✅ TRAINING COMPLETE")
        print("=" * 60)
        
        return result

if __name__ == "__main__":
    # Run training
    config = TrainingConfig(
        model_type="random_forest",
        n_estimators=100,
        output_dir="./data/models"
    )
    
    pipeline = TrainingPipeline(config)
    result = pipeline.run()
