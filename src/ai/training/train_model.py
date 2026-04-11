#!/usr/bin/env python3
"""
Sentinel3 ML Model Training Pipeline
====================================

Phase 3.2: Train RandomForest/XGBoost classifier using 43-dimensional features.

Features:
- Loads safe contracts (29 protocols) and exploit contracts
- Extracts 43-dimensional feature vectors using EnhancedBytecodeExtractor
- Handles class imbalance with SMOTE
- Trains RandomForestClassifier with feature importance analysis
- Generates confusion matrix and feature importance plots
- Saves trained model for production use

Usage:
    python src/ai/training/train_model.py
    python src/ai/training/train_model.py --model xgboost
    python src/ai/training/train_model.py --use-mock-exploits
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from datetime import datetime

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score
)
from imblearn.over_sampling import SMOTE
import joblib

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor
import structlog

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer()
    ]
)

logger = structlog.get_logger(__name__)

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SAFE_SAMPLES_DIR = PROJECT_ROOT / "src" / "ai" / "data" / "safe_samples"
MODEL_DIR = PROJECT_ROOT / "src" / "ai" / "models"
MODEL_PATH = MODEL_DIR / "classifier.pkl"
FEATURE_IMPORTANCE_PLOT = MODEL_DIR / "feature_importance.png"
CONFUSION_MATRIX_PLOT = MODEL_DIR / "confusion_matrix.png"
METRICS_FILE = MODEL_DIR / "training_metrics.json"

# Feature names for interpretability
FEATURE_NAMES = [
    # Basic (4)
    "bytecode_length", "unique_opcodes", "total_instructions", "code_density",
    # Opcode counts (8)
    "call_count", "delegatecall_count", "staticcall_count", "create_count",
    "create2_count", "sload_count", "sstore_count", "selfdestruct_count",
    # CFG Complexity (6)
    "cfg_complexity_score", "jump_count", "jumpi_count", "basic_block_count",
    "max_nesting_depth", "loop_count",
    # External Calls (3)
    "external_call_depth", "external_call_sequence_length", "call_to_storage_ratio",
    # Entropy (3)
    "bytecode_entropy", "opcode_entropy", "push_data_entropy",
    # Gas (3)
    "estimated_gas_cost", "gas_per_instruction", "high_gas_opcode_ratio",
    # Patterns (8)
    "function_count", "has_flash_loan_callback", "has_withdraw_function",
    "has_mint_function", "has_burn_function", "has_admin_functions",
    "has_proxy_pattern", "has_factory_pattern",
    # Risk Patterns (5)
    "has_reentrancy_pattern", "has_delegatecall_pattern", "has_selfdestruct",
    "has_unchecked_call", "has_timestamp_dependency",
    # Advanced (3)
    "storage_intensity", "external_interaction_ratio", "risk_score"
]


class MockExploitGenerator:
    """
    Generates synthetic exploit bytecode for testing when real exploit
    bytecode is not available.
    
    Creates bytecode patterns that mimic common exploit characteristics:
    - Flash loan callbacks
    - Reentrancy patterns
    - Unchecked external calls
    - High CFG complexity
    """
    
    @staticmethod
    def generate_flash_loan_exploit() -> str:
        """Generate bytecode with flash loan callback pattern."""
        # Pattern: PUSH4 flash loan sig + CALL + SSTORE (reentrancy)
        return (
            "608060405234801561001057600080fd5b50600436106100415760003560e01c8063"
            "23e30c8b14610046578063c3924ed614610062575b600080fd5b6100606004803603"
            "810190610057919061024d565b61007e565b005b61007c6004803603810190610077"
            "91906102d0565b610101565b005b60008054905090565b600080543373ffffffff"
            "ffffffffffffffffffffffffffff1614156100ef573373ffffffffffffffffffff"
            "ffffffffffffffff166108fc600080549081150290604051600060405180830381"
            "858888f19350505050158015610030573d6000803e3d6000fd5b505b565b34600080"
            "82825401925050819055503373ffffffffffffffffffffffffffffffffffffffff"
            "166108fc600080549081150290604051600060405180830381858888f193505050"
            "50158015610030573d6000803e3d6000fd5b505b565b"
        )
    
    @staticmethod
    def generate_reentrancy_exploit() -> str:
        """Generate bytecode with reentrancy pattern."""
        # Pattern: CALL before SSTORE (classic reentrancy)
        return (
            "608060405234801561001057600080fd5b50600436106100415760003560e01c8063"
            "3ccfd60b14610046578063d0e30db01461006e575b600080fd5b61004e610078565b"
            "60405161005b9190610256565b60405180910390f35b61007761008c565b005b6100"
            "816100f1565b005b60008054905090565b600080543373ffffffffffffffffffff"
            "ffffffffffffffff1614156100ef573373ffffffffffffffffffffffffffffffff"
            "ffffffff166108fc600080549081150290604051600060405180830381858888f1"
            "9350505050158015610030573d6000803e3d6000fd5b505b565b3460008082825401"
            "925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc"
            "600080549081150290604051600060405180830381858888f19350505050158015"
            "610030573d6000803e3d6000fd5b505b565b"
        )
    
    @staticmethod
    def generate_unchecked_call_exploit() -> str:
        """Generate bytecode with unchecked external call."""
        # Pattern: CALL without ISZERO check
        return (
            "608060405234801561001057600080fd5b50600436106100415760003560e01c8063"
            "f1f1f1f1146100465780633ccfd60b14610064578063d0e30db01461006e575b6000"
            "80fd5b61004e610078565b60405161005b9190610256565b60405180910390f35b"
            "61007761008c565b005b6100816100f1565b005b60008054905090565b60008054"
            "3373ffffffffffffffffffffffffffffffffffffffff1614156100ef573373ffff"
            "ffffffffffffffffffffffffffffffffffff166108fc6000805490811502906040"
            "51600060405180830381858888f19350505050158015610030573d6000803e3d60"
            "00fd5b505b565b3460008082825401925050819055503373ffffffffffffffffff"
            "ffffffffffffffffffffffffffff166108fc600080549081150290604051600060"
            "405180830381858888f19350505050158015610030573d6000803e3d6000fd5b505b"
            "565b"
        )
    
    @staticmethod
    def generate_all_mock_exploits(count: int = 50) -> List[Tuple[str, str]]:
        """Generate multiple mock exploit bytecodes."""
        exploits = []
        generators = [
            MockExploitGenerator.generate_flash_loan_exploit,
            MockExploitGenerator.generate_reentrancy_exploit,
            MockExploitGenerator.generate_unchecked_call_exploit,
        ]
        
        for i in range(count):
            generator = generators[i % len(generators)]
            bytecode = generator()
            exploits.append((bytecode, f"mock_exploit_{i}"))
        
        return exploits


class ContractDataLoader:
    """Loads and prepares contract data for training."""
    
    def __init__(self, use_mock_exploits: bool = False):
        self.extractor = EnhancedBytecodeExtractor()
        self.use_mock_exploits = use_mock_exploits
        self.safe_samples_dir = SAFE_SAMPLES_DIR
    
    def load_safe_contracts(self) -> List[Tuple[str, str]]:
        """Load safe contract bytecode from safe_samples directory."""
        contracts = []
        
        if not self.safe_samples_dir.exists():
            logger.warning("safe_samples_dir_not_found", path=str(self.safe_samples_dir))
            return contracts
        
        metadata_file = self.safe_samples_dir / "metadata.json"
        if metadata_file.exists():
            with open(metadata_file) as f:
                metadata = json.load(f)
            
            for addr, contract_data in metadata.get("contracts", {}).items():
                chain = contract_data.get("chain", "ethereum")
                bytecode_file = self.safe_samples_dir / f"{chain}_{addr}.bin"
                
                if bytecode_file.exists():
                    with open(bytecode_file) as f:
                        bytecode = f.read().strip()
                    if bytecode and len(bytecode) > 4:
                        contracts.append((bytecode, f"{chain}_{addr}"))
        
        logger.info("safe_contracts_loaded", count=len(contracts))
        return contracts
    
    def load_exploit_contracts(self) -> List[Tuple[str, str]]:
        """Load exploit contract bytecode."""
        if self.use_mock_exploits:
            logger.info("using_mock_exploits")
            return MockExploitGenerator.generate_all_mock_exploits(50)
        
        # Try to load real exploit contracts
        
        # For now, use mock exploits as real bytecode fetching requires RPC calls
        # In production, you would fetch bytecode from blockchain using addresses
        # from EXPLOIT_DATABASE
        
        logger.warning(
            "real_exploit_bytecode_not_available",
            hint="Using mock exploits. For production, fetch bytecode from blockchain."
        )
        
        return MockExploitGenerator.generate_all_mock_exploits(50)
    
    def extract_features(self, bytecode: str) -> Optional[np.ndarray]:
        """Extract 43-dimensional feature vector from bytecode."""
        try:
            features = self.extractor.extract_features(bytecode)
            vector = features.to_vector()
            
            if len(vector) != 43:
                logger.warning(
                    "feature_vector_wrong_dimension",
                    expected=43,
                    actual=len(vector)
                )
                return None
            
            return np.array(vector)
        except Exception as e:
            logger.error("feature_extraction_failed", error=str(e))
            return None
    
    def prepare_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training dataset with features and labels."""
        logger.info("preparing_dataset")
        
        # Load safe contracts (label 0)
        safe_contracts = self.load_safe_contracts()
        logger.info("safe_contracts_loaded", count=len(safe_contracts))
        
        # Load exploit contracts (label 1)
        exploit_contracts = self.load_exploit_contracts()
        logger.info("exploit_contracts_loaded", count=len(exploit_contracts))
        
        # Extract features
        X = []
        y = []
        
        logger.info("extracting_features_from_safe_contracts")
        for bytecode, name in safe_contracts:
            features = self.extract_features(bytecode)
            if features is not None:
                X.append(features)
                y.append(0)  # Safe
        
        logger.info("extracting_features_from_exploit_contracts")
        for bytecode, name in exploit_contracts:
            features = self.extract_features(bytecode)
            if features is not None and len(features) == 43:
                X.append(features)
                y.append(1)  # Exploit
        
        if len(X) == 0:
            raise ValueError("No valid features extracted. Check bytecode format.")
        
        # Ensure all vectors have the same length
        X_array = []
        y_array = []
        for i, vec in enumerate(X):
            if len(vec) == 43:
                X_array.append(vec)
                y_array.append(y[i])
            else:
                logger.warning("skipping_mismatched_vector", length=len(vec), index=i)
        
        X = np.array(X_array)
        y = np.array(y_array)
        
        logger.info(
            "dataset_prepared",
            total_samples=len(X),
            safe_samples=np.sum(y == 0),
            exploit_samples=np.sum(y == 1),
            feature_dimension=X.shape[1]
        )
        
        return X, y


class ModelTrainer:
    """Trains and evaluates ML models."""
    
    def __init__(self, model_type: str = "random_forest"):
        self.model_type = model_type
        self.model = None
        self.feature_names = FEATURE_NAMES
    
    def create_model(self, **kwargs):
        """Create model instance."""
        if self.model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=kwargs.get("n_estimators", 100),
                max_depth=kwargs.get("max_depth", 20),
                min_samples_split=kwargs.get("min_samples_split", 5),
                min_samples_leaf=kwargs.get("min_samples_leaf", 2),
                class_weight=kwargs.get("class_weight", "balanced"),
                random_state=42,
                n_jobs=-1
            )
        elif self.model_type == "xgboost":
            try:
                import xgboost as xgb
                self.model = xgb.XGBClassifier(
                    n_estimators=kwargs.get("n_estimators", 100),
                    max_depth=kwargs.get("max_depth", 6),
                    learning_rate=kwargs.get("learning_rate", 0.1),
                    random_state=42,
                    n_jobs=-1
                )
            except ImportError:
                logger.error("xgboost_not_installed", hint="pip install xgboost")
                raise
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, use_smote: bool = True):
        """Train the model with optional SMOTE oversampling."""
        logger.info("training_model", model_type=self.model_type, use_smote=use_smote)
        
        # Apply SMOTE if requested
        if use_smote:
            logger.info("applying_smote")
            smote = SMOTE(random_state=42)
            X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
            logger.info(
                "smote_applied",
                original_samples=len(X_train),
                resampled_samples=len(X_train_resampled)
            )
        else:
            X_train_resampled, y_train_resampled = X_train, y_train
        
        # Train model
        self.model.fit(X_train_resampled, y_train_resampled)
        logger.info("model_trained")
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Evaluate model and return metrics."""
        logger.info("evaluating_model")
        
        # Predictions
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        
        # Metrics
        metrics = {
            "accuracy": float(np.mean(y_pred == y_test)),
            "precision": float(np.sum((y_pred == 1) & (y_test == 1)) / max(np.sum(y_pred == 1), 1)),
            "recall": float(np.sum((y_pred == 1) & (y_test == 1)) / max(np.sum(y_test == 1), 1)),
            "f1_score": 0.0,
            "roc_auc": float(roc_auc_score(y_test, y_pred_proba)),
            "average_precision": float(average_precision_score(y_test, y_pred_proba)),
        }
        
        # Calculate F1
        if metrics["precision"] + metrics["recall"] > 0:
            metrics["f1_score"] = 2 * (metrics["precision"] * metrics["recall"]) / (
                metrics["precision"] + metrics["recall"]
            )
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        metrics["confusion_matrix"] = cm.tolist()
        
        # Classification report
        report = classification_report(y_test, y_pred, output_dict=True)
        metrics["classification_report"] = report
        
        logger.info(
            "evaluation_complete",
            accuracy=f"{metrics['accuracy']:.3f}",
            precision=f"{metrics['precision']:.3f}",
            recall=f"{metrics['recall']:.3f}",
            f1=f"{metrics['f1_score']:.3f}",
            roc_auc=f"{metrics['roc_auc']:.3f}"
        )
        
        return metrics
    
    def plot_feature_importance(self, save_path: Path):
        """Plot feature importance."""
        if not hasattr(self.model, "feature_importances_"):
            logger.warning("model_has_no_feature_importances")
            return
        
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        # Plot top 20 features
        top_n = min(20, len(importances))
        plt.figure(figsize=(12, 8))
        plt.title(f"Top {top_n} Feature Importances ({self.model_type})")
        plt.barh(range(top_n), importances[indices[:top_n]])
        plt.yticks(range(top_n), [self.feature_names[i] for i in indices[:top_n]])
        plt.xlabel("Importance")
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
        plt.close()
        
        logger.info("feature_importance_plot_saved", path=str(save_path))
        
        # Print top features
        print("\n" + "=" * 70)
        print("  TOP 10 MOST IMPORTANT FEATURES")
        print("=" * 70)
        for i in range(min(10, len(indices))):
            idx = indices[i]
            print(f"  {i+1:2d}. {self.feature_names[idx]:35s} {importances[idx]:.4f}")
        print()
    
    def plot_confusion_matrix(self, y_test: np.ndarray, y_pred: np.ndarray, save_path: Path):
        """Plot confusion matrix."""
        cm = confusion_matrix(y_test, y_pred)
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=["Safe", "Exploit"],
            yticklabels=["Safe", "Exploit"]
        )
        plt.title("Confusion Matrix")
        plt.ylabel("True Label")
        plt.xlabel("Predicted Label")
        plt.tight_layout()
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
        plt.close()
        
        logger.info("confusion_matrix_plot_saved", path=str(save_path))
    
    def save_model(self, path: Path):
        """Save trained model."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path)
        logger.info("model_saved", path=str(path))


def main():
    """Main training pipeline."""
    parser = argparse.ArgumentParser(description="Train ML model for contract classification")
    parser.add_argument(
        "--model",
        type=str,
        choices=["random_forest", "xgboost"],
        default="random_forest",
        help="Model type to train"
    )
    parser.add_argument(
        "--use-mock-exploits",
        action="store_true",
        help="Use mock exploit bytecode instead of fetching from blockchain"
    )
    parser.add_argument(
        "--no-smote",
        action="store_true",
        help="Disable SMOTE oversampling"
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test set size (default: 0.2)"
    )
    
    args = parser.parse_args()
    
    print()
    print("=" * 70)
    print("  🛡️  Sentinel3 ML Model Training Pipeline")
    print("=" * 70)
    print(f"   Model:        {args.model}")
    print(f"   Mock Exploits: {args.use_mock_exploits}")
    print(f"   SMOTE:        {not args.no_smote}")
    print(f"   Test Size:    {args.test_size}")
    print()
    
    # Ensure model directory exists
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load data
    loader = ContractDataLoader(use_mock_exploits=args.use_mock_exploits)
    X, y = loader.prepare_dataset()
    
    if len(X) == 0:
        logger.error("no_data_loaded")
        return
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )
    
    logger.info(
        "data_split",
        train_samples=len(X_train),
        test_samples=len(X_test),
        train_safe=np.sum(y_train == 0),
        train_exploit=np.sum(y_train == 1)
    )
    
    # Train model
    trainer = ModelTrainer(model_type=args.model)
    trainer.create_model()
    trainer.train(X_train, y_train, use_smote=not args.no_smote)
    
    # Evaluate
    metrics = trainer.evaluate(X_test, y_test)
    
    # Generate plots
    trainer.plot_feature_importance(FEATURE_IMPORTANCE_PLOT)
    trainer.plot_confusion_matrix(y_test, trainer.model.predict(X_test), CONFUSION_MATRIX_PLOT)
    
    # Save model
    trainer.save_model(MODEL_PATH)
    
    # Save metrics
    metrics["training_date"] = datetime.now().isoformat()
    metrics["model_type"] = args.model
    metrics["feature_count"] = len(FEATURE_NAMES)
    
    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f, indent=2)
    
    # Print summary
    print()
    print("=" * 70)
    print("  📊 TRAINING SUMMARY")
    print("=" * 70)
    print(f"   Accuracy:        {metrics['accuracy']:.3f}")
    print(f"   Precision:       {metrics['precision']:.3f}")
    print(f"   Recall:          {metrics['recall']:.3f}")
    print(f"   F1 Score:        {metrics['f1_score']:.3f}")
    print(f"   ROC AUC:         {metrics['roc_auc']:.3f}")
    print(f"   Avg Precision:   {metrics['average_precision']:.3f}")
    print()
    print(f"   Model saved:     {MODEL_PATH}")
    print(f"   Plots saved:     {FEATURE_IMPORTANCE_PLOT}")
    print(f"                    {CONFUSION_MATRIX_PLOT}")
    print(f"   Metrics saved:   {METRICS_FILE}")
    print()
    
    # Feature importance interpretation
    print("=" * 70)
    print("  📈 FEATURE IMPORTANCE INTERPRETATION")
    print("=" * 70)
    print("""
  Higher importance values indicate features that are more predictive
  of exploit contracts. Key insights:

  • CFG Complexity: High complexity may indicate exploit logic
  • External Call Depth: Deep call chains suggest flash loan patterns
  • Entropy: Low entropy may indicate packed/obfuscated exploit code
  • Risk Patterns: Flags like has_reentrancy_pattern are direct indicators
  • Gas Analysis: Unusual gas patterns may indicate exploit optimization

  Use these insights to:
  1. Focus monitoring on high-importance features
  2. Tune detection thresholds based on feature values
  3. Improve feature engineering for low-importance features
    """)
    print()


if __name__ == "__main__":
    main()

