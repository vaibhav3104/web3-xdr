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
import pickle
import random
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from datetime import datetime

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
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
    Generates diverse synthetic exploit bytecodes with realistic variation.

    Each template is randomized with:
    - Random padding/filler opcodes
    - Variable-length PUSH data
    - Shuffled non-critical sections
    - Random contract sizes
    """

    @staticmethod
    def _random_hex(n: int) -> str:
        """Generate n random hex bytes."""
        return ''.join(random.choice('0123456789abcdef') for _ in range(n * 2))

    @staticmethod
    def _random_filler(min_ops: int = 5, max_ops: int = 30) -> str:
        """Generate random filler opcodes (arithmetic, stack, memory)."""
        safe_ops = [
            "01", "02", "03", "04", "05", "06",  # arithmetic
            "10", "11", "14", "15", "16", "17",  # comparison/bitwise
            "50", "51", "52", "53",  # stack/memory
            "80", "81", "82", "83",  # DUP1-4
            "90", "91", "92",  # SWAP1-3
        ]
        count = random.randint(min_ops, max_ops)
        ops = []
        for _ in range(count):
            op = random.choice(safe_ops)
            ops.append(op)
            # Occasionally add PUSH with random data
            if random.random() < 0.3:
                push_size = random.randint(1, 4)
                push_op = hex(0x5f + push_size)[2:]
                ops.append(push_op + MockExploitGenerator._random_hex(push_size))
        return ''.join(ops)

    @staticmethod
    def _solidity_preamble() -> str:
        """Standard Solidity contract preamble with variation."""
        # PUSH1 0x80 PUSH1 0x40 MSTORE [CALLVALUE DUP1 ISZERO ... REVERT]
        base = "6080604052"
        if random.random() < 0.7:
            base += "34801561001057600080fd5b50"
        base += MockExploitGenerator._random_filler(2, 8)
        return base

    @staticmethod
    def generate_flash_loan_exploit() -> str:
        """Flash loan exploit: callback sig + CALL + SSTORE pattern."""
        preamble = MockExploitGenerator._solidity_preamble()
        # Flash loan callback signatures
        sigs = ["23e30c8b", "c3924ed6", "ab803a65", "ee872558"]
        sig = random.choice(sigs)
        filler1 = MockExploitGenerator._random_filler(5, 15)
        # Function dispatcher with flash loan sig
        dispatcher = f"600035{'60' + sig[:2]}{'63' + sig}{filler1}"
        # SLOAD + CALL (external call) + SSTORE (state change after call = reentrancy risk)
        attack = (
            f"54{MockExploitGenerator._random_filler(2, 6)}"
            f"{'60' + MockExploitGenerator._random_hex(1)}73{MockExploitGenerator._random_hex(20)}"
            f"{'60' + MockExploitGenerator._random_hex(1)}f1"  # CALL
            f"{MockExploitGenerator._random_filler(1, 4)}55"  # SSTORE after CALL
        )
        # Extra CALL chains for depth
        extra_calls = ""
        for _ in range(random.randint(1, 3)):
            extra_calls += (
                f"{'60' + MockExploitGenerator._random_hex(1)}f1"
                f"{MockExploitGenerator._random_filler(1, 3)}"
            )
        suffix = MockExploitGenerator._random_filler(10, 40)
        return preamble + dispatcher + attack + extra_calls + suffix + "00"

    @staticmethod
    def generate_reentrancy_exploit() -> str:
        """Reentrancy: CALL before SSTORE, no guard check."""
        preamble = MockExploitGenerator._solidity_preamble()
        filler = MockExploitGenerator._random_filler(5, 15)
        # SLOAD balance, then CALL to send ETH, then SSTORE (update state AFTER call)
        attack = (
            f"54"  # SLOAD
            f"{MockExploitGenerator._random_filler(2, 5)}"
            f"73{MockExploitGenerator._random_hex(20)}"  # address
            f"{'6108fc' if random.random() < 0.5 else '60' + MockExploitGenerator._random_hex(1) + 'f1'}"
            f"{MockExploitGenerator._random_filler(1, 4)}"
            f"55"  # SSTORE after external call
        )
        # Withdraw function sig
        withdraw_sigs = ["3ccfd60b", "2e1a7d4d", "f3fef3a3"]
        sig = random.choice(withdraw_sigs)
        dispatcher = f"600435{'63' + sig}{MockExploitGenerator._random_filler(3, 8)}"
        suffix = MockExploitGenerator._random_filler(10, 30)
        return preamble + dispatcher + filler + attack + suffix + "00"

    @staticmethod
    def generate_unchecked_call_exploit() -> str:
        """Unchecked external call: CALL without return value check."""
        preamble = MockExploitGenerator._solidity_preamble()
        filler = MockExploitGenerator._random_filler(5, 20)
        # Multiple unchecked CALLs (no ISZERO after)
        calls = ""
        for _ in range(random.randint(2, 5)):
            calls += (
                f"73{MockExploitGenerator._random_hex(20)}"
                f"{'60' + MockExploitGenerator._random_hex(1)}f1"  # CALL
                f"50"  # POP return value (unchecked!)
                f"{MockExploitGenerator._random_filler(1, 4)}"
            )
        suffix = MockExploitGenerator._random_filler(5, 20)
        return preamble + filler + calls + suffix + "00"

    @staticmethod
    def generate_selfdestruct_exploit() -> str:
        """Selfdestruct: admin-gated self-destruct with ownership transfer."""
        preamble = MockExploitGenerator._solidity_preamble()
        # Admin sigs: renounceOwnership, transferOwnership
        admin_sigs = ["715018a6", "f2fde38b"]
        sig = random.choice(admin_sigs)
        dispatcher = f"600435{'63' + sig}{MockExploitGenerator._random_filler(3, 6)}"
        filler = MockExploitGenerator._random_filler(10, 25)
        # CALLER check + SELFDESTRUCT
        attack = (
            f"33"  # CALLER
            f"54"  # SLOAD (owner)
            f"14"  # EQ
            f"{MockExploitGenerator._random_filler(1, 3)}"
            f"73{MockExploitGenerator._random_hex(20)}"
            f"ff"  # SELFDESTRUCT
        )
        return preamble + dispatcher + filler + attack + "00"

    @staticmethod
    def generate_delegatecall_exploit() -> str:
        """Delegatecall: proxy-like contract with dangerous delegatecall."""
        preamble = MockExploitGenerator._solidity_preamble()
        # Proxy pattern sigs
        proxy_sigs = ["5c60da1b", "3659cfe6", "f851a440"]
        sig = random.choice(proxy_sigs)
        dispatcher = f"600435{'63' + sig}{MockExploitGenerator._random_filler(2, 6)}"
        filler = MockExploitGenerator._random_filler(5, 15)
        # Multiple DELEGATECALLs
        delegatecalls = ""
        for _ in range(random.randint(2, 4)):
            delegatecalls += (
                f"73{MockExploitGenerator._random_hex(20)}"
                f"{'60' + MockExploitGenerator._random_hex(1)}f4"  # DELEGATECALL
                f"55"  # SSTORE
                f"{MockExploitGenerator._random_filler(1, 3)}"
            )
        suffix = MockExploitGenerator._random_filler(5, 15)
        return preamble + dispatcher + filler + delegatecalls + suffix + "00"

    @staticmethod
    def generate_oracle_manipulation() -> str:
        """Oracle manipulation: price read + large swap + price read pattern."""
        preamble = MockExploitGenerator._solidity_preamble()
        filler = MockExploitGenerator._random_filler(10, 20)
        # Pattern: STATICCALL (read price) + CALL (swap) + STATICCALL (read again) + CALL (profit)
        attack = (
            f"73{MockExploitGenerator._random_hex(20)}"
            f"{'60' + MockExploitGenerator._random_hex(1)}fa"  # STATICCALL (price oracle)
            f"{MockExploitGenerator._random_filler(2, 5)}"
            f"73{MockExploitGenerator._random_hex(20)}"
            f"{'60' + MockExploitGenerator._random_hex(1)}f1"  # CALL (swap)
            f"{MockExploitGenerator._random_filler(2, 5)}"
            f"73{MockExploitGenerator._random_hex(20)}"
            f"{'60' + MockExploitGenerator._random_hex(1)}fa"  # STATICCALL (read again)
            f"{MockExploitGenerator._random_filler(2, 5)}"
            f"73{MockExploitGenerator._random_hex(20)}"
            f"{'60' + MockExploitGenerator._random_hex(1)}f1"  # CALL (profit)
        )
        suffix = MockExploitGenerator._random_filler(5, 15)
        return preamble + filler + attack + suffix + "00"

    @staticmethod
    def generate_timestamp_exploit() -> str:
        """Timestamp dependence: uses TIMESTAMP for pseudo-randomness."""
        preamble = MockExploitGenerator._solidity_preamble()
        filler = MockExploitGenerator._random_filler(5, 15)
        # TIMESTAMP used in conditional logic
        attack = (
            f"42"  # TIMESTAMP
            f"{MockExploitGenerator._random_filler(1, 3)}"
            f"06"  # MOD
            f"15"  # ISZERO
            f"57"  # JUMPI (conditional based on timestamp)
            f"5b"  # JUMPDEST
            f"73{MockExploitGenerator._random_hex(20)}"
            f"{'60' + MockExploitGenerator._random_hex(1)}f1"  # CALL
            f"55"  # SSTORE
        )
        suffix = MockExploitGenerator._random_filler(5, 20)
        return preamble + filler + attack + suffix + "00"

    @staticmethod
    def generate_all_mock_exploits(count: int = 80) -> List[Tuple[str, str]]:
        """Generate diverse mock exploit bytecodes with randomized variation."""
        exploits = []
        generators = [
            ("flash_loan", MockExploitGenerator.generate_flash_loan_exploit),
            ("reentrancy", MockExploitGenerator.generate_reentrancy_exploit),
            ("unchecked_call", MockExploitGenerator.generate_unchecked_call_exploit),
            ("selfdestruct", MockExploitGenerator.generate_selfdestruct_exploit),
            ("delegatecall", MockExploitGenerator.generate_delegatecall_exploit),
            ("oracle_manipulation", MockExploitGenerator.generate_oracle_manipulation),
            ("timestamp", MockExploitGenerator.generate_timestamp_exploit),
        ]

        for i in range(count):
            name, generator = generators[i % len(generators)]
            bytecode = generator()
            exploits.append((bytecode, f"mock_{name}_{i}"))

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
        """Save trained model in format compatible with ContractThreatClassifier."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)

        # Save as joblib for the training pipeline
        joblib.dump(self.model, path)
        logger.info("joblib_model_saved", path=str(path))

        # Also save in pickle dict format for ContractThreatClassifier.load_model()
        compat_path = path.parent / "contract_classifier.pkl"
        with open(compat_path, "wb") as f:
            pickle.dump({
                "model": self.model,
                "known_exploits": {},
                "rule_weights": None,
                "feature_count": len(self.feature_names),
                "feature_names": self.feature_names,
                "model_type": self.model_type,
                "training_date": datetime.now().isoformat(),
            }, f)
        logger.info("compat_model_saved", path=str(compat_path))


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
    
    # Evaluate on held-out test set
    metrics = trainer.evaluate(X_test, y_test)

    # Cross-validation on full dataset to check for overfitting
    cv_scores = cross_val_score(trainer.model, X, y, cv=min(5, len(X) // 4), scoring="f1")
    metrics["cv_f1_mean"] = float(np.mean(cv_scores))
    metrics["cv_f1_std"] = float(np.std(cv_scores))
    logger.info("cross_validation", cv_f1_mean=f"{np.mean(cv_scores):.3f}", cv_f1_std=f"{np.std(cv_scores):.3f}")

    # Generate plots
    trainer.plot_feature_importance(FEATURE_IMPORTANCE_PLOT)
    trainer.plot_confusion_matrix(y_test, trainer.model.predict(X_test), CONFUSION_MATRIX_PLOT)

    # Save model
    trainer.save_model(MODEL_PATH)

    # Save metrics
    metrics["training_date"] = datetime.now().isoformat()
    metrics["model_type"] = args.model
    metrics["feature_count"] = len(FEATURE_NAMES)
    metrics["total_samples"] = len(X)
    metrics["safe_samples"] = int(np.sum(y == 0))
    metrics["exploit_samples"] = int(np.sum(y == 1))
    
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
    print(f"   CV F1 (5-fold):  {metrics['cv_f1_mean']:.3f} +/- {metrics['cv_f1_std']:.3f}")
    print(f"   Total Samples:   {len(X)} (safe={np.sum(y==0)}, exploit={np.sum(y==1)})")
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

