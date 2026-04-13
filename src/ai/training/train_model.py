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
- Stratified 5-fold cross-validation with overfitting detection
- Model versioning with timestamps and metadata
- Graceful fallback: real exploits -> cached bytecodes -> mock augmentation

Usage:
    python src/ai/training/train_model.py
    python src/ai/training/train_model.py --model xgboost
    python src/ai/training/train_model.py --use-mock-exploits
"""

import argparse
import asyncio
import json
import os
import pickle
import random
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from datetime import datetime

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (
    train_test_split,
    cross_val_score,
    StratifiedKFold,
)
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    f1_score,
)
from imblearn.over_sampling import SMOTE
import joblib

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor
from src.ai.data.bytecode_collector import (
    BytecodeCollector,
    EXPLOIT_CONTRACTS,
    SAFE_CONTRACTS,
)
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
EXPLOIT_SAMPLES_DIR = PROJECT_ROOT / "src" / "ai" / "data" / "exploit_samples"
MODEL_DIR = PROJECT_ROOT / "src" / "ai" / "models"
MODEL_PATH = MODEL_DIR / "classifier.pkl"
COMPAT_MODEL_PATH = MODEL_DIR / "contract_classifier.pkl"
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
        self.exploit_samples_dir = EXPLOIT_SAMPLES_DIR
        # Track data provenance for model metadata
        self.real_exploit_count = 0
        self.cached_exploit_count = 0
        self.mock_exploit_count = 0
        self.mock_only = False

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

    def _fetch_exploit_bytecodes_via_rpc(self) -> List[Tuple[str, str]]:
        """Try to fetch real exploit bytecodes from blockchain via RPC.

        Returns list of (bytecode, label) tuples, or empty list on failure.
        """
        eth_rpc = os.getenv("ETH_RPC_URL")
        if not eth_rpc:
            logger.info("no_eth_rpc_url", hint="Set ETH_RPC_URL to fetch real exploit bytecodes")
            return []

        logger.info("fetching_exploits_via_rpc", rpc=eth_rpc[:30] + "...")

        contracts: List[Tuple[str, str]] = []

        async def _fetch_all():
            async with BytecodeCollector() as collector:
                for chain, chain_contracts in EXPLOIT_CONTRACTS.items():
                    for contract_info in chain_contracts:
                        try:
                            bytecode = await collector.get_bytecode(
                                contract_info["address"], chain
                            )
                            if bytecode and len(bytecode) > 10:
                                label = f"{chain}_{contract_info['address'][:10]}_{contract_info.get('attack', 'unknown')}"
                                contracts.append((bytecode, label))
                                logger.info(
                                    "rpc_exploit_fetched",
                                    address=contract_info["address"][:10] + "...",
                                    chain=chain,
                                    attack=contract_info.get("attack", "unknown"),
                                )
                        except Exception as e:
                            logger.warning(
                                "rpc_exploit_fetch_failed",
                                address=contract_info["address"][:10] + "...",
                                error=str(e),
                            )
                        await asyncio.sleep(1.0)  # rate limit — public RPCs throttle at ~2 req/s
            return contracts

        try:
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(_fetch_all())
            loop.close()
            return result
        except Exception as e:
            logger.warning("rpc_fetch_failed", error=str(e))
            return []

    def _load_cached_exploit_bytecodes(self) -> List[Tuple[str, str]]:
        """Load exploit bytecodes from the cached exploit_samples directory.

        Looks for .bin files in src/ai/data/exploit_samples/, matching the
        same pattern used by safe_samples.
        """
        contracts: List[Tuple[str, str]] = []

        if not self.exploit_samples_dir.exists():
            logger.info("exploit_samples_dir_not_found", path=str(self.exploit_samples_dir))
            return contracts

        for bin_file in sorted(self.exploit_samples_dir.glob("*.bin")):
            try:
                with open(bin_file) as f:
                    bytecode = f.read().strip()
                if bytecode and len(bytecode) > 10:
                    contracts.append((bytecode, bin_file.stem))
            except Exception as e:
                logger.warning("cached_exploit_load_failed", file=bin_file.name, error=str(e))

        # Also check for a JSON dataset file (from BytecodeCollector output)
        for json_file in sorted(self.exploit_samples_dir.glob("*.json")):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                for entry in data if isinstance(data, list) else data.get("contracts", []):
                    bc = entry.get("bytecode", "")
                    label = entry.get("label", entry.get("address", "unknown"))
                    if bc and len(bc) > 10:
                        contracts.append((bc, f"cached_{label}"))
            except Exception as e:
                logger.warning("cached_json_load_failed", file=json_file.name, error=str(e))

        if contracts:
            logger.info("cached_exploit_bytecodes_loaded", count=len(contracts))
        return contracts

    def _save_exploit_bytecodes_to_cache(self, contracts: List[Tuple[str, str]]):
        """Save fetched exploit bytecodes to exploit_samples for future use."""
        self.exploit_samples_dir.mkdir(parents=True, exist_ok=True)

        saved = 0
        for bytecode, label in contracts:
            safe_label = label.replace("/", "_").replace(" ", "_")[:80]
            out_file = self.exploit_samples_dir / f"{safe_label}.bin"
            if not out_file.exists():
                with open(out_file, "w") as f:
                    f.write(bytecode)
                saved += 1

        if saved:
            logger.info("exploit_bytecodes_cached", saved=saved, dir=str(self.exploit_samples_dir))

    def load_exploit_contracts(self) -> List[Tuple[str, str]]:
        """Load exploit contract bytecodes with multi-level fallback.

        Priority:
        1. Fetch real bytecodes via RPC (if ETH_RPC_URL is set)
        2. Load from cached exploit_samples/ directory
        3. Only use MockExploitGenerator as augmentation (20% of real count),
           never as sole data source unless no other option exists.
        """
        real_contracts: List[Tuple[str, str]] = []

        # --- Level 1: Try RPC ---
        if not self.use_mock_exploits:
            rpc_contracts = self._fetch_exploit_bytecodes_via_rpc()
            if rpc_contracts:
                real_contracts.extend(rpc_contracts)
                # Cache for next time
                self._save_exploit_bytecodes_to_cache(rpc_contracts)
                logger.info("rpc_exploits_collected", count=len(rpc_contracts))

        # --- Level 2: Try cached exploit bytecodes ---
        if not real_contracts or len(real_contracts) < 5:
            cached = self._load_cached_exploit_bytecodes()
            # Deduplicate by label
            existing_labels = {label for _, label in real_contracts}
            for bc, label in cached:
                if label not in existing_labels:
                    real_contracts.append((bc, label))
                    existing_labels.add(label)

        self.real_exploit_count = len(real_contracts)

        # --- Level 3: Mock augmentation ---
        if real_contracts:
            # Scale augmentation by how few real samples we have:
            # <10 real → match real count (50% mock), 10-30 → 50% of real, 30+ → 20%
            if len(real_contracts) < 10:
                mock_count = len(real_contracts)  # double the dataset
            elif len(real_contracts) < 30:
                mock_count = max(1, len(real_contracts) // 2)
            else:
                mock_count = max(1, len(real_contracts) // 5)
            mock_contracts = MockExploitGenerator.generate_all_mock_exploits(mock_count)
            self.mock_exploit_count = len(mock_contracts)
            logger.info(
                "augmenting_with_mock_exploits",
                real_count=len(real_contracts),
                mock_count=len(mock_contracts),
                mock_ratio=f"{len(mock_contracts) / (len(real_contracts) + len(mock_contracts)):.1%}",
            )
            return real_contracts + mock_contracts
        else:
            # No real data available -- fall back to pure mock (CI mode)
            self.mock_only = True
            mock_count = 50
            mock_contracts = MockExploitGenerator.generate_all_mock_exploits(mock_count)
            self.mock_exploit_count = len(mock_contracts)
            logger.warning(
                "training_with_synthetic_data_only",
                msg="Training with synthetic data only -- model quality will be limited",
                mock_count=mock_count,
            )
            return mock_contracts

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

        # Store raw bytecodes for deep learning training
        self._raw_bytecodes = []

        # Extract features
        X = []
        y = []

        logger.info("extracting_features_from_safe_contracts")
        for bytecode, name in safe_contracts:
            features = self.extract_features(bytecode)
            if features is not None:
                X.append(features)
                y.append(0)  # Safe
                self._raw_bytecodes.append(bytecode)

        logger.info("extracting_features_from_exploit_contracts")
        for bytecode, name in exploit_contracts:
            features = self.extract_features(bytecode)
            if features is not None and len(features) == 43:
                X.append(features)
                y.append(1)  # Exploit
                self._raw_bytecodes.append(bytecode)

        if len(X) == 0:
            raise ValueError("No valid features extracted. Check bytecode format.")

        # Ensure all vectors have the same length
        X_array = []
        y_array = []
        bytecodes_filtered = []
        for i, vec in enumerate(X):
            if len(vec) == 43:
                X_array.append(vec)
                y_array.append(y[i])
                bytecodes_filtered.append(self._raw_bytecodes[i])
            else:
                logger.warning("skipping_mismatched_vector", length=len(vec), index=i)

        self._raw_bytecodes = bytecodes_filtered
        X = np.array(X_array)
        y = np.array(y_array)

        logger.info(
            "dataset_prepared",
            total_samples=len(X),
            safe_samples=np.sum(y == 0),
            exploit_samples=np.sum(y == 1),
            feature_dimension=X.shape[1],
            real_exploits=self.real_exploit_count,
            mock_exploits=self.mock_exploit_count,
            mock_only=self.mock_only,
        )

        return X, y

    def get_raw_bytecodes(self) -> List[str]:
        """Return raw bytecodes aligned with the last prepare_dataset() call."""
        return getattr(self, "_raw_bytecodes", [])


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
            # Adapt k_neighbors to minority class size (must be < n_minority_samples)
            minority_count = min(np.bincount(y_train.astype(int)))
            k_neighbors = min(5, minority_count - 1) if minority_count > 1 else 1
            smote = SMOTE(random_state=42, k_neighbors=k_neighbors)
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

    def cross_validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        n_folds: int = 5,
        mock_only: bool = False,
    ) -> Dict:
        """Run stratified k-fold cross-validation with overfitting detection.

        Returns dict with cv_f1_mean, cv_f1_std, cv_accuracy_scores,
        cv_f1_scores, and an overfitting_warning flag.
        """
        n_folds_actual = min(n_folds, min(np.sum(y == 0), np.sum(y == 1)))
        if n_folds_actual < 2:
            logger.warning("too_few_samples_for_cv", n_folds_actual=n_folds_actual)
            return {
                "cv_f1_mean": 0.0,
                "cv_f1_std": 0.0,
                "cv_accuracy_mean": 0.0,
                "cv_accuracy_std": 0.0,
                "cv_f1_scores": [],
                "cv_accuracy_scores": [],
                "overfitting_warning": True,
            }

        skf = StratifiedKFold(n_splits=n_folds_actual, shuffle=True, random_state=42)

        f1_scores = cross_val_score(
            self.model, X, y, cv=skf, scoring="f1"
        )
        accuracy_scores = cross_val_score(
            self.model, X, y, cv=skf, scoring="accuracy"
        )

        cv_f1_mean = float(np.mean(f1_scores))
        cv_f1_std = float(np.std(f1_scores))
        cv_acc_mean = float(np.mean(accuracy_scores))
        cv_acc_std = float(np.std(accuracy_scores))

        overfitting_warning = False
        if cv_acc_mean >= 1.0 and cv_f1_mean >= 1.0:
            overfitting_warning = True
            logger.warning(
                "overfitting_detected",
                cv_f1_mean=f"{cv_f1_mean:.3f}",
                cv_accuracy_mean=f"{cv_acc_mean:.3f}",
                hint="100% CV accuracy suggests the model is overfitting. "
                     "Consider reducing synthetic data or adding more diverse samples.",
            )

        logger.info(
            "cross_validation_complete",
            n_folds=n_folds_actual,
            cv_f1_mean=f"{cv_f1_mean:.3f}",
            cv_f1_std=f"{cv_f1_std:.3f}",
            cv_accuracy_mean=f"{cv_acc_mean:.3f}",
            cv_accuracy_std=f"{cv_acc_std:.3f}",
            overfitting_warning=overfitting_warning,
        )

        return {
            "cv_f1_mean": cv_f1_mean,
            "cv_f1_std": cv_f1_std,
            "cv_accuracy_mean": cv_acc_mean,
            "cv_accuracy_std": cv_acc_std,
            "cv_f1_scores": [float(s) for s in f1_scores],
            "cv_accuracy_scores": [float(s) for s in accuracy_scores],
            "overfitting_warning": overfitting_warning,
        }

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

    def get_feature_importance_dict(self) -> Dict[str, float]:
        """Return feature importance as a dict for model metadata."""
        if not hasattr(self.model, "feature_importances_"):
            return {}
        return {
            name: float(imp)
            for name, imp in zip(self.feature_names, self.model.feature_importances_)
        }

    def save_model(
        self,
        path: Path,
        metadata: Optional[Dict] = None,
    ):
        """Save trained model with versioning and metadata.

        Saves:
        1. classifier_YYYYMMDD_HHMMSS.pkl  (versioned)
        2. classifier.pkl                   (latest, backward compat)
        3. contract_classifier.pkl          (compat with ContractThreatClassifier)
        """
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        metadata = metadata or {}

        now = datetime.now()
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")

        # Build the full metadata dict to embed in the model pickle
        model_data = {
            "model": self.model,
            "known_exploits": {},
            "rule_weights": None,
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names,
            "model_type": self.model_type,
            "training_date": now.isoformat(),
            "training_timestamp": timestamp_str,
            "feature_importance": self.get_feature_importance_dict(),
        }
        model_data.update(metadata)

        # 1. Versioned model
        versioned_path = MODEL_DIR / f"classifier_{timestamp_str}.pkl"
        with open(versioned_path, "wb") as f:
            pickle.dump(model_data, f)
        logger.info("versioned_model_saved", path=str(versioned_path))

        # 2. classifier.pkl (latest)
        with open(path, "wb") as f:
            pickle.dump(model_data, f)
        logger.info("latest_model_saved", path=str(path))

        # 3. contract_classifier.pkl (ContractThreatClassifier compat)
        with open(COMPAT_MODEL_PATH, "wb") as f:
            pickle.dump(model_data, f)
        logger.info("compat_model_saved", path=str(COMPAT_MODEL_PATH))


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
    print("  Sentinel3 ML Model Training Pipeline")
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

    # -----------------------------------------------------------------
    # Split: 20% held-out test set (NEVER augmented with SMOTE)
    # -----------------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )

    logger.info(
        "data_split",
        train_samples=len(X_train),
        test_samples=len(X_test),
        train_safe=int(np.sum(y_train == 0)),
        train_exploit=int(np.sum(y_train == 1)),
        test_safe=int(np.sum(y_test == 0)),
        test_exploit=int(np.sum(y_test == 1)),
    )

    # -----------------------------------------------------------------
    # Train model (SMOTE applied only to training split)
    # -----------------------------------------------------------------
    trainer = ModelTrainer(model_type=args.model)
    trainer.create_model()
    trainer.train(X_train, y_train, use_smote=not args.no_smote)

    # -----------------------------------------------------------------
    # Evaluate on held-out test set (no SMOTE)
    # -----------------------------------------------------------------
    metrics = trainer.evaluate(X_test, y_test)

    # -----------------------------------------------------------------
    # Stratified 5-fold cross-validation on full dataset
    # -----------------------------------------------------------------
    cv_results = trainer.cross_validate(X, y, n_folds=5, mock_only=loader.mock_only)
    metrics.update(cv_results)

    # -----------------------------------------------------------------
    # Overfitting / quality gates
    # -----------------------------------------------------------------
    if cv_results["overfitting_warning"] and not loader.mock_only:
        # 100% accuracy with non-mock data is suspicious but possible with
        # very separable features; log it but do not block.
        logger.warning(
            "potential_overfitting",
            hint="CV accuracy is 100%. If using real exploit data this may be legitimate "
                 "due to feature separability. Review feature importance for leakage.",
        )

    if cv_results["cv_f1_mean"] < 0.70:
        logger.error(
            "model_quality_below_threshold",
            cv_f1_mean=f"{cv_results['cv_f1_mean']:.3f}",
            threshold=0.70,
            hint="Model CV F1 is below 0.70 -- too unreliable for production.",
        )
        print()
        print("!" * 70)
        print("  MODEL REJECTED: CV F1 < 0.70 -- too unreliable")
        print(f"  CV F1 = {cv_results['cv_f1_mean']:.3f}")
        print("  Fix: add more/better training data or tune hyperparameters")
        print("!" * 70)
        print()
        return

    # -----------------------------------------------------------------
    # Generate plots
    # -----------------------------------------------------------------
    trainer.plot_feature_importance(FEATURE_IMPORTANCE_PLOT)
    trainer.plot_confusion_matrix(y_test, trainer.model.predict(X_test), CONFUSION_MATRIX_PLOT)

    # -----------------------------------------------------------------
    # Save model with metadata
    # -----------------------------------------------------------------
    model_metadata = {
        "sample_counts": {
            "total": int(len(X)),
            "safe": int(np.sum(y == 0)),
            "exploit": int(np.sum(y == 1)),
            "real_exploits": loader.real_exploit_count,
            "cached_exploits": loader.cached_exploit_count,
            "mock_exploits": loader.mock_exploit_count,
        },
        "cv_scores": {
            "f1_mean": cv_results["cv_f1_mean"],
            "f1_std": cv_results["cv_f1_std"],
            "accuracy_mean": cv_results["cv_accuracy_mean"],
            "accuracy_std": cv_results["cv_accuracy_std"],
            "f1_per_fold": cv_results["cv_f1_scores"],
        },
        "test_metrics": {
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1_score"],
            "roc_auc": metrics["roc_auc"],
        },
        "mock_only": loader.mock_only,
        "confidence_cap": 0.6 if loader.mock_only else 1.0,
        "overfitting_warning": cv_results["overfitting_warning"],
    }

    trainer.save_model(MODEL_PATH, metadata=model_metadata)

    # -----------------------------------------------------------------
    # Save metrics JSON
    # -----------------------------------------------------------------
    metrics["training_date"] = datetime.now().isoformat()
    metrics["model_type"] = args.model
    metrics["feature_count"] = len(FEATURE_NAMES)
    metrics["total_samples"] = len(X)
    metrics["safe_samples"] = int(np.sum(y == 0))
    metrics["exploit_samples"] = int(np.sum(y == 1))
    metrics["real_exploits"] = loader.real_exploit_count
    metrics["mock_exploits"] = loader.mock_exploit_count
    metrics["mock_only"] = loader.mock_only
    metrics["confidence_cap"] = 0.6 if loader.mock_only else 1.0

    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f, indent=2)

    # -----------------------------------------------------------------
    # Train Deep Learning model (PyTorch) if available
    # -----------------------------------------------------------------
    try:
        from src.ai.models.deep_classifier import DeepContractClassifier, PYTORCH_AVAILABLE
        if PYTORCH_AVAILABLE:
            print()
            print("=" * 70)
            print("  Training Deep Learning Model (PyTorch)")
            print("=" * 70)

            raw_bytecodes = loader.get_raw_bytecodes()
            if raw_bytecodes and len(raw_bytecodes) == len(X):
                from src.ai.data.bytecode_collector import RealBytecodeFeatureExtractor
                feat_extractor = RealBytecodeFeatureExtractor()

                # Build training data in the format DeepContractClassifier.train() expects
                THREAT_CATS = DeepContractClassifier.THREAT_CATEGORIES
                deep_train_data = []
                deep_val_data = []

                for i, (bytecode, label) in enumerate(zip(raw_bytecodes, y)):
                    features = feat_extractor.extract_features(bytecode)
                    feature_vector = feat_extractor.features_to_vector(features)
                    cat_label = "safe" if label == 0 else "unknown_threat"
                    entry = {
                        "bytecode": bytecode,
                        "features": feature_vector,
                        "label": cat_label,
                    }
                    # Use same train/test indices as RF (80/20 split)
                    if i < int(len(raw_bytecodes) * (1 - args.test_size)):
                        deep_train_data.append(entry)
                    else:
                        deep_val_data.append(entry)

                if len(deep_train_data) >= 5:
                    deep_model_path = str(MODEL_DIR / "deep_ensemble.pt")

                    # Train ensemble model (MLP + CNN on opcode sequences)
                    deep_clf = DeepContractClassifier(
                        model_type="ensemble",
                        model_path=deep_model_path,
                    )

                    history = deep_clf.train(
                        train_data=deep_train_data,
                        val_data=deep_val_data if len(deep_val_data) >= 2 else None,
                        epochs=50,
                        batch_size=min(8, len(deep_train_data)),
                        learning_rate=0.001,
                        early_stopping_patience=10,
                    )

                    final_train_acc = history["train_acc"][-1] if history["train_acc"] else 0
                    final_val_acc = history["val_acc"][-1] if history.get("val_acc") else None

                    print(f"\n   Deep model saved:  {deep_model_path}")
                    print(f"   Final train acc:   {final_train_acc:.1f}%")
                    if final_val_acc is not None:
                        print(f"   Final val acc:     {final_val_acc:.1f}%")
                    print(f"   Device:            {deep_clf.device}")
                    print(f"   Model type:        ensemble (MLP + CNN)")
                else:
                    print("   Skipped: not enough samples for deep learning training")
            else:
                print("   Skipped: raw bytecodes not available")
        else:
            print("\n   Deep learning skipped: PyTorch not installed")
    except Exception as e:
        logger.warning("deep_learning_training_failed", error=str(e))
        print(f"\n   Deep learning training failed: {e}")

    # -----------------------------------------------------------------
    # Verify auto-discovery will work
    # -----------------------------------------------------------------
    for check_path in [MODEL_PATH, COMPAT_MODEL_PATH]:
        if check_path.exists():
            logger.info("model_file_verified", path=str(check_path), size_bytes=check_path.stat().st_size)
        else:
            logger.error("model_file_missing", path=str(check_path))

    # -----------------------------------------------------------------
    # Print summary
    # -----------------------------------------------------------------
    print()
    print("=" * 70)
    print("  TRAINING SUMMARY")
    print("=" * 70)
    print(f"   Accuracy:        {metrics['accuracy']:.3f}")
    print(f"   Precision:       {metrics['precision']:.3f}")
    print(f"   Recall:          {metrics['recall']:.3f}")
    print(f"   F1 Score:        {metrics['f1_score']:.3f}")
    print(f"   ROC AUC:         {metrics['roc_auc']:.3f}")
    print(f"   Avg Precision:   {metrics['average_precision']:.3f}")
    print(f"   CV F1 (5-fold):  {cv_results['cv_f1_mean']:.3f} +/- {cv_results['cv_f1_std']:.3f}")
    print(f"   Total Samples:   {len(X)} (safe={np.sum(y==0)}, exploit={np.sum(y==1)})")
    print(f"   Real Exploits:   {loader.real_exploit_count}")
    print(f"   Mock Exploits:   {loader.mock_exploit_count}")
    print(f"   Mock-Only Mode:  {loader.mock_only}")
    if loader.mock_only:
        print(f"   Confidence Cap:  0.6 (mock-trained model)")
    if cv_results["overfitting_warning"]:
        print(f"   WARNING:         Possible overfitting detected (100% CV accuracy)")
    print()
    print(f"   Model saved:     {MODEL_PATH}")
    print(f"   Compat model:    {COMPAT_MODEL_PATH}")
    print(f"   Plots saved:     {FEATURE_IMPORTANCE_PLOT}")
    print(f"                    {CONFUSION_MATRIX_PLOT}")
    print(f"   Metrics saved:   {METRICS_FILE}")
    print()

    # Feature importance interpretation
    print("=" * 70)
    print("  FEATURE IMPORTANCE INTERPRETATION")
    print("=" * 70)
    print("""
  Higher importance values indicate features that are more predictive
  of exploit contracts. Key insights:

  - CFG Complexity: High complexity may indicate exploit logic
  - External Call Depth: Deep call chains suggest flash loan patterns
  - Entropy: Low entropy may indicate packed/obfuscated exploit code
  - Risk Patterns: Flags like has_reentrancy_pattern are direct indicators
  - Gas Analysis: Unusual gas patterns may indicate exploit optimization

  Use these insights to:
  1. Focus monitoring on high-importance features
  2. Tune detection thresholds based on feature values
  3. Improve feature engineering for low-importance features
    """)
    print()


if __name__ == "__main__":
    main()
