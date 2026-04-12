"""
ML Training Pipeline
====================

End-to-end training workflow for the threat detection model.
Supports:
- Local training with PyTorch
- Vertex AI training (cloud)
- Continuous learning from new incidents
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import numpy as np
import structlog

from .yaml_converter import YAMLToMLConverter
from .feature_extractor import FeatureExtractor
from .threat_detector import ThreatDetectorModel, ThreatTypes

logger = structlog.get_logger(__name__)

# Try to import ML libraries
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class TrainingDataset:
    """
    Training dataset for threat detection.
    
    Sources:
    1. Historical exploits (confirmed malicious)
    2. Normal transactions (confirmed safe)
    3. YAML rule matches (weak labels)
    4. Existing incidents (labeled by analysts)
    """
    
    def __init__(self):
        self.features: List[Dict[str, float]] = []
        self.labels: List[int] = []  # Class index
        self.weights: List[float] = []  # Sample weights
        self.metadata: List[Dict[str, Any]] = []
    
    def add_sample(
        self,
        features: Dict[str, float],
        label: str,  # Threat type
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Add a training sample."""
        self.features.append(features)
        
        # Convert label to class index
        label_idx = ThreatTypes.ALL_TYPES.index(label) if label in ThreatTypes.ALL_TYPES else 0
        self.labels.append(label_idx)
        
        # Weight by confidence
        self.weights.append(confidence)
        
        self.metadata.append(metadata or {})
    
    def to_tensors(self) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Convert to PyTorch tensors."""
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch not available")
        
        # Get feature names from first sample
        feature_names = list(self.features[0].keys()) if self.features else []
        
        # Convert features to matrix
        X = np.array([
            [f.get(name, 0.0) for name in feature_names]
            for f in self.features
        ], dtype=np.float32)
        
        y = np.array(self.labels, dtype=np.int64)
        weights = np.array(self.weights, dtype=np.float32)
        
        return (
            torch.from_numpy(X),
            torch.from_numpy(y),
            torch.from_numpy(weights)
        )
    
    def __len__(self):
        return len(self.features)


class TrainingPipeline:
    """
    End-to-end training pipeline.
    
    Steps:
    1. Load and convert YAML rules to features
    2. Collect training data from multiple sources
    3. Train the model
    4. Evaluate and export
    """
    
    def __init__(
        self,
        rules_dir: Optional[str] = None,
        output_dir: str = "data/models",
        device: Optional[str] = None
    ):
        """
        Initialize training pipeline.
        
        Args:
            rules_dir: Directory containing YAML rules
            output_dir: Directory for model outputs
            device: Training device (cuda, mps, cpu)
        """
        self.rules_dir = rules_dir
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.yaml_converter = YAMLToMLConverter(rules_dir)
        self.feature_extractor = FeatureExtractor()
        
        # Set device
        if TORCH_AVAILABLE:
            if device:
                self.device = torch.device(device)
            elif torch.cuda.is_available():
                self.device = torch.device("cuda")
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                self.device = torch.device("mps")
            else:
                self.device = torch.device("cpu")
        else:
            self.device = None
        
        # Training state
        self.model: Optional[ThreatDetectorModel] = None
        self.training_history: List[Dict[str, float]] = []
    
    async def prepare_training_data(
        self,
        db_connection: Optional[Any] = None,
        include_historical_exploits: bool = True,
        include_yaml_matches: bool = True,
        include_incidents: bool = True
    ) -> TrainingDataset:
        """
        Prepare training dataset from multiple sources.
        
        Args:
            db_connection: Database connection for incidents
            include_historical_exploits: Include known exploit data
            include_yaml_matches: Include YAML rule matches
            include_incidents: Include labeled incidents
            
        Returns:
            TrainingDataset ready for training
        """
        dataset = TrainingDataset()
        
        # 1. Extract knowledge from YAML rules
        logger.info("extracting_yaml_knowledge")
        knowledge = self.yaml_converter.load_and_convert()
        self.yaml_converter.get_feature_blueprint()
        
        # 2. Load historical exploits
        if include_historical_exploits:
            logger.info("loading_historical_exploits")
            await self._add_historical_exploits(dataset)
        
        # 3. Load YAML rule matches as weak labels
        if include_yaml_matches and db_connection:
            logger.info("loading_yaml_matches")
            await self._add_yaml_matches(dataset, db_connection, knowledge)
        
        # 4. Load labeled incidents
        if include_incidents and db_connection:
            logger.info("loading_labeled_incidents")
            await self._add_incidents(dataset, db_connection)
        
        # 5. Add synthetic safe samples
        logger.info("adding_safe_samples")
        await self._add_safe_samples(dataset)
        
        logger.info(
            "training_data_prepared",
            total_samples=len(dataset),
            class_distribution=self._get_class_distribution(dataset)
        )
        
        return dataset
    
    async def _add_historical_exploits(self, dataset: TrainingDataset):
        """Add historical exploit data."""
        # Known historical exploits with their characteristics
        historical_exploits = [
            {
                "name": "Wormhole Hack",
                "threat_type": ThreatTypes.BRIDGE_EXPLOIT,
                "features": {
                    "amount_usd": 320_000_000,
                    "event_type_transfer": 1.0,
                    "chain_ethereum": 1.0,
                    "to_is_new": 1.0,
                }
            },
            {
                "name": "Ronin Bridge Hack",
                "threat_type": ThreatTypes.ADMIN_KEY_COMPROMISE,
                "features": {
                    "amount_usd": 625_000_000,
                    "event_type_transfer": 1.0,
                    "chain_ethereum": 1.0,
                }
            },
            {
                "name": "Euler Finance Hack",
                "threat_type": ThreatTypes.FLASH_LOAN_ATTACK,
                "features": {
                    "amount_usd": 197_000_000,
                    "event_type_flashloan": 1.0,
                    "chain_ethereum": 1.0,
                }
            },
            {
                "name": "Mango Markets Exploit",
                "threat_type": ThreatTypes.ORACLE_MANIPULATION,
                "features": {
                    "amount_usd": 114_000_000,
                    "event_type_swap": 1.0,
                }
            },
            {
                "name": "Beanstalk Governance Attack",
                "threat_type": ThreatTypes.GOVERNANCE_ATTACK,
                "features": {
                    "amount_usd": 182_000_000,
                    "event_type_flashloan": 1.0,
                }
            },
            {
                "name": "Cream Finance Reentrancy",
                "threat_type": ThreatTypes.REENTRANCY,
                "features": {
                    "amount_usd": 130_000_000,
                    "event_type_flashloan": 1.0,
                }
            },
            {
                "name": "Typical Rug Pull",
                "threat_type": ThreatTypes.RUG_PULL,
                "features": {
                    "amount_usd": 5_000_000,
                    "event_type_transfer": 1.0,
                    "to_is_mixer": 1.0,
                    "from_graph_tx_count_log": 1.0,  # New contract
                }
            },
            {
                "name": "Sandwich Attack",
                "threat_type": ThreatTypes.SANDWICH_ATTACK,
                "features": {
                    "amount_usd": 50_000,
                    "event_type_swap": 1.0,
                    "is_night": 0.0,
                }
            },
        ]
        
        for exploit in historical_exploits:
            # Create full feature vector
            features = self._create_default_features()
            features.update(exploit["features"])
            
            # Add log-scaled amount
            features["amount_usd_log"] = np.log1p(features.get("amount_usd", 0))
            features["amount_usd_gt_1m"] = 1.0 if features.get("amount_usd", 0) > 1_000_000 else 0.0
            features["amount_usd_gt_10m"] = 1.0 if features.get("amount_usd", 0) > 10_000_000 else 0.0
            
            dataset.add_sample(
                features=features,
                label=exploit["threat_type"],
                confidence=1.0,  # High confidence - confirmed exploit
                metadata={"source": "historical", "name": exploit["name"]}
            )
            
            # Add variations to increase training data
            for _ in range(5):
                varied_features = self._add_noise(features.copy())
                dataset.add_sample(
                    features=varied_features,
                    label=exploit["threat_type"],
                    confidence=0.9,
                    metadata={"source": "historical_augmented", "name": exploit["name"]}
                )
    
    async def _add_yaml_matches(
        self,
        dataset: TrainingDataset,
        db_connection: Any,
        knowledge: Any
    ):
        """Add events that matched YAML rules as weak labels."""
        # Query events that triggered rules
        try:
            
            # This would be replaced with actual DB query
            # For now, we'll skip if no connection
            if not db_connection:
                return
            
            # Process results...
            
        except Exception as e:
            logger.warning("yaml_matches_load_failed", error=str(e))
    
    async def _add_incidents(
        self,
        dataset: TrainingDataset,
        db_connection: Any
    ):
        """Add labeled incidents from database."""
        try:
            # Query confirmed incidents
            
            if not db_connection:
                return
            
            # Process results...
            
        except Exception as e:
            logger.warning("incidents_load_failed", error=str(e))
    
    async def _add_safe_samples(self, dataset: TrainingDataset):
        """Add synthetic safe transaction samples."""
        # Generate safe transaction patterns
        safe_patterns = [
            # Normal small transfer
            {
                "amount_usd": 100,
                "event_type_transfer": 1.0,
                "to_is_exchange": 1.0,
            },
            # Normal swap
            {
                "amount_usd": 1000,
                "event_type_swap": 1.0,
                "is_business_hours": 1.0,
            },
            # Normal deposit
            {
                "amount_usd": 5000,
                "event_type_deposit": 1.0,
            },
            # Normal withdrawal
            {
                "amount_usd": 2000,
                "event_type_withdraw": 1.0,
            },
        ]
        
        for pattern in safe_patterns:
            # Generate multiple variations
            for _ in range(50):
                features = self._create_default_features()
                features.update(pattern)
                
                # Add random variation
                features["amount_usd"] = pattern["amount_usd"] * (0.5 + np.random.random())
                features["amount_usd_log"] = np.log1p(features["amount_usd"])
                
                dataset.add_sample(
                    features=features,
                    label=ThreatTypes.SAFE,
                    confidence=0.8,
                    metadata={"source": "synthetic_safe"}
                )
    
    def _create_default_features(self) -> Dict[str, float]:
        """Create default feature vector with zeros."""
        return {
            # Chain features
            "chain_ethereum": 0.0,
            "chain_polygon": 0.0,
            "chain_arbitrum": 0.0,
            "chain_optimism": 0.0,
            "chain_bsc": 0.0,
            "chain_avalanche": 0.0,
            "chain_base": 0.0,
            
            # Event type features
            "event_type_transfer": 0.0,
            "event_type_swap": 0.0,
            "event_type_flashloan": 0.0,
            "event_type_liquidation": 0.0,
            "event_type_deposit": 0.0,
            "event_type_withdraw": 0.0,
            "event_type_borrow": 0.0,
            "event_type_repay": 0.0,
            "event_type_approval": 0.0,
            "event_type_adminaction": 0.0,
            "event_type_unknown": 0.0,
            
            # Amount features
            "amount": 0.0,
            "amount_log": 0.0,
            "amount_usd": 0.0,
            "amount_usd_log": 0.0,
            "amount_usd_gt_1k": 0.0,
            "amount_usd_gt_10k": 0.0,
            "amount_usd_gt_100k": 0.0,
            "amount_usd_gt_1m": 0.0,
            "amount_usd_gt_10m": 0.0,
            
            # Address features
            "has_from_address": 1.0,
            "has_to_address": 1.0,
            "from_is_zero": 0.0,
            "to_is_zero": 0.0,
            "is_self_transfer": 0.0,
            "from_is_exchange": 0.0,
            "from_is_mixer": 0.0,
            "from_is_hacker": 0.0,
            "to_is_exchange": 0.0,
            "to_is_mixer": 0.0,
            "to_is_hacker": 0.0,
            "to_is_new": 0.0,
            
            # Temporal features
            "hour_sin": 0.0,
            "hour_cos": 1.0,
            "day_sin": 0.0,
            "day_cos": 1.0,
            "is_weekend": 0.0,
            "is_night": 0.0,
            "is_business_hours": 1.0,
            
            # Graph features
            "from_graph_risk_score": 0.0,
            "from_graph_tx_count_log": 5.0,
            "from_graph_hacker_connections": 0.0,
            "from_graph_mixer_connections": 0.0,
            "to_graph_risk_score": 0.0,
            "to_graph_is_mixer": 0.0,
            "to_graph_is_hacker": 0.0,
            
            # Context features
            "severity_score": 0.25,
        }
    
    def _add_noise(self, features: Dict[str, float], noise_level: float = 0.1) -> Dict[str, float]:
        """Add random noise to features for data augmentation."""
        for key, value in features.items():
            if isinstance(value, (int, float)) and value != 0:
                # Add gaussian noise
                features[key] = value * (1 + np.random.normal(0, noise_level))
        return features
    
    def _get_class_distribution(self, dataset: TrainingDataset) -> Dict[str, int]:
        """Get class distribution in dataset."""
        distribution = {}
        for label_idx in dataset.labels:
            label = ThreatTypes.ALL_TYPES[label_idx]
            distribution[label] = distribution.get(label, 0) + 1
        return distribution
    
    def train(
        self,
        dataset: TrainingDataset,
        epochs: int = 100,
        batch_size: int = 32,
        learning_rate: float = 0.001,
        validation_split: float = 0.2
    ) -> Dict[str, Any]:
        """
        Train the threat detection model.
        
        Args:
            dataset: Training dataset
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            validation_split: Fraction for validation
            
        Returns:
            Training results and metrics
        """
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch required for training")
        
        logger.info(
            "starting_training",
            samples=len(dataset),
            epochs=epochs,
            device=str(self.device)
        )
        
        # Convert to tensors
        X, y, weights = dataset.to_tensors()
        
        # Split into train/val
        if SKLEARN_AVAILABLE:
            X_train, X_val, y_train, y_val, w_train, w_val = train_test_split(
                X.numpy(), y.numpy(), weights.numpy(),
                test_size=validation_split,
                stratify=y.numpy(),
                random_state=42
            )
            X_train = torch.from_numpy(X_train)
            X_val = torch.from_numpy(X_val)
            y_train = torch.from_numpy(y_train)
            y_val = torch.from_numpy(y_val)
            w_train = torch.from_numpy(w_train)
        else:
            # Simple split
            split_idx = int(len(X) * (1 - validation_split))
            X_train, X_val = X[:split_idx], X[split_idx:]
            y_train, y_val = y[:split_idx], y[split_idx:]
            w_train = weights[:split_idx]
        
        # Create data loaders
        train_dataset = TensorDataset(X_train, y_train, w_train)
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        
        # Initialize model
        input_dim = X_train.shape[1]
        self.model = ThreatDetectorModel(
            input_dim=input_dim,
            num_classes=len(ThreatTypes.ALL_TYPES)
        ).to(self.device)
        
        # Loss and optimizer
        criterion = nn.CrossEntropyLoss(reduction='none')
        risk_criterion = nn.MSELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10)
        
        # Training loop
        best_val_loss = float('inf')
        best_model_state = None
        
        for epoch in range(epochs):
            self.model.train()
            train_loss = 0.0
            
            for batch_X, batch_y, batch_w in train_loader:
                batch_X = batch_X.to(self.device)
                batch_y = batch_y.to(self.device)
                batch_w = batch_w.to(self.device)
                
                optimizer.zero_grad()
                
                # Forward pass
                class_logits, risk_scores = self.model(batch_X)
                
                # Classification loss (weighted)
                class_loss = criterion(class_logits, batch_y)
                weighted_loss = (class_loss * batch_w).mean()
                
                # Risk score loss (target based on class)
                target_risk = torch.zeros_like(risk_scores)
                target_risk[batch_y > 0] = 70.0  # Threats have high risk
                target_risk[batch_y == 0] = 10.0  # Safe has low risk
                risk_loss = risk_criterion(risk_scores, target_risk)
                
                # Combined loss
                loss = weighted_loss + 0.1 * risk_loss
                
                loss.backward()
                optimizer.step()
                
                train_loss += loss.item()
            
            # Validation
            self.model.eval()
            with torch.no_grad():
                X_val_device = X_val.to(self.device)
                y_val_device = y_val.to(self.device)
                
                val_logits, val_risk = self.model(X_val_device)
                val_loss = criterion(val_logits, y_val_device).mean().item()
                
                # Calculate accuracy
                val_preds = torch.argmax(val_logits, dim=1)
                val_acc = (val_preds == y_val_device).float().mean().item()
            
            # Learning rate scheduling
            scheduler.step(val_loss)
            
            # Save best model
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_model_state = self.model.state_dict().copy()
            
            # Log progress
            if epoch % 10 == 0:
                logger.info(
                    "training_progress",
                    epoch=epoch,
                    train_loss=train_loss / len(train_loader),
                    val_loss=val_loss,
                    val_acc=val_acc
                )
            
            self.training_history.append({
                "epoch": epoch,
                "train_loss": train_loss / len(train_loader),
                "val_loss": val_loss,
                "val_acc": val_acc
            })
        
        # Load best model
        if best_model_state:
            self.model.load_state_dict(best_model_state)
        
        # Final evaluation
        metrics = self._evaluate(X_val, y_val)
        
        logger.info("training_complete", **metrics)
        
        return {
            "final_metrics": metrics,
            "training_history": self.training_history,
            "best_val_loss": best_val_loss
        }
    
    def _evaluate(
        self,
        X: torch.Tensor,
        y: torch.Tensor
    ) -> Dict[str, Any]:
        """Evaluate model on dataset."""
        self.model.eval()
        
        with torch.no_grad():
            X_device = X.to(self.device)
            logits, risk_scores = self.model(X_device)
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            y_numpy = y.numpy()
        
        # Calculate metrics
        accuracy = (preds == y_numpy).mean()
        
        # Per-class metrics
        if SKLEARN_AVAILABLE:
            # Only include labels that appear in the data
            unique_labels = sorted(set(y_numpy) | set(preds))
            label_names = [ThreatTypes.ALL_TYPES[i] for i in unique_labels if i < len(ThreatTypes.ALL_TYPES)]
            
            report = classification_report(
                y_numpy, preds,
                labels=unique_labels,
                target_names=label_names,
                output_dict=True,
                zero_division=0
            )
        else:
            report = {}
        
        return {
            "accuracy": float(accuracy),
            "classification_report": report
        }
    
    def save_model(self, filename: str = "threat_detector.pt"):
        """Save trained model."""
        if not self.model:
            raise ValueError("No model to save")
        
        model_path = self.output_dir / filename
        torch.save(self.model.state_dict(), model_path)
        
        # Save metadata
        metadata = {
            "model_version": "1.0.0",
            "input_dim": self.model.input_dim,
            "num_classes": self.model.num_classes,
            "threat_types": ThreatTypes.ALL_TYPES,
            "training_history": self.training_history,
            "saved_at": datetime.now(timezone.utc).isoformat()
        }
        
        metadata_path = self.output_dir / f"{filename}.meta.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("model_saved", path=str(model_path))
        
        return str(model_path)
    
    def export_for_vertex_ai(self, output_dir: Optional[str] = None):
        """Export model and artifacts for Vertex AI."""
        export_dir = Path(output_dir) if output_dir else self.output_dir / "vertex_export"
        export_dir.mkdir(parents=True, exist_ok=True)
        
        # Export YAML knowledge
        self.yaml_converter.export_for_vertex_ai(str(export_dir / "yaml_knowledge"))
        
        # Export model
        if self.model:
            self.save_model("threat_detector.pt")
            
            # Also save in ONNX format for Vertex AI
            try:
                dummy_input = torch.randn(1, self.model.input_dim)
                onnx_path = export_dir / "model.onnx"
                torch.onnx.export(
                    self.model,
                    dummy_input,
                    str(onnx_path),
                    input_names=["features"],
                    output_names=["class_logits", "risk_score"],
                    dynamic_axes={"features": {0: "batch_size"}}
                )
                logger.info("onnx_export_complete", path=str(onnx_path))
            except Exception as e:
                logger.warning("onnx_export_failed", error=str(e))
        
        logger.info("vertex_export_complete", path=str(export_dir))
