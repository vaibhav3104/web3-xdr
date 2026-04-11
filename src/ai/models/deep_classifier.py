"""
Deep Learning Contract Threat Classifier
Uses PyTorch neural networks for advanced pattern detection

Models:
1. BytecodeTransformer - Attention-based sequence model
2. BytecodeCNN - Convolutional neural network for pattern detection
3. EnsembleClassifier - Combines multiple models
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import pickle

# Check for PyTorch availability
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import Dataset, DataLoader
    PYTORCH_AVAILABLE = True
except ImportError:
    PYTORCH_AVAILABLE = False
    print("Warning: PyTorch not installed. Deep learning models disabled.")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class DeepClassificationResult:
    """Result from deep learning classifier"""
    category: str
    risk_score: float
    confidence: float
    probabilities: Dict[str, float]
    model_used: str
    features_used: int
    inference_time_ms: float


# =============================================================================
# NEURAL NETWORK ARCHITECTURES
# =============================================================================

if PYTORCH_AVAILABLE:
    
    class BytecodeMLP(nn.Module):
        """
        Multi-Layer Perceptron for bytecode classification
        Good for feature-based classification
        """
        
        def __init__(
            self,
            input_dim: int = 20,
            hidden_dims: List[int] = [128, 64, 32],
            num_classes: int = 10,
            dropout: float = 0.3
        ):
            super().__init__()
            
            layers = []
            prev_dim = input_dim
            
            for hidden_dim in hidden_dims:
                layers.extend([
                    nn.Linear(prev_dim, hidden_dim),
                    nn.LayerNorm(hidden_dim),  # LayerNorm works with batch_size=1
                    nn.ReLU(),
                    nn.Dropout(dropout)
                ])
                prev_dim = hidden_dim
            
            layers.append(nn.Linear(prev_dim, num_classes))
            
            self.network = nn.Sequential(*layers)
        
        def forward(self, x):
            return self.network(x)
    
    
    class BytecodeCNN(nn.Module):
        """
        1D Convolutional Neural Network for bytecode sequence analysis
        Detects local patterns in opcode sequences
        """
        
        def __init__(
            self,
            vocab_size: int = 256,  # Number of unique opcodes
            embedding_dim: int = 64,
            num_filters: int = 128,
            filter_sizes: List[int] = [3, 5, 7],
            num_classes: int = 10,
            dropout: float = 0.5
        ):
            super().__init__()
            
            self.embedding = nn.Embedding(vocab_size, embedding_dim)
            
            # Multiple filter sizes for different pattern lengths
            self.convs = nn.ModuleList([
                nn.Conv1d(embedding_dim, num_filters, kernel_size=fs, padding=fs//2)
                for fs in filter_sizes
            ])
            
            self.dropout = nn.Dropout(dropout)
            self.fc = nn.Linear(num_filters * len(filter_sizes), num_classes)
        
        def forward(self, x):
            # x: [batch, seq_len] - integer sequence of opcodes
            x = self.embedding(x)  # [batch, seq_len, embed_dim]
            x = x.permute(0, 2, 1)  # [batch, embed_dim, seq_len]
            
            # Apply convolutions and max pooling
            conv_outputs = []
            for conv in self.convs:
                conv_out = F.relu(conv(x))  # [batch, num_filters, seq_len]
                pooled = F.max_pool1d(conv_out, conv_out.size(2)).squeeze(2)  # [batch, num_filters]
                conv_outputs.append(pooled)
            
            # Concatenate all filter outputs
            x = torch.cat(conv_outputs, dim=1)  # [batch, num_filters * num_filter_sizes]
            x = self.dropout(x)
            x = self.fc(x)
            
            return x
    
    
    class BytecodeTransformer(nn.Module):
        """
        Transformer-based model for bytecode analysis
        Uses attention to find important patterns across the entire contract
        """
        
        def __init__(
            self,
            vocab_size: int = 256,
            embedding_dim: int = 128,
            num_heads: int = 4,
            num_layers: int = 2,
            hidden_dim: int = 256,
            num_classes: int = 10,
            max_seq_len: int = 2048,
            dropout: float = 0.3
        ):
            super().__init__()
            
            self.embedding = nn.Embedding(vocab_size, embedding_dim)
            self.pos_embedding = nn.Embedding(max_seq_len, embedding_dim)
            
            encoder_layer = nn.TransformerEncoderLayer(
                d_model=embedding_dim,
                nhead=num_heads,
                dim_feedforward=hidden_dim,
                dropout=dropout,
                batch_first=True
            )
            
            self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
            
            self.fc = nn.Sequential(
                nn.Linear(embedding_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim, num_classes)
            )
        
        def forward(self, x, attention_mask=None):
            # x: [batch, seq_len]
            batch_size, seq_len = x.size()
            
            # Create position indices
            positions = torch.arange(seq_len, device=x.device).unsqueeze(0).expand(batch_size, -1)
            
            # Embed tokens and positions
            x = self.embedding(x) + self.pos_embedding(positions)
            
            # Apply transformer
            x = self.transformer(x, src_key_padding_mask=attention_mask)
            
            # Global average pooling
            x = x.mean(dim=1)
            
            # Classify
            x = self.fc(x)
            
            return x
    
    
    class EnsembleClassifier(nn.Module):
        """
        Ensemble of multiple models for robust classification
        Combines MLP, CNN, and Transformer predictions
        """
        
        def __init__(
            self,
            feature_dim: int = 20,
            vocab_size: int = 256,
            num_classes: int = 10,
            max_seq_len: int = 2048
        ):
            super().__init__()
            
            # Component models
            self.mlp = BytecodeMLP(
                input_dim=feature_dim,
                hidden_dims=[128, 64],
                num_classes=num_classes
            )
            
            self.cnn = BytecodeCNN(
                vocab_size=vocab_size,
                num_classes=num_classes
            )
            
            # Attention weights for ensemble
            self.attention = nn.Sequential(
                nn.Linear(num_classes * 2, 64),
                nn.ReLU(),
                nn.Linear(64, 2),
                nn.Softmax(dim=1)
            )
        
        def forward(self, features, opcodes):
            """
            Args:
                features: [batch, feature_dim] - extracted features
                opcodes: [batch, seq_len] - opcode sequence
            """
            # Get predictions from each model
            mlp_out = self.mlp(features)  # [batch, num_classes]
            cnn_out = self.cnn(opcodes)   # [batch, num_classes]
            
            # Calculate attention weights
            combined = torch.cat([mlp_out, cnn_out], dim=1)
            weights = self.attention(combined)  # [batch, 2]
            
            # Weighted combination
            final = weights[:, 0:1] * mlp_out + weights[:, 1:2] * cnn_out
            
            return final


# =============================================================================
# DATASET
# =============================================================================

if PYTORCH_AVAILABLE:
    
    class BytecodeDataset(Dataset):
        """Dataset for training bytecode classifiers"""
        
        def __init__(
            self,
            data: List[Dict],
            max_seq_len: int = 2048,
            use_features: bool = True,
            use_opcodes: bool = True
        ):
            self.data = data
            self.max_seq_len = max_seq_len
            self.use_features = use_features
            self.use_opcodes = use_opcodes
            
            # Build label mapping
            labels = list(set(d["label"] for d in data))
            self.label_to_idx = {label: i for i, label in enumerate(labels)}
            self.idx_to_label = {i: label for label, i in self.label_to_idx.items()}
        
        def __len__(self):
            return len(self.data)
        
        def __getitem__(self, idx):
            item = self.data[idx]
            
            result = {
                "label": self.label_to_idx[item["label"]]
            }
            
            if self.use_features:
                features = item.get("features", [0.0] * 20)
                result["features"] = torch.tensor(features, dtype=torch.float32)
            
            if self.use_opcodes and "bytecode" in item:
                opcodes = self._bytecode_to_opcodes(item["bytecode"])
                result["opcodes"] = torch.tensor(opcodes, dtype=torch.long)
            
            return result
        
        def _bytecode_to_opcodes(self, bytecode: str) -> List[int]:
            """Convert bytecode hex string to opcode sequence"""
            if bytecode.startswith("0x"):
                bytecode = bytecode[2:]
            
            opcodes = []
            i = 0
            
            while i < len(bytecode) and len(opcodes) < self.max_seq_len:
                try:
                    opcode = int(bytecode[i:i+2], 16)
                    opcodes.append(opcode)
                    
                    # Skip PUSH data
                    if 0x60 <= opcode <= 0x7F:  # PUSH1-PUSH32
                        push_size = opcode - 0x5F
                        i += push_size * 2
                    
                    i += 2
                except ValueError:
                    i += 2
            
            # Pad or truncate
            if len(opcodes) < self.max_seq_len:
                opcodes.extend([0] * (self.max_seq_len - len(opcodes)))
            else:
                opcodes = opcodes[:self.max_seq_len]
            
            return opcodes


# =============================================================================
# DEEP CLASSIFIER
# =============================================================================

class DeepContractClassifier:
    """
    Deep learning-based contract threat classifier
    """
    
    THREAT_CATEGORIES = [
        "safe",
        "flash_loan_exploit",
        "reentrancy_exploit",
        "oracle_manipulation",
        "governance_attack",
        "bridge_exploit",
        "price_manipulation",
        "rug_pull",
        "honeypot",
        "unknown_threat"
    ]
    
    def __init__(
        self,
        model_type: str = "mlp",  # mlp, cnn, transformer, ensemble
        model_path: Optional[str] = None,
        device: str = "auto"
    ):
        if not PYTORCH_AVAILABLE:
            raise RuntimeError("PyTorch is required for DeepContractClassifier")
        
        self.model_type = model_type
        self.model_path = model_path or f"./data/models/deep_{model_type}.pt"
        
        # Set device (priority: CUDA > MPS > CPU)
        if device == "auto":
            if torch.cuda.is_available():
                self.device = torch.device("cuda")
                logger.info("using_cuda_gpu")
            elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                self.device = torch.device("mps")
                logger.info("using_apple_mps_gpu")
            else:
                self.device = torch.device("cpu")
                logger.info("using_cpu")
        else:
            self.device = torch.device(device)
        
        # Initialize model
        self.model = self._create_model()
        self.model.to(self.device)
        
        # Load weights if available
        if os.path.exists(self.model_path):
            self._load_weights()
        
        self.model.eval()
        
        # Feature extractor
        self._extractor = None
    
    @property
    def extractor(self):
        if self._extractor is None:
            from ..data.bytecode_collector import RealBytecodeFeatureExtractor
            self._extractor = RealBytecodeFeatureExtractor()
        return self._extractor
    
    def _create_model(self):
        """Create the neural network model"""
        num_classes = len(self.THREAT_CATEGORIES)
        
        if self.model_type == "mlp":
            return BytecodeMLP(
                input_dim=20,
                hidden_dims=[128, 64, 32],
                num_classes=num_classes
            )
        elif self.model_type == "cnn":
            return BytecodeCNN(
                vocab_size=256,
                num_classes=num_classes
            )
        elif self.model_type == "transformer":
            return BytecodeTransformer(
                vocab_size=256,
                num_classes=num_classes,
                max_seq_len=2048
            )
        elif self.model_type == "ensemble":
            return EnsembleClassifier(
                feature_dim=20,
                vocab_size=256,
                num_classes=num_classes
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def _load_weights(self):
        """Load model weights from file"""
        try:
            state_dict = torch.load(self.model_path, map_location=self.device, weights_only=True)  # nosec B614
            self.model.load_state_dict(state_dict)
            logger.info("model_weights_loaded", path=self.model_path)
        except Exception as e:
            logger.warning("model_weights_load_failed", error=str(e))
    
    def _save_weights(self):
        """Save model weights to file"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        torch.save(self.model.state_dict(), self.model_path)
        self._model_mtime = os.path.getmtime(self.model_path)
        logger.info("model_weights_saved", path=self.model_path)

    def reload_if_updated(self) -> bool:
        """Hot-reload model weights if file on disk is newer."""
        if not os.path.exists(self.model_path):
            return False
        current_mtime = os.path.getmtime(self.model_path)
        if not hasattr(self, '_model_mtime') or self._model_mtime is None or current_mtime > self._model_mtime:
            self._load_weights()
            self._model_mtime = current_mtime
            self.model.eval()
            return True
        return False
    
    def classify(self, bytecode: str) -> DeepClassificationResult:
        """
        Classify a contract by its bytecode
        
        Args:
            bytecode: Hex string of contract bytecode
            
        Returns:
            DeepClassificationResult with threat category and scores
        """
        import time
        start_time = time.time()
        
        self.model.eval()
        
        with torch.no_grad():
            # Extract features
            features = self.extractor.extract_features(bytecode)
            feature_vector = self.extractor.features_to_vector(features)
            feature_tensor = torch.tensor([feature_vector], dtype=torch.float32).to(self.device)
            
            # Get predictions
            if self.model_type in ["mlp"]:
                logits = self.model(feature_tensor)
            elif self.model_type in ["cnn", "transformer"]:
                # Convert bytecode to opcode sequence
                opcodes = self._bytecode_to_opcodes(bytecode)
                opcode_tensor = torch.tensor([opcodes], dtype=torch.long).to(self.device)
                logits = self.model(opcode_tensor)
            elif self.model_type == "ensemble":
                opcodes = self._bytecode_to_opcodes(bytecode)
                opcode_tensor = torch.tensor([opcodes], dtype=torch.long).to(self.device)
                logits = self.model(feature_tensor, opcode_tensor)
            
            # Apply softmax to get probabilities
            probs = F.softmax(logits, dim=1)[0]
            
            # Get top prediction
            top_prob, top_idx = probs.max(0)
            category = self.THREAT_CATEGORIES[top_idx.item()]
            
            # Calculate risk score
            safe_prob = probs[self.THREAT_CATEGORIES.index("safe")].item()
            risk_score = 1.0 - safe_prob
            
            # Build probability dict
            probabilities = {
                cat: probs[i].item()
                for i, cat in enumerate(self.THREAT_CATEGORIES)
            }
        
        inference_time = (time.time() - start_time) * 1000
        
        return DeepClassificationResult(
            category=category,
            risk_score=risk_score,
            confidence=top_prob.item(),
            probabilities=probabilities,
            model_used=f"deep_{self.model_type}",
            features_used=len(feature_vector),
            inference_time_ms=inference_time
        )
    
    def _bytecode_to_opcodes(self, bytecode: str, max_len: int = 2048) -> List[int]:
        """Convert bytecode to opcode sequence"""
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        
        opcodes = []
        i = 0
        
        while i < len(bytecode) and len(opcodes) < max_len:
            try:
                opcode = int(bytecode[i:i+2], 16)
                opcodes.append(opcode)
                
                if 0x60 <= opcode <= 0x7F:
                    push_size = opcode - 0x5F
                    i += push_size * 2
                
                i += 2
            except ValueError:
                i += 2
        
        # Pad
        if len(opcodes) < max_len:
            opcodes.extend([0] * (max_len - len(opcodes)))
        
        return opcodes[:max_len]
    
    def train(
        self,
        train_data: List[Dict],
        val_data: List[Dict] = None,
        epochs: int = 50,
        batch_size: int = 32,
        learning_rate: float = 0.001,
        early_stopping_patience: int = 10
    ) -> Dict:
        """
        Train the model on bytecode data
        
        Args:
            train_data: List of {"bytecode": str, "features": List[float], "label": str}
            val_data: Validation data (same format)
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            early_stopping_patience: Stop if no improvement for N epochs
            
        Returns:
            Training history dict
        """
        if not PYTORCH_AVAILABLE:
            raise RuntimeError("PyTorch required for training")
        
        logger.info("training_started", model_type=self.model_type, epochs=epochs)
        
        # Create datasets
        train_dataset = BytecodeDataset(
            train_data,
            use_features=self.model_type in ["mlp", "ensemble"],
            use_opcodes=self.model_type in ["cnn", "transformer", "ensemble"]
        )
        
        train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            shuffle=True
        )
        
        if val_data:
            val_dataset = BytecodeDataset(
                val_data,
                use_features=self.model_type in ["mlp", "ensemble"],
                use_opcodes=self.model_type in ["cnn", "transformer", "ensemble"]
            )
            val_loader = DataLoader(val_dataset, batch_size=batch_size)
        
        # Loss and optimizer
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode='min', factor=0.5, patience=5
        )
        
        # Training loop
        self.model.train()
        history = {
            "train_loss": [],
            "train_acc": [],
            "val_loss": [],
            "val_acc": [],
        }
        
        best_val_loss = float("inf")
        patience_counter = 0
        
        for epoch in range(epochs):
            # Training phase
            train_loss = 0.0
            train_correct = 0
            train_total = 0
            
            for batch in train_loader:
                optimizer.zero_grad()
                
                labels = batch["label"].to(self.device)
                
                if self.model_type == "mlp":
                    features = batch["features"].to(self.device)
                    logits = self.model(features)
                elif self.model_type in ["cnn", "transformer"]:
                    opcodes = batch["opcodes"].to(self.device)
                    logits = self.model(opcodes)
                elif self.model_type == "ensemble":
                    features = batch["features"].to(self.device)
                    opcodes = batch["opcodes"].to(self.device)
                    logits = self.model(features, opcodes)
                
                loss = criterion(logits, labels)
                loss.backward()
                optimizer.step()
                
                train_loss += loss.item()
                _, predicted = logits.max(1)
                train_total += labels.size(0)
                train_correct += predicted.eq(labels).sum().item()
            
            avg_train_loss = train_loss / len(train_loader)
            train_acc = 100.0 * train_correct / train_total
            
            history["train_loss"].append(avg_train_loss)
            history["train_acc"].append(train_acc)
            
            # Validation phase
            if val_data:
                self.model.eval()
                val_loss = 0.0
                val_correct = 0
                val_total = 0
                
                with torch.no_grad():
                    for batch in val_loader:
                        labels = batch["label"].to(self.device)
                        
                        if self.model_type == "mlp":
                            features = batch["features"].to(self.device)
                            logits = self.model(features)
                        elif self.model_type in ["cnn", "transformer"]:
                            opcodes = batch["opcodes"].to(self.device)
                            logits = self.model(opcodes)
                        elif self.model_type == "ensemble":
                            features = batch["features"].to(self.device)
                            opcodes = batch["opcodes"].to(self.device)
                            logits = self.model(features, opcodes)
                        
                        loss = criterion(logits, labels)
                        val_loss += loss.item()
                        
                        _, predicted = logits.max(1)
                        val_total += labels.size(0)
                        val_correct += predicted.eq(labels).sum().item()
                
                avg_val_loss = val_loss / len(val_loader)
                val_acc = 100.0 * val_correct / val_total
                
                history["val_loss"].append(avg_val_loss)
                history["val_acc"].append(val_acc)
                
                scheduler.step(avg_val_loss)
                
                # Early stopping
                if avg_val_loss < best_val_loss:
                    best_val_loss = avg_val_loss
                    patience_counter = 0
                    self._save_weights()
                else:
                    patience_counter += 1
                    if patience_counter >= early_stopping_patience:
                        logger.info("early_stopping", epoch=epoch)
                        break
                
                self.model.train()
            
            if (epoch + 1) % 10 == 0:
                log_msg = f"Epoch {epoch+1}/{epochs} - Loss: {avg_train_loss:.4f}, Acc: {train_acc:.2f}%"
                if val_data:
                    log_msg += f" - Val Loss: {avg_val_loss:.4f}, Val Acc: {val_acc:.2f}%"
                print(log_msg)
        
        self._save_weights()
        
        logger.info(
            "training_completed",
            final_train_acc=history["train_acc"][-1],
            final_val_acc=history["val_acc"][-1] if val_data else None
        )
        
        return history


# =============================================================================
# HYBRID CLASSIFIER (Combines Traditional ML + Deep Learning)
# =============================================================================

class HybridClassifier:
    """
    Combines RandomForest and Deep Learning for best accuracy
    Uses confidence-weighted voting
    """
    
    def __init__(
        self,
        rf_model_path: str = "./data/models/contract_classifier.pkl",
        deep_model_type: str = "mlp",
        deep_model_path: str = None
    ):
        self.rf_model_path = rf_model_path
        self.deep_classifier = None
        self.rf_model = None
        self.rf_labels = None
        
        # Load RandomForest model
        if os.path.exists(rf_model_path):
            with open(rf_model_path, "rb") as f:
                data = pickle.load(f)
                self.rf_model = data.get("model")
                self.rf_labels = data.get("label_decoder", {})
        
        # Load Deep Learning model
        if PYTORCH_AVAILABLE:
            self.deep_classifier = DeepContractClassifier(
                model_type=deep_model_type,
                model_path=deep_model_path
            )
    
    def classify(self, bytecode: str) -> Dict:
        """
        Classify using both models and combine results
        """
        from ..data.bytecode_collector import RealBytecodeFeatureExtractor
        extractor = RealBytecodeFeatureExtractor()
        
        features = extractor.extract_features(bytecode)
        feature_vector = extractor.features_to_vector(features)
        
        results = {}
        
        # RandomForest prediction
        if self.rf_model is not None:
            try:
                rf_probs = self.rf_model.predict_proba([feature_vector])[0]
                rf_pred = self.rf_model.predict([feature_vector])[0]
                rf_category = self.rf_labels.get(rf_pred, "unknown")
                rf_confidence = max(rf_probs)
                
                results["random_forest"] = {
                    "category": rf_category,
                    "confidence": rf_confidence,
                    "risk_score": 1.0 - rf_probs[list(self.rf_labels.values()).index("safe")] if "safe" in self.rf_labels.values() else 0.5
                }
            except Exception as e:
                logger.error("rf_prediction_error", error=str(e))
        
        # Deep Learning prediction
        if self.deep_classifier is not None:
            try:
                deep_result = self.deep_classifier.classify(bytecode)
                results["deep_learning"] = {
                    "category": deep_result.category,
                    "confidence": deep_result.confidence,
                    "risk_score": deep_result.risk_score,
                    "probabilities": deep_result.probabilities
                }
            except Exception as e:
                logger.error("deep_prediction_error", error=str(e))
        
        # Combine results (confidence-weighted voting)
        if results:
            total_confidence = sum(r["confidence"] for r in results.values())
            weighted_risk = sum(
                r["risk_score"] * r["confidence"] / total_confidence
                for r in results.values()
            )
            
            # Vote on category
            category_votes = {}
            for model, r in results.items():
                cat = r["category"]
                category_votes[cat] = category_votes.get(cat, 0) + r["confidence"]
            
            final_category = max(category_votes, key=category_votes.get)
            
            results["combined"] = {
                "category": final_category,
                "risk_score": weighted_risk,
                "confidence": total_confidence / len(results),
                "is_threat": final_category != "safe" and weighted_risk > 0.5
            }
        
        return results


if __name__ == "__main__":
    if PYTORCH_AVAILABLE:
        print("Testing Deep Contract Classifier...")
        
        # Create classifier
        classifier = DeepContractClassifier(model_type="mlp")
        
        # Test bytecode (simple contract)
        test_bytecode = "0x608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50"
        
        result = classifier.classify(test_bytecode)
        print(f"\nClassification Result:")
        print(f"  Category: {result.category}")
        print(f"  Risk Score: {result.risk_score:.2f}")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Inference Time: {result.inference_time_ms:.2f}ms")
    else:
        print("PyTorch not available. Install with: pip install torch")

