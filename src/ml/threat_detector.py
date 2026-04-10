"""
ML Threat Detector
==================

Machine learning model for threat detection.
Replaces YAML rules with intelligent classification.

Supports:
- Local inference (PyTorch)
- Vertex AI inference (cloud)
- Ensemble of multiple models
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import numpy as np
import structlog

logger = structlog.get_logger(__name__)

# Try to import ML libraries
try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("pytorch_not_available")

try:
    from google.cloud import aiplatform
    VERTEX_AVAILABLE = True
except ImportError:
    VERTEX_AVAILABLE = False


@dataclass
class ThreatPrediction:
    """Prediction result from threat detector."""
    
    # Classification
    is_threat: bool
    threat_probability: float  # 0-1
    threat_type: str  # e.g., "flash_loan_attack", "rug_pull", etc.
    
    # Confidence
    confidence: float  # 0-1
    
    # Risk score (0-100)
    risk_score: int
    
    # Explainability
    top_factors: List[Dict[str, Any]]  # Features that contributed most
    
    # Severity mapping
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Model info
    model_version: str
    inference_time_ms: float


class ThreatTypes:
    """Known threat types for classification."""
    
    SAFE = "safe"
    FLASH_LOAN_ATTACK = "flash_loan_attack"
    REENTRANCY = "reentrancy"
    ORACLE_MANIPULATION = "oracle_manipulation"
    RUG_PULL = "rug_pull"
    SANDWICH_ATTACK = "sandwich_attack"
    FRONT_RUNNING = "front_running"
    GOVERNANCE_ATTACK = "governance_attack"
    BRIDGE_EXPLOIT = "bridge_exploit"
    ADMIN_KEY_COMPROMISE = "admin_key_compromise"
    LIQUIDITY_DRAIN = "liquidity_drain"
    PRICE_MANIPULATION = "price_manipulation"
    SUSPICIOUS_TRANSFER = "suspicious_transfer"
    UNKNOWN_THREAT = "unknown_threat"
    
    ALL_TYPES = [
        SAFE, FLASH_LOAN_ATTACK, REENTRANCY, ORACLE_MANIPULATION,
        RUG_PULL, SANDWICH_ATTACK, FRONT_RUNNING, GOVERNANCE_ATTACK,
        BRIDGE_EXPLOIT, ADMIN_KEY_COMPROMISE, LIQUIDITY_DRAIN,
        PRICE_MANIPULATION, SUSPICIOUS_TRANSFER, UNKNOWN_THREAT
    ]


class ThreatDetectorModel(nn.Module):
    """
    PyTorch model for threat detection.
    
    Architecture:
    - Input: Feature vector from FeatureExtractor
    - Hidden layers with attention
    - Output: Multi-class classification + risk score
    """
    
    def __init__(
        self,
        input_dim: int = 100,
        hidden_dim: int = 256,
        num_classes: int = len(ThreatTypes.ALL_TYPES),
        dropout: float = 0.3
    ):
        super().__init__()
        
        self.input_dim = input_dim
        self.num_classes = num_classes
        
        # Feature processing
        self.input_norm = nn.BatchNorm1d(input_dim)
        
        # Main network
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, hidden_dim // 2)
        
        # Attention mechanism
        self.attention = nn.MultiheadAttention(
            embed_dim=hidden_dim // 2,
            num_heads=4,
            dropout=dropout,
            batch_first=True
        )
        
        # Output heads
        self.classifier = nn.Linear(hidden_dim // 2, num_classes)
        self.risk_scorer = nn.Linear(hidden_dim // 2, 1)
        
        # Regularization
        self.dropout = nn.Dropout(dropout)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            x: Input tensor of shape (batch_size, input_dim)
            
        Returns:
            Tuple of (class_logits, risk_scores)
        """
        # Normalize input
        x = self.input_norm(x)
        
        # Process through layers
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.relu(self.fc2(x))
        x = self.dropout(x)
        x = self.relu(self.fc3(x))
        
        # Self-attention (reshape for attention)
        x = x.unsqueeze(1)  # (batch, 1, hidden_dim//2)
        x, _ = self.attention(x, x, x)
        x = x.squeeze(1)  # (batch, hidden_dim//2)
        
        # Output heads
        class_logits = self.classifier(x)
        risk_scores = self.sigmoid(self.risk_scorer(x)) * 100  # Scale to 0-100
        
        return class_logits, risk_scores


class ThreatDetector:
    """
    Main threat detector class.
    
    Supports:
    - Local PyTorch inference
    - Vertex AI endpoint inference
    - Ensemble of multiple models
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        vertex_endpoint: Optional[str] = None,
        use_gpu: bool = True
    ):
        """
        Initialize threat detector.
        
        Args:
            model_path: Path to local PyTorch model
            vertex_endpoint: Vertex AI endpoint ID
            use_gpu: Whether to use GPU for local inference
        """
        self.model_path = model_path
        self.vertex_endpoint = vertex_endpoint
        self.model_version = "1.0.0"
        
        # Initialize device
        if TORCH_AVAILABLE:
            if use_gpu and torch.cuda.is_available():
                self.device = torch.device("cuda")
            elif use_gpu and hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                self.device = torch.device("mps")
            else:
                self.device = torch.device("cpu")
        else:
            self.device = None
        
        # Load model
        self.model: Optional[ThreatDetectorModel] = None
        self.vertex_client = None
        
        self._load_model()
    
    def _load_model(self):
        """Load the ML model."""
        if self.model_path and TORCH_AVAILABLE:
            try:
                # Load local model
                self.model = ThreatDetectorModel()
                
                if os.path.exists(self.model_path):
                    state_dict = torch.load(self.model_path, map_location=self.device)
                    self.model.load_state_dict(state_dict)
                    logger.info("local_model_loaded", path=self.model_path)
                else:
                    logger.warning("model_path_not_found", path=self.model_path)
                
                self.model.to(self.device)
                self.model.eval()
                
            except Exception as e:
                logger.error("model_load_failed", error=str(e))
        
        if self.vertex_endpoint and VERTEX_AVAILABLE:
            try:
                aiplatform.init(
                    project=os.getenv("GCP_PROJECT", "web3-xdr"),
                    location=os.getenv("GCP_REGION", "us-central1")
                )
                self.vertex_client = aiplatform.Endpoint(self.vertex_endpoint)
                logger.info("vertex_endpoint_connected", endpoint=self.vertex_endpoint)
            except Exception as e:
                logger.error("vertex_connection_failed", error=str(e))
    
    async def predict(
        self,
        features: Dict[str, float],
        use_vertex: bool = False
    ) -> ThreatPrediction:
        """
        Make a threat prediction.
        
        Args:
            features: Feature dictionary from FeatureExtractor
            use_vertex: Whether to use Vertex AI (vs local model)
            
        Returns:
            ThreatPrediction with classification results
        """
        start_time = datetime.now(timezone.utc)
        
        if use_vertex and self.vertex_client:
            prediction = await self._predict_vertex(features)
        elif self.model:
            prediction = await self._predict_local(features)
        else:
            # Fallback to rule-based heuristics
            prediction = self._predict_heuristic(features)
        
        inference_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        prediction.inference_time_ms = inference_time
        
        return prediction
    
    async def _predict_local(self, features: Dict[str, float]) -> ThreatPrediction:
        """Make prediction using local PyTorch model."""
        if not self.model:
            return self._predict_heuristic(features)
        
        # Convert features to tensor
        feature_values = list(features.values())
        
        # Pad or truncate to expected input size
        expected_size = self.model.input_dim
        if len(feature_values) < expected_size:
            feature_values.extend([0.0] * (expected_size - len(feature_values)))
        elif len(feature_values) > expected_size:
            feature_values = feature_values[:expected_size]
        
        x = torch.tensor([feature_values], dtype=torch.float32).to(self.device)
        
        with torch.no_grad():
            class_logits, risk_scores = self.model(x)
            
            # Get probabilities
            probs = torch.softmax(class_logits, dim=1)[0]
            
            # Get top prediction
            top_class_idx = torch.argmax(probs).item()
            top_prob = probs[top_class_idx].item()
            
            # Get risk score
            risk_score = int(risk_scores[0].item())
        
        # Map to threat type
        threat_type = ThreatTypes.ALL_TYPES[top_class_idx]
        is_threat = threat_type != ThreatTypes.SAFE
        
        # Calculate confidence
        confidence = top_prob if is_threat else (1 - probs[0].item())
        
        # Get top contributing features
        top_factors = self._get_top_factors(features, probs)
        
        return ThreatPrediction(
            is_threat=is_threat,
            threat_probability=1 - probs[0].item(),  # P(not safe)
            threat_type=threat_type,
            confidence=confidence,
            risk_score=risk_score,
            top_factors=top_factors,
            severity=self._risk_to_severity(risk_score),
            model_version=self.model_version,
            inference_time_ms=0
        )
    
    async def _predict_vertex(self, features: Dict[str, float]) -> ThreatPrediction:
        """Make prediction using Vertex AI endpoint."""
        if not self.vertex_client:
            return self._predict_heuristic(features)
        
        try:
            # Prepare instance for Vertex AI
            instance = [list(features.values())]
            
            # Call endpoint
            response = self.vertex_client.predict(instances=instance)
            
            # Parse response
            predictions = response.predictions[0]
            
            threat_type = predictions.get("threat_type", ThreatTypes.SAFE)
            threat_prob = predictions.get("threat_probability", 0.0)
            risk_score = int(predictions.get("risk_score", 0))
            
            return ThreatPrediction(
                is_threat=threat_type != ThreatTypes.SAFE,
                threat_probability=threat_prob,
                threat_type=threat_type,
                confidence=predictions.get("confidence", 0.5),
                risk_score=risk_score,
                top_factors=predictions.get("top_factors", []),
                severity=self._risk_to_severity(risk_score),
                model_version=self.model_version,
                inference_time_ms=0
            )
            
        except Exception as e:
            logger.error("vertex_prediction_failed", error=str(e))
            return self._predict_heuristic(features)
    
    def _predict_heuristic(self, features: Dict[str, float]) -> ThreatPrediction:
        """
        Fallback heuristic-based prediction.
        Uses feature thresholds derived from YAML rules.
        """
        risk_score = 0
        threat_type = ThreatTypes.SAFE
        factors = []
        
        # Check for high-risk indicators
        
        # Large amount
        amount_usd = features.get("amount_usd", 0)
        if amount_usd > 10_000_000:
            risk_score += 40
            factors.append({"factor": "Very large amount (>$10M)", "impact": 40})
            threat_type = ThreatTypes.LIQUIDITY_DRAIN
        elif amount_usd > 1_000_000:
            risk_score += 25
            factors.append({"factor": "Large amount (>$1M)", "impact": 25})
        
        # Mixer interaction
        if features.get("to_is_mixer", 0) > 0 or features.get("from_is_mixer", 0) > 0:
            risk_score += 50
            factors.append({"factor": "Mixer interaction", "impact": 50})
            threat_type = ThreatTypes.SUSPICIOUS_TRANSFER
        
        # Hacker connection
        if features.get("to_is_hacker", 0) > 0 or features.get("from_is_hacker", 0) > 0:
            risk_score += 80
            factors.append({"factor": "Connected to known hacker", "impact": 80})
            threat_type = ThreatTypes.SUSPICIOUS_TRANSFER
        
        # Graph risk
        from_risk = features.get("from_graph_risk_score", 0) * 100
        to_risk = features.get("to_graph_risk_score", 0) * 100
        
        if from_risk > 60:
            risk_score += 30
            factors.append({"factor": f"High-risk sender (score: {from_risk:.0f})", "impact": 30})
        
        if to_risk > 60:
            risk_score += 30
            factors.append({"factor": f"High-risk recipient (score: {to_risk:.0f})", "impact": 30})
        
        # Flash loan event
        if features.get("event_type_flashloan", 0) > 0:
            if amount_usd > 1_000_000:
                risk_score += 30
                factors.append({"factor": "Large flash loan", "impact": 30})
                threat_type = ThreatTypes.FLASH_LOAN_ATTACK
        
        # Night activity
        if features.get("is_night", 0) > 0 and amount_usd > 100_000:
            risk_score += 10
            factors.append({"factor": "Large night-time transaction", "impact": 10})
        
        # New entity
        if features.get("from_graph_tx_count_log", 10) < 2:  # log(7) ≈ 2
            risk_score += 15
            factors.append({"factor": "New/low-activity sender", "impact": 15})
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        # Determine if threat
        is_threat = risk_score >= 40
        
        if not is_threat:
            threat_type = ThreatTypes.SAFE
        elif threat_type == ThreatTypes.SAFE and is_threat:
            threat_type = ThreatTypes.UNKNOWN_THREAT
        
        return ThreatPrediction(
            is_threat=is_threat,
            threat_probability=risk_score / 100,
            threat_type=threat_type,
            confidence=0.6,  # Heuristic has moderate confidence
            risk_score=risk_score,
            top_factors=factors[:5],
            severity=self._risk_to_severity(risk_score),
            model_version="heuristic-1.0",
            inference_time_ms=0
        )
    
    def _get_top_factors(
        self,
        features: Dict[str, float],
        probs: torch.Tensor
    ) -> List[Dict[str, Any]]:
        """Get top contributing features using simple importance estimation."""
        factors = []
        
        # Sort features by absolute value (simple importance proxy)
        sorted_features = sorted(
            features.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )
        
        for name, value in sorted_features[:5]:
            if value != 0:
                factors.append({
                    "factor": name,
                    "value": value,
                    "impact": "high" if abs(value) > 0.5 else "medium"
                })
        
        return factors
    
    def _risk_to_severity(self, risk_score: int) -> str:
        """Convert risk score to severity level."""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    async def batch_predict(
        self,
        feature_list: List[Dict[str, float]],
        use_vertex: bool = False
    ) -> List[ThreatPrediction]:
        """
        Make predictions for multiple events.
        
        Args:
            feature_list: List of feature dictionaries
            use_vertex: Whether to use Vertex AI
            
        Returns:
            List of ThreatPrediction objects
        """
        if use_vertex and self.vertex_client:
            # Batch prediction for Vertex AI
            return await self._batch_predict_vertex(feature_list)
        else:
            # Sequential local predictions
            predictions = []
            for features in feature_list:
                pred = await self.predict(features, use_vertex=False)
                predictions.append(pred)
            return predictions
    
    async def _batch_predict_vertex(
        self,
        feature_list: List[Dict[str, float]]
    ) -> List[ThreatPrediction]:
        """Batch prediction using Vertex AI."""
        try:
            instances = [list(f.values()) for f in feature_list]
            response = self.vertex_client.predict(instances=instances)
            
            predictions = []
            for pred in response.predictions:
                predictions.append(ThreatPrediction(
                    is_threat=pred.get("threat_type") != ThreatTypes.SAFE,
                    threat_probability=pred.get("threat_probability", 0),
                    threat_type=pred.get("threat_type", ThreatTypes.SAFE),
                    confidence=pred.get("confidence", 0.5),
                    risk_score=int(pred.get("risk_score", 0)),
                    top_factors=pred.get("top_factors", []),
                    severity=self._risk_to_severity(int(pred.get("risk_score", 0))),
                    model_version=self.model_version,
                    inference_time_ms=0
                ))
            
            return predictions
            
        except Exception as e:
            logger.error("batch_vertex_prediction_failed", error=str(e))
            # Fallback to sequential heuristic
            return [self._predict_heuristic(f) for f in feature_list]
