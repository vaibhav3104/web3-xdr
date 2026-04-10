"""
Advanced ML Alert Analyzer - Transformer + XGBoost Ensemble
============================================================

This module uses an ensemble of:
1. Transformer Model - For sequential pattern recognition
2. XGBoost - For tabular feature classification
3. Graph Neural Network features - For relationship-based risk

The ensemble provides more accurate TP/FP classification than simple MLP.
"""

import json
import hashlib
import pickle
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)

# ML Dependencies
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None
    nn = None

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    xgb = None

# GCS for model persistence
try:
    from google.cloud import storage as gcs_storage
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False
    gcs_storage = None

import os
import tempfile
import io


class AlertVerdict(Enum):
    """Verdict from ML analysis"""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


@dataclass
class AlertContext:
    """Enriched context for an alert"""
    # Basic alert info
    rule_id: str
    rule_name: str
    severity: str
    chain_id: str
    
    # Event data
    event_type: str
    contract_address: Optional[str] = None
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    amount_usd: float = 0
    
    # Historical context
    address_age_days: float = 0
    address_tx_count: int = 0
    address_is_known_entity: bool = False
    address_entity_type: Optional[str] = None
    
    # Pattern context
    similar_alerts_24h: int = 0
    similar_alerts_7d: int = 0
    rule_historical_tp_rate: float = 0.5
    
    # Graph context
    hops_to_known_hacker: int = -1
    hops_to_mixer: int = -1
    connected_to_sanctioned: bool = False
    
    # On-chain context
    contract_verified: bool = False
    contract_age_days: float = 0
    contract_tx_count: int = 0
    is_proxy_contract: bool = False
    
    # Sequence context (for Transformer)
    recent_events: List[Dict] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Result of ML alert analysis"""
    verdict: AlertVerdict
    confidence: float
    tp_probability: float
    risk_score: float
    reasoning: List[str]
    recommended_action: str
    should_create_incident: bool
    adjusted_severity: str
    model_used: str = "ensemble"


# =============================================================================
# TRANSFORMER MODEL FOR ALERT ANALYSIS
# =============================================================================

class AlertTransformerEncoder(nn.Module):
    """
    Transformer encoder for analyzing alert sequences and context.
    
    Uses self-attention to understand relationships between:
    - Current alert features
    - Historical alert patterns
    - Entity relationships
    """
    
    def __init__(
        self,
        feature_dim: int = 64,
        num_heads: int = 4,
        num_layers: int = 3,
        dropout: float = 0.1
    ):
        super().__init__()
        
        self.feature_dim = feature_dim
        
        # Feature embedding layers
        self.numeric_embed = nn.Linear(29, feature_dim)  # 29 numeric features
        self.rule_embed = nn.Embedding(200, feature_dim // 4)  # Rule type embedding
        self.chain_embed = nn.Embedding(10, feature_dim // 4)  # Chain embedding
        self.entity_embed = nn.Embedding(10, feature_dim // 4)  # Entity type embedding
        
        # Positional encoding for sequence
        self.pos_encoding = nn.Parameter(torch.randn(1, 100, feature_dim))
        
        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=feature_dim,
            nhead=num_heads,
            dim_feedforward=feature_dim * 4,
            dropout=dropout,
            activation='gelu',
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # Output layers
        self.attention_pool = nn.MultiheadAttention(feature_dim, num_heads, batch_first=True)
        self.classifier = nn.Sequential(
            nn.Linear(feature_dim, feature_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(feature_dim // 2, 1),
            nn.Sigmoid()
        )
        
        # Risk score head
        self.risk_head = nn.Sequential(
            nn.Linear(feature_dim, feature_dim // 2),
            nn.GELU(),
            nn.Linear(feature_dim // 2, 1),
            nn.Sigmoid()
        )
    
    def forward(self, numeric_features, rule_ids=None, chain_ids=None, entity_ids=None):
        """
        Forward pass.
        
        Args:
            numeric_features: [batch, seq_len, 29] numeric features
            rule_ids: [batch, seq_len] rule type indices
            chain_ids: [batch, seq_len] chain indices
            entity_ids: [batch, seq_len] entity type indices
        
        Returns:
            tp_probability: [batch, 1] true positive probability
            risk_score: [batch, 1] risk score
        """
        batch_size, seq_len, _ = numeric_features.shape
        
        # Embed numeric features
        x = self.numeric_embed(numeric_features)  # [batch, seq, feature_dim]
        
        # Add positional encoding
        x = x + self.pos_encoding[:, :seq_len, :]
        
        # Transformer encoding
        x = self.transformer(x)  # [batch, seq, feature_dim]
        
        # Attention pooling - use last token as query
        query = x[:, -1:, :]  # [batch, 1, feature_dim]
        pooled, _ = self.attention_pool(query, x, x)  # [batch, 1, feature_dim]
        pooled = pooled.squeeze(1)  # [batch, feature_dim]
        
        # Classification
        tp_prob = self.classifier(pooled)
        risk_score = self.risk_head(pooled)
        
        return tp_prob, risk_score


# =============================================================================
# XGBOOST MODEL FOR TABULAR FEATURES
# =============================================================================

class XGBoostAlertClassifier:
    """XGBoost classifier for tabular alert features."""
    
    def __init__(self):
        self.model = None
        self.feature_names = [
            "amount_usd_log", "address_age_days", "address_tx_count_log",
            "is_known_entity", "entity_is_risky", "similar_alerts_24h",
            "similar_alerts_7d", "rule_historical_tp_rate", "hops_to_hacker",
            "hops_to_mixer", "connected_to_sanctioned", "contract_verified",
            "contract_age_days", "contract_tx_count_log", "is_proxy",
            "severity_critical", "severity_high", "severity_medium",
            "chain_ethereum", "chain_polygon", "chain_arbitrum",
            "chain_optimism", "chain_base", "rule_flash_loan",
            "rule_price_impact", "rule_liquidity", "rule_bridge",
            "rule_whale", "rule_admin"
        ]
    
    def train(self, X: np.ndarray, y: np.ndarray, val_X: np.ndarray = None, val_y: np.ndarray = None):
        """Train the XGBoost model."""
        if not XGBOOST_AVAILABLE:
            raise ImportError("XGBoost not available")
        
        params = {
            'objective': 'binary:logistic',
            'eval_metric': ['logloss', 'auc'],
            'max_depth': 6,
            'learning_rate': 0.1,
            'n_estimators': 100,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'reg_alpha': 0.1,
            'reg_lambda': 1.0,
            'random_state': 42
        }
        
        self.model = xgb.XGBClassifier(**params)
        
        eval_set = [(X, y)]
        if val_X is not None and val_y is not None:
            eval_set.append((val_X, val_y))
        
        self.model.fit(
            X, y,
            eval_set=eval_set,
            verbose=False
        )
        
        return self.model
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict TP probability."""
        if self.model is None:
            raise ValueError("Model not trained")
        return self.model.predict_proba(X)[:, 1]
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores."""
        if self.model is None:
            return {}
        importance = self.model.feature_importances_
        return dict(zip(self.feature_names, importance))
    
    def save(self, path: str):
        """Save model to disk."""
        if self.model:
            self.model.save_model(path)
    
    def load(self, path: str):
        """Load model from disk."""
        if not XGBOOST_AVAILABLE:
            raise ImportError("XGBoost not available")
        self.model = xgb.XGBClassifier()
        self.model.load_model(path)


# =============================================================================
# ENSEMBLE MODEL
# =============================================================================

class EnsembleAlertAnalyzer:
    """
    Ensemble model combining:
    1. Transformer - For pattern recognition
    2. XGBoost - For tabular classification
    3. Rule-based - For domain knowledge
    
    Final prediction is weighted average of all models.
    Models are persisted to Google Cloud Storage for cross-instance availability.
    """
    
    # GCS Configuration
    GCS_BUCKET = os.environ.get("ML_MODEL_BUCKET", "web3-xdr-ml-models")
    GCS_PREFIX = "alert-analyzer"
    
    def __init__(self, model_dir: str = "./data/models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize models
        self.transformer = None
        self.xgboost = XGBoostAlertClassifier()
        
        # Model weights for ensemble
        self.weights = {
            "transformer": 0.4,
            "xgboost": 0.4,
            "rule_based": 0.2
        }
        
        # Training state
        self.is_trained = False
        self.training_stats = {}
        
        # Rule-based TP rates (domain knowledge)
        self.rule_tp_rates = {
            "admin": 0.85,
            "ownership": 0.85,
            "flash_loan": 0.70,
            "flash": 0.70,
            "price_impact": 0.80,
            "price": 0.80,
            "liquidity_removal": 0.60,
            "liquidity": 0.60,
            "bridge": 0.70,
            "cross-chain": 0.70,
            "whale": 0.65,
            "large": 0.65,
            "velocity": 0.55,
            "failed": 0.50,
            "inbox": 0.75,  # Arbitrum inbox
            "stargate": 0.70,
            "wormhole": 0.75,
            "default": 0.60
        }
        
        # GCS client
        self._gcs_client = None
        
        # Try to load pre-trained models (first from GCS, then local)
        self._load_models()
    
    def _get_gcs_client(self):
        """Get or create GCS client."""
        if self._gcs_client is None and GCS_AVAILABLE:
            try:
                self._gcs_client = gcs_storage.Client()
                logger.info("gcs_client_initialized")
            except Exception as e:
                logger.warning("gcs_client_init_failed", error=str(e))
        return self._gcs_client
    
    def _upload_to_gcs(self, local_path: str, gcs_path: str) -> bool:
        """Upload a file to GCS."""
        client = self._get_gcs_client()
        if not client:
            logger.warning("gcs_upload_skipped", reason="no_client")
            return False
        
        try:
            bucket = client.bucket(self.GCS_BUCKET)
            blob = bucket.blob(f"{self.GCS_PREFIX}/{gcs_path}")
            blob.upload_from_filename(local_path)
            logger.info("gcs_upload_success", path=gcs_path)
            return True
        except Exception as e:
            logger.error("gcs_upload_failed", path=gcs_path, error=str(e))
            return False
    
    def _download_from_gcs(self, gcs_path: str, local_path: str) -> bool:
        """Download a file from GCS."""
        client = self._get_gcs_client()
        if not client:
            logger.warning("gcs_download_skipped", reason="no_client")
            return False
        
        try:
            bucket = client.bucket(self.GCS_BUCKET)
            blob = bucket.blob(f"{self.GCS_PREFIX}/{gcs_path}")
            
            if not blob.exists():
                logger.info("gcs_blob_not_found", path=gcs_path)
                return False
            
            blob.download_to_filename(local_path)
            logger.info("gcs_download_success", path=gcs_path, local=local_path)
            return True
        except Exception as e:
            logger.error("gcs_download_failed", path=gcs_path, error=str(e))
            return False
    
    def _load_models(self):
        """Load pre-trained models. First try GCS, then local disk."""
        # Try to load from GCS first
        gcs_loaded = self._load_models_from_gcs()
        
        if gcs_loaded:
            logger.info("models_loaded_from_gcs")
            return
        
        # Fall back to local disk
        self._load_models_from_disk()
    
    def _load_models_from_gcs(self) -> bool:
        """Load models from GCS."""
        if not GCS_AVAILABLE:
            return False
        
        loaded_any = False
        
        try:
            # Load XGBoost from GCS
            xgb_local = str(self.model_dir / "alert_xgboost.json")
            if self._download_from_gcs("alert_xgboost.json", xgb_local):
                if XGBOOST_AVAILABLE:
                    self.xgboost.load(xgb_local)
                    logger.info("xgboost_loaded_from_gcs")
                    loaded_any = True
            
            # Load Transformer from GCS
            transformer_local = str(self.model_dir / "alert_transformer.pt")
            if self._download_from_gcs("alert_transformer.pt", transformer_local):
                if TORCH_AVAILABLE:
                    self.transformer = AlertTransformerEncoder()
                    self.transformer.load_state_dict(
                        torch.load(transformer_local, map_location='cpu')
                    )
                    self.transformer.eval()
                    logger.info("transformer_loaded_from_gcs")
                    loaded_any = True
            
            # Load training stats from GCS
            stats_local = str(self.model_dir / "alert_analyzer_stats.json")
            if self._download_from_gcs("alert_analyzer_stats.json", stats_local):
                with open(stats_local, 'r') as f:
                    self.training_stats = json.load(f)
                self.is_trained = True
                logger.info("training_stats_loaded_from_gcs")
            
            if loaded_any:
                self.is_trained = True
            
            return loaded_any
            
        except Exception as e:
            logger.error("gcs_model_load_failed", error=str(e))
            return False
    
    def _load_models_from_disk(self):
        """Load pre-trained models from local disk."""
        try:
            # Load XGBoost
            xgb_path = self.model_dir / "alert_xgboost.json"
            if xgb_path.exists() and XGBOOST_AVAILABLE:
                self.xgboost.load(str(xgb_path))
                logger.info("xgboost_model_loaded", path=str(xgb_path))
            
            # Load Transformer
            transformer_path = self.model_dir / "alert_transformer.pt"
            if transformer_path.exists() and TORCH_AVAILABLE:
                self.transformer = AlertTransformerEncoder()
                self.transformer.load_state_dict(torch.load(transformer_path, map_location='cpu'))
                self.transformer.eval()
                logger.info("transformer_model_loaded", path=str(transformer_path))
            
            # Load training stats
            stats_path = self.model_dir / "alert_analyzer_stats.json"
            if stats_path.exists():
                with open(stats_path) as f:
                    self.training_stats = json.load(f)
                self.is_trained = True
                
        except Exception as e:
            logger.warning("model_load_failed", error=str(e))
    
    def extract_features(self, context: AlertContext) -> np.ndarray:
        """Extract feature vector from alert context."""
        import math
        
        features = []
        
        # Amount (log scale)
        features.append(math.log10(max(context.amount_usd, 1)))
        
        # Address features
        features.append(min(context.address_age_days, 365) / 365)
        features.append(math.log10(max(context.address_tx_count, 1)))
        features.append(1.0 if context.address_is_known_entity else 0.0)
        
        risky_entities = ['Mixer', 'Hacker', 'Sanctioned', 'Exploit']
        features.append(1.0 if context.address_entity_type in risky_entities else 0.0)
        
        # Pattern features
        features.append(min(context.similar_alerts_24h, 100) / 100)
        features.append(min(context.similar_alerts_7d, 500) / 500)
        features.append(context.rule_historical_tp_rate)
        
        # Graph features
        features.append(1.0 / (context.hops_to_known_hacker + 1) if context.hops_to_known_hacker >= 0 else 0.0)
        features.append(1.0 / (context.hops_to_mixer + 1) if context.hops_to_mixer >= 0 else 0.0)
        features.append(1.0 if context.connected_to_sanctioned else 0.0)
        
        # Contract features
        features.append(1.0 if context.contract_verified else 0.0)
        features.append(min(context.contract_age_days, 365) / 365)
        features.append(math.log10(max(context.contract_tx_count, 1)))
        features.append(1.0 if context.is_proxy_contract else 0.0)
        
        # Severity one-hot
        features.append(1.0 if context.severity.lower() == 'critical' else 0.0)
        features.append(1.0 if context.severity.lower() == 'high' else 0.0)
        features.append(1.0 if context.severity.lower() == 'medium' else 0.0)
        
        # Chain one-hot
        chain = context.chain_id.lower()
        features.append(1.0 if chain in ['ethereum', 'eth', '1'] else 0.0)
        features.append(1.0 if chain in ['polygon', 'matic', '137'] else 0.0)
        features.append(1.0 if chain in ['arbitrum', 'arb', '42161'] else 0.0)
        features.append(1.0 if chain in ['optimism', 'op', '10'] else 0.0)
        features.append(1.0 if chain in ['base', '8453'] else 0.0)
        
        # Rule type one-hot
        rule = context.rule_name.lower()
        features.append(1.0 if 'flash' in rule or 'loan' in rule else 0.0)
        features.append(1.0 if 'price' in rule or 'impact' in rule else 0.0)
        features.append(1.0 if 'liquidity' in rule or 'removal' in rule else 0.0)
        features.append(1.0 if 'bridge' in rule or 'cross-chain' in rule else 0.0)
        features.append(1.0 if 'whale' in rule or 'large' in rule else 0.0)
        features.append(1.0 if 'admin' in rule or 'owner' in rule else 0.0)
        
        return np.array(features, dtype=np.float32)
    
    def _get_rule_based_tp_rate(self, rule_name: str) -> float:
        """Get TP rate based on rule name using domain knowledge."""
        rule_lower = rule_name.lower()
        for keyword, rate in self.rule_tp_rates.items():
            if keyword in rule_lower:
                return rate
        return self.rule_tp_rates["default"]
    
    def _rule_based_predict(self, context: AlertContext) -> Tuple[float, List[str]]:
        """Rule-based prediction with reasoning."""
        reasoning = []
        risk_factors = 0
        
        # Base TP rate from rule type
        base_tp = self._get_rule_based_tp_rate(context.rule_name)
        reasoning.append(f"Rule '{context.rule_name}' base TP rate: {base_tp*100:.0f}%")
        
        # Amount risk
        if context.amount_usd > 1_000_000:
            risk_factors += 2
            reasoning.append(f"Large amount: ${context.amount_usd:,.0f}")
        elif context.amount_usd > 100_000:
            risk_factors += 1
            reasoning.append(f"Significant amount: ${context.amount_usd:,.0f}")
        
        # Entity risk
        if context.address_entity_type in ['Hacker', 'Exploit']:
            risk_factors += 3
            reasoning.append(f"Address linked to known {context.address_entity_type}")
        elif context.address_entity_type == 'Mixer':
            risk_factors += 2
            reasoning.append("Address linked to mixer")
        elif context.address_entity_type == 'Sanctioned':
            risk_factors += 3
            reasoning.append("SANCTIONED address")
        
        # Graph proximity
        if 0 <= context.hops_to_known_hacker <= 2:
            risk_factors += 2
            reasoning.append(f"{context.hops_to_known_hacker} hops from known hacker")
        
        if 0 <= context.hops_to_mixer <= 1:
            risk_factors += 1
            reasoning.append(f"Connected to mixer ({context.hops_to_mixer} hops)")
        
        # Contract risk
        if not context.contract_verified and context.contract_age_days < 7:
            risk_factors += 1
            reasoning.append("Unverified new contract")
        
        # Noise detection
        if context.similar_alerts_24h > 10:
            risk_factors -= 1
            reasoning.append(f"High alert volume ({context.similar_alerts_24h}/24h) - possible noise")
        
        # Calculate final TP probability
        tp_prob = min(0.95, base_tp + (risk_factors * 0.05))
        tp_prob = max(0.1, tp_prob)
        
        return tp_prob, reasoning
    
    def predict(self, context: AlertContext) -> AnalysisResult:
        """
        Predict if alert is True Positive using ensemble.
        
        Returns AnalysisResult with verdict, confidence, and reasoning.
        """
        features = self.extract_features(context)
        reasoning = []
        models_used = []
        predictions = []
        
        # 1. Rule-based prediction
        rule_tp, rule_reasoning = self._rule_based_predict(context)
        predictions.append(("rule_based", rule_tp, self.weights["rule_based"]))
        reasoning.extend(rule_reasoning)
        models_used.append("rule_based")
        
        # 2. XGBoost prediction
        if self.xgboost.model is not None and XGBOOST_AVAILABLE:
            try:
                xgb_tp = self.xgboost.predict_proba(features.reshape(1, -1))[0]
                predictions.append(("xgboost", xgb_tp, self.weights["xgboost"]))
                reasoning.append(f"XGBoost TP probability: {xgb_tp*100:.1f}%")
                models_used.append("xgboost")
            except Exception as e:
                logger.warning("xgboost_predict_failed", error=str(e))
        
        # 3. Transformer prediction
        if self.transformer is not None and TORCH_AVAILABLE:
            try:
                with torch.no_grad():
                    x = torch.tensor(features).unsqueeze(0).unsqueeze(0)  # [1, 1, 29]
                    tp_prob, risk = self.transformer(x)
                    transformer_tp = tp_prob.item()
                    predictions.append(("transformer", transformer_tp, self.weights["transformer"]))
                    reasoning.append(f"Transformer TP probability: {transformer_tp*100:.1f}%")
                    models_used.append("transformer")
            except Exception as e:
                logger.warning("transformer_predict_failed", error=str(e))
        
        # Ensemble: weighted average
        if len(predictions) > 1:
            total_weight = sum(w for _, _, w in predictions)
            tp_probability = sum(p * w for _, p, w in predictions) / total_weight
        else:
            tp_probability = predictions[0][1]
        
        # Calculate risk score
        risk_score = min(1.0, 0.3 + (tp_probability * 0.5) + (context.amount_usd / 10_000_000))
        
        # Determine verdict
        if tp_probability >= 0.75:
            verdict = AlertVerdict.TRUE_POSITIVE
            should_create = True
            action = "Create incident - High confidence TP"
        elif tp_probability >= 0.5:
            verdict = AlertVerdict.NEEDS_REVIEW
            should_create = True
            action = "Create incident for manual review"
        else:
            verdict = AlertVerdict.FALSE_POSITIVE
            should_create = False
            action = "Suppressed as likely false positive"
        
        # Adjust severity
        if tp_probability >= 0.85 and context.severity.lower() != 'critical':
            adjusted_severity = 'CRITICAL'
            reasoning.append("Severity upgraded to CRITICAL (high TP probability)")
        elif tp_probability < 0.6 and context.severity.lower() == 'critical':
            adjusted_severity = 'HIGH'
            reasoning.append("Severity downgraded to HIGH (lower TP probability)")
        else:
            adjusted_severity = context.severity.upper()
        
        return AnalysisResult(
            verdict=verdict,
            confidence=abs(tp_probability - 0.5) * 2,
            tp_probability=tp_probability,
            risk_score=risk_score,
            reasoning=reasoning,
            recommended_action=action,
            should_create_incident=should_create,
            adjusted_severity=adjusted_severity,
            model_used="+".join(models_used)
        )
    
    async def train(self, training_data: List[Dict] = None) -> Dict:
        """
        Train the ensemble models.
        
        If training_data is None, fetches from database.
        
        training_data format:
        [
            {
                "rule_id": "flash-loan-001",
                "rule_name": "Large Flash Loan",
                "severity": "critical",
                "chain_id": "ethereum",
                "amount_usd": 1000000,
                "was_true_positive": True,
                ...
            }
        ]
        """
        logger.info("ensemble_training_started")
        
        # Fetch training data from database if not provided
        if training_data is None:
            training_data = await self._fetch_training_data()
        
        if len(training_data) < 50:
            logger.warning("insufficient_training_data", count=len(training_data))
            # Generate synthetic data to supplement
            training_data = self._generate_synthetic_data(training_data)
        
        logger.info("training_data_prepared", samples=len(training_data))
        
        # Extract features and labels
        X = []
        y = []
        
        for sample in training_data:
            context = AlertContext(
                rule_id=sample.get("rule_id", "unknown"),
                rule_name=sample.get("rule_name", "Unknown Rule"),
                severity=sample.get("severity", "medium"),
                chain_id=sample.get("chain_id", "ethereum"),
                event_type=sample.get("event_type", "unknown"),
                amount_usd=float(sample.get("amount_usd", 0) or 0),
                contract_address=sample.get("contract_address"),
                address_entity_type=sample.get("entity_type"),
                address_is_known_entity=sample.get("is_known_entity", False),
                hops_to_known_hacker=sample.get("hops_to_hacker", -1),
                hops_to_mixer=sample.get("hops_to_mixer", -1),
            )
            
            features = self.extract_features(context)
            X.append(features)
            y.append(1.0 if sample.get("was_true_positive", True) else 0.0)
        
        X = np.array(X, dtype=np.float32)
        y = np.array(y, dtype=np.float32)
        
        # Split data
        split_idx = int(len(X) * 0.8)
        indices = np.random.permutation(len(X))
        train_idx, val_idx = indices[:split_idx], indices[split_idx:]
        
        X_train, X_val = X[train_idx], X[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]
        
        results = {"samples": len(training_data)}
        
        # Train XGBoost
        if XGBOOST_AVAILABLE:
            try:
                logger.info("training_xgboost")
                self.xgboost.train(X_train, y_train, X_val, y_val)
                
                # Evaluate
                val_preds = self.xgboost.predict_proba(X_val)
                val_acc = ((val_preds > 0.5) == y_val).mean()
                
                # Convert feature importance to regular floats for JSON serialization
                feature_importance = self.xgboost.get_feature_importance()
                feature_importance = {k: float(v) for k, v in feature_importance.items()}
                
                results["xgboost"] = {
                    "accuracy": float(val_acc),
                    "feature_importance": feature_importance
                }
                
                # Save model
                self.xgboost.save(str(self.model_dir / "alert_xgboost.json"))
                logger.info("xgboost_trained", accuracy=val_acc)
                
            except Exception as e:
                logger.error("xgboost_training_failed", error=str(e))
                results["xgboost"] = {"error": str(e)}
        
        # Train Transformer
        if TORCH_AVAILABLE:
            try:
                logger.info("training_transformer")
                self.transformer = AlertTransformerEncoder()
                
                # Convert to tensors
                X_train_t = torch.tensor(X_train).unsqueeze(1)  # [N, 1, 29]
                y_train_t = torch.tensor(y_train).unsqueeze(1)  # [N, 1]
                X_val_t = torch.tensor(X_val).unsqueeze(1)
                y_val_t = torch.tensor(y_val).unsqueeze(1)
                
                optimizer = torch.optim.AdamW(self.transformer.parameters(), lr=0.001)
                criterion = nn.BCELoss()
                
                best_val_acc = 0
                epochs = 50
                batch_size = 32
                
                for epoch in range(epochs):
                    self.transformer.train()
                    total_loss = 0
                    
                    for i in range(0, len(X_train_t), batch_size):
                        batch_X = X_train_t[i:i+batch_size]
                        batch_y = y_train_t[i:i+batch_size]
                        
                        optimizer.zero_grad()
                        tp_prob, _ = self.transformer(batch_X)
                        loss = criterion(tp_prob, batch_y)
                        loss.backward()
                        optimizer.step()
                        
                        total_loss += loss.item()
                    
                    # Validation
                    self.transformer.eval()
                    with torch.no_grad():
                        val_pred, _ = self.transformer(X_val_t)
                        val_acc = ((val_pred > 0.5) == y_val_t).float().mean().item()
                        
                        if val_acc > best_val_acc:
                            best_val_acc = val_acc
                            torch.save(
                                self.transformer.state_dict(),
                                self.model_dir / "alert_transformer.pt"
                            )
                    
                    if epoch % 10 == 0:
                        logger.info("transformer_epoch", epoch=epoch, loss=total_loss, val_acc=val_acc)
                
                results["transformer"] = {
                    "accuracy": float(best_val_acc),
                    "epochs": epochs
                }
                logger.info("transformer_trained", accuracy=best_val_acc)
                
            except Exception as e:
                logger.error("transformer_training_failed", error=str(e))
                results["transformer"] = {"error": str(e)}
        
        # Save training stats
        self.training_stats = {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "samples": len(training_data),
            "results": results
        }
        
        stats_path = self.model_dir / "alert_analyzer_stats.json"
        with open(stats_path, "w") as f:
            json.dump(self.training_stats, f, indent=2, default=str)
        
        self.is_trained = True
        logger.info("ensemble_training_complete", results=results)
        
        # Upload models to GCS for cross-instance persistence
        self._save_models_to_gcs()
        
        return results
    
    def _save_models_to_gcs(self):
        """Save trained models to GCS for persistence across instances."""
        if not GCS_AVAILABLE:
            logger.warning("gcs_save_skipped", reason="gcs_not_available")
            return
        
        try:
            # Upload XGBoost model
            xgb_path = self.model_dir / "alert_xgboost.json"
            if xgb_path.exists():
                self._upload_to_gcs(str(xgb_path), "alert_xgboost.json")
            
            # Upload Transformer model
            transformer_path = self.model_dir / "alert_transformer.pt"
            if transformer_path.exists():
                self._upload_to_gcs(str(transformer_path), "alert_transformer.pt")
            
            # Upload training stats
            stats_path = self.model_dir / "alert_analyzer_stats.json"
            if stats_path.exists():
                self._upload_to_gcs(str(stats_path), "alert_analyzer_stats.json")
            
            logger.info("models_saved_to_gcs", bucket=self.GCS_BUCKET)
            
        except Exception as e:
            logger.error("gcs_save_failed", error=str(e))
    
    async def _fetch_training_data(self) -> List[Dict]:
        """Fetch training data from historical incidents."""
        training_data = []
        
        try:
            from ..database.service import DatabaseService
            
            # Get historical incidents
            incidents = await DatabaseService.get_incidents(limit=500)
            
            for inc in incidents:
                # Determine if it was a true positive based on status
                status = (inc.status or "").upper()
                was_tp = status not in ["FALSE_POSITIVE", "CLOSED_FALSE_POSITIVE"]
                
                # Extract rule info
                rule_ids = inc.rule_ids or []
                attack_type = inc.attack_type or "unknown"
                
                training_data.append({
                    "rule_id": rule_ids[0] if rule_ids else "unknown",
                    "rule_name": inc.title or attack_type,
                    "severity": inc.severity or "medium",
                    "chain_id": inc.chain_id or (inc.affected_chains[0] if inc.affected_chains else "ethereum"),
                    "amount_usd": float(inc.estimated_loss_usd or 0),
                    "contract_address": inc.contract_address,
                    "was_true_positive": was_tp,
                    "event_type": attack_type
                })
            
            logger.info("training_data_fetched", count=len(training_data))
            
        except Exception as e:
            logger.warning("training_data_fetch_failed", error=str(e))
        
        return training_data
    
    def _generate_synthetic_data(self, existing_data: List[Dict]) -> List[Dict]:
        """Generate synthetic training data based on domain knowledge."""
        import random
        
        synthetic = list(existing_data)  # Start with existing
        
        # Known TP patterns
        tp_patterns = [
            {"rule_name": "Admin Ownership Change", "severity": "critical", "tp_rate": 0.85},
            {"rule_name": "Large Flash Loan", "severity": "critical", "tp_rate": 0.70},
            {"rule_name": "Price Impact High", "severity": "critical", "tp_rate": 0.80},
            {"rule_name": "Liquidity Removal", "severity": "high", "tp_rate": 0.60},
            {"rule_name": "Whale Transfer", "severity": "high", "tp_rate": 0.65},
            {"rule_name": "Bridge Transfer Large", "severity": "high", "tp_rate": 0.70},
            {"rule_name": "Arbitrum Inbox Anomaly", "severity": "high", "tp_rate": 0.75},
            {"rule_name": "Failed Transaction Spike", "severity": "medium", "tp_rate": 0.50},
        ]
        
        chains = ["ethereum", "polygon", "arbitrum", "optimism", "base"]
        
        # Generate samples
        for _ in range(200):
            pattern = random.choice(tp_patterns)
            is_tp = random.random() < pattern["tp_rate"]
            
            # Add risk factors for TPs
            amount = random.uniform(1000, 10_000_000) if is_tp else random.uniform(100, 100_000)
            
            synthetic.append({
                "rule_id": f"synth-{random.randint(1, 1000)}",
                "rule_name": pattern["rule_name"],
                "severity": pattern["severity"],
                "chain_id": random.choice(chains),
                "amount_usd": amount,
                "was_true_positive": is_tp,
                "event_type": "synthetic",
                "is_known_entity": is_tp and random.random() < 0.3,
                "entity_type": "Hacker" if is_tp and random.random() < 0.2 else None,
                "hops_to_hacker": random.randint(0, 3) if is_tp else -1,
            })
        
        logger.info("synthetic_data_generated", count=len(synthetic) - len(existing_data))
        return synthetic


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

_ensemble_analyzer: Optional[EnsembleAlertAnalyzer] = None


def get_alert_analyzer() -> EnsembleAlertAnalyzer:
    """Get or create the global ensemble analyzer instance."""
    global _ensemble_analyzer
    if _ensemble_analyzer is None:
        _ensemble_analyzer = EnsembleAlertAnalyzer()
    return _ensemble_analyzer


async def analyze_yaml_alert(
    rule_id: str,
    rule_name: str,
    severity: str,
    chain_id: str,
    event: Dict
) -> AnalysisResult:
    """
    Analyze a YAML rule alert using the ensemble model.
    
    Returns AnalysisResult with verdict, confidence, and reasoning.
    """
    analyzer = get_alert_analyzer()
    
    context = AlertContext(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        chain_id=chain_id,
        event_type=event.get('event_type', 'unknown'),
        contract_address=event.get('contract_address'),
        from_address=event.get('from_address'),
        to_address=event.get('to_address'),
        amount_usd=float(event.get('amount_usd', 0) or 0)
    )
    
    return analyzer.predict(context)
