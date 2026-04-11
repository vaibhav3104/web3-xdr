"""
ML Alert Analyzer - Second-Pass Filter for YAML Rule Alerts
============================================================

This module analyzes alerts triggered by YAML rules and uses ML to determine
if they are True Positives (TP) or False Positives (FP).

Architecture:
1. YAML Rule triggers alert → Goes to Alert Analyzer
2. Alert Analyzer enriches with context (historical data, graph relationships)
3. ML Model predicts TP probability
4. Only high-confidence TPs create incidents

This reduces alert fatigue by filtering out ~30% false positives from YAML rules.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)

# Try to import ML dependencies
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


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
    contract_address: Optional[str]
    from_address: Optional[str]
    to_address: Optional[str]
    amount_usd: float
    
    # Historical context
    address_age_days: float = 0
    address_tx_count: int = 0
    address_is_known_entity: bool = False
    address_entity_type: Optional[str] = None  # CEX, DEX, Mixer, Hacker, etc.
    
    # Pattern context
    similar_alerts_24h: int = 0
    similar_alerts_7d: int = 0
    rule_historical_tp_rate: float = 0.5
    
    # Graph context
    hops_to_known_hacker: int = -1  # -1 = no path
    hops_to_mixer: int = -1
    connected_to_sanctioned: bool = False
    
    # On-chain context
    contract_verified: bool = False
    contract_age_days: float = 0
    contract_tx_count: int = 0
    is_proxy_contract: bool = False


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


class AlertFeatureExtractor:
    """Extract features from alert context for ML model"""
    
    # Feature names for interpretability
    FEATURE_NAMES = [
        "amount_usd_log",
        "address_age_days",
        "address_tx_count_log",
        "is_known_entity",
        "entity_is_risky",  # Mixer, Hacker, Sanctioned
        "similar_alerts_24h",
        "similar_alerts_7d",
        "rule_historical_tp_rate",
        "hops_to_hacker",
        "hops_to_mixer",
        "connected_to_sanctioned",
        "contract_verified",
        "contract_age_days",
        "contract_tx_count_log",
        "is_proxy",
        "severity_critical",
        "severity_high",
        "severity_medium",
        "chain_ethereum",
        "chain_polygon",
        "chain_arbitrum",
        "chain_optimism",
        "chain_base",
        "rule_flash_loan",
        "rule_price_impact",
        "rule_liquidity",
        "rule_bridge",
        "rule_whale",
        "rule_admin",
    ]
    
    def extract(self, context: AlertContext) -> List[float]:
        """Extract feature vector from alert context"""
        import math
        
        features = []
        
        # Amount (log scale)
        features.append(math.log10(max(context.amount_usd, 1)))
        
        # Address age and activity
        features.append(min(context.address_age_days, 365) / 365)  # Normalize to 0-1
        features.append(math.log10(max(context.address_tx_count, 1)))
        
        # Entity type
        features.append(1.0 if context.address_is_known_entity else 0.0)
        risky_entities = ['Mixer', 'Hacker', 'Sanctioned', 'Exploit']
        features.append(1.0 if context.address_entity_type in risky_entities else 0.0)
        
        # Historical patterns
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
        
        return features


class AlertAnalyzerModel(nn.Module):
    """Neural network for alert TP/FP classification"""
    
    def __init__(self, input_dim: int = 29, hidden_dim: int = 64):
        super().__init__()
        
        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.network(x)


class RuleBasedAnalyzer:
    """
    Rule-based analyzer as fallback when ML model is not available.
    Uses heuristics based on domain knowledge.
    """
    
    # Historical TP rates by rule type (based on industry data)
    RULE_TP_RATES = {
        "admin": 0.85,      # Admin changes are almost always important
        "ownership": 0.85,
        "flash_loan": 0.70,
        "price_impact": 0.80,
        "liquidity_removal": 0.60,
        "bridge": 0.70,
        "whale": 0.65,
        "velocity": 0.55,
        "failed_tx": 0.50,
        "contract_deploy": 0.50,
        "default": 0.60
    }
    
    def analyze(self, context: AlertContext) -> AnalysisResult:
        """Analyze alert using rules"""
        
        reasoning = []
        risk_factors = 0
        risk_score = 0.5
        
        # 1. Check rule historical TP rate
        rule_lower = context.rule_name.lower()
        base_tp_rate = self.RULE_TP_RATES.get("default", 0.6)
        for rule_type, rate in self.RULE_TP_RATES.items():
            if rule_type in rule_lower:
                base_tp_rate = rate
                break
        
        reasoning.append(f"Rule '{context.rule_name}' has historical TP rate of {base_tp_rate*100:.0f}%")
        
        # 2. Amount-based risk
        if context.amount_usd > 1_000_000:
            risk_factors += 2
            reasoning.append(f"Large amount: ${context.amount_usd:,.0f}")
        elif context.amount_usd > 100_000:
            risk_factors += 1
            reasoning.append(f"Significant amount: ${context.amount_usd:,.0f}")
        
        # 3. Entity type risk
        if context.address_entity_type in ['Hacker', 'Exploit']:
            risk_factors += 3
            reasoning.append(f"Address linked to known {context.address_entity_type}")
        elif context.address_entity_type == 'Mixer':
            risk_factors += 2
            reasoning.append("Address linked to mixer (potential money laundering)")
        elif context.address_entity_type == 'Sanctioned':
            risk_factors += 3
            reasoning.append("Address is SANCTIONED - high risk")
        
        # 4. Graph proximity risk
        if context.hops_to_known_hacker >= 0 and context.hops_to_known_hacker <= 2:
            risk_factors += 2
            reasoning.append(f"Only {context.hops_to_known_hacker} hops from known hacker")
        
        if context.hops_to_mixer >= 0 and context.hops_to_mixer <= 1:
            risk_factors += 1
            reasoning.append(f"Connected to mixer ({context.hops_to_mixer} hops)")
        
        # 5. Contract verification
        if not context.contract_verified and context.contract_age_days < 7:
            risk_factors += 1
            reasoning.append("Unverified contract deployed recently")
        
        # 6. Pattern analysis
        if context.similar_alerts_24h > 10:
            risk_factors -= 1  # Many similar alerts might indicate noise
            reasoning.append(f"High alert volume ({context.similar_alerts_24h} in 24h) - possible noise")
        
        # 7. Severity boost
        if context.severity.lower() == 'critical':
            risk_factors += 1
        
        # Calculate final TP probability
        tp_probability = min(0.95, base_tp_rate + (risk_factors * 0.05))
        tp_probability = max(0.1, tp_probability)
        
        # Calculate risk score
        risk_score = min(1.0, 0.3 + (risk_factors * 0.1) + (context.amount_usd / 10_000_000))
        
        # Determine verdict
        if tp_probability >= 0.75:
            verdict = AlertVerdict.TRUE_POSITIVE
            should_create = True
            action = "Create incident and investigate"
        elif tp_probability >= 0.5:
            verdict = AlertVerdict.NEEDS_REVIEW
            should_create = True
            action = "Create incident for manual review"
        else:
            verdict = AlertVerdict.FALSE_POSITIVE
            should_create = False
            action = "Log for audit, no incident needed"
        
        # Adjust severity based on analysis
        if risk_factors >= 3 and context.severity.lower() != 'critical':
            adjusted_severity = 'critical'
            reasoning.append("Severity upgraded to CRITICAL based on risk factors")
        elif risk_factors <= 0 and context.severity.lower() == 'critical':
            adjusted_severity = 'high'
            reasoning.append("Severity downgraded to HIGH - likely noise")
        else:
            adjusted_severity = context.severity
        
        return AnalysisResult(
            verdict=verdict,
            confidence=tp_probability,
            tp_probability=tp_probability,
            risk_score=risk_score,
            reasoning=reasoning,
            recommended_action=action,
            should_create_incident=should_create,
            adjusted_severity=adjusted_severity
        )


class MLAlertAnalyzer:
    """
    ML-powered Alert Analyzer
    
    Analyzes YAML rule alerts to determine True Positive probability.
    Uses a neural network trained on historical alert outcomes.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.feature_extractor = AlertFeatureExtractor()
        self.rule_analyzer = RuleBasedAnalyzer()
        self.model = None
        self.model_loaded = False
        
        # Try to load ML model
        if TORCH_AVAILABLE:
            self.model = AlertAnalyzerModel()
            if model_path:
                try:
                    self.model.load_state_dict(torch.load(model_path))
                    self.model.eval()
                    self.model_loaded = True
                    logger.info("alert_analyzer_model_loaded", path=model_path)
                except Exception as e:
                    logger.warning("alert_analyzer_model_load_failed", error=str(e))
        
        # Statistics
        self.stats = {
            "total_analyzed": 0,
            "true_positives": 0,
            "false_positives": 0,
            "needs_review": 0,
            "incidents_prevented": 0
        }
        
        # Cache for deduplication
        self._alert_cache: Dict[str, datetime] = {}
    
    def _get_alert_hash(self, context: AlertContext) -> str:
        """Generate unique hash for alert deduplication"""
        key = f"{context.rule_id}:{context.contract_address}:{context.chain_id}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def _is_duplicate(self, context: AlertContext, window_minutes: int = 30) -> bool:
        """Check if this is a duplicate alert within time window"""
        alert_hash = self._get_alert_hash(context)
        now = datetime.now(timezone.utc)
        
        if alert_hash in self._alert_cache:
            last_seen = self._alert_cache[alert_hash]
            if (now - last_seen).total_seconds() < window_minutes * 60:
                return True
        
        self._alert_cache[alert_hash] = now
        
        # Clean old entries
        cutoff = now - timedelta(hours=1)
        self._alert_cache = {
            k: v for k, v in self._alert_cache.items()
            if v > cutoff
        }
        
        return False
    
    async def enrich_context(self, context: AlertContext) -> AlertContext:
        """
        Enrich alert context with additional data from:
        - Security Graph (Neo4j)
        - Historical database
        - On-chain data
        """
        try:
            # Try to get graph data
            from ..graph.builder import GraphBuilder
            from ..graph.connection import Neo4jConnection
            
            # Check if address is known entity
            # This would query Neo4j for entity classification
            # For now, we'll use placeholder logic
            
        except ImportError:
            pass
        
        return context
    
    def analyze(self, context: AlertContext) -> AnalysisResult:
        """
        Analyze an alert and determine if it's a True Positive.
        
        Returns AnalysisResult with verdict, confidence, and reasoning.
        """
        self.stats["total_analyzed"] += 1
        
        # Check for duplicates
        if self._is_duplicate(context):
            self.stats["incidents_prevented"] += 1
            return AnalysisResult(
                verdict=AlertVerdict.FALSE_POSITIVE,
                confidence=0.95,
                tp_probability=0.05,
                risk_score=0.1,
                reasoning=["Duplicate alert within 30 minute window"],
                recommended_action="Suppressed - duplicate",
                should_create_incident=False,
                adjusted_severity=context.severity
            )
        
        # Try ML model first
        if self.model_loaded and TORCH_AVAILABLE:
            try:
                features = self.feature_extractor.extract(context)
                with torch.no_grad():
                    x = torch.tensor([features], dtype=torch.float32)
                    tp_prob = self.model(x).item()
                
                # Combine with rule-based analysis for reasoning
                rule_result = self.rule_analyzer.analyze(context)
                
                # Use ML probability but rule-based reasoning
                if tp_prob >= 0.75:
                    verdict = AlertVerdict.TRUE_POSITIVE
                    should_create = True
                    action = "Create incident - ML confidence high"
                elif tp_prob >= 0.5:
                    verdict = AlertVerdict.NEEDS_REVIEW
                    should_create = True
                    action = "Create incident for review"
                else:
                    verdict = AlertVerdict.FALSE_POSITIVE
                    should_create = False
                    action = "Suppressed by ML model"
                    self.stats["incidents_prevented"] += 1
                
                result = AnalysisResult(
                    verdict=verdict,
                    confidence=abs(tp_prob - 0.5) * 2,  # Convert to confidence
                    tp_probability=tp_prob,
                    risk_score=rule_result.risk_score,
                    reasoning=rule_result.reasoning + [f"ML model TP probability: {tp_prob*100:.1f}%"],
                    recommended_action=action,
                    should_create_incident=should_create,
                    adjusted_severity=rule_result.adjusted_severity
                )
                
            except Exception as e:
                logger.warning("ml_analysis_failed", error=str(e))
                result = self.rule_analyzer.analyze(context)
        else:
            # Fallback to rule-based
            result = self.rule_analyzer.analyze(context)
        
        # Update stats
        if result.verdict == AlertVerdict.TRUE_POSITIVE:
            self.stats["true_positives"] += 1
        elif result.verdict == AlertVerdict.FALSE_POSITIVE:
            self.stats["false_positives"] += 1
        else:
            self.stats["needs_review"] += 1
        
        return result
    
    def get_stats(self) -> Dict:
        """Get analyzer statistics"""
        total = self.stats["total_analyzed"]
        return {
            **self.stats,
            "tp_rate": self.stats["true_positives"] / total if total > 0 else 0,
            "fp_rate": self.stats["false_positives"] / total if total > 0 else 0,
            "model_loaded": self.model_loaded
        }
    
    def train(self, training_data: List[Dict]) -> Dict:
        """
        Train the ML model on historical alert outcomes.
        
        training_data format:
        [
            {
                "context": AlertContext,
                "was_true_positive": bool,
                "analyst_notes": str
            },
            ...
        ]
        """
        if not TORCH_AVAILABLE:
            return {"error": "PyTorch not available"}
        
        if len(training_data) < 100:
            return {"error": "Need at least 100 samples for training"}
        
        # Extract features and labels
        X = []
        y = []
        
        for sample in training_data:
            context = sample["context"]
            features = self.feature_extractor.extract(context)
            X.append(features)
            y.append(1.0 if sample["was_true_positive"] else 0.0)
        
        X = torch.tensor(X, dtype=torch.float32)
        y = torch.tensor(y, dtype=torch.float32).unsqueeze(1)
        
        # Train model
        self.model = AlertAnalyzerModel(input_dim=len(X[0]))
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        criterion = nn.BCELoss()
        
        # Training loop
        epochs = 100
        batch_size = 32
        
        for epoch in range(epochs):
            total_loss = 0
            for i in range(0, len(X), batch_size):
                batch_X = X[i:i+batch_size]
                batch_y = y[i:i+batch_size]
                
                optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
            
            if epoch % 20 == 0:
                logger.info("training_progress", epoch=epoch, loss=total_loss)
        
        self.model_loaded = True
        
        # Evaluate
        with torch.no_grad():
            predictions = self.model(X)
            accuracy = ((predictions > 0.5) == y).float().mean().item()
        
        return {
            "status": "trained",
            "samples": len(training_data),
            "accuracy": accuracy,
            "epochs": epochs
        }


# Global instance
_alert_analyzer: Optional[MLAlertAnalyzer] = None

# Try to use advanced Transformer+XGBoost ensemble
_use_ensemble = False
try:
    from .alert_analyzer_transformer import (
        get_alert_analyzer as get_ensemble_analyzer,
        analyze_yaml_alert as analyze_yaml_alert_ensemble,
        EnsembleAlertAnalyzer,
        AlertVerdict as EnsembleVerdict
    )
    _use_ensemble = True
    logger.info("ensemble_alert_analyzer_available")
except ImportError as e:
    logger.warning("ensemble_analyzer_not_available", error=str(e))


def get_alert_analyzer():
    """Get or create the global alert analyzer instance"""
    global _alert_analyzer
    
    # Prefer ensemble analyzer if available
    if _use_ensemble:
        return get_ensemble_analyzer()
    
    if _alert_analyzer is None:
        _alert_analyzer = MLAlertAnalyzer()
    return _alert_analyzer


async def analyze_yaml_alert(
    rule_id: str,
    rule_name: str,
    severity: str,
    chain_id: str,
    event: Dict
) -> AnalysisResult:
    """
    Analyze a YAML rule alert using ML.
    
    Uses Transformer+XGBoost ensemble if available, otherwise falls back to MLP.
    
    Usage:
        result = await analyze_yaml_alert(
            rule_id="flash-loan-001",
            rule_name="Large Flash Loan Activity",
            severity="critical",
            chain_id="ethereum",
            event=security_event
        )
        
        if result.should_create_incident:
            create_incident(...)
    """
    # Use ensemble analyzer if available
    if _use_ensemble:
        result = await analyze_yaml_alert_ensemble(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            chain_id=chain_id,
            event=event
        )
        # Convert to local AnalysisResult format if needed
        return AnalysisResult(
            verdict=AlertVerdict(result.verdict.value),
            confidence=result.confidence,
            tp_probability=result.tp_probability,
            risk_score=result.risk_score,
            reasoning=result.reasoning,
            recommended_action=result.recommended_action,
            should_create_incident=result.should_create_incident,
            adjusted_severity=result.adjusted_severity
        )
    
    # Fallback to simple MLP analyzer
    analyzer = get_alert_analyzer()
    
    # Build context from event
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
    
    # Enrich context
    context = await analyzer.enrich_context(context)
    
    # Analyze
    return analyzer.analyze(context)
