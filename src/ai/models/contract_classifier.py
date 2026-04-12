"""
Contract Threat Classifier
ML model to classify smart contracts as safe or malicious
"""

import pickle
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import numpy as np

# Import our feature extractor
from ..data.bytecode_extractor import BytecodeExtractor, BytecodeFeatures, features_to_vector

class ThreatCategory(Enum):
    """Classification categories for contracts"""
    SAFE = "safe"
    FLASH_LOAN_EXPLOIT = "flash_loan_exploit"
    REENTRANCY_EXPLOIT = "reentrancy_exploit"
    BRIDGE_EXPLOIT = "bridge_exploit"
    ORACLE_MANIPULATION = "oracle_manipulation"
    GOVERNANCE_ATTACK = "governance_attack"
    RUG_PULL = "rug_pull"
    HONEYPOT = "honeypot"
    UNKNOWN_THREAT = "unknown_threat"

@dataclass
class ClassificationResult:
    """Result of contract classification"""
    contract_address: str
    threat_category: ThreatCategory
    confidence: float
    risk_score: float
    risk_factors: List[str]
    similar_exploits: List[str]
    recommendation: str

class ContractThreatClassifier:
    """
    ML-based contract threat classifier

    Uses a combination of:
    1. Rule-based heuristics (fast, interpretable)
    2. Feature-based ML model (learned patterns)
    3. Similarity matching (known exploits)

    Supports hot-reload: call reload_model() after retraining to pick up
    new weights without restarting the process.
    """

    # Default model search paths (checked in order)
    DEFAULT_MODEL_PATHS = [
        Path(__file__).parent / "contract_classifier.pkl",
        Path(__file__).parent / "classifier.pkl",
        Path("./data/models/contract_classifier.pkl"),
    ]

    def __init__(self, model_path: Optional[str] = None):
        self.extractor = BytecodeExtractor()
        self._enhanced_extractor = None  # Lazy-loaded for 43-feature models
        self.model = None
        self._model_feature_count = 20  # Default to basic extractor
        self.known_exploits: Dict[str, Dict] = {}
        self._model_path = model_path
        self._model_loaded_at: Optional[float] = None

        # Try to load model: explicit path, or auto-discover
        if model_path and Path(model_path).exists():
            self.load_model(model_path)
        else:
            self._auto_discover_model()

        # Initialize with rule-based classifier
        self._init_rule_weights()

    def _auto_discover_model(self):
        """Try to find and load a trained model from default paths."""
        for path in self.DEFAULT_MODEL_PATHS:
            if path.exists():
                try:
                    self.load_model(str(path))
                    return
                except Exception:
                    continue
    
    def _init_rule_weights(self):
        """Initialize weights for rule-based classification"""
        self.rule_weights = {
            "has_flash_loan_callback": {
                ThreatCategory.FLASH_LOAN_EXPLOIT: 0.6,
                ThreatCategory.REENTRANCY_EXPLOIT: 0.2,
            },
            "has_reentrancy_pattern": {
                ThreatCategory.REENTRANCY_EXPLOIT: 0.7,
                ThreatCategory.FLASH_LOAN_EXPLOIT: 0.2,
            },
            "has_delegatecall_pattern": {
                ThreatCategory.UNKNOWN_THREAT: 0.4,
                ThreatCategory.RUG_PULL: 0.3,
            },
            "has_selfdestruct": {
                ThreatCategory.RUG_PULL: 0.5,
                ThreatCategory.HONEYPOT: 0.3,
            },
            "has_mint_function": {
                ThreatCategory.BRIDGE_EXPLOIT: 0.3,
                ThreatCategory.RUG_PULL: 0.2,
            },
            "has_admin_functions": {
                ThreatCategory.GOVERNANCE_ATTACK: 0.2,
                ThreatCategory.RUG_PULL: 0.2,
            },
        }
    
    def classify(
        self, 
        bytecode: str, 
        contract_address: Optional[str] = None
    ) -> ClassificationResult:
        """
        Classify a contract based on its bytecode
        
        Args:
            bytecode: Hex string of contract bytecode
            contract_address: Optional address for tracking
        
        Returns:
            ClassificationResult with threat assessment
        """
        # Extract features
        features = self.extractor.extract_features(bytecode)
        
        # Get bytecode hash for similarity matching
        bytecode_hash = self.extractor.get_bytecode_hash(bytecode)
        
        # Check known exploits first
        if bytecode_hash in self.known_exploits:
            known = self.known_exploits[bytecode_hash]
            return ClassificationResult(
                contract_address=contract_address or "unknown",
                threat_category=ThreatCategory[known["category"]],
                confidence=0.99,
                risk_score=100.0,
                risk_factors=["KNOWN EXPLOIT: " + known["name"]],
                similar_exploits=[known["name"]],
                recommendation="CRITICAL: This is a known exploit contract. Block immediately."
            )
        
        # Rule-based classification
        category_scores = self._rule_based_classify(features)
        
        # ML-based classification (if model loaded)
        if self.model:
            ml_scores = self._ml_classify(features, bytecode=bytecode)
            ml_weight = 0.7 if self._model_feature_count == 43 else 0.6
            rule_weight = 1.0 - ml_weight

            if ml_scores:
                # For binary classifiers: scale ALL category scores by ML confidence
                ml_safe_prob = ml_scores.get(ThreatCategory.SAFE, 0.0)
                ml_threat_prob = 1.0 - ml_safe_prob

                for cat in category_scores:
                    if cat == ThreatCategory.SAFE:
                        category_scores[cat] = category_scores[cat] * rule_weight + ml_safe_prob * ml_weight
                    else:
                        # Scale threat categories by ML threat probability
                        category_scores[cat] = category_scores[cat] * rule_weight * ml_threat_prob + \
                            ml_scores.get(cat, 0.0) * ml_weight
        
        # Find similar known exploits
        similar = self._find_similar_exploits(bytecode)
        
        # Determine final category
        final_category = max(category_scores, key=category_scores.get)
        confidence = category_scores[final_category]
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            final_category, confidence, features.risk_score
        )
        
        return ClassificationResult(
            contract_address=contract_address or "unknown",
            threat_category=final_category,
            confidence=confidence,
            risk_score=features.risk_score,
            risk_factors=features.risk_factors,
            similar_exploits=similar,
            recommendation=recommendation
        )
    
    def _rule_based_classify(
        self, 
        features: BytecodeFeatures
    ) -> Dict[ThreatCategory, float]:
        """Apply rule-based classification"""
        scores = {cat: 0.0 for cat in ThreatCategory}
        scores[ThreatCategory.SAFE] = 0.5  # Default assumption
        
        # Apply rules based on features
        if features.has_flash_loan_callback:
            for cat, weight in self.rule_weights["has_flash_loan_callback"].items():
                scores[cat] += weight
            scores[ThreatCategory.SAFE] -= 0.4
        
        if features.has_reentrancy_pattern:
            for cat, weight in self.rule_weights["has_reentrancy_pattern"].items():
                scores[cat] += weight
            scores[ThreatCategory.SAFE] -= 0.5
        
        if features.has_delegatecall_pattern:
            for cat, weight in self.rule_weights["has_delegatecall_pattern"].items():
                scores[cat] += weight
            scores[ThreatCategory.SAFE] -= 0.2
        
        if features.has_selfdestruct:
            for cat, weight in self.rule_weights["has_selfdestruct"].items():
                scores[cat] += weight
            scores[ThreatCategory.SAFE] -= 0.3
        
        if features.has_mint_function and features.has_burn_function:
            scores[ThreatCategory.BRIDGE_EXPLOIT] += 0.2
        
        # Normalize scores
        total = sum(scores.values())
        if total > 0:
            scores = {k: v/total for k, v in scores.items()}
        
        return scores
    
    def _ml_classify(
        self,
        features: BytecodeFeatures,
        bytecode: str = None,
    ) -> Dict[ThreatCategory, float]:
        """Apply ML model classification. Handles both 20 and 43 feature models."""
        if not self.model:
            return {}

        try:
            if self._model_feature_count == 43 and bytecode:
                # Use enhanced extractor for 43-feature model
                if self._enhanced_extractor is None:
                    from ..data.enhanced_extractor import EnhancedBytecodeExtractor
                    self._enhanced_extractor = EnhancedBytecodeExtractor()
                enhanced_features = self._enhanced_extractor.extract_features(bytecode)
                vector = np.array(enhanced_features.to_vector()).reshape(1, -1)
            else:
                vector = np.array(features_to_vector(features)).reshape(1, -1)

            # Binary classifier returns [safe_prob, exploit_prob]
            probabilities = self.model.predict_proba(vector)[0]
            classes = self.model.classes_

            if len(classes) == 2:
                # Binary: map exploit probability to threat categories
                exploit_prob = float(probabilities[list(classes).index(1)] if 1 in classes else probabilities[1])
                safe_prob = 1.0 - exploit_prob
                return {
                    ThreatCategory.SAFE: safe_prob,
                    ThreatCategory.UNKNOWN_THREAT: exploit_prob,
                }
            else:
                return {ThreatCategory(cat): prob for cat, prob in zip(classes, probabilities)}
        except Exception as e:
            print(f"ML prediction error: {e}")
            return {}
    
    def _find_similar_exploits(self, bytecode: str) -> List[str]:
        """Find similar known exploits based on bytecode similarity"""
        similar = []
        
        for hash_key, exploit in self.known_exploits.items():
            if "bytecode" in exploit:
                similarity = self.extractor.compare_similarity(bytecode, exploit["bytecode"])
                if similarity > 0.7:  # 70% similarity threshold
                    similar.append(f"{exploit['name']} ({similarity:.0%} similar)")
        
        return similar[:5]  # Top 5
    
    def _generate_recommendation(
        self, 
        category: ThreatCategory, 
        confidence: float,
        risk_score: float
    ) -> str:
        """Generate actionable recommendation"""
        if category == ThreatCategory.SAFE:
            if risk_score > 50:
                return "Contract appears safe but has some risk indicators. Monitor closely."
            return "Contract appears safe. Standard monitoring recommended."
        
        severity = "CRITICAL" if confidence > 0.8 else "HIGH" if confidence > 0.5 else "MEDIUM"
        
        recommendations = {
            ThreatCategory.FLASH_LOAN_EXPLOIT: 
                f"{severity}: Likely flash loan exploit contract. "
                "Block transactions and alert protocol team immediately.",
            
            ThreatCategory.REENTRANCY_EXPLOIT:
                f"{severity}: Reentrancy exploit pattern detected. "
                "Verify target protocol has reentrancy guards. Consider pausing.",
            
            ThreatCategory.BRIDGE_EXPLOIT:
                f"{severity}: Bridge exploit pattern detected. "
                "Alert bridge operators. Consider emergency pause on bridge contracts.",
            
            ThreatCategory.ORACLE_MANIPULATION:
                f"{severity}: Oracle manipulation pattern detected. "
                "Verify oracle freshness and TWAP protections.",
            
            ThreatCategory.GOVERNANCE_ATTACK:
                f"{severity}: Governance attack pattern detected. "
                "Check for flash loan governance. Alert DAO.",
            
            ThreatCategory.RUG_PULL:
                f"{severity}: Potential rug pull contract. "
                "Advise users not to interact. May drain funds.",
            
            ThreatCategory.HONEYPOT:
                f"{severity}: Honeypot contract detected. "
                "Users may not be able to withdraw. Block interactions.",
            
            ThreatCategory.UNKNOWN_THREAT:
                f"{severity}: Unknown threat pattern. "
                "Manual review recommended. Monitor for unusual activity.",
        }
        
        return recommendations.get(category, "Review recommended.")
    
    def add_known_exploit(
        self, 
        bytecode_hash: str, 
        name: str, 
        category: str,
        bytecode: Optional[str] = None
    ):
        """Add a known exploit to the database"""
        self.known_exploits[bytecode_hash] = {
            "name": name,
            "category": category,
            "bytecode": bytecode
        }
    
    def save_model(self, path: str):
        """Save the model to disk"""
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'known_exploits': self.known_exploits,
                'rule_weights': self.rule_weights
            }, f)
    
    def load_model(self, path: str):
        """Load the model from disk. Supports both pickle dict and joblib formats."""
        import os
        import joblib

        try:
            # Try pickle dict format first (ContractThreatClassifier.save_model format)
            with open(path, 'rb') as f:
                data = pickle.load(f)  # nosec B301 — trusted local model files only

            if isinstance(data, dict):
                self.model = data.get('model')
                self.known_exploits = data.get('known_exploits', {})
                if data.get('rule_weights') is not None:
                    self.rule_weights = data['rule_weights']
                self._model_feature_count = data.get('feature_count', 20)
            else:
                # Raw sklearn model saved by joblib
                self.model = data
                # Detect feature count from model
                if hasattr(self.model, 'n_features_in_'):
                    self._model_feature_count = self.model.n_features_in_
        except Exception:
            # Try joblib format
            self.model = joblib.load(path)
            if hasattr(self.model, 'n_features_in_'):
                self._model_feature_count = self.model.n_features_in_

        self._model_path = path
        self._model_loaded_at = os.path.getmtime(path)

    def reload_model(self) -> bool:
        """Hot-reload model from disk if the file has been updated."""
        if not self._model_path or not Path(self._model_path).exists():
            return False
        import os
        current_mtime = os.path.getmtime(self._model_path)
        if self._model_loaded_at is None or current_mtime > self._model_loaded_at:
            self.load_model(self._model_path)
            return True
        return False

    def check_for_update(self) -> bool:
        """Check if the model file on disk is newer than the loaded version."""
        if not self._model_path or not Path(self._model_path).exists():
            return False
        import os
        current_mtime = os.path.getmtime(self._model_path)
        return self._model_loaded_at is None or current_mtime > self._model_loaded_at

# Training utilities
class ContractClassifierTrainer:
    """Train the contract threat classifier"""
    
    def __init__(self):
        self.extractor = BytecodeExtractor()
        self.training_data: List[Tuple[List[float], str]] = []
    
    def add_training_sample(self, bytecode: str, category: str):
        """Add a labeled training sample"""
        features = self.extractor.extract_features(bytecode)
        vector = features_to_vector(features)
        self.training_data.append((vector, category))
    
    def train(self) -> 'ContractThreatClassifier':
        """Train the model on collected samples"""
        if len(self.training_data) < 10:
            raise ValueError("Need at least 10 training samples")
        
        # Prepare data
        X = np.array([sample[0] for sample in self.training_data])
        y = np.array([sample[1] for sample in self.training_data])
        
        # Train a simple classifier (can be replaced with more sophisticated model)
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        model.fit(X_train, y_train)
        
        # Evaluate
        accuracy = model.score(X_test, y_test)
        print(f"Model accuracy: {accuracy:.2%}")
        
        # Create classifier
        classifier = ContractThreatClassifier()
        classifier.model = model
        
        return classifier

if __name__ == "__main__":
    # Demo usage
    classifier = ContractThreatClassifier()
    
    # Sample exploit-like bytecode (with flash loan callback signature)
    exploit_bytecode = """
    608060405234801561001057600080fd5b506040516104a03803806104a0833981810160405281019061003291906100f8565b
    63c3924ed6000000000000000000000000000000000000000000000000000000000000000
    f1f1f155555555
    """
    
    result = classifier.classify(exploit_bytecode, "0x1234...")
    
    print("=" * 60)
    print("CONTRACT CLASSIFICATION RESULT")
    print("=" * 60)
    print(f"Address:        {result.contract_address}")
    print(f"Category:       {result.threat_category.value}")
    print(f"Confidence:     {result.confidence:.2%}")
    print(f"Risk Score:     {result.risk_score}/100")
    print(f"Risk Factors:   {result.risk_factors}")
    print(f"Similar To:     {result.similar_exploits}")
    print(f"Recommendation: {result.recommendation}")
    print("=" * 60)
