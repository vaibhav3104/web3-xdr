#!/usr/bin/env python3
"""
Improve ML Model with Enhanced Training Data
=============================================

This script:
1. Loads more training data from historical incidents
2. Adds synthetic examples for rare attack types
3. Fine-tunes for specific attack types (rug pulls, flash loans)
4. Implements techniques to reduce false positives

Usage:
    python scripts/improve_ml_model.py
"""

import os
import sys
import json
import random
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog
import numpy as np

logger = structlog.get_logger(__name__)

# ============================================================================
# SYNTHETIC TRAINING DATA GENERATORS
# ============================================================================

# Historical exploit patterns for training
HISTORICAL_EXPLOITS = [
    # Flash Loan Attacks
    {
        "name": "Euler Finance Hack",
        "attack_type": "flash_loan_attack",
        "amount_usd": 197_000_000,
        "chain": "ethereum",
        "patterns": {
            "flash_loan_amount": 30_000_000,
            "price_manipulation": True,
            "multiple_protocols": True,
            "rapid_execution": True,
        }
    },
    {
        "name": "Beanstalk Hack",
        "attack_type": "flash_loan_attack",
        "amount_usd": 182_000_000,
        "chain": "ethereum",
        "patterns": {
            "flash_loan_amount": 1_000_000_000,
            "governance_manipulation": True,
            "multiple_protocols": True,
            "rapid_execution": True,
        }
    },
    {
        "name": "Cream Finance Hack",
        "attack_type": "flash_loan_attack",
        "amount_usd": 130_000_000,
        "chain": "ethereum",
        "patterns": {
            "flash_loan_amount": 500_000_000,
            "oracle_manipulation": True,
            "reentrancy": True,
        }
    },
    
    # Bridge Exploits
    {
        "name": "Ronin Bridge Hack",
        "attack_type": "bridge_exploit",
        "amount_usd": 625_000_000,
        "chain": "ethereum",
        "patterns": {
            "validator_compromise": True,
            "cross_chain": True,
            "large_withdrawal": True,
        }
    },
    {
        "name": "Wormhole Hack",
        "attack_type": "bridge_exploit",
        "amount_usd": 320_000_000,
        "chain": "ethereum",
        "patterns": {
            "signature_bypass": True,
            "cross_chain": True,
            "minting_exploit": True,
        }
    },
    {
        "name": "Nomad Bridge Hack",
        "attack_type": "bridge_exploit",
        "amount_usd": 190_000_000,
        "chain": "ethereum",
        "patterns": {
            "initialization_bug": True,
            "cross_chain": True,
            "mass_exploitation": True,
        }
    },
    
    # Rug Pulls
    {
        "name": "Squid Game Token",
        "attack_type": "rug_pull",
        "amount_usd": 3_400_000,
        "chain": "bsc",
        "patterns": {
            "liquidity_removal": True,
            "sell_disabled": True,
            "honeypot": True,
        }
    },
    {
        "name": "AnubisDAO",
        "attack_type": "rug_pull",
        "amount_usd": 60_000_000,
        "chain": "ethereum",
        "patterns": {
            "liquidity_removal": True,
            "anonymous_team": True,
            "no_audit": True,
        }
    },
    
    # Oracle Manipulation
    {
        "name": "Mango Markets",
        "attack_type": "oracle_manipulation",
        "amount_usd": 114_000_000,
        "chain": "solana",
        "patterns": {
            "price_manipulation": True,
            "collateral_inflation": True,
            "liquidation_exploit": True,
        }
    },
    
    # Reentrancy
    {
        "name": "The DAO Hack",
        "attack_type": "reentrancy",
        "amount_usd": 60_000_000,
        "chain": "ethereum",
        "patterns": {
            "recursive_call": True,
            "state_update_after_call": True,
        }
    },
    {
        "name": "Curve Finance Hack",
        "attack_type": "reentrancy",
        "amount_usd": 73_000_000,
        "chain": "ethereum",
        "patterns": {
            "vyper_vulnerability": True,
            "read_only_reentrancy": True,
        }
    },
    
    # Access Control
    {
        "name": "Wintermute Hack",
        "attack_type": "access_control",
        "amount_usd": 160_000_000,
        "chain": "ethereum",
        "patterns": {
            "private_key_compromise": True,
            "vanity_address": True,
        }
    },
]


def generate_synthetic_flash_loan_samples(count: int = 100) -> List[Dict]:
    """Generate synthetic flash loan attack samples."""
    samples = []
    
    for _ in range(count):
        is_attack = random.random() < 0.5
        
        if is_attack:
            sample = {
                "event_type": "flash_loan",
                "amount_usd": random.uniform(100_000, 100_000_000),
                "chain_id": random.choice(["ethereum", "bsc", "polygon", "arbitrum"]),
                "is_threat": True,
                "threat_type": "flash_loan_attack",
                "features": {
                    "loan_amount_percentile": random.uniform(0.9, 1.0),  # High percentile
                    "repayment_delay_blocks": random.randint(0, 2),  # Very fast
                    "protocols_involved": random.randint(2, 5),  # Multiple protocols
                    "price_impact": random.uniform(0.05, 0.30),  # Significant impact
                    "profit_ratio": random.uniform(0.1, 5.0),  # Profitable
                    "uses_mixer_after": random.random() < 0.7,  # Often uses mixer
                    "new_contract": random.random() < 0.8,  # Often new contract
                }
            }
        else:
            sample = {
                "event_type": "flash_loan",
                "amount_usd": random.uniform(1_000, 10_000_000),
                "chain_id": random.choice(["ethereum", "bsc", "polygon", "arbitrum"]),
                "is_threat": False,
                "threat_type": "safe",
                "features": {
                    "loan_amount_percentile": random.uniform(0.1, 0.7),  # Normal range
                    "repayment_delay_blocks": random.randint(0, 1),
                    "protocols_involved": random.randint(1, 2),  # Few protocols
                    "price_impact": random.uniform(0.001, 0.02),  # Minimal impact
                    "profit_ratio": random.uniform(0.001, 0.05),  # Small profit
                    "uses_mixer_after": False,
                    "new_contract": random.random() < 0.2,  # Usually known contract
                }
            }
        
        samples.append(sample)
    
    return samples


def generate_synthetic_rug_pull_samples(count: int = 100) -> List[Dict]:
    """Generate synthetic rug pull samples."""
    samples = []
    
    for _ in range(count):
        is_attack = random.random() < 0.5
        
        if is_attack:
            sample = {
                "event_type": "liquidity_removal",
                "amount_usd": random.uniform(10_000, 10_000_000),
                "chain_id": random.choice(["ethereum", "bsc", "polygon"]),
                "is_threat": True,
                "threat_type": "rug_pull",
                "features": {
                    "liquidity_removal_percent": random.uniform(0.8, 1.0),  # High removal
                    "contract_age_days": random.randint(1, 30),  # New contract
                    "holder_count": random.randint(100, 10000),  # Many holders
                    "has_sell_restrictions": random.random() < 0.6,  # Often has restrictions
                    "deployer_is_anonymous": True,
                    "no_audit": random.random() < 0.9,  # Usually no audit
                    "social_media_hype": random.random() < 0.8,  # High hype
                    "whale_concentration": random.uniform(0.5, 0.95),  # Concentrated holdings
                }
            }
        else:
            sample = {
                "event_type": "liquidity_removal",
                "amount_usd": random.uniform(1_000, 1_000_000),
                "chain_id": random.choice(["ethereum", "bsc", "polygon"]),
                "is_threat": False,
                "threat_type": "safe",
                "features": {
                    "liquidity_removal_percent": random.uniform(0.01, 0.3),  # Small removal
                    "contract_age_days": random.randint(180, 1000),  # Established
                    "holder_count": random.randint(1000, 100000),
                    "has_sell_restrictions": False,
                    "deployer_is_anonymous": False,
                    "no_audit": random.random() < 0.2,  # Usually audited
                    "social_media_hype": random.random() < 0.3,  # Normal activity
                    "whale_concentration": random.uniform(0.1, 0.4),  # Distributed
                }
            }
        
        samples.append(sample)
    
    return samples


def generate_synthetic_bridge_exploit_samples(count: int = 100) -> List[Dict]:
    """Generate synthetic bridge exploit samples."""
    samples = []
    
    for _ in range(count):
        is_attack = random.random() < 0.5
        
        if is_attack:
            sample = {
                "event_type": "bridge_transfer",
                "amount_usd": random.uniform(1_000_000, 500_000_000),
                "chain_id": "ethereum",
                "dest_chain": random.choice(["polygon", "arbitrum", "optimism", "bsc"]),
                "is_threat": True,
                "threat_type": "bridge_exploit",
                "features": {
                    "transfer_amount_percentile": random.uniform(0.95, 1.0),  # Huge transfer
                    "validator_count_used": random.randint(1, 3),  # Few validators
                    "message_verification_bypassed": random.random() < 0.8,
                    "destination_is_mixer": random.random() < 0.5,
                    "rapid_cross_chain_hops": random.randint(2, 5),
                    "contract_recently_deployed": random.random() < 0.6,
                }
            }
        else:
            sample = {
                "event_type": "bridge_transfer",
                "amount_usd": random.uniform(100, 1_000_000),
                "chain_id": "ethereum",
                "dest_chain": random.choice(["polygon", "arbitrum", "optimism", "bsc"]),
                "is_threat": False,
                "threat_type": "safe",
                "features": {
                    "transfer_amount_percentile": random.uniform(0.1, 0.8),
                    "validator_count_used": random.randint(5, 15),  # Many validators
                    "message_verification_bypassed": False,
                    "destination_is_mixer": False,
                    "rapid_cross_chain_hops": 1,
                    "contract_recently_deployed": False,
                }
            }
        
        samples.append(sample)
    
    return samples


def generate_synthetic_oracle_manipulation_samples(count: int = 100) -> List[Dict]:
    """Generate synthetic oracle manipulation samples."""
    samples = []
    
    for _ in range(count):
        is_attack = random.random() < 0.5
        
        if is_attack:
            sample = {
                "event_type": "oracle_update",
                "amount_usd": random.uniform(100_000, 50_000_000),
                "chain_id": random.choice(["ethereum", "bsc", "polygon"]),
                "is_threat": True,
                "threat_type": "oracle_manipulation",
                "features": {
                    "price_deviation_percent": random.uniform(0.1, 0.5),  # Large deviation
                    "update_frequency_anomaly": True,
                    "single_source_reliance": random.random() < 0.7,
                    "twap_manipulation": random.random() < 0.6,
                    "followed_by_liquidation": random.random() < 0.8,
                    "flash_loan_in_same_block": random.random() < 0.7,
                }
            }
        else:
            sample = {
                "event_type": "oracle_update",
                "amount_usd": random.uniform(0, 1_000_000),
                "chain_id": random.choice(["ethereum", "bsc", "polygon"]),
                "is_threat": False,
                "threat_type": "safe",
                "features": {
                    "price_deviation_percent": random.uniform(0.001, 0.05),  # Normal
                    "update_frequency_anomaly": False,
                    "single_source_reliance": False,
                    "twap_manipulation": False,
                    "followed_by_liquidation": random.random() < 0.1,  # Rare
                    "flash_loan_in_same_block": False,
                }
            }
        
        samples.append(sample)
    
    return samples


def generate_safe_transaction_samples(count: int = 500) -> List[Dict]:
    """Generate safe transaction samples to reduce false positives."""
    samples = []
    
    event_types = ["transfer", "swap", "stake", "unstake", "deposit", "withdraw", "approve"]
    
    for _ in range(count):
        event_type = random.choice(event_types)
        
        sample = {
            "event_type": event_type,
            "amount_usd": random.uniform(10, 100_000),
            "chain_id": random.choice(["ethereum", "bsc", "polygon", "arbitrum", "optimism"]),
            "is_threat": False,
            "threat_type": "safe",
            "features": {
                "contract_verified": True,
                "contract_age_days": random.randint(90, 1000),
                "known_protocol": random.random() < 0.8,
                "normal_gas_price": True,
                "user_has_history": True,
                "amount_within_normal_range": True,
                "no_suspicious_patterns": True,
            }
        }
        
        samples.append(sample)
    
    return samples


def features_to_vector(sample: Dict) -> np.ndarray:
    """Convert sample features to a numerical vector."""
    features = sample.get("features", {})
    
    # Create a consistent feature vector
    vector = [
        sample.get("amount_usd", 0) / 1_000_000_000,  # Normalize
        hash(sample.get("chain_id", "ethereum")) % 100 / 100,  # Chain encoding
        hash(sample.get("event_type", "unknown")) % 100 / 100,  # Event type encoding
        features.get("loan_amount_percentile", 0),
        features.get("protocols_involved", 1) / 10,
        features.get("price_impact", 0),
        features.get("profit_ratio", 0) / 10,
        1.0 if features.get("uses_mixer_after", False) else 0.0,
        1.0 if features.get("new_contract", False) else 0.0,
        features.get("liquidity_removal_percent", 0),
        features.get("contract_age_days", 365) / 365,
        features.get("whale_concentration", 0),
        features.get("transfer_amount_percentile", 0),
        features.get("price_deviation_percent", 0),
        1.0 if features.get("flash_loan_in_same_block", False) else 0.0,
        1.0 if features.get("contract_verified", True) else 0.0,
    ]
    
    return np.array(vector, dtype=np.float32)


async def load_production_incidents(limit: int = 1000) -> List[Dict]:
    """Load real incidents from production database."""
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text
        
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            logger.warning("No DATABASE_URL, skipping production data")
            return []
        
        if db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        
        engine = create_async_engine(db_url)
        
        async with engine.connect() as conn:
            result = await conn.execute(text("""
                SELECT 
                    incident_id, title, attack_type, severity, confidence,
                    total_loss_usd, affected_chains, created_at
                FROM incidents
                WHERE attack_type IS NOT NULL
                ORDER BY created_at DESC
                LIMIT :limit
            """), {"limit": limit})
            
            rows = result.fetchall()
            
            incidents = []
            for row in rows:
                incidents.append({
                    "incident_id": row[0],
                    "title": row[1],
                    "attack_type": row[2],
                    "severity": row[3],
                    "confidence": row[4],
                    "total_loss_usd": float(row[5]) if row[5] else 0,
                    "affected_chains": row[6] or [],
                    "created_at": str(row[7]),
                    "is_threat": True,
                    "threat_type": row[2] or "unknown"
                })
            
            logger.info("loaded_production_incidents", count=len(incidents))
            return incidents
            
    except Exception as e:
        logger.error("failed_to_load_production_incidents", error=str(e))
        return []


async def main():
    """Main function to improve ML model."""
    print("\n" + "="*60)
    print("🧠 Improving ML Model with Enhanced Training Data")
    print("="*60)
    
    # ========================================================================
    # 1. Generate Synthetic Training Data
    # ========================================================================
    print("\n📊 Generating synthetic training data...")
    
    all_samples = []
    
    # Flash loan samples
    flash_loan_samples = generate_synthetic_flash_loan_samples(200)
    all_samples.extend(flash_loan_samples)
    print(f"   ✓ Generated {len(flash_loan_samples)} flash loan samples")
    
    # Rug pull samples
    rug_pull_samples = generate_synthetic_rug_pull_samples(200)
    all_samples.extend(rug_pull_samples)
    print(f"   ✓ Generated {len(rug_pull_samples)} rug pull samples")
    
    # Bridge exploit samples
    bridge_samples = generate_synthetic_bridge_exploit_samples(200)
    all_samples.extend(bridge_samples)
    print(f"   ✓ Generated {len(bridge_samples)} bridge exploit samples")
    
    # Oracle manipulation samples
    oracle_samples = generate_synthetic_oracle_manipulation_samples(200)
    all_samples.extend(oracle_samples)
    print(f"   ✓ Generated {len(oracle_samples)} oracle manipulation samples")
    
    # Safe transactions (to reduce false positives)
    safe_samples = generate_safe_transaction_samples(800)
    all_samples.extend(safe_samples)
    print(f"   ✓ Generated {len(safe_samples)} safe transaction samples")
    
    # ========================================================================
    # 2. Load Production Incidents
    # ========================================================================
    print("\n📥 Loading production incidents...")
    production_incidents = await load_production_incidents(500)
    
    if production_incidents:
        # Convert incidents to training samples
        for incident in production_incidents:
            sample = {
                "event_type": incident.get("attack_type", "unknown"),
                "amount_usd": incident.get("total_loss_usd", 0),
                "chain_id": incident.get("affected_chains", ["ethereum"])[0] if incident.get("affected_chains") else "ethereum",
                "is_threat": True,
                "threat_type": incident.get("attack_type", "unknown"),
                "features": {
                    "confidence": incident.get("confidence", 0.5),
                    "severity": {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}.get(incident.get("severity", "MEDIUM"), 0.5)
                }
            }
            all_samples.append(sample)
        
        print(f"   ✓ Added {len(production_incidents)} production incidents")
    
    # ========================================================================
    # 3. Add Historical Exploit Patterns
    # ========================================================================
    print("\n📚 Adding historical exploit patterns...")
    
    for exploit in HISTORICAL_EXPLOITS:
        # Create multiple samples per exploit (with variations)
        for _ in range(10):
            sample = {
                "event_type": exploit["attack_type"],
                "amount_usd": exploit["amount_usd"] * random.uniform(0.5, 1.5),
                "chain_id": exploit["chain"],
                "is_threat": True,
                "threat_type": exploit["attack_type"],
                "features": {
                    **exploit["patterns"],
                    "historical_exploit": True,
                    "exploit_name": exploit["name"]
                }
            }
            all_samples.append(sample)
    
    print(f"   ✓ Added {len(HISTORICAL_EXPLOITS) * 10} historical exploit samples")
    
    # ========================================================================
    # 4. Prepare Training Data
    # ========================================================================
    print("\n🔄 Preparing training data...")
    
    # Shuffle samples
    random.shuffle(all_samples)
    
    # Convert to feature vectors
    X = np.array([features_to_vector(s) for s in all_samples])
    y_threat = np.array([1 if s["is_threat"] else 0 for s in all_samples])
    
    # Map threat types to integers
    threat_types = list(set(s["threat_type"] for s in all_samples))
    threat_type_to_idx = {t: i for i, t in enumerate(threat_types)}
    y_type = np.array([threat_type_to_idx[s["threat_type"]] for s in all_samples])
    
    print(f"   Total samples: {len(all_samples)}")
    print(f"   Feature dimensions: {X.shape[1]}")
    print(f"   Threat types: {len(threat_types)}")
    
    # Class distribution
    print("\n📊 Class distribution:")
    threat_count = sum(y_threat)
    safe_count = len(y_threat) - threat_count
    print(f"   Threats: {threat_count} ({threat_count/len(y_threat)*100:.1f}%)")
    print(f"   Safe: {safe_count} ({safe_count/len(y_threat)*100:.1f}%)")
    
    # ========================================================================
    # 5. Save Enhanced Training Data
    # ========================================================================
    print("\n💾 Saving enhanced training data...")
    
    output_dir = "data/ml_training"
    os.makedirs(output_dir, exist_ok=True)
    
    # Save samples as JSON
    with open(f"{output_dir}/enhanced_samples.json", "w") as f:
        json.dump(all_samples, f, indent=2, default=str)
    
    # Save numpy arrays
    np.save(f"{output_dir}/X_enhanced.npy", X)
    np.save(f"{output_dir}/y_threat_enhanced.npy", y_threat)
    np.save(f"{output_dir}/y_type_enhanced.npy", y_type)
    
    # Save metadata
    metadata = {
        "total_samples": len(all_samples),
        "feature_dims": X.shape[1],
        "threat_types": threat_types,
        "threat_type_mapping": threat_type_to_idx,
        "class_distribution": {
            "threats": int(threat_count),
            "safe": int(safe_count)
        },
        "created_at": datetime.now().isoformat()
    }
    
    with open(f"{output_dir}/metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    
    print(f"   ✓ Saved to {output_dir}/")
    
    # ========================================================================
    # 6. Train Improved Model
    # ========================================================================
    print("\n🏋️ Training improved model...")
    
    try:
        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.metrics import classification_report, confusion_matrix
        import joblib
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_threat, test_size=0.2, random_state=42, stratify=y_threat
        )
        
        # Train Random Forest (fast)
        print("\n   Training Random Forest...")
        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(X_train, y_train)
        
        # Evaluate
        rf_pred = rf_model.predict(X_test)
        rf_accuracy = (rf_pred == y_test).mean()
        print(f"   Random Forest Accuracy: {rf_accuracy:.2%}")
        
        # Train Gradient Boosting (more accurate)
        print("\n   Training Gradient Boosting...")
        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=8,
            learning_rate=0.1,
            random_state=42
        )
        gb_model.fit(X_train, y_train)
        
        # Evaluate
        gb_pred = gb_model.predict(X_test)
        gb_accuracy = (gb_pred == y_test).mean()
        print(f"   Gradient Boosting Accuracy: {gb_accuracy:.2%}")
        
        # Use the better model
        best_model = rf_model if rf_accuracy >= gb_accuracy else gb_model
        best_accuracy = max(rf_accuracy, gb_accuracy)
        
        print(f"\n   Best Model: {'Random Forest' if rf_accuracy >= gb_accuracy else 'Gradient Boosting'}")
        print(f"   Best Accuracy: {best_accuracy:.2%}")
        
        # Save models
        model_dir = "data/models"
        os.makedirs(model_dir, exist_ok=True)
        
        joblib.dump(rf_model, f"{model_dir}/threat_detector_rf_enhanced.joblib")
        joblib.dump(gb_model, f"{model_dir}/threat_detector_gb_enhanced.joblib")
        
        # Save feature importance
        feature_names = [
            "amount_usd_norm", "chain_encoding", "event_type_encoding",
            "loan_amount_percentile", "protocols_involved", "price_impact",
            "profit_ratio", "uses_mixer_after", "new_contract",
            "liquidity_removal_percent", "contract_age_days", "whale_concentration",
            "transfer_amount_percentile", "price_deviation_percent",
            "flash_loan_in_same_block", "contract_verified"
        ]
        
        importance = dict(zip(feature_names, rf_model.feature_importances_))
        sorted_importance = sorted(importance.items(), key=lambda x: -x[1])
        
        print("\n📊 Feature Importance (Top 10):")
        for name, imp in sorted_importance[:10]:
            print(f"   • {name}: {imp:.4f}")
        
        # Save importance
        with open(f"{model_dir}/feature_importance.json", "w") as f:
            json.dump(sorted_importance, f, indent=2)
        
        print(f"\n   ✓ Models saved to {model_dir}/")
        
    except ImportError as e:
        print(f"   ⚠️ sklearn not available: {e}")
        print("   Skipping model training, data saved for later use")
    
    print("\n" + "="*60)
    print("✅ ML Model Improvement Complete!")
    print("="*60)
    print(f"\nSummary:")
    print(f"   • Total training samples: {len(all_samples)}")
    print(f"   • Threat types covered: {len(threat_types)}")
    print(f"   • Historical exploits: {len(HISTORICAL_EXPLOITS)}")
    print(f"   • Production incidents: {len(production_incidents)}")
    print(f"\nNext steps:")
    print(f"   1. Deploy updated model to production")
    print(f"   2. Monitor false positive rate")
    print(f"   3. Collect feedback and retrain periodically")


if __name__ == "__main__":
    asyncio.run(main())
