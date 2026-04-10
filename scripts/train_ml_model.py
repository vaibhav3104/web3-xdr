#!/usr/bin/env python3
"""
ML Model Training Script
========================

Trains the threat detection model using:
1. Historical exploits (confirmed attacks)
2. Real incidents from database
3. YAML rule matches
4. Normal transaction samples

Usage:
    python scripts/train_ml_model.py --epochs 100 --output data/models/threat_detector.pt
"""

import os
import sys
import asyncio
import argparse
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog

logger = structlog.get_logger(__name__)

# Import ML components
from src.ml.yaml_converter import YAMLToMLConverter
from src.ml.feature_extractor import FeatureExtractor
from src.ml.threat_detector import ThreatTypes
from src.ml.training_pipeline import TrainingPipeline, TrainingDataset


# Historical exploits with detailed information
HISTORICAL_EXPLOITS = [
    {
        "name": "Ronin Bridge Hack",
        "date": "2022-03-23",
        "chain": "ethereum",
        "amount_usd": 625_000_000,
        "threat_type": ThreatTypes.ADMIN_KEY_COMPROMISE,
        "attacker": "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
        "target": "0x8407dc57739bcda7aa53ca6f12f82f9d51c2f21e",
        "description": "Compromised 5 of 9 validator keys to authorize withdrawals",
        "features": {
            "event_type_transfer": 1.0,
            "chain_ethereum": 1.0,
            "amount_usd_gt_10m": 1.0,
            "from_graph_risk_score": 0.0,  # New attacker address
            "to_is_exchange": 0.0,
        }
    },
    {
        "name": "Wormhole Bridge Hack",
        "date": "2022-02-02",
        "chain": "ethereum",
        "amount_usd": 320_000_000,
        "threat_type": ThreatTypes.BRIDGE_EXPLOIT,
        "attacker": "0x0864b86886f9c79c4b7c0b7e5c5f9a6c0c8c8e8e",
        "target": "0x3ee18b2214aff97000d974cf647e7c347e8fa585",
        "description": "Exploited signature verification bypass to mint wrapped ETH",
        "features": {
            "event_type_transfer": 1.0,
            "chain_ethereum": 1.0,
            "amount_usd_gt_10m": 1.0,
            "from_is_zero": 1.0,  # Minting from zero address
        }
    },
    {
        "name": "Euler Finance Hack",
        "date": "2023-03-13",
        "chain": "ethereum",
        "amount_usd": 197_000_000,
        "threat_type": ThreatTypes.FLASH_LOAN_ATTACK,
        "attacker": "0xb4d24dacbdffa1bbf9a624044484b3feeb7fdf74",
        "target": "0x27182842e098f60e3d576794a5bffb0777e025d3",
        "description": "Flash loan attack exploiting donation mechanism",
        "features": {
            "event_type_flashloan": 1.0,
            "chain_ethereum": 1.0,
            "amount_usd_gt_10m": 1.0,
        }
    },
    {
        "name": "Beanstalk Governance Attack",
        "date": "2022-04-17",
        "chain": "ethereum",
        "amount_usd": 182_000_000,
        "threat_type": ThreatTypes.GOVERNANCE_ATTACK,
        "attacker": "0x1c5dcdd006ea78a7e4783f9e6021c32935a10fb4",
        "target": "0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5",
        "description": "Flash loan to acquire governance tokens and pass malicious proposal",
        "features": {
            "event_type_flashloan": 1.0,
            "chain_ethereum": 1.0,
            "amount_usd_gt_10m": 1.0,
        }
    },
    {
        "name": "Cream Finance Reentrancy",
        "date": "2021-10-27",
        "chain": "ethereum",
        "amount_usd": 130_000_000,
        "threat_type": ThreatTypes.REENTRANCY,
        "attacker": "0x24354d31bc9d90f62fe5f2454709c32049cf866b",
        "target": "0xd06527d5e56a3495252a528c4987003b712860ee",
        "description": "Reentrancy attack via flash loan",
        "features": {
            "event_type_flashloan": 1.0,
            "chain_ethereum": 1.0,
            "amount_usd_gt_10m": 1.0,
        }
    },
    {
        "name": "Mango Markets Oracle Manipulation",
        "date": "2022-10-11",
        "chain": "solana",
        "amount_usd": 114_000_000,
        "threat_type": ThreatTypes.ORACLE_MANIPULATION,
        "attacker": "0x5d4b6a5c8b6c9d0e1f2a3b4c5d6e7f8a9b0c1d2e",
        "target": "0x1234567890abcdef1234567890abcdef12345678",
        "description": "Manipulated MNGO token price to borrow against inflated collateral",
        "features": {
            "event_type_swap": 1.0,
            "amount_usd_gt_10m": 1.0,
        }
    },
    {
        "name": "Nomad Bridge Hack",
        "date": "2022-08-01",
        "chain": "ethereum",
        "amount_usd": 190_000_000,
        "threat_type": ThreatTypes.BRIDGE_EXPLOIT,
        "attacker": "multiple",
        "target": "0x88a69b4e698a4b090df6cf5bd7b2d47325ad30a3",
        "description": "Initialization bug allowed anyone to drain funds",
        "features": {
            "event_type_transfer": 1.0,
            "chain_ethereum": 1.0,
            "amount_usd_gt_1m": 1.0,
        }
    },
    {
        "name": "Wintermute Hack",
        "date": "2022-09-20",
        "chain": "ethereum",
        "amount_usd": 160_000_000,
        "threat_type": ThreatTypes.ADMIN_KEY_COMPROMISE,
        "attacker": "0xe74b28c2eae8679e3ccc3a94d5d0de83ccb84705",
        "target": "0x00000000ae347930bd1e7b0f35588b92280f9e75",
        "description": "Vanity address private key compromise",
        "features": {
            "event_type_transfer": 1.0,
            "chain_ethereum": 1.0,
            "amount_usd_gt_10m": 1.0,
        }
    },
    {
        "name": "BonqDAO Oracle Manipulation",
        "date": "2023-02-01",
        "chain": "polygon",
        "amount_usd": 120_000_000,
        "threat_type": ThreatTypes.ORACLE_MANIPULATION,
        "attacker": "0x1234567890abcdef1234567890abcdef12345679",
        "target": "0x1234567890abcdef1234567890abcdef12345680",
        "description": "Manipulated Tellor oracle to mint unlimited stablecoins",
        "features": {
            "event_type_transfer": 1.0,
            "chain_polygon": 1.0,
            "amount_usd_gt_10m": 1.0,
        }
    },
    {
        "name": "Typical Rug Pull",
        "date": "2023-01-15",
        "chain": "ethereum",
        "amount_usd": 5_000_000,
        "threat_type": ThreatTypes.RUG_PULL,
        "attacker": "0xabcdef1234567890abcdef1234567890abcdef12",
        "target": "0x1234567890abcdef1234567890abcdef12345681",
        "description": "Developer removed liquidity and transferred to mixer",
        "features": {
            "event_type_transfer": 1.0,
            "chain_ethereum": 1.0,
            "amount_usd_gt_1m": 1.0,
            "to_is_mixer": 1.0,
            "from_graph_tx_count_log": 1.0,  # New contract
        }
    },
    {
        "name": "MEV Sandwich Attack",
        "date": "2023-06-01",
        "chain": "ethereum",
        "amount_usd": 50_000,
        "threat_type": ThreatTypes.SANDWICH_ATTACK,
        "attacker": "0xae2fc483527b8ef99eb5d9b44875f005ba1fae13",
        "target": "victim_swap",
        "description": "Front-run and back-run a large swap to extract MEV",
        "features": {
            "event_type_swap": 1.0,
            "chain_ethereum": 1.0,
            "amount_usd_gt_10k": 1.0,
        }
    },
]


async def load_incidents_from_db(db_url: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load real incidents from database."""
    if not db_url:
        db_url = os.getenv("DATABASE_URL")
    
    if not db_url:
        logger.warning("no_database_url", message="Skipping database incidents")
        return []
    
    try:
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy import text
        
        # Convert postgres:// to postgresql+asyncpg://
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        
        engine = create_async_engine(db_url)
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            # Query incidents with their events
            result = await session.execute(text("""
                SELECT 
                    i.id,
                    i.attack_type,
                    i.severity,
                    i.status,
                    i.total_loss_usd,
                    i.affected_contracts,
                    i.affected_addresses,
                    i.explanation_json,
                    i.created_at
                FROM incidents i
                WHERE i.status IN ('resolved', 'acknowledged', 'triggered', 'OPEN_PENDING')
                ORDER BY i.created_at DESC
                LIMIT 500
            """))
            
            incidents = result.fetchall()
            logger.info("loaded_incidents_from_db", count=len(incidents))
            
            return [
                {
                    "id": str(row[0]),
                    "threat_category": row[1],  # attack_type column
                    "severity": row[2],
                    "status": row[3],
                    "total_loss_usd": float(row[4]) if row[4] else 0,
                    "affected_contracts": row[5] or [],
                    "affected_addresses": row[6] or [],
                    "raw_data": row[7] or {},  # explanation_json column
                    "created_at": row[8]
                }
                for row in incidents
            ]
            
    except Exception as e:
        logger.error("database_load_failed", error=str(e))
        return []


def map_threat_category_to_type(category: str) -> str:
    """Map incident threat category to ThreatTypes."""
    mapping = {
        "flash_loan_attack": ThreatTypes.FLASH_LOAN_ATTACK,
        "reentrancy": ThreatTypes.REENTRANCY,
        "reentrancy_exploit": ThreatTypes.REENTRANCY,
        "oracle_manipulation": ThreatTypes.ORACLE_MANIPULATION,
        "rug_pull": ThreatTypes.RUG_PULL,
        "sandwich_attack": ThreatTypes.SANDWICH_ATTACK,
        "front_running": ThreatTypes.FRONT_RUNNING,
        "governance_attack": ThreatTypes.GOVERNANCE_ATTACK,
        "bridge_exploit": ThreatTypes.BRIDGE_EXPLOIT,
        "admin_key_compromise": ThreatTypes.ADMIN_KEY_COMPROMISE,
        "liquidity_drain": ThreatTypes.LIQUIDITY_DRAIN,
        "price_manipulation": ThreatTypes.PRICE_MANIPULATION,
        "suspicious_transfer": ThreatTypes.SUSPICIOUS_TRANSFER,
        "malicious_contract": ThreatTypes.UNKNOWN_THREAT,
        "rule_triggered": ThreatTypes.UNKNOWN_THREAT,
    }
    
    category_lower = category.lower().replace(" ", "_") if category else ""
    return mapping.get(category_lower, ThreatTypes.UNKNOWN_THREAT)


async def prepare_training_data(
    include_historical: bool = True,
    include_db_incidents: bool = True,
    db_url: Optional[str] = None
) -> TrainingDataset:
    """Prepare comprehensive training dataset."""
    
    dataset = TrainingDataset()
    feature_extractor = FeatureExtractor()
    
    print("\n📊 Preparing Training Data...")
    
    # 1. Historical exploits
    if include_historical:
        print(f"\n   Loading {len(HISTORICAL_EXPLOITS)} historical exploits...")
        
        for exploit in HISTORICAL_EXPLOITS:
            # Create base features
            features = feature_extractor._create_default_features() if hasattr(feature_extractor, '_create_default_features') else {}
            
            # Add exploit-specific features
            features.update(exploit.get("features", {}))
            features["amount_usd"] = exploit["amount_usd"]
            features["amount_usd_log"] = __import__("math").log1p(exploit["amount_usd"])
            
            # Add sample
            dataset.add_sample(
                features=features,
                label=exploit["threat_type"],
                confidence=1.0,  # High confidence - confirmed exploit
                metadata={
                    "source": "historical_exploit",
                    "name": exploit["name"],
                    "date": exploit["date"]
                }
            )
            
            # Add augmented variations
            import numpy as np
            for i in range(10):  # 10 variations per exploit
                varied_features = features.copy()
                # Add noise to numeric features
                for key in ["amount_usd", "amount_usd_log"]:
                    if key in varied_features:
                        varied_features[key] *= (0.5 + np.random.random())
                
                dataset.add_sample(
                    features=varied_features,
                    label=exploit["threat_type"],
                    confidence=0.9,
                    metadata={"source": "historical_augmented", "name": exploit["name"]}
                )
        
        print(f"   ✓ Added {len(HISTORICAL_EXPLOITS) * 11} samples from historical exploits")
    
    # 2. Database incidents
    if include_db_incidents:
        print("\n   Loading incidents from database...")
        incidents = await load_incidents_from_db(db_url)
        
        if incidents:
            for incident in incidents:
                threat_type = map_threat_category_to_type(incident.get("threat_category", ""))
                
                # Create features from incident
                features = {}
                raw_data = incident.get("raw_data", {})
                
                # Extract features from raw_data
                features["amount_usd"] = incident.get("total_loss_usd", 0) or raw_data.get("amount_usd", 0)
                features["amount_usd_log"] = __import__("math").log1p(features["amount_usd"])
                
                # Severity mapping
                severity = incident.get("severity", "low")
                severity_map = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.8, "critical": 1.0}
                features["severity_score"] = severity_map.get(severity.lower() if severity else "low", 0.3)
                
                # Determine confidence based on status
                status = incident.get("status", "")
                confidence = 0.9 if status in ["resolved", "acknowledged"] else 0.7
                
                dataset.add_sample(
                    features=features,
                    label=threat_type,
                    confidence=confidence,
                    metadata={
                        "source": "database_incident",
                        "id": incident.get("id"),
                        "status": status
                    }
                )
            
            print(f"   ✓ Added {len(incidents)} samples from database")
        else:
            print("   ⏭ No database incidents found")
    
    # 3. Safe transaction samples
    print("\n   Generating safe transaction samples...")
    safe_patterns = [
        {"amount_usd": 100, "event_type_transfer": 1.0, "to_is_exchange": 1.0},
        {"amount_usd": 1000, "event_type_swap": 1.0, "is_business_hours": 1.0},
        {"amount_usd": 5000, "event_type_deposit": 1.0},
        {"amount_usd": 2000, "event_type_withdraw": 1.0},
        {"amount_usd": 500, "event_type_approval": 1.0},
        {"amount_usd": 10000, "event_type_transfer": 1.0, "from_is_exchange": 1.0},
    ]
    
    import numpy as np
    for pattern in safe_patterns:
        for _ in range(100):  # 100 variations per pattern
            features = pattern.copy()
            features["amount_usd"] = pattern["amount_usd"] * (0.1 + np.random.random() * 2)
            features["amount_usd_log"] = __import__("math").log1p(features["amount_usd"])
            
            dataset.add_sample(
                features=features,
                label=ThreatTypes.SAFE,
                confidence=0.8,
                metadata={"source": "synthetic_safe"}
            )
    
    print(f"   ✓ Added {len(safe_patterns) * 100} safe transaction samples")
    
    # Summary
    print(f"\n📈 Training Data Summary:")
    print(f"   Total samples: {len(dataset)}")
    
    # Class distribution
    class_counts = {}
    for label_idx in dataset.labels:
        label = ThreatTypes.ALL_TYPES[label_idx]
        class_counts[label] = class_counts.get(label, 0) + 1
    
    print(f"   Class distribution:")
    for label, count in sorted(class_counts.items(), key=lambda x: -x[1]):
        print(f"      • {label}: {count}")
    
    return dataset


async def train_model(
    epochs: int = 100,
    batch_size: int = 32,
    learning_rate: float = 0.001,
    output_path: str = "data/models/threat_detector.pt",
    include_historical: bool = True,
    include_db_incidents: bool = True,
    db_url: Optional[str] = None
):
    """Train the threat detection model."""
    
    print("\n" + "="*60)
    print("🧠 Sentinel3 ML Model Training")
    print("="*60)
    
    # Prepare data
    dataset = await prepare_training_data(
        include_historical=include_historical,
        include_db_incidents=include_db_incidents,
        db_url=db_url
    )
    
    if len(dataset) < 100:
        print("\n⚠️  Warning: Very small dataset. Consider adding more training data.")
    
    # Initialize training pipeline
    print("\n🔧 Initializing training pipeline...")
    pipeline = TrainingPipeline(output_dir=os.path.dirname(output_path))
    
    # Train
    print(f"\n🏋️ Training model for {epochs} epochs...")
    print(f"   Batch size: {batch_size}")
    print(f"   Learning rate: {learning_rate}")
    print(f"   Device: {pipeline.device}")
    
    results = pipeline.train(
        dataset=dataset,
        epochs=epochs,
        batch_size=batch_size,
        learning_rate=learning_rate,
        validation_split=0.2
    )
    
    # Save model
    print(f"\n💾 Saving model to {output_path}...")
    model_path = pipeline.save_model(os.path.basename(output_path))
    
    # Print results
    print("\n" + "="*60)
    print("✅ Training Complete!")
    print("="*60)
    
    metrics = results.get("final_metrics", {})
    print(f"\n📊 Final Metrics:")
    print(f"   Accuracy: {metrics.get('accuracy', 0):.4f}")
    print(f"   Best validation loss: {results.get('best_val_loss', 0):.4f}")
    
    print(f"\n📁 Model saved to: {model_path}")
    
    # Export for Vertex AI
    print("\n🌐 Exporting for Vertex AI...")
    export_dir = os.path.join(os.path.dirname(output_path), "vertex_export")
    pipeline.export_for_vertex_ai(export_dir)
    print(f"   Exported to: {export_dir}")
    
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Sentinel3 threat detection model")
    parser.add_argument("--epochs", type=int, default=100, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--learning-rate", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--output", default="data/models/threat_detector.pt", help="Output model path")
    parser.add_argument("--db-url", help="Database URL for loading incidents")
    parser.add_argument("--no-historical", action="store_true", help="Skip historical exploits")
    parser.add_argument("--no-db", action="store_true", help="Skip database incidents")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    
    asyncio.run(train_model(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        output_path=args.output,
        include_historical=not args.no_historical,
        include_db_incidents=not args.no_db,
        db_url=args.db_url
    ))
