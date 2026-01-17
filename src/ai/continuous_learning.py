"""
Continuous Learning System for Sentinel3
Runs 24/7/365 - Auto-collects contracts and retrains models

Features:
- Continuous contract collection across all chains
- Automatic model retraining on schedule
- Multiple model support (MLP, CNN, Transformer, Ensemble)
- Incremental learning with new data
- Model versioning and rollback
"""

import os
import sys
import json
import asyncio
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)

@dataclass
class LearningConfig:
    """Configuration for continuous learning"""
    # Chains to monitor
    chains: List[str] = field(default_factory=lambda: [
        "ethereum", "arbitrum", "polygon", "bsc", "optimism", "base"
    ])
    
    # Retraining schedule
    retrain_interval_hours: int = 6  # Retrain every 6 hours
    min_new_samples: int = 50  # Minimum new samples before retraining
    
    # Model types to train
    model_types: List[str] = field(default_factory=lambda: [
        "mlp", "random_forest"
    ])
    
    # Training settings
    epochs: int = 50
    batch_size: int = 64
    learning_rate: float = 0.0005
    
    # Data settings
    max_training_samples: int = 10000  # Max samples to keep
    synthetic_augmentation: bool = True
    
    # Storage
    data_dir: str = "./data/continuous_learning"
    models_dir: str = "./data/models"
    
    # Alerting
    alert_on_threat: bool = True
    min_threat_confidence: float = 0.7


@dataclass
class LearningStats:
    """Statistics for continuous learning"""
    started_at: datetime = field(default_factory=datetime.utcnow)
    contracts_collected: int = 0
    contracts_analyzed: int = 0
    threats_detected: int = 0
    models_trained: int = 0
    last_retrain: Optional[datetime] = None
    next_retrain: Optional[datetime] = None
    
    # Per-chain stats
    by_chain: Dict[str, int] = field(default_factory=dict)
    
    # Per-model stats
    model_accuracies: Dict[str, float] = field(default_factory=dict)
    
    # Collected samples awaiting training
    pending_samples: int = 0


class ContinuousLearningSystem:
    """
    24/7/365 Continuous Learning System
    
    Workflow:
    1. Auto-collector monitors all chains for new contracts
    2. New contracts are analyzed and stored
    3. Periodically retrains all models with accumulated data
    4. Models are versioned for rollback capability
    """
    
    def __init__(self, config: Optional[LearningConfig] = None):
        self.config = config or LearningConfig()
        self.stats = LearningStats()
        self.running = False
        
        # Components
        self.collector = None
        self.training_lock = asyncio.Lock()
        
        # Callbacks
        self.threat_callbacks: List[Callable] = []
        self.training_callbacks: List[Callable] = []
        self.analysis_callbacks: List[Callable] = []  # Called for ALL analyzed contracts
        
        # Data storage
        self.collected_samples: List[Dict] = []
        self.training_data: List[Dict] = []
        
        # Ensure directories exist
        Path(self.config.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.config.models_dir).mkdir(parents=True, exist_ok=True)
        
        # Load existing data
        self._load_existing_data()
    
    def _load_existing_data(self):
        """Load previously collected data"""
        data_file = Path(self.config.data_dir) / "collected_contracts.json"
        
        if data_file.exists():
            try:
                with open(data_file, 'r') as f:
                    data = json.load(f)
                    self.collected_samples = data.get("samples", [])
                    self.training_data = data.get("training_data", [])
                    
                logger.info(
                    "loaded_existing_data",
                    collected=len(self.collected_samples),
                    training=len(self.training_data)
                )
            except Exception as e:
                logger.error("load_data_error", error=str(e))
        
        # Also load real bytecode training data
        real_data_file = Path("./data/bytecode/training_data_real.json")
        if real_data_file.exists():
            try:
                with open(real_data_file, 'r') as f:
                    real_data = json.load(f)
                    # Add to training data if not already present
                    existing_addresses = {d.get("address") for d in self.training_data}
                    for sample in real_data:
                        if sample.get("address") not in existing_addresses:
                            self.training_data.append(sample)
                
                logger.info("loaded_real_bytecode_data", count=len(real_data))
            except Exception as e:
                logger.error("load_real_data_error", error=str(e))
    
    def _save_data(self):
        """Save collected data to disk"""
        data_file = Path(self.config.data_dir) / "collected_contracts.json"
        
        try:
            with open(data_file, 'w') as f:
                json.dump({
                    "samples": self.collected_samples[-self.config.max_training_samples:],
                    "training_data": self.training_data[-self.config.max_training_samples:],
                    "stats": asdict(self.stats),
                    "updated_at": datetime.utcnow().isoformat()
                }, f, indent=2, default=str)
                
            logger.debug("data_saved", samples=len(self.collected_samples))
        except Exception as e:
            logger.error("save_data_error", error=str(e))
    
    async def start(self):
        """Start the continuous learning system"""
        logger.info(
            "continuous_learning_starting",
            chains=self.config.chains,
            retrain_interval_hours=self.config.retrain_interval_hours,
            model_types=self.config.model_types
        )
        
        self.running = True
        self.stats.started_at = datetime.utcnow()
        self.stats.next_retrain = datetime.utcnow() + timedelta(hours=self.config.retrain_interval_hours)
        
        # Start background tasks
        tasks = [
            asyncio.create_task(self._run_collector()),
            asyncio.create_task(self._run_training_scheduler()),
            asyncio.create_task(self._run_stats_reporter()),
            asyncio.create_task(self._run_data_saver()),
        ]
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   🚀 SENTINEL3 CONTINUOUS LEARNING SYSTEM STARTED                            ║
║                                                                              ║
║   📡 Monitoring Chains: {', '.join(self.config.chains):<44}║
║   🧠 Model Types: {', '.join(self.config.model_types):<50}║
║   ⏱️  Retrain Interval: Every {self.config.retrain_interval_hours} hours{' ' * 42}║
║   📊 Current Training Samples: {len(self.training_data):<38}║
║                                                                              ║
║   Press Ctrl+C to stop                                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("continuous_learning_cancelled")
        except KeyboardInterrupt:
            logger.info("continuous_learning_interrupted")
        finally:
            await self.stop()
    
    async def stop(self):
        """Stop the continuous learning system"""
        self.running = False
        
        # Stop collector
        if self.collector:
            await self.collector.stop()
        
        # Save final data
        self._save_data()
        
        logger.info(
            "continuous_learning_stopped",
            total_collected=self.stats.contracts_collected,
            total_threats=self.stats.threats_detected,
            models_trained=self.stats.models_trained
        )
    
    async def _run_collector(self):
        """Run the auto-collector continuously"""
        from .collectors.auto_collector import AutoContractCollector, ContractAnalysis
        
        async def on_analysis(analysis: ContractAnalysis):
            """Handle analyzed contract"""
            self.stats.contracts_analyzed += 1
            
            # Store for training
            sample = {
                "address": analysis.contract.address,
                "chain": analysis.contract.chain,
                "deployer": analysis.contract.deployer,
                "label": analysis.threat_category,
                "features": list(analysis.features.values()) if analysis.features else [],
                "risk_score": analysis.risk_score,
                "confidence": analysis.confidence,
                "collected_at": datetime.utcnow().isoformat(),
                "is_threat": analysis.is_threat,
            }
            
            self.collected_samples.append(sample)
            
            # Add to training data if analyzed
            if analysis.features:
                feature_vector = self._features_to_vector(analysis.features)
                self.training_data.append({
                    "address": analysis.contract.address,
                    "chain": analysis.contract.chain,
                    "label": analysis.threat_category,
                    "features": feature_vector,
                    "source": "auto_collected"
                })
                self.stats.pending_samples += 1
            
            # Log
            status = "🔴 THREAT" if analysis.is_threat else "🟢 SAFE"
            print(f"{datetime.now().strftime('%H:%M:%S')} | {status} | {analysis.contract.chain:10} | {analysis.contract.address[:16]}... | {analysis.threat_category}")
            
            # Call registered analysis callbacks (for ALL contracts, not just threats)
            for callback in self.analysis_callbacks:
                try:
                    await callback(analysis)
                except Exception as e:
                    logger.error("analysis_callback_error", error=str(e))
        
        async def on_threat(analysis: ContractAnalysis):
            """Handle detected threat"""
            self.stats.threats_detected += 1
            
            # Alert
            if self.config.alert_on_threat and analysis.confidence >= self.config.min_threat_confidence:
                print(f"\n{'🚨' * 20}")
                print(f"   THREAT DETECTED!")
                print(f"   Contract: {analysis.contract.address}")
                print(f"   Chain: {analysis.contract.chain}")
                print(f"   Type: {analysis.threat_category}")
                print(f"   Risk: {analysis.risk_score:.2%}")
                print(f"   Confidence: {analysis.confidence:.2%}")
                print(f"{'🚨' * 20}\n")
                
                # Call registered callbacks
                for callback in self.threat_callbacks:
                    try:
                        await callback(analysis)
                    except Exception as e:
                        logger.error("threat_callback_error", error=str(e))
        
        # Create collector
        self.collector = AutoContractCollector(
            chains=self.config.chains,
            analysis_callback=on_analysis,
            threat_callback=on_threat,
            storage_path=os.path.join(self.config.data_dir, "contracts")
        )
        
        # Override stats tracking
        original_handler = self.collector._handle_deployment
        
        async def tracked_handler(*args, **kwargs):
            self.stats.contracts_collected += 1
            chain = args[0] if args else kwargs.get('chain', 'unknown')
            self.stats.by_chain[chain] = self.stats.by_chain.get(chain, 0) + 1
            return await original_handler(*args, **kwargs)
        
        self.collector._handle_deployment = tracked_handler
        
        # Run collector
        await self.collector.start()
    
    def _features_to_vector(self, features: Dict) -> List[float]:
        """Convert features dict to vector"""
        # Standard feature order
        feature_keys = [
            "bytecode_length_normalized", "call_count_normalized",
            "delegatecall_count_normalized", "staticcall_count",
            "selfdestruct_count", "sstore_count_normalized",
            "sload_count_normalized", "balance_count",
            "extcode_count", "jumps_count", "push_count",
            "has_flash_loan_callback", "has_reentrancy_pattern",
            "has_delegatecall_pattern", "has_selfdestruct",
            "has_mint_function", "has_admin_functions",
            "has_proxy_pattern", "unique_opcodes", "risk_score"
        ]
        
        vector = []
        for key in feature_keys:
            val = features.get(key, 0)
            if isinstance(val, bool):
                val = float(val)
            elif val is None:
                val = 0.0
            vector.append(float(val))
        
        # Pad to 20 features if needed
        while len(vector) < 20:
            vector.append(0.0)
        
        return vector[:20]
    
    async def _run_training_scheduler(self):
        """Periodically retrain models"""
        while self.running:
            try:
                # Wait until next training time
                now = datetime.utcnow()
                
                if self.stats.next_retrain and now >= self.stats.next_retrain:
                    # Check if we have enough new samples
                    if self.stats.pending_samples >= self.config.min_new_samples:
                        print(f"\n{'=' * 60}")
                        print(f"📚 SCHEDULED RETRAINING - {now.strftime('%Y-%m-%d %H:%M:%S')}")
                        print(f"   New samples: {self.stats.pending_samples}")
                        print(f"   Total training data: {len(self.training_data)}")
                        print(f"{'=' * 60}\n")
                        
                        await self._retrain_all_models()
                        self.stats.pending_samples = 0
                    else:
                        logger.info(
                            "skipping_retrain",
                            pending=self.stats.pending_samples,
                            min_required=self.config.min_new_samples
                        )
                    
                    # Schedule next training
                    self.stats.next_retrain = now + timedelta(hours=self.config.retrain_interval_hours)
                
                # Sleep for 1 minute before checking again
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error("training_scheduler_error", error=str(e))
                await asyncio.sleep(60)
    
    async def _retrain_all_models(self):
        """Retrain all configured models"""
        async with self.training_lock:
            for model_type in self.config.model_types:
                try:
                    print(f"\n🔧 Training {model_type.upper()} model...")
                    
                    accuracy = await self._train_model(model_type)
                    
                    if accuracy:
                        self.stats.model_accuracies[model_type] = accuracy
                        self.stats.models_trained += 1
                        print(f"   ✅ {model_type.upper()}: {accuracy:.2f}% accuracy")
                    
                except Exception as e:
                    logger.error("model_training_error", model=model_type, error=str(e))
                    print(f"   ❌ {model_type.upper()}: Failed - {str(e)}")
            
            self.stats.last_retrain = datetime.utcnow()
            
            # Call training callbacks
            for callback in self.training_callbacks:
                try:
                    await callback(self.stats)
                except Exception as e:
                    logger.error("training_callback_error", error=str(e))
    
    async def _train_model(self, model_type: str) -> Optional[float]:
        """Train a specific model type"""
        
        # Prepare training data with augmentation
        training_data = self._prepare_training_data()
        
        if len(training_data) < 100:
            logger.warning("insufficient_training_data", count=len(training_data))
            return None
        
        if model_type == "random_forest":
            return await self._train_random_forest(training_data)
        elif model_type == "mlp":
            return await self._train_deep_model(training_data, "mlp")
        elif model_type == "cnn":
            return await self._train_deep_model(training_data, "cnn")
        elif model_type == "transformer":
            return await self._train_deep_model(training_data, "transformer")
        else:
            logger.warning("unknown_model_type", model_type=model_type)
            return None
    
    def _prepare_training_data(self) -> List[Dict]:
        """Prepare and augment training data"""
        import random
        
        data = list(self.training_data)
        
        if not self.config.synthetic_augmentation:
            return data
        
        # Count current labels
        labels = {}
        for d in data:
            label = d.get("label", "unknown")
            labels[label] = labels.get(label, 0) + 1
        
        # Augment underrepresented classes
        target_count = max(labels.values()) if labels else 100
        
        exploit_patterns = {
            "flash_loan_exploit": [0.5, 0.4, 0.1, 0.1, 0.0, 0.3, 0.3, 0.1, 0.1, 0.2, 0.3, 1.0, 0.2, 0.1, 0.0, 0.1, 0.1, 0.0, 0.3, 0.75],
            "reentrancy_exploit": [0.4, 0.5, 0.2, 0.1, 0.0, 0.4, 0.3, 0.1, 0.1, 0.3, 0.2, 0.3, 1.0, 0.1, 0.0, 0.1, 0.1, 0.0, 0.3, 0.70],
            "governance_attack": [0.5, 0.3, 0.1, 0.1, 0.0, 0.2, 0.2, 0.0, 0.1, 0.2, 0.3, 1.0, 0.1, 0.1, 0.0, 0.1, 1.0, 0.0, 0.3, 0.65],
            "bridge_exploit": [0.3, 0.3, 0.2, 0.1, 0.0, 0.2, 0.2, 0.1, 0.1, 0.2, 0.2, 0.2, 0.1, 0.0, 1.0, 0.1, 0.1, 0.0, 0.3, 0.80],
            "oracle_manipulation": [0.4, 0.4, 0.1, 0.2, 0.0, 0.3, 0.4, 0.1, 0.2, 0.2, 0.3, 0.3, 0.1, 0.0, 0.0, 0.1, 0.1, 0.0, 0.3, 0.60],
            "rug_pull": [0.3, 0.2, 0.1, 0.0, 1.0, 0.2, 0.1, 0.0, 0.0, 0.1, 0.2, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.2, 0.85],
            "honeypot": [0.3, 0.3, 0.3, 0.1, 0.5, 0.2, 0.2, 0.0, 0.0, 0.2, 0.2, 0.0, 0.0, 0.0, 0.0, 1.0, 0.5, 0.5, 0.3, 0.80],
            "unknown_threat": [0.4, 0.3, 0.2, 0.1, 0.1, 0.3, 0.3, 0.1, 0.1, 0.2, 0.3, 0.2, 0.2, 0.0, 0.0, 0.2, 0.2, 0.1, 0.3, 0.55],
            "price_manipulation": [0.6, 0.5, 0.1, 0.2, 0.0, 0.3, 0.4, 0.1, 0.2, 0.3, 0.4, 0.4, 0.2, 0.0, 0.0, 0.1, 0.2, 0.0, 0.4, 0.70],
            "safe": [0.3, 0.1, 0.0, 0.1, 0.0, 0.2, 0.2, 0.0, 0.0, 0.1, 0.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.2, 0.15],
        }
        
        for label, pattern in exploit_patterns.items():
            current = labels.get(label, 0)
            needed = max(0, target_count - current)
            
            for _ in range(min(needed, 100)):  # Cap at 100 synthetic per class
                features = [f + random.uniform(-0.15, 0.15) for f in pattern]
                features = [max(0, min(1, f)) for f in features]
                
                data.append({
                    "address": f"0x{random.randbytes(20).hex()}",
                    "chain": random.choice(self.config.chains),
                    "label": label,
                    "features": features,
                    "source": "synthetic"
                })
        
        return data
    
    async def _train_random_forest(self, data: List[Dict]) -> Optional[float]:
        """Train RandomForest model"""
        try:
            from .training.pipeline import TrainingPipeline, TrainingConfig
            
            config = TrainingConfig(
                model_type="random_forest",
                n_estimators=100,
                output_dir=self.config.models_dir
            )
            
            pipeline = TrainingPipeline(config)
            pipeline.training_data = [
                {"features": d["features"], "label": d["label"], "source": d.get("source", "unknown")}
                for d in data if d.get("features")
            ]
            
            result = pipeline.train()
            pipeline.save_model(result)
            
            return result.accuracy * 100
            
        except Exception as e:
            logger.error("random_forest_training_error", error=str(e))
            return None
    
    async def _train_deep_model(self, data: List[Dict], model_type: str) -> Optional[float]:
        """Train deep learning model"""
        try:
            from .models.deep_classifier import DeepContractClassifier
            from sklearn.model_selection import train_test_split
            
            # Filter data with features
            valid_data = [d for d in data if d.get("features") and len(d["features"]) >= 20]
            
            if len(valid_data) < 100:
                return None
            
            # Split data
            labels = [d["label"] for d in valid_data]
            train_data, val_data = train_test_split(
                valid_data, test_size=0.2, stratify=labels, random_state=42
            )
            
            # Train
            classifier = DeepContractClassifier(
                model_type=model_type,
                model_path=f"{self.config.models_dir}/deep_{model_type}.pt"
            )
            
            history = classifier.train(
                train_data=train_data,
                val_data=val_data,
                epochs=self.config.epochs,
                batch_size=self.config.batch_size,
                learning_rate=self.config.learning_rate
            )
            
            return history["val_acc"][-1] if history.get("val_acc") else None
            
        except Exception as e:
            logger.error("deep_model_training_error", model=model_type, error=str(e))
            return None
    
    async def _run_stats_reporter(self):
        """Periodically report stats"""
        while self.running:
            await asyncio.sleep(300)  # Every 5 minutes
            
            uptime = datetime.utcnow() - self.stats.started_at
            
            print(f"\n{'─' * 60}")
            print(f"📊 STATS | Uptime: {uptime} | {datetime.now().strftime('%H:%M:%S')}")
            print(f"   Collected: {self.stats.contracts_collected} | Analyzed: {self.stats.contracts_analyzed} | Threats: {self.stats.threats_detected}")
            print(f"   Pending samples: {self.stats.pending_samples} | Next retrain: {self.stats.next_retrain.strftime('%H:%M:%S') if self.stats.next_retrain else 'N/A'}")
            if self.stats.model_accuracies:
                acc_str = " | ".join(f"{k}: {v:.1f}%" for k, v in self.stats.model_accuracies.items())
                print(f"   Model Accuracies: {acc_str}")
            print(f"{'─' * 60}\n")
    
    async def _run_data_saver(self):
        """Periodically save data to disk"""
        while self.running:
            await asyncio.sleep(60)  # Every minute
            self._save_data()
    
    def add_threat_callback(self, callback: Callable):
        """Add a callback for threat detection"""
        self.threat_callbacks.append(callback)
    
    def add_analysis_callback(self, callback: Callable):
        """Add a callback for ALL analyzed contracts (threats and safe)"""
        self.analysis_callbacks.append(callback)
    
    def add_training_callback(self, callback: Callable):
        """Add a callback for model training"""
        self.training_callbacks.append(callback)
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        return asdict(self.stats)
    
    async def force_retrain(self):
        """Force immediate model retraining"""
        print("\n🔄 Forcing immediate model retraining...")
        await self._retrain_all_models()


# Global instance
_learning_system: Optional[ContinuousLearningSystem] = None

def get_learning_system() -> Optional[ContinuousLearningSystem]:
    """Get the global learning system instance"""
    return _learning_system

async def start_continuous_learning(config: Optional[LearningConfig] = None):
    """Start the continuous learning system"""
    global _learning_system
    
    if _learning_system and _learning_system.running:
        logger.warning("learning_system_already_running")
        return _learning_system
    
    _learning_system = ContinuousLearningSystem(config)
    asyncio.create_task(_learning_system.start())
    
    return _learning_system

async def stop_continuous_learning():
    """Stop the continuous learning system"""
    global _learning_system
    
    if _learning_system:
        await _learning_system.stop()
        _learning_system = None


if __name__ == "__main__":
    # Run the continuous learning system
    config = LearningConfig(
        chains=["ethereum", "polygon", "arbitrum", "bsc"],
        model_types=["mlp", "random_forest"],
        retrain_interval_hours=6,
        min_new_samples=50
    )
    
    async def main():
        system = ContinuousLearningSystem(config)
        await system.start()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down...")

