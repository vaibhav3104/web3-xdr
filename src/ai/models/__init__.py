from .contract_classifier import (
    ContractThreatClassifier,
    ThreatCategory,
    ClassificationResult,
    ContractClassifierTrainer
)

# Deep learning models (optional - requires PyTorch)
try:
    from .deep_classifier import (
        DeepContractClassifier,
        DeepClassificationResult,
        HybridClassifier,
        BytecodeMLP,
        BytecodeCNN,
        BytecodeTransformer,
        EnsembleClassifier,
    )
    DEEP_LEARNING_AVAILABLE = True
except ImportError:
    DEEP_LEARNING_AVAILABLE = False
    DeepContractClassifier = None
    DeepClassificationResult = None
    HybridClassifier = None
    BytecodeMLP = None
    BytecodeCNN = None
    BytecodeTransformer = None
    EnsembleClassifier = None

__all__ = [
    'ContractThreatClassifier',
    'ThreatCategory',
    'ClassificationResult',
    'ContractClassifierTrainer',
    # Deep learning (optional)
    'DeepContractClassifier',
    'DeepClassificationResult',
    'HybridClassifier',
    'DEEP_LEARNING_AVAILABLE',
]
