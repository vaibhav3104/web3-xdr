"""
AI Module for Web3 XDR
Contract threat detection using ML and rule-based analysis
"""

from .models import ContractThreatClassifier, ThreatCategory, ClassificationResult
from .data import BytecodeExtractor, get_statistics
from .inference import SimulatedDeploymentMonitor, ThreatAlert

__all__ = [
    'ContractThreatClassifier',
    'ThreatCategory',
    'ClassificationResult',
    'BytecodeExtractor',
    'get_statistics',
    'SimulatedDeploymentMonitor',
    'ThreatAlert'
]
