"""
Sentinel3 ML Module
===================

Machine Learning components for Web3 threat detection.
Replaces YAML rules with intelligent ML-based detection.

Components:
- YAMLToMLConverter: Extracts features from YAML rules
- FeatureExtractor: Converts events to ML features
- ThreatDetector: ML model for threat classification
- TrainingPipeline: End-to-end training workflow
"""

from .yaml_converter import YAMLToMLConverter
from .feature_extractor import FeatureExtractor
from .threat_detector import ThreatDetector
from .training_pipeline import TrainingPipeline

__all__ = [
    "YAMLToMLConverter",
    "FeatureExtractor", 
    "ThreatDetector",
    "TrainingPipeline"
]
