"""
Explainability Module
=====================

Phase 4: Structured explanations for incidents.
"""

from .engine import (
    ExplainabilityEngine,
    Explanation,
    TimelineEntry,
    TechnicalContext,
    Evidence,
    RecommendedAction
)
from .templates import ExplanationTemplate

__all__ = [
    "ExplainabilityEngine",
    "Explanation",
    "TimelineEntry",
    "TechnicalContext",
    "Evidence",
    "RecommendedAction",
    "ExplanationTemplate",
]
