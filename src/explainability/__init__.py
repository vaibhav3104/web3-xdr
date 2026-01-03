"""
Explainability Engine.

Converts raw detections into human-readable explanations:
- Deterministic template-based explanations
- What happened / Why it's dangerous / What to do
- Confidence scoring
- Evidence compilation
"""

from .engine import ExplainabilityEngine
from .templates import ExplanationTemplates
from .explanation import Explanation

__all__ = [
    "ExplainabilityEngine",
    "ExplanationTemplates",
    "Explanation",
]

