"""
AI-Powered Incident Analysis for Web3 XDR.

Uses LLMs (OpenAI/Claude/Local) to explain security incidents
in human-readable language with actionable recommendations.
"""

from .analyzer import AIAnalyzer, analyze_incident
from .prompts import INCIDENT_ANALYSIS_PROMPT, ATTACK_PATTERNS

__all__ = [
    "AIAnalyzer",
    "analyze_incident",
    "INCIDENT_ANALYSIS_PROMPT",
    "ATTACK_PATTERNS"
]

