"""
LLM-Powered Analysis Module

Three integrated LLM components:
1. IncidentTriage - Auto TP/FP classification of alerts
2. RuleTuner - Suggests threshold and exclusion changes from FP patterns
3. BytecodeAnalyzer - Natural language contract analysis for novel exploit detection

Plus shared infrastructure:
- rate_limiter: RPM throttling and daily spend caps
- client: Shared Anthropic client singleton
"""

from .incident_triage import IncidentTriage, TriageVerdict
from .rule_tuner import RuleTuner, TuningRecommendation
from .bytecode_analyzer import BytecodeAnalyzer, ContractAnalysis
from .rate_limiter import LLMRateLimiter, get_rate_limiter, make_llm_call

__all__ = [
    "IncidentTriage",
    "TriageVerdict",
    "RuleTuner",
    "TuningRecommendation",
    "BytecodeAnalyzer",
    "ContractAnalysis",
    "LLMRateLimiter",
    "get_rate_limiter",
    "make_llm_call",
]
