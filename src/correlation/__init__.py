"""
XDR Correlation Engine.

Correlates events and violations into unified incidents:
- Entity graph for tracking relationships
- Attack pattern matching
- Cross-chain correlation
- Incident aggregation
"""

from .entity_graph import EntityGraph, EntityGraphBuilder
from .pattern_matcher import AttackPatternMatcher, PatternMatch
from .correlator import XDRCorrelator
from .incident_builder import IncidentBuilder

__all__ = [
    "EntityGraph",
    "EntityGraphBuilder",
    "AttackPatternMatcher",
    "PatternMatch",
    "XDRCorrelator",
    "IncidentBuilder",
]

