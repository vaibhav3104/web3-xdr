"""
Event Enrichment Layer
======================

Adds contextual information to raw blockchain events:
- Entity classification (exchanges, mixers, smart money)
- TVL tracking for drain detection
- Block-level analysis for MEV detection
- Price and value calculations
"""

from .entity_registry import EntityRegistry, EntityType, get_entity_registry
from .tvl_tracker import TVLTracker, get_tvl_tracker
from .mev_detector import MEVDetector, get_mev_detector
from .enricher import EventEnricher, get_enricher

__all__ = [
    "EntityRegistry",
    "EntityType", 
    "get_entity_registry",
    "TVLTracker",
    "get_tvl_tracker",
    "MEVDetector",
    "get_mev_detector",
    "EventEnricher",
    "get_enricher",
]
