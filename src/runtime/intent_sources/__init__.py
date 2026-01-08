"""
Intent Sources - Abstraction for pending transaction feeds
==========================================================

Provides interfaces and implementations for ingesting transaction intents
that can be simulated before confirmation.

Implementations:
- PseudoIntentBlockSource: Treats new blocks as "near-real-time" intents
- BloxrouteMempoolSource: Real-time mempool feed via bloXroute Cloud-API
"""

