"""
Bridge Adapters Module
======================

Protocol-specific adapters for bridge event correlation and invariant checking.
"""

from .base import (
    BridgeAdapter,
    BridgeProtocol,
    BridgeEventSemantic,
    CorrelationKey,
    ExpectedAmounts
)
from .wormhole import WormholeAdapter
from .layerzero import LayerZeroAdapter
from .stargate import StargateAdapter

__all__ = [
    "BridgeAdapter",
    "BridgeProtocol",
    "BridgeEventSemantic",
    "CorrelationKey",
    "ExpectedAmounts",
    "WormholeAdapter",
    "LayerZeroAdapter",
    "StargateAdapter",
]

