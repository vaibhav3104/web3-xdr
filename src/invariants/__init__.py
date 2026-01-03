"""
Invariant Detection Engine.

Detects violations of economic and security invariants:
- Lock/Mint parity (minted <= locked)
- Temporal sequences (lock before mint)
- Velocity thresholds (TVL drain rate)
- Governance rules (timelock, signatures)
"""

from .base import Invariant, InvariantContext, InvariantRegistry
from .economic import MintLockParityInvariant, UnbackedMintInvariant
from .temporal import SequenceInvariant, TimelockInvariant
from .velocity import TVLVelocityInvariant, TransactionVelocityInvariant
from .threshold import SignatureThresholdInvariant, AdminActionInvariant
from .engine import InvariantEngine

__all__ = [
    "Invariant",
    "InvariantContext",
    "InvariantRegistry",
    "InvariantEngine",
    "MintLockParityInvariant",
    "UnbackedMintInvariant",
    "SequenceInvariant",
    "TimelockInvariant",
    "TVLVelocityInvariant",
    "TransactionVelocityInvariant",
    "SignatureThresholdInvariant",
    "AdminActionInvariant",
]

