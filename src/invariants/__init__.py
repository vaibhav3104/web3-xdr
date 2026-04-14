"""
Invariant Detection Engine.

Detects violations of economic and security invariants:
- Lock/Mint parity (minted <= locked)
- Temporal sequences (lock before mint)
- Velocity thresholds (TVL drain rate)
- Governance rules (timelock, signatures)
- MEV detection (sandwich, frontrunning, backrunning, JIT liquidity)
"""

from .base import Invariant, InvariantContext, InvariantRegistry
from .economic import MintLockParityInvariant, UnbackedMintInvariant
from .temporal import SequenceInvariant, TimelockInvariant
from .velocity import TVLVelocityInvariant, TransactionVelocityInvariant
from .threshold import SignatureThresholdInvariant, AdminActionInvariant
from .mev import (
    SandwichAttackDetector,
    FrontrunningDetector,
    BackrunningDetector,
    JITLiquidityDetector,
)
from .engine import InvariantEngine
from .dsl import DSLInvariant, DSLLoader, DSLInvariantDef, DSLCondition

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
    "SandwichAttackDetector",
    "FrontrunningDetector",
    "BackrunningDetector",
    "JITLiquidityDetector",
    "DSLInvariant",
    "DSLLoader",
    "DSLInvariantDef",
    "DSLCondition",
]
