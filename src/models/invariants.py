"""
Invariant Models - Results from invariant checks.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from .events import Severity


class InvariantType(Enum):
    """Types of invariants we check."""
    ECONOMIC = "economic"
    TEMPORAL = "temporal"
    GOVERNANCE = "governance"
    VELOCITY = "velocity"
    THRESHOLD = "threshold"


@dataclass
class InvariantResult:
    """
    Result of an invariant evaluation.
    """
    
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Invariant info
    invariant_name: str = ""
    invariant_type: InvariantType = InvariantType.ECONOMIC
    
    # Result
    violated: bool = False
    severity: Severity = Severity.INFO
    confidence: float = 1.0  # 0.0 - 1.0
    
    # Violation details
    violation_amount: Decimal = Decimal("0")
    violation_amount_usd: float = 0.0
    
    # Scope
    chain_id: Optional[str] = None
    bridge_id: Optional[str] = None
    contract_address: Optional[str] = None
    
    # Evidence
    evidence: Dict[str, Any] = field(default_factory=dict)
    related_event_ids: List[str] = field(default_factory=list)
    
    # Description
    description: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "invariant_name": self.invariant_name,
            "invariant_type": self.invariant_type.value,
            "violated": self.violated,
            "severity": self.severity.name,
            "confidence": self.confidence,
            "violation_amount": str(self.violation_amount),
            "violation_amount_usd": self.violation_amount_usd,
            "chain_id": self.chain_id,
            "bridge_id": self.bridge_id,
            "evidence": self.evidence,
            "related_event_ids": self.related_event_ids,
            "description": self.description,
        }


@dataclass
class InvariantState:
    """
    Current state for tracking invariant over time.
    """
    
    invariant_name: str
    bridge_id: str
    
    # Accumulated values
    total_locked: Decimal = Decimal("0")
    total_minted: Decimal = Decimal("0")
    total_burned: Decimal = Decimal("0")
    total_unlocked: Decimal = Decimal("0")
    
    # Time-windowed values
    locked_in_window: Decimal = Decimal("0")
    minted_in_window: Decimal = Decimal("0")
    
    # Tracking
    last_lock_block: int = 0
    last_mint_block: int = 0
    last_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Per-chain breakdown
    chain_locks: Dict[str, Decimal] = field(default_factory=dict)
    chain_mints: Dict[str, Decimal] = field(default_factory=dict)
    
    def get_imbalance(self) -> Decimal:
        """Calculate current imbalance (should be 0 or negative)."""
        return self.total_minted - self.total_locked
    
    def is_balanced(self, tolerance: Decimal = Decimal("0")) -> bool:
        """Check if locked/minted are balanced within tolerance."""
        imbalance = self.get_imbalance()
        return imbalance <= tolerance


@dataclass
class TVLSnapshot:
    """
    Point-in-time TVL snapshot for a bridge.
    """
    
    bridge_id: str
    chain_id: str
    timestamp: datetime
    block_number: int
    tvl_usd: float
    
    # Breakdown by asset
    asset_balances: Dict[str, float] = field(default_factory=dict)


@dataclass
class VelocityMetrics:
    """
    Velocity metrics for detecting rapid changes.
    """
    
    bridge_id: str
    
    # TVL velocity
    tvl_change_1h: float = 0.0
    tvl_change_24h: float = 0.0
    tvl_change_percent_1h: float = 0.0
    tvl_change_percent_24h: float = 0.0
    
    # Transaction velocity
    tx_count_1h: int = 0
    tx_count_24h: int = 0
    avg_tx_count_per_hour: float = 0.0
    
    # Large transaction detection
    large_tx_count_1h: int = 0
    large_tx_threshold_usd: float = 100000.0
    
    # Calculated thresholds
    is_abnormal_velocity: bool = False
    velocity_score: float = 0.0  # 0.0 (normal) to 1.0 (highly abnormal)

