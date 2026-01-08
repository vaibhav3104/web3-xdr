"""
Predicted Incident Models - Simulation-based pre-incidents
==========================================================

Runtime Security Plane: Models for incidents predicted via simulation
before they are confirmed on-chain.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class PredictedIncidentStatus(Enum):
    """Status of a predicted incident."""
    OPEN = "OPEN"  # Predicted, awaiting confirmation
    DISMISSED = "DISMISSED"  # Operator dismissed as false positive
    CONFIRMED_MATCH = "CONFIRMED_MATCH"  # Later matched a confirmed incident
    CONFIRMED_MISMATCH = "CONFIRMED_MISMATCH"  # Prediction did not materialize


class SimulationMode(Enum):
    """Simulation execution mode."""
    FAST = "FAST"  # Quick simulation, limited tracing
    FULL = "FULL"  # Full simulation with complete state diff
    BUNDLE = "BUNDLE"  # Simulate transaction bundle


class SimulationStatus(Enum):
    """Status of a simulation run."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


@dataclass
class StateDiffFingerprint:
    """
    Compact, stable fingerprint of state changes from simulation.
    """
    # Token balance deltas for protected addresses
    token_balance_deltas: Dict[str, Dict[str, Decimal]] = field(default_factory=dict)
    # Format: {address: {token_address: delta}}
    
    # Total supply deltas for watched tokens
    total_supply_deltas: Dict[str, Decimal] = field(default_factory=dict)
    # Format: {token_address: delta}
    
    # Reserve deltas for watched pools/vaults
    reserve_deltas: Dict[str, Dict[str, Decimal]] = field(default_factory=dict)
    # Format: {pool_address: {token: delta}}
    
    # Admin/proxy slot changes (if detectable)
    admin_changes: List[Dict[str, str]] = field(default_factory=list)
    # Format: [{"contract": address, "slot": slot, "old": old_value, "new": new_value}]
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "token_balance_deltas": {
                addr: {token: str(delta) for token, delta in tokens.items()}
                for addr, tokens in self.token_balance_deltas.items()
            },
            "total_supply_deltas": {
                token: str(delta) for token, delta in self.total_supply_deltas.items()
            },
            "reserve_deltas": {
                pool: {token: str(delta) for token, delta in tokens.items()}
                for pool, tokens in self.reserve_deltas.items()
            },
            "admin_changes": self.admin_changes,
        }


@dataclass
class ConfidenceReasons:
    """
    Structured reasons for confidence score.
    """
    calibration_score: float = 0.0  # Simulator fidelity (0-1)
    bundle_context: bool = False  # Simulated in bundle vs alone
    correlation_strength: float = 0.0  # Presence of strong correlation keys
    violation_margin: float = 0.0  # How far beyond tolerance
    oracle_deviation: bool = False  # Oracle deviation detected
    anomaly_score: float = 0.0  # Anomaly detection score
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "calibration_score": self.calibration_score,
            "bundle_context": self.bundle_context,
            "correlation_strength": self.correlation_strength,
            "violation_margin": self.violation_margin,
            "oracle_deviation": self.oracle_deviation,
            "anomaly_score": self.anomaly_score,
        }


@dataclass
class SimulationRun:
    """
    Audit record of a simulation execution.
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    
    # Block reference
    block_number: int = 0
    block_hash: str = ""
    
    # Transaction reference
    tx_hash: str = ""
    tx_from: Optional[str] = None
    tx_to: Optional[str] = None
    tx_selector: Optional[str] = None  # Function selector (first 4 bytes)
    
    # Simulation details
    mode: SimulationMode = SimulationMode.FAST
    status: SimulationStatus = SimulationStatus.SUCCESS
    
    # Timing
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: int = 0
    
    # Resource usage
    rpc_calls: int = 0
    
    # Results
    state_diff_fingerprint: Optional[StateDiffFingerprint] = None
    invariant_results: List[Dict[str, Any]] = field(default_factory=list)
    
    # Confidence
    confidence: float = 0.0
    confidence_reasons: Optional[ConfidenceReasons] = None
    
    # Assumptions
    assumptions: Dict[str, Any] = field(default_factory=dict)
    # e.g., {"simulated_alone": True, "missing_context": ["pending_txs"]}
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "tx_hash": self.tx_hash,
            "tx_from": self.tx_from,
            "tx_to": self.tx_to,
            "tx_selector": self.tx_selector,
            "mode": self.mode.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "duration_ms": self.duration_ms,
            "rpc_calls": self.rpc_calls,
            "state_diff_fingerprint": self.state_diff_fingerprint.to_dict() if self.state_diff_fingerprint else None,
            "invariant_results": self.invariant_results,
            "confidence": self.confidence,
            "confidence_reasons": self.confidence_reasons.to_dict() if self.confidence_reasons else None,
            "assumptions": self.assumptions,
        }


@dataclass
class PredictedIncident:
    """
    A predicted incident based on simulation results.
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    tx_hash: str = ""
    
    # Classification
    protocol_id: Optional[str] = None
    predicted_type: str = ""  # e.g., "MINT_WITHOUT_LOCK", "REENTRANCY"
    severity: str = "MEDIUM"  # Severity level
    
    # Confidence & status
    confidence: float = 0.0
    status: PredictedIncidentStatus = PredictedIncidentStatus.OPEN
    
    # Deduplication
    dedupe_key: str = ""  # Composite key for deduplication
    
    # Explanation
    explanation_json: Dict[str, Any] = field(default_factory=dict)
    # Must include: summary, timeline, technical_context, evidence, recommended_action
    
    # Evidence
    evidence_json: Dict[str, Any] = field(default_factory=dict)
    # State diff fingerprint, invariant violations, etc.
    
    # Linked simulation
    linked_simulation_run_id: Optional[str] = None
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Linked confirmed incident (if matched)
    confirmed_incident_id: Optional[str] = None
    matched_at: Optional[datetime] = None
    
    # Financial impact (Phase 9)
    potential_loss_usd: Optional[Decimal] = None
    potential_loss_token_symbol: Optional[str] = None
    financial_impact_json: Dict[str, Any] = field(default_factory=dict)
    # Format: {"loss_usd": str, "loss_by_token": {...}, "primary_token": str}
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "chain_id": self.chain_id,
            "tx_hash": self.tx_hash,
            "protocol_id": self.protocol_id,
            "predicted_type": self.predicted_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status.value,
            "dedupe_key": self.dedupe_key,
            "explanation_json": self.explanation_json,
            "evidence_json": self.evidence_json,
            "linked_simulation_run_id": self.linked_simulation_run_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "confirmed_incident_id": self.confirmed_incident_id,
            "matched_at": self.matched_at.isoformat() if self.matched_at else None,
            "potential_loss_usd": str(self.potential_loss_usd) if self.potential_loss_usd else None,
            "potential_loss_token_symbol": self.potential_loss_token_symbol,
            "financial_impact_json": self.financial_impact_json,
        }

