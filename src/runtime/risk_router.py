"""
Risk Router - Efficient gating for simulation decisions
=======================================================

Decides when to run deep analysis (simulation) vs. cheap checks only.
Implements budgets to prevent system overload.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Set
import structlog
import os

from ..models.predicted_incidents import SimulationMode
from ..runtime.intent_sources.base import PendingTx

logger = structlog.get_logger(__name__)


class RouterDecision(Enum):
    """Decision on how to process a transaction."""
    IGNORE = "ignore"  # Skip entirely
    HOT_ONLY = "hot_only"  # Cheap checks only (no simulation)
    SIM_FAST = "sim_fast"  # Fast simulation
    SIM_FULL = "sim_full"  # Full simulation with complete state diff
    TRACE = "trace"  # Full simulation + trace (future)


@dataclass
class RiskRouterConfig:
    """Configuration for risk router."""
    # Protected contracts (always simulate)
    critical_contracts: Set[str] = field(default_factory=set)
    
    # Dangerous function selectors
    dangerous_selectors: Set[str] = field(default_factory=lambda: {
        "0x8456cb59",  # pause()
        "0x3f4ba83a",  # unpause()
        "0x3659cfe6",  # upgradeTo(address)
        "0x4f1ef286",  # upgradeToAndCall(address,bytes)
        "0x2f2ff15d",  # grantRole(bytes32,address)
        "0xd547741f",  # revokeRole(bytes32,address)
        "0xf2fde38b",  # transferOwnership(address)
        "0x2e1a7d4d",  # withdraw(uint256)
        "0xba087652",  # redeem(uint256)
        "0x4e71d92d",  # claim()
    })
    
    # Value thresholds (in native units)
    large_value_threshold: int = 1000 * 10**18  # 1000 ETH equivalent
    critical_value_threshold: int = 10000 * 10**18  # 10000 ETH equivalent
    
    # Budgets (per minute)
    per_chain_sim_budget: int = 60  # simulations per minute per chain
    per_protocol_sim_budget: int = 20  # simulations per minute per protocol
    
    # Address reputation (seen in incidents)
    malicious_addresses: Set[str] = field(default_factory=set)
    
    # Oracle deviation threshold (stub - would come from oracle module)
    oracle_deviation_threshold: float = 0.05  # 5% deviation
    
    # Anomaly score threshold (stub - would come from anomaly module)
    anomaly_score_threshold: float = 0.7  # 70% anomaly score


@dataclass
class BudgetTracker:
    """Tracks budget usage per chain/protocol."""
    chain_budget: Dict[str, List[datetime]] = field(default_factory=dict)  # chain_id -> timestamps
    protocol_budget: Dict[str, List[datetime]] = field(default_factory=dict)  # protocol_id -> timestamps
    
    def check_budget(
        self,
        chain_id: str,
        protocol_id: Optional[str],
        per_chain_limit: int,
        per_protocol_limit: int,
        window_seconds: int = 60
    ) -> Tuple[bool, str]:
        """
        Check if budget allows simulation.
        
        Returns:
            (allowed, reason)
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=window_seconds)
        
        # Check chain budget
        chain_timestamps = self.chain_budget.get(chain_id, [])
        chain_timestamps = [ts for ts in chain_timestamps if ts > window_start]
        
        if len(chain_timestamps) >= per_chain_limit:
            return False, f"chain_budget_exceeded ({len(chain_timestamps)}/{per_chain_limit})"
        
        # Check protocol budget
        if protocol_id:
            protocol_timestamps = self.protocol_budget.get(protocol_id, [])
            protocol_timestamps = [ts for ts in protocol_timestamps if ts > window_start]
            
            if len(protocol_timestamps) >= per_protocol_limit:
                return False, f"protocol_budget_exceeded ({len(protocol_timestamps)}/{per_protocol_limit})"
        
        return True, "budget_ok"
    
    def record_simulation(self, chain_id: str, protocol_id: Optional[str]):
        """Record a simulation for budget tracking."""
        now = datetime.now(timezone.utc)
        
        if chain_id not in self.chain_budget:
            self.chain_budget[chain_id] = []
        self.chain_budget[chain_id].append(now)
        
        if protocol_id:
            if protocol_id not in self.protocol_budget:
                self.protocol_budget[protocol_id] = []
            self.protocol_budget[protocol_id].append(now)
        
        # Cleanup old timestamps (keep last 2 minutes)
        window_start = now - timedelta(minutes=2)
        self.chain_budget[chain_id] = [ts for ts in self.chain_budget[chain_id] if ts > window_start]
        if protocol_id:
            self.protocol_budget[protocol_id] = [ts for ts in self.protocol_budget[protocol_id] if ts > window_start]


class RiskRouter:
    """
    Routes transactions to appropriate analysis depth based on risk factors.
    
    Decision factors:
    - Protected contract (critical_contracts)
    - Dangerous function selector
    - Transaction value
    - Address reputation
    - Oracle deviation (stub)
    - Anomaly score (stub)
    - Budget constraints
    """
    
    def __init__(self, config: Optional[RiskRouterConfig] = None):
        self.config = config or RiskRouterConfig()
        self.budget_tracker = BudgetTracker()
        
        # Load config from environment
        self._load_config_from_env()
        
        logger.info(
            "risk_router_initialized",
            critical_contracts=len(self.config.critical_contracts),
            dangerous_selectors=len(self.config.dangerous_selectors),
            per_chain_budget=self.config.per_chain_sim_budget,
            per_protocol_budget=self.config.per_protocol_sim_budget
        )
    
    def _load_config_from_env(self):
        """Load configuration from environment variables."""
        # Critical contracts (comma-separated)
        critical_contracts = os.getenv("RUNTIME_CRITICAL_CONTRACTS", "")
        if critical_contracts:
            self.config.critical_contracts.update(
                addr.lower().strip() for addr in critical_contracts.split(",") if addr.strip()
            )
        
        # Budgets
        per_chain_budget = os.getenv("RUNTIME_PER_CHAIN_SIM_BUDGET")
        if per_chain_budget:
            self.config.per_chain_sim_budget = int(per_chain_budget)
        
        per_protocol_budget = os.getenv("RUNTIME_PER_PROTOCOL_SIM_BUDGET")
        if per_protocol_budget:
            self.config.per_protocol_sim_budget = int(per_protocol_budget)
    
    def route(
        self,
        pending_tx: PendingTx,
        protocol_id: Optional[str] = None,
        oracle_deviation: Optional[float] = None,
        anomaly_score: Optional[float] = None
    ) -> Tuple[RouterDecision, str]:
        """
        Route a transaction to appropriate analysis depth.
        
        Args:
            pending_tx: The pending transaction
            protocol_id: Protocol identifier (if known)
            oracle_deviation: Oracle price deviation (if available)
            anomaly_score: Anomaly detection score (if available)
        
        Returns:
            (decision, reason)
        """
        # Factor 1: Protected contract
        if pending_tx.to_address and pending_tx.to_address.lower() in self.config.critical_contracts:
            # Check budget first
            allowed, reason = self.budget_tracker.check_budget(
                pending_tx.chain_id,
                protocol_id,
                self.config.per_chain_sim_budget,
                self.config.per_protocol_sim_budget
            )
            if allowed:
                self.budget_tracker.record_simulation(pending_tx.chain_id, protocol_id)
                return RouterDecision.SIM_FULL, "protected_contract"
            else:
                return RouterDecision.HOT_ONLY, f"protected_contract_budget_exceeded: {reason}"
        
        # Factor 2: Dangerous selector
        if pending_tx.selector and pending_tx.selector.lower() in self.config.dangerous_selectors:
            allowed, reason = self.budget_tracker.check_budget(
                pending_tx.chain_id,
                protocol_id,
                self.config.per_chain_sim_budget,
                self.config.per_protocol_sim_budget
            )
            if allowed:
                self.budget_tracker.record_simulation(pending_tx.chain_id, protocol_id)
                return RouterDecision.SIM_FAST, "dangerous_selector"
            else:
                return RouterDecision.HOT_ONLY, f"dangerous_selector_budget_exceeded: {reason}"
        
        # Factor 3: Large value
        if pending_tx.value >= self.config.critical_value_threshold:
            allowed, reason = self.budget_tracker.check_budget(
                pending_tx.chain_id,
                protocol_id,
                self.config.per_chain_sim_budget,
                self.config.per_protocol_sim_budget
            )
            if allowed:
                self.budget_tracker.record_simulation(pending_tx.chain_id, protocol_id)
                return RouterDecision.SIM_FULL, "critical_value"
            else:
                return RouterDecision.HOT_ONLY, f"critical_value_budget_exceeded: {reason}"
        
        if pending_tx.value >= self.config.large_value_threshold:
            allowed, reason = self.budget_tracker.check_budget(
                pending_tx.chain_id,
                protocol_id,
                self.config.per_chain_sim_budget,
                self.config.per_protocol_sim_budget
            )
            if allowed:
                self.budget_tracker.record_simulation(pending_tx.chain_id, protocol_id)
                return RouterDecision.SIM_FAST, "large_value"
            else:
                return RouterDecision.HOT_ONLY, f"large_value_budget_exceeded: {reason}"
        
        # Factor 4: Malicious address
        if pending_tx.from_address.lower() in self.config.malicious_addresses:
            allowed, reason = self.budget_tracker.check_budget(
                pending_tx.chain_id,
                protocol_id,
                self.config.per_chain_sim_budget,
                self.config.per_protocol_sim_budget
            )
            if allowed:
                self.budget_tracker.record_simulation(pending_tx.chain_id, protocol_id)
                return RouterDecision.SIM_FAST, "malicious_address"
            else:
                return RouterDecision.HOT_ONLY, f"malicious_address_budget_exceeded: {reason}"
        
        # Factor 5: Oracle deviation (stub)
        if oracle_deviation is not None and oracle_deviation > self.config.oracle_deviation_threshold:
            allowed, reason = self.budget_tracker.check_budget(
                pending_tx.chain_id,
                protocol_id,
                self.config.per_chain_sim_budget,
                self.config.per_protocol_sim_budget
            )
            if allowed:
                self.budget_tracker.record_simulation(pending_tx.chain_id, protocol_id)
                return RouterDecision.SIM_FAST, "oracle_deviation"
            else:
                return RouterDecision.HOT_ONLY, f"oracle_deviation_budget_exceeded: {reason}"
        
        # Factor 6: Anomaly score (stub)
        if anomaly_score is not None and anomaly_score > self.config.anomaly_score_threshold:
            allowed, reason = self.budget_tracker.check_budget(
                pending_tx.chain_id,
                protocol_id,
                self.config.per_chain_sim_budget,
                self.config.per_protocol_sim_budget
            )
            if allowed:
                self.budget_tracker.record_simulation(pending_tx.chain_id, protocol_id)
                return RouterDecision.SIM_FAST, "anomaly_score"
            else:
                return RouterDecision.HOT_ONLY, f"anomaly_score_budget_exceeded: {reason}"
        
        # Default: HOT_ONLY (cheap checks)
        return RouterDecision.HOT_ONLY, "no_risk_factors"
    
    def add_malicious_address(self, address: str):
        """Add an address to the malicious addresses set."""
        self.config.malicious_addresses.add(address.lower())
        logger.info("malicious_address_added", address=address.lower())
    
    def add_critical_contract(self, address: str):
        """Add a contract to the critical contracts set."""
        self.config.critical_contracts.add(address.lower())
        logger.info("critical_contract_added", address=address.lower())

