"""
Runtime Engine - Orchestrates intent -> routing -> simulation -> predicted incident
===================================================================================

Main orchestration engine for the Runtime Security Plane.
Coordinates intent sources, risk router, simulator, and incident creation.
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
import structlog
import hashlib

from .intent_sources.base import PendingTxSource, PendingTx
from .risk_router import RiskRouter, RouterDecision
from .simulator.base import Simulator
from .simulator.anvil import AnvilSimulator
from ..models.predicted_incidents import (
    PredictedIncident,
    PredictedIncidentStatus,
    SimulationRun,
    SimulationMode,
    StateDiffFingerprint,
    ConfidenceReasons,
)
from ..models.invariants import InvariantResult
from ..invariants.engine import InvariantEngine
from ..telemetry.rpc_client import MultiRpcProvider
from .pubsub import get_runtime_pubsub
from .simulator.financial_impact import FinancialImpactCalculator

logger = structlog.get_logger(__name__)


class RuntimeEngine:
    """
    Orchestrates the runtime security plane.
    
    Flow:
    1. Get pending transactions from intent source
    2. Route each transaction through risk router
    3. Simulate high-risk transactions
    4. Evaluate invariants on simulation results
    5. Create predicted incidents for violations
    """
    
    def __init__(
        self,
        chain_id: str,
        intent_source: PendingTxSource,
        risk_router: RiskRouter,
        simulator: Simulator,
        invariant_engine: InvariantEngine,
        rpc_provider: MultiRpcProvider
    ):
        self.chain_id = chain_id
        self.intent_source = intent_source
        self.risk_router = risk_router
        self.simulator = simulator
        self.invariant_engine = invariant_engine
        self.rpc_provider = rpc_provider
        
        self._running = False
        self._predicted_incidents: Dict[str, PredictedIncident] = {}  # dedupe_key -> incident
        
        # Protected addresses for state diff extraction
        self.protected_addresses: Set[str] = set()
        self.watched_tokens: Set[str] = set()
        self.watched_pools: Set[str] = set()
        
        # Financial impact calculator (Phase 9)
        self.financial_calculator = FinancialImpactCalculator()
        
        logger.info("runtime_engine_initialized", chain_id=chain_id)
    
    async def initialize(self):
        """Initialize the runtime engine."""
        await self.intent_source.start()
        await self.simulator.initialize()
        logger.info("runtime_engine_initialized_complete", chain_id=self.chain_id)
    
    async def shutdown(self):
        """Shutdown the runtime engine."""
        self._running = False
        await self.intent_source.stop()
        await self.simulator.shutdown()
        logger.info("runtime_engine_shutdown", chain_id=self.chain_id)
    
    async def process_cycle(self) -> List[PredictedIncident]:
        """
        Process one cycle: get intents, route, simulate, evaluate.
        
        Returns:
            List of newly created predicted incidents
        """
        if not self._running:
            return []
        
        new_incidents: List[PredictedIncident] = []
        
        try:
            # Step 1: Get pending transactions
            pending_txs = await self.intent_source.get_pending_txs(limit=100)
            
            if not pending_txs:
                return []
            
            logger.info("processing_pending_txs", count=len(pending_txs), chain_id=self.chain_id)
            
            # Get pubsub instance for broadcasting
            pubsub = await get_runtime_pubsub()
            
            # Step 2: Route and simulate
            for pending_tx in pending_txs:
                try:
                    # Publish intent scan
                    await pubsub.publish_intent(
                        chain_id=self.chain_id,
                        tx_hash=pending_tx.tx_hash,
                        contract=pending_tx.to_address or "",
                        risk_score=0.0
                    )
                    
                    # Route transaction
                    decision, reason = self.risk_router.route(pending_tx)
                    
                    if decision == RouterDecision.IGNORE:
                        continue
                    
                    if decision == RouterDecision.HOT_ONLY:
                        # Cheap checks only - skip simulation
                        continue
                    
                    # Determine simulation mode
                    sim_mode = SimulationMode.FAST
                    if decision == RouterDecision.SIM_FULL:
                        sim_mode = SimulationMode.FULL
                    
                    # Publish simulation start
                    await pubsub.publish_simulation(
                        chain_id=self.chain_id,
                        tx_hash=pending_tx.tx_hash,
                        contract=pending_tx.to_address or "",
                        risk_score=0.0,
                        status="simulating"
                    )
                    
                    # Step 3: Simulate transaction
                    simulation_run = await self.simulator.simulate(
                        pending_tx,
                        mode=sim_mode,
                        fork_block=pending_tx.block_number,
                        fork_block_hash=pending_tx.block_hash,
                        timeout_seconds=30
                    )
                    
                    if simulation_run.status.value != "SUCCESS":
                        logger.warning(
                            "simulation_failed",
                            tx_hash=pending_tx.tx_hash[:16],
                            status=simulation_run.status.value
                        )
                        # Publish simulation failure
                        await pubsub.publish_simulation(
                            chain_id=self.chain_id,
                            tx_hash=pending_tx.tx_hash,
                            contract=pending_tx.to_address or "",
                            risk_score=0.0,
                            status="safe"
                        )
                        continue
                    
                    # Step 4: Extract state diff
                    state_diff = await self.simulator.extract_state_diff(
                        simulation_run.to_dict(),
                        list(self.protected_addresses),
                        list(self.watched_tokens),
                        list(self.watched_pools)
                    )
                    simulation_run.state_diff_fingerprint = state_diff
                    
                    # Step 5: Evaluate invariants
                    # Create a synthetic SecurityEvent from simulation
                    # (This is a simplified approach - full implementation would
                    #  create events from simulated logs)
                    invariant_results = await self._evaluate_invariants_on_simulation(
                        simulation_run,
                        pending_tx
                    )
                    
                    # Publish simulation result (safe if no violations)
                    violations = [r for r in invariant_results if r.violated]
                    if not violations:
                        await pubsub.publish_simulation(
                            chain_id=self.chain_id,
                            tx_hash=pending_tx.tx_hash,
                            contract=pending_tx.to_address or "",
                            risk_score=0.0,
                            status="safe"
                        )
                    
                    # Step 6: Create predicted incident if violations found
                    if violations:
                        predicted_incident = await self._create_predicted_incident(
                            pending_tx,
                            simulation_run,
                            violations,
                            state_diff
                        )
                        
                        if predicted_incident:
                            # Dedupe check
                            if predicted_incident.dedupe_key not in self._predicted_incidents:
                                self._predicted_incidents[predicted_incident.dedupe_key] = predicted_incident
                                new_incidents.append(predicted_incident)
                                
                                # Publish threat
                                await pubsub.publish_threat(
                                    chain_id=self.chain_id,
                                    tx_hash=pending_tx.tx_hash,
                                    contract=pending_tx.to_address or "",
                                    protocol=predicted_incident.protocol_id or "",
                                    risk_score=predicted_incident.confidence,
                                    details={
                                        "predicted_type": predicted_incident.predicted_type,
                                        "severity": predicted_incident.severity.value,
                                        "violations": len(violations)
                                    }
                                )
                                
                                # Also publish as predicted incident
                                await pubsub.publish_predicted_incident(predicted_incident.model_dump())
                                
                                logger.info(
                                    "predicted_incident_created",
                                    incident_id=predicted_incident.id,
                                    tx_hash=pending_tx.tx_hash[:16],
                                    violations=len(violations)
                                )
                            else:
                                # Update existing incident
                                existing = self._predicted_incidents[predicted_incident.dedupe_key]
                                existing.violation_results.extend(violations)
                                existing.updated_at = datetime.now(timezone.utc)
                                logger.debug(
                                    "predicted_incident_updated",
                                    incident_id=existing.id,
                                    tx_hash=pending_tx.tx_hash[:16]
                                )
                
                except Exception as e:
                    logger.error(
                        "failed_to_process_tx",
                        tx_hash=pending_tx.tx_hash[:16] if pending_tx else "unknown",
                        error=str(e)
                    )
                    continue
            
            return new_incidents
        
        except Exception as e:
            logger.error("runtime_engine_cycle_failed", chain_id=self.chain_id, error=str(e))
            return []
    
    async def _evaluate_invariants_on_simulation(
        self,
        simulation_run: SimulationRun,
        pending_tx: PendingTx
    ) -> List[InvariantResult]:
        """
        Evaluate invariants on simulation results.
        
        This creates synthetic SecurityEvents from the simulation and
        evaluates them through the invariant engine.
        """
        # TODO: Full implementation would:
        # 1. Extract events from simulation logs
        # 2. Create SecurityEvent objects
        # 3. Pass to invariant engine
        
        # For now, return empty list (invariants would be evaluated elsewhere)
        return []
    
    async def _create_predicted_incident(
        self,
        pending_tx: PendingTx,
        simulation_run: SimulationRun,
        violations: List[InvariantResult],
        state_diff: StateDiffFingerprint
    ) -> Optional[PredictedIncident]:
        """
        Create a predicted incident from simulation results.
        """
        # Generate dedupe key
        dedupe_key = self._generate_dedupe_key(pending_tx, violations)
        
        # Determine predicted type from violations
        predicted_type = violations[0].invariant_name if violations else "UNKNOWN"
        
        # Determine severity (highest from violations)
        severity = max((v.severity for v in violations), default="MEDIUM")
        
        # Calculate financial impact (Phase 9)
        financial_impact = await self.financial_calculator.calculate_loss(
            state_diff=state_diff,
            protected_addresses=list(self.protected_addresses),
            chain_id=self.chain_id
        )
        
        potential_loss_usd = Decimal(str(financial_impact["loss_usd"]))
        primary_token_symbol = financial_impact.get("primary_token_symbol")
        
        # Compute confidence
        confidence = self._compute_confidence(simulation_run, violations, state_diff)
        
        # Create explanation
        explanation = {
            "summary": f"SIMULATION-BASED PREDICTION: {predicted_type} detected via transaction simulation",
            "timeline": [
                {
                    "timestamp": simulation_run.created_at.isoformat(),
                    "description": f"Transaction {pending_tx.tx_hash[:16]} simulated at block {simulation_run.block_number}",
                }
            ],
            "technical_context": {
                "block_ref": {
                    "number": simulation_run.block_number,
                    "hash": simulation_run.block_hash,
                },
                "tx_hash": pending_tx.tx_hash,
                "from": pending_tx.from_address,
                "to": pending_tx.to_address,
                "selector": pending_tx.selector,
            },
            "evidence": {
                "state_diff": state_diff.to_dict(),
                "violations": [v.to_dict() for v in violations],
            },
            "assumptions": simulation_run.assumptions,
            "recommended_action": "Monitor closely. Consider manual review if confidence is high.",
        }
        
        # Create evidence
        evidence = {
            "simulation_run_id": simulation_run.id,
            "state_diff_fingerprint": state_diff.to_dict(),
            "invariant_violations": [v.to_dict() for v in violations],
        }
        
        predicted_incident = PredictedIncident(
            chain_id=self.chain_id,
            tx_hash=pending_tx.tx_hash,
            protocol_id=None,  # Would be inferred from adapter
            predicted_type=predicted_type,
            severity=severity.name if hasattr(severity, 'name') else str(severity),
            confidence=confidence,
            status=PredictedIncidentStatus.OPEN,
            dedupe_key=dedupe_key,
            explanation_json=explanation,
            evidence_json=evidence,
            linked_simulation_run_id=simulation_run.id,
            # Financial impact (Phase 9)
            potential_loss_usd=potential_loss_usd if potential_loss_usd > 0 else None,
            potential_loss_token_symbol=primary_token_symbol,
            financial_impact_json=financial_impact,
        )
        
        logger.info(
            "predicted_incident_with_financial_impact",
            tx_hash=pending_tx.tx_hash[:16],
            potential_loss_usd=str(potential_loss_usd),
            token_symbol=primary_token_symbol
        )
        
        return predicted_incident
    
    def _generate_dedupe_key(self, pending_tx: PendingTx, violations: List[InvariantResult]) -> str:
        """Generate deduplication key for predicted incident."""
        # Composite key: chain_id + tx_hash + violation_types
        violation_types = ",".join(sorted(set(v.invariant_name for v in violations)))
        key_string = f"{self.chain_id}:{pending_tx.tx_hash}:{violation_types}"
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]
    
    def _compute_confidence(
        self,
        simulation_run: SimulationRun,
        violations: List[InvariantResult],
        state_diff: StateDiffFingerprint
    ) -> float:
        """
        Compute confidence score for predicted incident.
        
        Factors:
        - Simulator calibration score
        - Bundle context (simulated alone vs in bundle)
        - Violation margin
        - Number of independent signals
        """
        base_confidence = 0.5
        
        # Calibration score (would come from calibration harness)
        calibration_score = 0.8  # Default, would be per-chain
        
        # Bundle context (simulated alone = lower confidence)
        if simulation_run.assumptions.get("simulated_alone", True):
            base_confidence *= 0.8
        
        # Violation margin (how far beyond tolerance)
        if violations:
            max_margin = max((v.confidence for v in violations), default=0.5)
            base_confidence = max(base_confidence, max_margin)
        
        # Multiple independent signals
        if len(violations) > 1:
            base_confidence += 0.1
        
        # Apply calibration
        base_confidence *= calibration_score
        
        return min(base_confidence, 1.0)
    
    async def start(self):
        """Start the runtime engine."""
        self._running = True
        await self.initialize()
        logger.info("runtime_engine_started", chain_id=self.chain_id)
    
    async def stop(self):
        """Stop the runtime engine."""
        await self.shutdown()

