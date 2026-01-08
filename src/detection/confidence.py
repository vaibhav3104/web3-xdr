"""
Confidence Scoring System
=========================

Phase 4: Heuristic-based confidence scoring (0.0 to 1.0) for incidents.

Factors:
- Block finality (+0.4)
- Correlation key match (+0.3)
- Amount match (+0.2)
- Multi-chain trace (+0.1)
- Price oracle staleness (-0.5)
"""

from decimal import Decimal
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import structlog

from ..models.events import SecurityEvent, EventStatus
from ..models.invariants import InvariantResult
from ..correlation.incident_builder import Incident

logger = structlog.get_logger(__name__)


class ConfidenceScorer:
    """
    Calculates confidence scores for incidents.
    
    Uses heuristics based on evidence quality and chain finality.
    """
    
    def __init__(self):
        self.logger = structlog.get_logger(__name__)
    
    def score_incident(
        self,
        incident: Incident,
        violations: list[InvariantResult],
        events: list[SecurityEvent],
        oracle_stale: bool = False
    ) -> float:
        """
        Calculate confidence score for an incident.
        
        Args:
            incident: The incident to score
            violations: List of violations
            events: List of related events
            oracle_stale: Whether price oracle is stale/missing
        
        Returns:
            Confidence score (0.0 to 1.0)
        """
        score = 0.0
        
        # Factor 1: Block Finality (+0.4)
        finality_score = self._score_finality(events)
        score += finality_score * 0.4
        
        # Factor 2: Correlation Key Match (+0.3)
        correlation_score = self._score_correlation(violations)
        score += correlation_score * 0.3
        
        # Factor 3: Amount Match (+0.2)
        amount_score = self._score_amount_match(violations, events)
        score += amount_score * 0.2
        
        # Factor 4: Multi-Chain Trace (+0.1)
        trace_score = self._score_multi_chain_trace(incident, events)
        score += trace_score * 0.1
        
        # Penalty: Oracle Staleness (-0.5)
        if oracle_stale:
            score -= 0.5
        
        # Clamp to [0.0, 1.0]
        score = max(0.0, min(1.0, score))
        
        logger.debug(
            "confidence_score_calculated",
            incident_id=incident.incident_id,
            score=score,
            finality=finality_score,
            correlation=correlation_score,
            amount=amount_score,
            trace=trace_score,
            oracle_stale=oracle_stale
        )
        
        return score
    
    def _score_finality(self, events: list[SecurityEvent]) -> float:
        """
        Score based on block finality.
        
        +1.0 if all events are CONFIRMED
        +0.5 if some events are CONFIRMED
        +0.0 if all events are PENDING
        """
        if not events:
            return 0.0
        
        confirmed_count = sum(1 for e in events if e.status == EventStatus.CONFIRMED)
        total_count = len(events)
        
        if confirmed_count == total_count:
            return 1.0
        elif confirmed_count > 0:
            return 0.5
        else:
            return 0.0
    
    def _score_correlation(self, violations: list[InvariantResult]) -> float:
        """
        Score based on correlation key matching.
        
        +1.0 if correlation keys match exactly (cryptographic proof)
        +0.5 if correlation keys partially match
        +0.0 if no correlation keys
        """
        if not violations:
            return 0.0
        
        matched_keys = []
        unmatched_keys = []
        
        for violation in violations:
            evidence = violation.evidence
            
            # Check for exact match
            source_msg_id = evidence.get("source_msg_id")
            dest_msg_id = evidence.get("dest_msg_id")
            
            if source_msg_id and dest_msg_id:
                if source_msg_id == dest_msg_id:
                    matched_keys.append(source_msg_id)
                else:
                    unmatched_keys.append((source_msg_id, dest_msg_id))
            elif evidence.get("correlation_key"):
                # Partial match (has correlation key but no exact match)
                matched_keys.append(evidence["correlation_key"])
        
        if matched_keys:
            # Exact cryptographic match
            return 1.0
        elif unmatched_keys:
            # Partial match
            return 0.5
        else:
            # No correlation
            return 0.0
    
    def _score_amount_match(
        self,
        violations: list[InvariantResult],
        events: list[SecurityEvent]
    ) -> float:
        """
        Score based on amount matching.
        
        +1.0 if amounts match perfectly
        +0.5 if amounts match within tolerance
        +0.0 if amounts don't match or missing
        """
        if not violations or not events:
            return 0.0
        
        # Get amounts from violations
        violation = violations[0]
        evidence = violation.evidence
        
        source_amount = evidence.get("source_amount")
        dest_amount = evidence.get("dest_amount")
        
        if not source_amount or not dest_amount:
            return 0.0
        
        source_amount_dec = Decimal(str(source_amount))
        dest_amount_dec = Decimal(str(dest_amount))
        
        # Perfect match
        if source_amount_dec == dest_amount_dec:
            return 1.0
        
        # Check tolerance (within 1%)
        tolerance = source_amount_dec * Decimal("0.01")
        diff = abs(source_amount_dec - dest_amount_dec)
        
        if diff <= tolerance:
            return 0.5
        
        return 0.0
    
    def _score_multi_chain_trace(
        self,
        incident: Incident,
        events: list[SecurityEvent]
    ) -> float:
        """
        Score based on multi-chain trace confirmation.
        
        +1.0 if trace spans multiple chains and is complete
        +0.5 if trace spans multiple chains but incomplete
        +0.0 if single chain or no trace
        """
        if not events:
            return 0.0
        
        # Count unique chains
        unique_chains = set(e.chain_id for e in events)
        
        if len(unique_chains) >= 2:
            # Multi-chain trace
            # Check if we have both source and destination
            if incident.source_chain and incident.target_chain:
                if incident.source_chain in unique_chains and incident.target_chain in unique_chains:
                    return 1.0  # Complete trace
                else:
                    return 0.5  # Incomplete trace
            else:
                return 0.5  # Multi-chain but no explicit source/dest
        else:
            return 0.0  # Single chain
    
    def check_oracle_staleness(
        self,
        events: list[SecurityEvent],
        max_age_minutes: int = 5
    ) -> bool:
        """
        Check if price oracle data is stale.
        
        Returns True if oracle is stale/missing.
        """
        if not events:
            return True
        
        # Check if events have USD amounts
        has_usd_amounts = any(e.amount_usd for e in events)
        
        if not has_usd_amounts:
            return True  # Missing oracle data
        
        # Check if USD amounts are recent (within max_age)
        cutoff = datetime.now() - timedelta(minutes=max_age_minutes)
        recent_events = [e for e in events if e.block_timestamp >= cutoff]
        
        if not recent_events:
            return True  # All events are old
        
        return False  # Oracle data is fresh

