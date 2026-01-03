"""
Attack Pattern Matcher - Detects known attack patterns.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import structlog

from ..models.events import SecurityEvent, EventType
from ..models.incidents import AttackType

logger = structlog.get_logger()


class PatternOperator(Enum):
    """Operators for pattern matching."""
    EQUALS = "equals"
    CONTAINS = "contains"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    IN_SAME_BLOCK = "in_same_block"
    IN_SAME_TX = "in_same_tx"
    SEQUENCE = "sequence"


@dataclass
class PatternCondition:
    """A condition to check in a pattern step."""
    field: str
    operator: PatternOperator
    value: Any = None


@dataclass
class PatternStep:
    """A step in an attack pattern."""
    
    event_type: Optional[EventType] = None
    chain: Optional[str] = None  # "source", "dest", or specific chain ID
    required: bool = True
    min_count: int = 1
    max_count: Optional[int] = None
    time_relation: Optional[str] = None  # "before", "after", "same_block"
    conditions: List[PatternCondition] = field(default_factory=list)
    description: str = ""
    
    def matches(self, event: SecurityEvent) -> bool:
        """Check if an event matches this step."""
        if self.event_type and event.event_type != self.event_type:
            return False
        
        # Check conditions
        for condition in self.conditions:
            if not self._check_condition(event, condition):
                return False
        
        return True
    
    def _check_condition(
        self,
        event: SecurityEvent,
        condition: PatternCondition
    ) -> bool:
        """Check a single condition."""
        value = getattr(event, condition.field, None)
        
        if condition.operator == PatternOperator.EQUALS:
            return value == condition.value
        elif condition.operator == PatternOperator.CONTAINS:
            return condition.value in str(value)
        elif condition.operator == PatternOperator.GREATER_THAN:
            return float(value or 0) > float(condition.value)
        elif condition.operator == PatternOperator.LESS_THAN:
            return float(value or 0) < float(condition.value)
        elif condition.operator == PatternOperator.EXISTS:
            return value is not None
        elif condition.operator == PatternOperator.NOT_EXISTS:
            return value is None
        
        return True


@dataclass
class PatternMatch:
    """Result of a pattern match."""
    pattern_name: str
    attack_type: AttackType
    matched_events: List[SecurityEvent]
    confidence: float
    start_time: datetime
    end_time: datetime
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def get_total_volume(self) -> float:
        """Get total volume of matched events."""
        return sum(float(e.amount_usd) for e in self.matched_events)


@dataclass
class AttackPattern:
    """Definition of an attack pattern."""
    name: str
    attack_type: AttackType
    description: str
    steps: List[PatternStep]
    time_window: timedelta = timedelta(hours=1)
    min_confidence: float = 0.7
    
    # Optional custom validation
    validator: Optional[Callable[[List[SecurityEvent]], bool]] = None


class AttackPatternMatcher:
    """
    Matches event sequences to known attack patterns.
    
    Patterns are defined as sequences of steps that must occur.
    """
    
    def __init__(self):
        self.patterns: Dict[str, AttackPattern] = {}
        self._register_default_patterns()
    
    def _register_default_patterns(self):
        """Register built-in attack patterns."""
        
        # Pattern: Unbacked Mint
        self.register_pattern(AttackPattern(
            name="UNBACKED_MINT",
            attack_type=AttackType.UNBACKED_MINT,
            description="Tokens minted without corresponding lock",
            steps=[
                PatternStep(
                    event_type=EventType.MINT,
                    required=True,
                    description="Mint event on destination chain"
                ),
                PatternStep(
                    event_type=EventType.LOCK,
                    required=False,  # Missing = pattern match
                    time_relation="before",
                    description="Lock event on source chain (should exist)"
                )
            ],
            time_window=timedelta(minutes=30)
        ))
        
        # Pattern: Flash Loan Exploit
        self.register_pattern(AttackPattern(
            name="FLASH_LOAN_EXPLOIT",
            attack_type=AttackType.FLASH_LOAN_EXPLOIT,
            description="Flash loan borrow, exploit, repay in single tx",
            steps=[
                PatternStep(
                    event_type=EventType.FLASH_BORROW,
                    required=True,
                    conditions=[
                        PatternCondition(
                            field="amount_usd",
                            operator=PatternOperator.GREATER_THAN,
                            value=100000
                        )
                    ]
                ),
                PatternStep(
                    event_type=EventType.SWAP,
                    required=True,
                    min_count=1,
                    time_relation="same_block"
                ),
                PatternStep(
                    event_type=EventType.FLASH_REPAY,
                    required=True,
                    time_relation="same_block"
                )
            ],
            time_window=timedelta(minutes=1),
            validator=lambda events: len(set(e.tx_hash for e in events)) == 1
        ))
        
        # Pattern: Validator Compromise
        self.register_pattern(AttackPattern(
            name="VALIDATOR_COMPROMISE",
            attack_type=AttackType.VALIDATOR_COMPROMISE,
            description="Bridge operation with insufficient signatures",
            steps=[
                PatternStep(
                    event_type=EventType.MINT,
                    required=True,
                    conditions=[
                        PatternCondition(
                            field="signature_count",
                            operator=PatternOperator.EXISTS
                        )
                    ]
                )
            ],
            validator=lambda events: any(
                e.signature_count is not None and 
                e.threshold is not None and 
                e.signature_count < e.threshold 
                for e in events
            )
        ))
        
        # Pattern: Governance Attack
        self.register_pattern(AttackPattern(
            name="GOVERNANCE_ATTACK",
            attack_type=AttackType.GOVERNANCE_ATTACK,
            description="Governance action executed without proper delay",
            steps=[
                PatternStep(
                    event_type=EventType.PROPOSAL_EXECUTED,
                    required=True
                ),
                PatternStep(
                    event_type=EventType.PROPOSAL_CREATED,
                    required=False,  # Missing or too recent = attack
                    time_relation="before"
                )
            ]
        ))
        
        # Pattern: Liquidity Drain
        self.register_pattern(AttackPattern(
            name="LIQUIDITY_DRAIN",
            attack_type=AttackType.LIQUIDITY_DRAIN,
            description="Rapid sequential withdrawals draining liquidity",
            steps=[
                PatternStep(
                    event_type=EventType.UNLOCK,
                    required=True,
                    min_count=3,
                    conditions=[
                        PatternCondition(
                            field="amount_usd",
                            operator=PatternOperator.GREATER_THAN,
                            value=100000
                        )
                    ]
                )
            ],
            time_window=timedelta(minutes=10)
        ))
        
        # Pattern: Cross-Chain Laundering
        self.register_pattern(AttackPattern(
            name="CROSS_CHAIN_LAUNDERING",
            attack_type=AttackType.CROSS_CHAIN_LAUNDERING,
            description="Funds moving across chains to obfuscate origin",
            steps=[
                PatternStep(
                    event_type=EventType.LOCK,
                    required=True
                ),
                PatternStep(
                    event_type=EventType.MINT,
                    required=True,
                    time_relation="after"
                ),
                PatternStep(
                    event_type=EventType.TRANSFER,
                    required=True,
                    min_count=2,
                    time_relation="after"
                )
            ],
            time_window=timedelta(hours=24)
        ))
    
    def register_pattern(self, pattern: AttackPattern):
        """Register an attack pattern."""
        self.patterns[pattern.name] = pattern
        logger.debug("pattern_registered", name=pattern.name)
    
    async def match_events(
        self,
        events: List[SecurityEvent],
        pattern_names: Optional[List[str]] = None
    ) -> List[PatternMatch]:
        """
        Match events against patterns.
        
        Args:
            events: List of events to analyze
            pattern_names: Optional list of patterns to check (default: all)
        
        Returns:
            List of pattern matches
        """
        matches = []
        
        patterns_to_check = (
            [self.patterns[name] for name in pattern_names if name in self.patterns]
            if pattern_names
            else list(self.patterns.values())
        )
        
        for pattern in patterns_to_check:
            match = await self._match_pattern(events, pattern)
            if match:
                matches.append(match)
        
        return matches
    
    async def _match_pattern(
        self,
        events: List[SecurityEvent],
        pattern: AttackPattern
    ) -> Optional[PatternMatch]:
        """
        Match events against a single pattern.
        """
        matched_events = []
        step_matches: Dict[int, List[SecurityEvent]] = {}
        
        # Try to match each step
        for i, step in enumerate(pattern.steps):
            step_events = [e for e in events if step.matches(e)]
            
            if step.required and len(step_events) < step.min_count:
                if step.required:
                    return None  # Required step not matched
            
            step_matches[i] = step_events
            matched_events.extend(step_events[:step.max_count or len(step_events)])
        
        if not matched_events:
            return None
        
        # Check time window
        times = [e.block_timestamp for e in matched_events]
        time_span = max(times) - min(times)
        
        if time_span > pattern.time_window:
            return None
        
        # Run custom validator
        if pattern.validator and not pattern.validator(matched_events):
            return None
        
        # Calculate confidence
        confidence = self._calculate_confidence(pattern, step_matches, matched_events)
        
        if confidence < pattern.min_confidence:
            return None
        
        return PatternMatch(
            pattern_name=pattern.name,
            attack_type=pattern.attack_type,
            matched_events=matched_events,
            confidence=confidence,
            start_time=min(times),
            end_time=max(times),
            description=pattern.description,
            evidence={
                "step_matches": {
                    i: len(events) for i, events in step_matches.items()
                },
                "time_span_seconds": time_span.total_seconds()
            }
        )
    
    def _calculate_confidence(
        self,
        pattern: AttackPattern,
        step_matches: Dict[int, List[SecurityEvent]],
        matched_events: List[SecurityEvent]
    ) -> float:
        """Calculate confidence score for a match."""
        confidence = 0.5  # Base confidence
        
        # All required steps matched
        required_matched = all(
            len(step_matches[i]) >= step.min_count
            for i, step in enumerate(pattern.steps)
            if step.required
        )
        if required_matched:
            confidence += 0.2
        
        # Optional steps found (negative indicator - expected to be missing)
        optional_missing = all(
            len(step_matches[i]) == 0
            for i, step in enumerate(pattern.steps)
            if not step.required
        )
        if optional_missing:
            confidence += 0.2
        
        # High volume increases confidence
        total_volume = sum(float(e.amount_usd) for e in matched_events)
        if total_volume > 1000000:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def get_pattern(self, name: str) -> Optional[AttackPattern]:
        """Get a pattern by name."""
        return self.patterns.get(name)
    
    def list_patterns(self) -> List[str]:
        """List all registered pattern names."""
        return list(self.patterns.keys())

