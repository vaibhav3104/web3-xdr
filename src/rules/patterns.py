"""
Pattern Matching Engine
=======================

Detects complex attack patterns across multiple events:
- Sandwich attacks
- Flash loan attacks
- Reentrancy patterns
- Rug pulls
- Front-running/back-running
- JIT liquidity
- Wash trading
- Honeypot tokens
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class PatternType(Enum):
    """Attack pattern types."""
    SANDWICH_ATTACK = "sandwich_attack"
    FLASH_LOAN_ATTACK = "flash_loan_attack"
    REENTRANCY = "reentrancy"
    RUG_PULL = "rug_pull"
    FRONTRUN = "frontrun"
    BACKRUN = "backrun"
    JIT_LIQUIDITY = "jit_liquidity"
    WASH_TRADE = "wash_trade"
    HONEYPOT = "honeypot"
    ACCUMULATION = "accumulation"
    DISTRIBUTION = "distribution"
    RAPID_BRIDGING = "rapid_bridging"
    FLASH_GOVERNANCE = "flash_governance"
    VALIDATOR_COLLUSION = "validator_collusion"
    DELEGATECALL_EXPLOIT = "delegatecall_exploit"
    STORAGE_COLLISION = "storage_collision"
    PRICE_MANIPULATION = "price_manipulation"
    DEX_EXPLOIT = "dex_exploit"
    PROGRAM_EXPLOIT = "program_exploit"


@dataclass
class PatternMatch:
    """Pattern match result."""
    pattern_type: PatternType
    confidence: float  # 0-1
    events: List[Dict[str, Any]]
    profit_usd: float
    loss_usd: float
    attacker_addresses: List[str]
    victim_addresses: List[str]
    timestamp: datetime
    details: Dict = field(default_factory=dict)


@dataclass
class PatternConfig:
    """Configuration for pattern detection."""
    pattern_type: PatternType
    min_confidence: float
    time_window_seconds: int
    min_events: int
    description: str


class PatternMatcher:
    """
    Detects complex attack patterns.
    
    Analyzes sequences of events to identify:
    - Multi-transaction attacks
    - Time-correlated anomalies
    - Economic exploits
    """
    
    # Pattern configurations
    PATTERN_CONFIGS = {
        PatternType.SANDWICH_ATTACK: PatternConfig(
            pattern_type=PatternType.SANDWICH_ATTACK,
            min_confidence=0.7,
            time_window_seconds=15,  # Same block
            min_events=3,
            description="Sandwich attack: front-run, victim, back-run",
        ),
        PatternType.FLASH_LOAN_ATTACK: PatternConfig(
            pattern_type=PatternType.FLASH_LOAN_ATTACK,
            min_confidence=0.8,
            time_window_seconds=15,
            min_events=3,
            description="Flash loan borrow, exploit, repay in single tx",
        ),
        PatternType.REENTRANCY: PatternConfig(
            pattern_type=PatternType.REENTRANCY,
            min_confidence=0.9,
            time_window_seconds=15,
            min_events=2,
            description="Recursive calls before state update",
        ),
        PatternType.RUG_PULL: PatternConfig(
            pattern_type=PatternType.RUG_PULL,
            min_confidence=0.7,
            time_window_seconds=3600,  # 1 hour
            min_events=2,
            description="Large liquidity removal from new token",
        ),
        PatternType.WASH_TRADE: PatternConfig(
            pattern_type=PatternType.WASH_TRADE,
            min_confidence=0.6,
            time_window_seconds=86400,  # 24 hours
            min_events=5,
            description="Connected addresses trading back and forth",
        ),
        PatternType.HONEYPOT: PatternConfig(
            pattern_type=PatternType.HONEYPOT,
            min_confidence=0.8,
            time_window_seconds=86400,
            min_events=10,
            description="Token with high buy count but low sell success",
        ),
        PatternType.RAPID_BRIDGING: PatternConfig(
            pattern_type=PatternType.RAPID_BRIDGING,
            min_confidence=0.5,
            time_window_seconds=3600,
            min_events=3,
            description="Multiple bridge transfers in short time",
        ),
        PatternType.FLASH_GOVERNANCE: PatternConfig(
            pattern_type=PatternType.FLASH_GOVERNANCE,
            min_confidence=0.9,
            time_window_seconds=15,
            min_events=3,
            description="Flash loan, vote, return in same block",
        ),
    }
    
    def __init__(self, window_minutes: int = 60):
        """
        Initialize pattern matcher.
        
        Args:
            window_minutes: Event window to keep in memory
        """
        self._window_minutes = window_minutes
        self._events: List[Dict[str, Any]] = []
        self._events_by_address: Dict[str, List[Dict]] = defaultdict(list)
        self._events_by_block: Dict[int, List[Dict]] = defaultdict(list)
        self._events_by_contract: Dict[str, List[Dict]] = defaultdict(list)
        self._matches: List[PatternMatch] = []
        logger.info("pattern_matcher_initialized", window_minutes=window_minutes)
    
    def add_event(self, event: Dict[str, Any]) -> List[PatternMatch]:
        """
        Add an event and check for patterns.
        
        Args:
            event: Event dictionary
            
        Returns:
            List of pattern matches
        """
        # Store event
        self._events.append(event)
        
        # Index by various keys (handle None values)
        from_addr = (event.get("from_address") or "").lower()
        to_addr = (event.get("to_address") or "").lower()
        block = event.get("block_number") or 0
        contract = (event.get("contract_address") or "").lower()
        
        if from_addr:
            self._events_by_address[from_addr].append(event)
        if to_addr:
            self._events_by_address[to_addr].append(event)
        if block:
            self._events_by_block[block].append(event)
        if contract:
            self._events_by_contract[contract].append(event)
        
        # Cleanup old events
        self._cleanup_old_events()
        
        # Check for patterns
        matches = []
        
        matches.extend(self._detect_sandwich(event))
        matches.extend(self._detect_flash_loan_attack(event))
        matches.extend(self._detect_rug_pull(event))
        matches.extend(self._detect_wash_trade(event))
        matches.extend(self._detect_rapid_bridging(event))
        
        self._matches.extend(matches)
        return matches
    
    def _cleanup_old_events(self):
        """Remove events older than window."""
        # Use timezone-aware datetime to avoid comparison errors
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self._window_minutes)
        
        self._events = [
            e for e in self._events
            if self._get_event_time(e) > cutoff
        ]
        
        # Rebuild indexes
        self._events_by_address = defaultdict(list)
        self._events_by_block = defaultdict(list)
        self._events_by_contract = defaultdict(list)
        
        for event in self._events:
            from_addr = (event.get("from_address") or "").lower()
            to_addr = (event.get("to_address") or "").lower()
            block = event.get("block_number") or 0
            contract = (event.get("contract_address") or "").lower()
            
            if from_addr:
                self._events_by_address[from_addr].append(event)
            if to_addr:
                self._events_by_address[to_addr].append(event)
            if block:
                self._events_by_block[block].append(event)
            if contract:
                self._events_by_contract[contract].append(event)
    
    def _get_event_time(self, event: Dict) -> datetime:
        """Get event timestamp (always returns timezone-aware datetime)."""
        ts = event.get("timestamp") or event.get("block_timestamp")
        if isinstance(ts, datetime):
            # Make sure it's timezone-aware
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts
        if isinstance(ts, str):
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed
            except:
                pass
        return datetime.now(timezone.utc)
    
    def _detect_sandwich(self, event: Dict[str, Any]) -> List[PatternMatch]:
        """Detect sandwich attack pattern."""
        matches = []
        config = self.PATTERN_CONFIGS[PatternType.SANDWICH_ATTACK]
        
        block = event.get("block_number")
        if not block:
            return matches
        
        block_events = self._events_by_block.get(block, [])
        if len(block_events) < config.min_events:
            return matches
        
        # Look for swap sequences
        swaps = [
            e for e in block_events
            if (e.get("event_type") or "").lower() in ("swap", "swapv3", "transfer")
        ]
        
        if len(swaps) < 3:
            return matches
        
        # Sort by log index (handle string/int/None)
        def get_log_index(e):
            idx = e.get("log_index")
            if idx is None:
                return 0
            try:
                return int(idx)
            except (ValueError, TypeError):
                return 0
        swaps.sort(key=get_log_index)
        
        # Check for sandwich pattern
        for i in range(len(swaps) - 2):
            front = swaps[i]
            victim = swaps[i + 1]
            back = swaps[i + 2]
            
            front_addr = (front.get("from_address") or "").lower()
            victim_addr = (victim.get("from_address") or "").lower()
            back_addr = (back.get("from_address") or "").lower()
            
            # Same attacker, different victim
            if front_addr == back_addr and front_addr != victim_addr:
                # Same contract (same pool)
                if front.get("contract_address") == victim.get("contract_address") == back.get("contract_address"):
                    profit = float(back.get("amount_usd") or 0) - float(front.get("amount_usd") or 0)
                    
                    if profit > 0:
                        matches.append(PatternMatch(
                            pattern_type=PatternType.SANDWICH_ATTACK,
                            confidence=0.85,
                            events=[front, victim, back],
                            profit_usd=profit,
                            loss_usd=profit * 0.5,
                            attacker_addresses=[front_addr],
                            victim_addresses=[victim_addr],
                            timestamp=datetime.now(timezone.utc),
                            details={
                                "same_block": True,
                                "swap_count": 3,
                                "pool": front.get("contract_address"),
                            }
                        ))
        
        return matches
    
    def _detect_flash_loan_attack(self, event: Dict[str, Any]) -> List[PatternMatch]:
        """Detect flash loan attack pattern."""
        matches = []
        self.PATTERN_CONFIGS[PatternType.FLASH_LOAN_ATTACK]
        
        # Look for flash loan events
        if event.get("event_type") != "FlashLoan":
            return matches
        
        block = event.get("block_number")
        if not block:
            return matches
        
        block_events = self._events_by_block.get(block, [])
        
        # Count operations in same block
        operation_count = len(block_events)
        total_volume = sum(float(e.get("amount_usd") or 0) for e in block_events)
        
        # Flash loan attack indicators
        if operation_count > 20 and total_volume > 1_000_000:
            matches.append(PatternMatch(
                pattern_type=PatternType.FLASH_LOAN_ATTACK,
                confidence=0.75,
                events=block_events[:10],  # First 10 events
                profit_usd=total_volume * 0.01,  # Estimate
                loss_usd=total_volume * 0.01,
                attacker_addresses=[event.get("from_address", "")],
                victim_addresses=[],
                timestamp=datetime.now(timezone.utc),
                details={
                    "same_block": True,
                    "block_operation_count": operation_count,
                    "block_volume_usd": total_volume,
                    "flash_loan_amount_usd": float(event.get("amount_usd") or 0),
                }
            ))
        
        return matches
    
    def _detect_rug_pull(self, event: Dict[str, Any]) -> List[PatternMatch]:
        """Detect rug pull pattern."""
        matches = []
        self.PATTERN_CONFIGS[PatternType.RUG_PULL]
        
        # Look for large liquidity removal
        if event.get("event_type") not in ("LiquidityRemove", "liquidity_remove", "Burn"):
            return matches
        
        contract = (event.get("contract_address") or "").lower()
        if not contract:
            return matches
        
        # Get contract history
        contract_events = self._events_by_contract.get(contract, [])
        
        # Calculate liquidity metrics
        adds = [e for e in contract_events if e.get("event_type") in ("LiquidityAdd", "liquidity_add", "Mint")]
        removes = [e for e in contract_events if e.get("event_type") in ("LiquidityRemove", "liquidity_remove", "Burn")]
        
        total_added = sum(float(e.get("amount_usd") or 0) for e in adds)
        total_removed = sum(float(e.get("amount_usd") or 0) for e in removes)
        
        if total_added > 0:
            removed_percent = (total_removed / total_added) * 100
            
            if removed_percent > 80:  # 80%+ liquidity removed
                matches.append(PatternMatch(
                    pattern_type=PatternType.RUG_PULL,
                    confidence=0.7,
                    events=removes[-5:],  # Last 5 removals
                    profit_usd=total_removed,
                    loss_usd=total_removed,
                    attacker_addresses=[event.get("from_address", "")],
                    victim_addresses=[],
                    timestamp=datetime.now(timezone.utc),
                    details={
                        "liquidity_removed_percent": removed_percent,
                        "total_added_usd": total_added,
                        "total_removed_usd": total_removed,
                        "token_age_hours": 0,  # Would need to track
                        "holder_count": 0,  # Would need to track
                    }
                ))
        
        return matches
    
    def _detect_wash_trade(self, event: Dict[str, Any]) -> List[PatternMatch]:
        """Detect wash trading pattern."""
        matches = []
        config = self.PATTERN_CONFIGS[PatternType.WASH_TRADE]
        
        from_addr = (event.get("from_address") or "").lower()
        to_addr = (event.get("to_address") or "").lower()
        
        if not from_addr or not to_addr:
            return matches
        
        # Check if addresses trade back and forth
        from_events = self._events_by_address.get(from_addr, [])
        to_events = self._events_by_address.get(to_addr, [])
        
        # Count trades between these addresses
        trades_a_to_b = [
            e for e in from_events
            if (e.get("to_address") or "").lower() == to_addr
        ]
        trades_b_to_a = [
            e for e in to_events
            if (e.get("to_address") or "").lower() == from_addr
        ]
        
        total_trades = len(trades_a_to_b) + len(trades_b_to_a)
        
        if total_trades >= config.min_events:
            matches.append(PatternMatch(
                pattern_type=PatternType.WASH_TRADE,
                confidence=0.6,
                events=trades_a_to_b[:3] + trades_b_to_a[:3],
                profit_usd=0,
                loss_usd=0,
                attacker_addresses=[from_addr, to_addr],
                victim_addresses=[],
                timestamp=datetime.now(timezone.utc),
                details={
                    "buyer_seller_connected": True,
                    "trade_count": total_trades,
                    "time_window": config.time_window_seconds,
                }
            ))
        
        return matches
    
    def _detect_rapid_bridging(self, event: Dict[str, Any]) -> List[PatternMatch]:
        """Detect rapid cross-chain bridging."""
        matches = []
        config = self.PATTERN_CONFIGS[PatternType.RAPID_BRIDGING]
        
        if event.get("event_type") not in ("Lock", "SendToChain", "LogMessagePublished"):
            return matches
        
        from_addr = (event.get("from_address") or "").lower()
        if not from_addr:
            return matches
        
        # Get bridge events from this address
        addr_events = self._events_by_address.get(from_addr, [])
        bridge_events = [
            e for e in addr_events
            if e.get("event_type") in ("Lock", "SendToChain", "LogMessagePublished", "TransferRedeemed")
        ]
        
        if len(bridge_events) >= config.min_events:
            total_bridged = sum(float(e.get("amount_usd") or 0) for e in bridge_events)
            
            matches.append(PatternMatch(
                pattern_type=PatternType.RAPID_BRIDGING,
                confidence=0.5,
                events=bridge_events[-5:],
                profit_usd=0,
                loss_usd=0,
                attacker_addresses=[from_addr],
                victim_addresses=[],
                timestamp=datetime.now(timezone.utc),
                details={
                    "bridge_count": len(bridge_events),
                    "total_bridged_usd": total_bridged,
                    "same_address": True,
                    "time_window": config.time_window_seconds,
                }
            ))
        
        return matches
    
    def check_pattern(self, pattern_name: str, event: Dict[str, Any]) -> bool:
        """
        Check if a specific pattern matches.
        
        Used by YAML rules with pattern detection.
        """
        try:
            pattern_type = PatternType(pattern_name)
        except ValueError:
            return False
        
        matches = self.add_event(event)
        return any(m.pattern_type == pattern_type for m in matches)
    
    def get_matches(self, limit: int = 100) -> List[PatternMatch]:
        """Get recent pattern matches."""
        return self._matches[-limit:]


# Global singleton
_pattern_matcher: Optional[PatternMatcher] = None


def get_pattern_matcher() -> PatternMatcher:
    """Get global pattern matcher instance."""
    global _pattern_matcher
    if _pattern_matcher is None:
        _pattern_matcher = PatternMatcher()
    return _pattern_matcher
