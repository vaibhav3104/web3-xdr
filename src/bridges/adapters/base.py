"""
Bridge Adapter Base Interface
=============================

Protocol-specific adapters for extracting correlation keys and
classifying events. Replaces one-size-fits-all mint/lock parity
with protocol-aware invariants.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Any, List, Optional

from ...models.events import SecurityEvent


class BridgeProtocol(Enum):
    """Supported bridge protocols."""
    WORMHOLE = "wormhole"
    LAYERZERO = "layerzero"
    STARGATE = "stargate"
    ACROSS = "across"
    HOP = "hop"
    SYNAPSE = "synapse"
    CELER = "celer"
    MULTICHAIN = "multichain"
    POLYGON_POS = "polygon_pos"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    UNKNOWN = "unknown"


class BridgeEventSemantic(Enum):
    """Semantic event types for bridges."""
    LOCK = "lock"  # Asset locked on source chain
    MINT = "mint"  # Asset minted on dest chain
    BURN = "burn"  # Asset burned on dest chain
    UNLOCK = "unlock"  # Asset unlocked on source chain
    DEPOSIT = "deposit"  # Liquidity bridge deposit
    WITHDRAW = "withdraw"  # Liquidity bridge withdrawal
    FILL = "fill"  # Liquidity bridge fill
    MESSAGE_SENT = "message_sent"  # Cross-chain message sent
    MESSAGE_RECEIVED = "message_received"  # Cross-chain message received
    MESSAGE_VERIFIED = "message_verified"  # Message verified by validators


@dataclass
class CorrelationKey:
    """Correlation key for matching cross-chain events."""
    protocol_id: str
    key: str  # Message ID, sequence number, nonce, etc.
    src_chain: str
    dst_chain: Optional[str]
    confidence: float = 1.0  # 0.0-1.0, based on key strength
    
    def __hash__(self) -> int:
        return hash((self.protocol_id, self.key, self.src_chain, self.dst_chain))
    
    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, CorrelationKey):
            return False
        return (
            self.protocol_id == other.protocol_id and
            self.key == other.key and
            self.src_chain == other.src_chain and
            self.dst_chain == other.dst_chain
        )


@dataclass
class ExpectedAmounts:
    """Expected amounts after fees for a bridge operation."""
    source_amount: Decimal
    dest_amount: Decimal
    fee_amount: Decimal
    fee_bps: int  # Fee in basis points
    tolerance_bps: int  # Tolerance in basis points


class BridgeAdapter(ABC):
    """
    Base class for bridge protocol adapters.
    
    Each adapter knows how to:
    1. Identify if an event belongs to this protocol
    2. Extract correlation keys
    3. Classify event semantics
    4. Calculate expected amounts (with fees)
    5. Determine which invariants apply
    """
    
    def __init__(self, protocol_id: BridgeProtocol):
        self.protocol_id = protocol_id
    
    @abstractmethod
    def identify_protocol(self, event: SecurityEvent) -> bool:
        """
        Check if this event belongs to this protocol.
        
        Returns:
            True if event is from this protocol
        """
        pass
    
    @abstractmethod
    def extract_correlation_key(self, event: SecurityEvent) -> Optional[CorrelationKey]:
        """
        Extract correlation key from event.
        
        Returns:
            CorrelationKey if extractable, None otherwise
        """
        pass
    
    @abstractmethod
    def classify_event(self, event: SecurityEvent) -> Optional[BridgeEventSemantic]:
        """
        Classify event semantic type.
        
        Returns:
            BridgeEventSemantic or None if not a bridge event
        """
        pass
    
    @abstractmethod
    def expected_amounts(
        self,
        source_event: SecurityEvent,
        dest_event: Optional[SecurityEvent] = None
    ) -> Optional[ExpectedAmounts]:
        """
        Calculate expected amounts after fees.
        
        Args:
            source_event: Source chain event (LOCK/DEPOSIT)
            dest_event: Optional destination event (MINT/FILL)
        
        Returns:
            ExpectedAmounts or None if cannot calculate
        """
        pass
    
    @abstractmethod
    def supported_invariants(self) -> List[str]:
        """
        List of invariant names supported by this protocol.
        
        Examples:
            - "MINT_LOCK_PARITY" (for mint/burn bridges)
            - "DEPOSIT_FILL_PARITY" (for liquidity bridges)
            - "MESSAGE_VERIFICATION" (for message-based bridges)
        """
        pass
    
    def get_tolerance_bps(self, route: Optional[str] = None, token: Optional[str] = None) -> int:
        """
        Get tolerance in basis points for a route/token.
        
        Default: 100 bps (1%)
        Override in subclasses for protocol-specific tolerances.
        """
        return 100
    
    def get_max_latency_seconds(self, route: Optional[str] = None) -> int:
        """
        Get maximum expected latency in seconds for a route.
        
        Default: 300 seconds (5 minutes)
        Override in subclasses for protocol-specific latencies.
        """
        return 300

