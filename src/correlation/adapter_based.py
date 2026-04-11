"""
Adapter-Based Cross-Chain Correlation
======================================

Phase 3: Uses bridge adapters to extract correlation keys and build paths.
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import structlog

from ..models.events import SecurityEvent, EventStatus
from ..bridges.registry import BridgeAdapterRegistry
from ..bridges.adapters.base import BridgeEventSemantic, CorrelationKey

logger = structlog.get_logger(__name__)


class CorrelationPath:
    """
    Represents a correlation path across chains.
    
    Example: L2 -> L1 -> L2 (multi-hop)
    """
    
    def __init__(self, protocol_id: str, correlation_key: CorrelationKey):
        self.protocol_id = protocol_id
        self.correlation_key = correlation_key
        self.events: List[SecurityEvent] = []
        self.semantic_types: List[BridgeEventSemantic] = []
        self.path: List[Tuple[str, BridgeEventSemantic]] = []  # (chain, semantic)
    
    def add_event(self, event: SecurityEvent, semantic: BridgeEventSemantic):
        """Add an event to the path."""
        self.events.append(event)
        self.semantic_types.append(semantic)
        self.path.append((event.chain_id, semantic))
    
    def is_complete(self) -> bool:
        """Check if path is complete (has source and destination)."""
        if not self.path:
            return False
        
        # Check for compatible semantic pairs
        has_lock = BridgeEventSemantic.LOCK in self.semantic_types
        has_mint = BridgeEventSemantic.MINT in self.semantic_types
        has_deposit = BridgeEventSemantic.DEPOSIT in self.semantic_types
        has_fill = BridgeEventSemantic.FILL in self.semantic_types
        
        # Mint/burn bridges: need LOCK + MINT
        if has_lock and has_mint:
            return True
        
        # Liquidity bridges: need DEPOSIT + FILL
        if has_deposit and has_fill:
            return True
        
        return False
    
    def get_violations(self) -> List[Dict[str, any]]:
        """Check for violations in the path."""
        violations = []
        
        # Check semantic compatibility
        if BridgeEventSemantic.MINT in self.semantic_types:
            if BridgeEventSemantic.LOCK not in self.semantic_types:
                violations.append({
                    "type": "MINT_WITHOUT_LOCK",
                    "path": self.path
                })
        
        if BridgeEventSemantic.FILL in self.semantic_types:
            if BridgeEventSemantic.DEPOSIT not in self.semantic_types:
                violations.append({
                    "type": "FILL_WITHOUT_DEPOSIT",
                    "path": self.path
                })
        
        # Check amount parity
        if len(self.events) >= 2:
            source_event = self.events[0]
            dest_event = self.events[-1]
            
            if source_event.amount and dest_event.amount:
                # Get adapter to calculate expected amounts
                registry = BridgeAdapterRegistry()
                adapter = registry.get_adapter(source_event)
                if adapter:
                    expected = adapter.expected_amounts(source_event, dest_event)
                    if expected:
                        tolerance = source_event.amount * Decimal(expected.tolerance_bps) / Decimal(10000)
                        max_allowed = source_event.amount - expected.fee_amount + tolerance
                        
                        if dest_event.amount > max_allowed:
                            violations.append({
                                "type": "AMOUNT_MISMATCH",
                                "source_amount": source_event.amount,
                                "dest_amount": dest_event.amount,
                                "max_allowed": max_allowed,
                                "deviation": dest_event.amount - max_allowed
                            })
        
        return violations


class AdapterBasedCorrelator:
    """
    Cross-chain correlator using bridge adapters.
    
    Builds correlation paths instead of simple A-to-B matching.
    """
    
    def __init__(self):
        self.adapter_registry = BridgeAdapterRegistry()
        self.paths: Dict[str, CorrelationPath] = {}  # correlation_key -> path
        self.orphans: Dict[str, SecurityEvent] = {}  # Events without matches
    
    def process_event(self, event: SecurityEvent) -> Optional[CorrelationPath]:
        """
        Process an event and update correlation paths.
        
        Returns:
            CorrelationPath if path is complete, None otherwise
        """
        # Only process confirmed events
        if event.status != EventStatus.CONFIRMED:
            return None
        
        # Get adapter
        adapter = self.adapter_registry.get_adapter(event)
        if not adapter:
            return None
        
        # Classify event
        semantic = adapter.classify_event(event)
        if not semantic:
            return None
        
        # Extract correlation key
        corr_key = adapter.extract_correlation_key(event)
        if not corr_key:
            return None
        
        key_str = corr_key.key
        
        # Get or create path
        if key_str not in self.paths:
            self.paths[key_str] = CorrelationPath(
                protocol_id=corr_key.protocol_id,
                correlation_key=corr_key
            )
        
        path = self.paths[key_str]
        path.add_event(event, semantic)
        
        # Check if path is complete
        if path.is_complete():
            violations = path.get_violations()
            if violations:
                logger.warning(
                    "correlation_path_violations",
                    protocol=corr_key.protocol_id,
                    correlation_key=key_str[:32],
                    violations=len(violations)
                )
            
            return path
        
        return None
    
    def get_orphans(self, max_age_minutes: int = 30) -> List[SecurityEvent]:
        """Get orphan events (no matching correlation)."""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        
        orphans = []
        for event in self.orphans.values():
            if event.block_timestamp >= cutoff:
                orphans.append(event)
        
        return orphans
    
    def get_paths_by_protocol(self, protocol_id: str) -> List[CorrelationPath]:
        """Get all paths for a protocol."""
        return [
            path for path in self.paths.values()
            if path.protocol_id == protocol_id
        ]

