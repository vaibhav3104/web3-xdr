"""
Bridge Adapter Registry
======================

Auto-detects protocol from events and routes to correct adapter.
"""

from typing import Dict, List, Optional
import structlog

from .adapters import (
    BridgeAdapter,
    WormholeAdapter,
    LayerZeroAdapter,
    StargateAdapter
)
from ..models.events import SecurityEvent

logger = structlog.get_logger(__name__)


class BridgeAdapterRegistry:
    """
    Registry for bridge protocol adapters.
    
    Automatically detects protocol from events and routes to correct adapter.
    """
    
    def __init__(self):
        self.adapters: List[BridgeAdapter] = [
            WormholeAdapter(),
            LayerZeroAdapter(),
            StargateAdapter(),
        ]
        
        # Cache for protocol detection
        self._protocol_cache: Dict[str, Optional[BridgeAdapter]] = {}
        
        logger.info(
            "bridge_adapter_registry_initialized",
            adapter_count=len(self.adapters)
        )
    
    def get_adapter(self, event: SecurityEvent) -> Optional[BridgeAdapter]:
        """
        Get adapter for an event.
        
        Returns:
            BridgeAdapter if protocol identified, None otherwise
        """
        # Check cache first
        cache_key = f"{event.chain_id}:{event.contract_address}:{event.tx_hash}"
        if cache_key in self._protocol_cache:
            return self._protocol_cache[cache_key]
        
        # Try each adapter
        for adapter in self.adapters:
            if adapter.identify_protocol(event):
                self._protocol_cache[cache_key] = adapter
                return adapter
        
        self._protocol_cache[cache_key] = None
        return None
    
    def get_adapter_by_protocol(self, protocol_id: str) -> Optional[BridgeAdapter]:
        """Get adapter by protocol ID."""
        for adapter in self.adapters:
            if adapter.protocol_id.value == protocol_id:
                return adapter
        return None
    
    def get_all_adapters(self) -> List[BridgeAdapter]:
        """Get all registered adapters."""
        return self.adapters

