"""
Event Enricher
==============

Main enrichment orchestrator that adds contextual information to events.

Enriches events with:
- Entity classification (from/to addresses)
- USD values (from price feed)
- TVL tracking (for protocols)
- MEV detection (block-level analysis)
- Protocol identification
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone
from decimal import Decimal
import structlog

from .entity_registry import EntityRegistry, EntityType, get_entity_registry
from .tvl_tracker import TVLTracker, get_tvl_tracker
from .mev_detector import MEVDetector, Transaction, get_mev_detector

# Import price feed
try:
    from src.telemetry.price_feed import PriceFeed, get_price_feed
except ImportError:
    PriceFeed = None
    get_price_feed = None

# Import event normalizer
try:
    from src.telemetry.event_normalizer import normalize_event_type
except ImportError:
    def normalize_event_type(t): return t

logger = structlog.get_logger(__name__)


class EventEnricher:
    """
    Enriches raw blockchain events with contextual information.
    
    Adds fields needed for YAML rule evaluation:
    - amount_usd: USD value of transfer
    - from_is_exchange, to_is_exchange: Entity classification
    - from_is_mixer, to_is_mixer: Privacy protocol detection
    - from_is_known_hacker: Risk detection
    - address_is_sanctioned: OFAC compliance
    - buyer_is_smart_money, seller_is_smart_money: Smart money tracking
    - drain_percent_per_hour, drain_amount_usd: TVL tracking
    - same_block, block_operation_count, block_volume_usd: MEV detection
    """
    
    def __init__(
        self,
        entity_registry: Optional[EntityRegistry] = None,
        tvl_tracker: Optional[TVLTracker] = None,
        mev_detector: Optional[MEVDetector] = None,
        price_feed: Optional[PriceFeed] = None,
    ):
        """
        Initialize event enricher.
        
        Args:
            entity_registry: Entity classification service
            tvl_tracker: TVL tracking service
            mev_detector: MEV detection service
            price_feed: Price feed service
        """
        self._entity_registry = entity_registry or get_entity_registry()
        self._tvl_tracker = tvl_tracker or get_tvl_tracker()
        self._mev_detector = mev_detector or get_mev_detector()
        self._price_feed = price_feed or (get_price_feed() if get_price_feed else None)
        
        logger.info("event_enricher_initialized")
    
    async def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an event with contextual information.
        
        Args:
            event: Raw event dictionary
            
        Returns:
            Enriched event dictionary
        """
        enriched = event.copy()
        
        # Normalize event type
        if "event_type" in enriched:
            enriched["event_type_normalized"] = normalize_event_type(enriched["event_type"])
        
        # Enrich addresses
        enriched = self._enrich_addresses(enriched)
        
        # Enrich with USD value
        enriched = await self._enrich_usd_value(enriched)
        
        # Enrich with TVL data
        enriched = self._enrich_tvl(enriched)
        
        # Enrich with MEV data
        enriched = self._enrich_mev(enriched)
        
        return enriched
    
    def enrich_sync(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronous version of enrich (no USD conversion).
        
        Args:
            event: Raw event dictionary
            
        Returns:
            Enriched event dictionary
        """
        enriched = event.copy()
        
        # Normalize event type
        if "event_type" in enriched:
            enriched["event_type_normalized"] = normalize_event_type(enriched["event_type"])
        
        # Enrich addresses
        enriched = self._enrich_addresses(enriched)
        
        # Enrich with TVL data
        enriched = self._enrich_tvl(enriched)
        
        # Enrich with MEV data
        enriched = self._enrich_mev(enriched)
        
        return enriched
    
    def _enrich_addresses(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Add entity classification for addresses."""
        
        # From address
        from_addr = event.get("from_address") or event.get("source_address")
        if from_addr:
            from_entity = self._entity_registry.classify(from_addr)
            event["from_entity_type"] = from_entity.entity_type.value
            event["from_entity_name"] = from_entity.name
            event["from_risk_score"] = from_entity.risk_score
            
            # Boolean flags for rule matching
            event["from_is_exchange"] = from_entity.entity_type in (EntityType.CEX, EntityType.DEX)
            event["from_is_mixer"] = from_entity.entity_type in (EntityType.MIXER, EntityType.TUMBLER, EntityType.TORNADO)
            event["from_is_known_hacker"] = from_entity.entity_type == EntityType.HACKER
            event["from_is_sanctioned"] = from_entity.entity_type == EntityType.SANCTIONED
            event["from_is_smart_money"] = from_entity.entity_type in (EntityType.SMART_MONEY, EntityType.VC, EntityType.WHALE)
            event["from_is_team_wallet"] = from_entity.entity_type == EntityType.TEAM_WALLET
            event["seller_is_smart_money"] = event["from_is_smart_money"]
        
        # To address
        to_addr = event.get("to_address") or event.get("dest_address")
        if to_addr:
            to_entity = self._entity_registry.classify(to_addr)
            event["to_entity_type"] = to_entity.entity_type.value
            event["to_entity_name"] = to_entity.name
            event["to_risk_score"] = to_entity.risk_score
            
            # Boolean flags for rule matching
            event["to_is_exchange"] = to_entity.entity_type in (EntityType.CEX, EntityType.DEX)
            event["to_is_mixer"] = to_entity.entity_type in (EntityType.MIXER, EntityType.TUMBLER, EntityType.TORNADO)
            event["to_is_known_hacker"] = to_entity.entity_type == EntityType.HACKER
            event["to_is_sanctioned"] = to_entity.entity_type == EntityType.SANCTIONED
            event["to_is_smart_money"] = to_entity.entity_type in (EntityType.SMART_MONEY, EntityType.VC, EntityType.WHALE)
            event["buyer_is_smart_money"] = event["to_is_smart_money"]
        
        # Combined risk
        event["address_is_sanctioned"] = event.get("from_is_sanctioned", False) or event.get("to_is_sanctioned", False)
        event["involves_mixer"] = event.get("from_is_mixer", False) or event.get("to_is_mixer", False)
        event["involves_hacker"] = event.get("from_is_known_hacker", False) or event.get("to_is_known_hacker", False)
        
        return event
    
    async def _enrich_usd_value(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Add USD value calculation."""
        
        if not self._price_feed:
            return event
        
        # Get amount
        amount = event.get("amount")
        if amount is None:
            return event
        
        # Convert to Decimal
        try:
            amount = Decimal(str(amount))
        except:
            return event
        
        # Get chain and token
        chain = event.get("chain_id") or event.get("chain")
        token_address = event.get("contract_address") or event.get("asset_address")
        
        if not chain or not token_address:
            return event
        
        # Get price
        try:
            price = await self._price_feed.get_price(chain, token_address)
            if price > 0:
                amount_usd = float(amount) * price
                event["amount_usd"] = amount_usd
                event["token_price_usd"] = price
                event["token_symbol"] = self._price_feed.get_token_symbol(chain, token_address)
        except Exception as e:
            logger.debug("price_fetch_error", error=str(e))
        
        return event
    
    def _enrich_tvl(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Add TVL tracking data."""
        
        # Get protocol and chain
        protocol = event.get("protocol") or event.get("contract_address", "")[:10]
        chain = event.get("chain_id") or event.get("chain")
        
        if not protocol or not chain:
            return event
        
        # Get drain rate
        drain_rate, drain_usd = self._tvl_tracker.get_drain_rate(protocol, chain)
        event["drain_percent_per_hour"] = drain_rate
        event["drain_amount_usd"] = drain_usd
        
        # Get liquidity change
        event["liquidity_change_percent"] = self._tvl_tracker.get_liquidity_change_percent(protocol, chain)
        
        # Check if draining
        event["is_draining"] = self._tvl_tracker.is_draining(protocol, chain)
        
        # Get current TVL
        event["current_tvl_usd"] = self._tvl_tracker.get_current_tvl(protocol, chain)
        
        return event
    
    def _enrich_mev(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Add MEV detection data."""
        
        block_number = event.get("block_number") or event.get("block")
        if not block_number:
            return event
        
        # Get block stats
        event["block_operation_count"] = self._mev_detector.get_block_operation_count(block_number)
        event["block_volume_usd"] = self._mev_detector.get_block_volume_usd(block_number)
        
        # Create transaction for MEV analysis
        try:
            tx = Transaction(
                tx_hash=event.get("tx_hash") or "",
                block_number=block_number,
                tx_index=event.get("log_index") or 0,
                from_address=event.get("from_address") or "",
                to_address=event.get("to_address") or "",
                event_type=event.get("event_type") or "",
                amount_usd=float(event.get("amount_usd") or 0),
                gas_price=event.get("gas_price") or 0,
                timestamp=datetime.now(timezone.utc),
                contract_address=event.get("contract_address"),
            )
            
            # Add to MEV detector and check for patterns
            detections = self._mev_detector.add_transaction(tx)
            
            if detections:
                event["mev_detected"] = True
                event["mev_types"] = [d.mev_type.value for d in detections]
                event["mev_profit_usd"] = sum(d.profit_usd for d in detections)
            else:
                event["mev_detected"] = False
                
        except Exception as e:
            logger.debug("mev_analysis_error", error=str(e))
        
        # Same block analysis (for rules that check same_block)
        event["same_block"] = True  # All events in a batch are same-block by definition
        
        return event
    
    def record_tvl(
        self,
        protocol: str,
        chain: str,
        tvl_usd: float,
        block_number: int,
    ):
        """
        Record TVL snapshot for a protocol.
        
        Call this when processing liquidity events.
        """
        self._tvl_tracker.record_tvl(protocol, chain, tvl_usd, block_number)


# Global singleton
_enricher: Optional[EventEnricher] = None


def get_enricher() -> EventEnricher:
    """Get global event enricher instance."""
    global _enricher
    if _enricher is None:
        _enricher = EventEnricher()
    return _enricher
