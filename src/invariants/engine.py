"""
Invariant Engine - Orchestrates invariant evaluation.
"""

from datetime import datetime, timezone
from typing import Awaitable, Any, Callable, List, Optional
import asyncio
import structlog

from .base import Invariant, InvariantContext, InvariantRegistry
from ..models.events import SecurityEvent
from ..models.invariants import InvariantResult

logger = structlog.get_logger()


class InvariantEngine:
    """
    Orchestrates real-time invariant evaluation.
    
    Features:
    - Event-driv
    en evaluation
    - Periodic background checks
    - Result aggregation
    - Handler callbacks
    """
    
    def __init__(self, context: Optional[InvariantContext] = None, price_feed=None):
        self.context = context or InvariantContext(price_feed=price_feed)
        self.invariants: List[Invariant] = []
        self.result_handlers: List[Callable[[InvariantResult], Awaitable[Any]]] = []
        
        self._is_running = False
        self._background_task: Optional[asyncio.Task] = None
        
        # Statistics
        self._stats = {
            "events_processed": 0,
            "invariants_checked": 0,
            "violations_detected": 0,
            "last_event_time": None,
            "last_check_time": None,
        }
    
    def add_invariant(self, invariant: Invariant):
        """Add an invariant to monitor."""
        self.invariants.append(invariant)
        logger.info(
            "invariant_added",
            name=invariant.name,
            type=invariant.invariant_type.value
        )
    
    def add_invariants_from_config(self, config: dict):
        """
        Add invariants from configuration.
        
        Config format:
        {
            "invariants": [
                {
                    "name": "MINT_LOCK_PARITY",
                    "enabled": true,
                    "params": {
                        "bridge_id": "wormhole",
                        "source_chain": "ethereum",
                        "dest_chain": "solana"
                    }
                }
            ]
        }
        """
        for inv_config in config.get("invariants", []):
            if not inv_config.get("enabled", True):
                continue
            
            invariant = InvariantRegistry.create(
                inv_config["name"],
                **inv_config.get("params", {})
            )
            
            if invariant:
                self.add_invariant(invariant)
            else:
                logger.warning(
                    "unknown_invariant",
                    name=inv_config["name"]
                )
    
    def add_result_handler(
        self,
        handler: Callable[[InvariantResult], Awaitable[Any]]
    ):
        """Add a handler for invariant violations."""
        self.result_handlers.append(handler)
    
    async def process_event(self, event: SecurityEvent):
        """
        Process a new security event.
        
        Adds to context and triggers relevant invariant checks.
        """
        # Add to context
        self.context.add_event(event)
        
        self._stats["events_processed"] += 1
        self._stats["last_event_time"] = datetime.now(timezone.utc)
        
        # Trigger event-driven invariants
        await self._check_invariants(event_triggered=True)
    
    async def _check_invariants(self, event_triggered: bool = False):
        """
        Check all invariants.
        """
        results = []
        
        for invariant in self.invariants:
            if not invariant.should_check():
                continue
            
            try:
                result = await invariant.evaluate(self.context)
                self._stats["invariants_checked"] += 1
                
                if result.violated:
                    self._stats["violations_detected"] += 1
                    results.append(result)
                    
                    logger.warning(
                        "invariant_violation",
                        invariant=invariant.name,
                        severity=result.severity.name,
                        confidence=result.confidence
                    )
                    
            except Exception as e:
                logger.error(
                    "invariant_check_error",
                    invariant=invariant.name,
                    error=str(e)
                )
        
        self._stats["last_check_time"] = datetime.now(timezone.utc)
        
        # Notify handlers
        for result in results:
            await self._notify_handlers(result)
        
        return results
    
    async def _notify_handlers(self, result: InvariantResult):
        """Notify all result handlers of a violation."""
        await asyncio.gather(
            *[handler(result) for handler in self.result_handlers],
            return_exceptions=True
        )
    
    async def start_background_checks(self, interval_seconds: int = 60):
        """
        Start periodic background checks.
        
        Some invariants need periodic evaluation (e.g., TVL velocity)
        even without new events.
        """
        self._is_running = True
        
        async def background_loop():
            while self._is_running:
                try:
                    await self._check_invariants(event_triggered=False)
                except Exception as e:
                    logger.error("background_check_error", error=str(e))
                
                await asyncio.sleep(interval_seconds)
        
        self._background_task = asyncio.create_task(background_loop())
        logger.info(
            "background_checks_started",
            interval_seconds=interval_seconds
        )
    
    async def stop(self):
        """Stop the engine."""
        self._is_running = False
        
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
        
        logger.info("invariant_engine_stopped")
    
    def get_stats(self) -> dict:
        """Get engine statistics."""
        return {
            **self._stats,
            "invariant_count": len(self.invariants),
            "handler_count": len(self.result_handlers),
            "is_running": self._is_running,
        }
    
    def get_invariant_status(self) -> List[dict]:
        """Get status of all invariants."""
        return [inv.get_metadata() for inv in self.invariants]


def create_default_engine(config: dict) -> InvariantEngine:
    """
    Factory function to create an engine with standard invariants.
    """
    from ..telemetry.price_feed import get_price_feed

    price_feed = get_price_feed()
    engine = InvariantEngine(price_feed=price_feed)
    
    # Add invariants based on config
    bridges = config.get("bridges", [])
    
    for bridge in bridges:
        bridge_id = bridge["id"]
        source_chain = bridge["source_chain"]
        dest_chain = bridge["dest_chain"]
        
        # Core economic invariants
        from .economic import (
            MintLockParityInvariant,
            UnbackedMintInvariant,
        )
        
        engine.add_invariant(MintLockParityInvariant(
            bridge_id=bridge_id,
            source_chain=source_chain,
            dest_chain=dest_chain,
        ))
        
        engine.add_invariant(UnbackedMintInvariant(
            bridge_id=bridge_id,
            source_chain=source_chain,
            dest_chain=dest_chain,
        ))
        
        # Temporal invariants
        from .temporal import SequenceInvariant, ReplayProtectionInvariant
        
        engine.add_invariant(SequenceInvariant(bridge_id=bridge_id))
        engine.add_invariant(ReplayProtectionInvariant(bridge_id=bridge_id))
        
        # Velocity invariants
        from .velocity import TVLVelocityInvariant, LargeTransactionVelocityInvariant
        
        engine.add_invariant(TVLVelocityInvariant(bridge_id=bridge_id))
        engine.add_invariant(LargeTransactionVelocityInvariant(bridge_id=bridge_id))
        
        # Threshold invariants
        if "contracts" in bridge:
            from .threshold import AdminActionInvariant
            engine.add_invariant(AdminActionInvariant(
                contract_addresses=bridge["contracts"]
            ))
    
    logger.info(
        "default_engine_created",
        invariant_count=len(engine.invariants)
    )
    
    return engine

