"""Mempool pre-detection alerter.

Monitors pending transactions before they are confirmed on-chain,
enabling early warning for attacks still in the mempool.

Bridges the bloXroute (or pseudo) mempool source to the invariant
engine and alert pipeline so that suspicious transactions generate
pre-confirmation alerts marked with status=PENDING.
"""

import asyncio
from collections import deque
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import structlog

from .intent_sources.base import PendingTx, PendingTxSource
from .pubsub import get_runtime_pubsub
from ..models.events import EventType, SecurityEvent, Severity

logger = structlog.get_logger(__name__)

# Well-known function selectors
_SELECTOR_EVENT_TYPE = {
    "0xa9059cbb": EventType.TRANSFER,      # transfer(address,uint256)
    "0x23b872dd": EventType.TRANSFER,      # transferFrom
    "0x095ea7b3": EventType.TRANSFER,      # approve
    "0x38ed1739": EventType.SWAP,           # swapExactTokensForTokens
    "0x7ff36ab5": EventType.SWAP,           # swapExactETHForTokens
    "0x18cbafe5": EventType.SWAP,           # swapExactTokensForETH
}

_DANGEROUS_SELECTORS = {
    "0x5c19a95c": "delegate (governance attack)",
    "0x4e71d92d": "claim (potential exploit)",
    "0x8456cb59": "pause()",
    "0x3659cfe6": "upgradeTo(address)",
    "0x4f1ef286": "upgradeToAndCall(address,bytes)",
    "0xf2fde38b": "transferOwnership(address)",
}


class MempoolAlerter:
    """Bridges mempool data to the detection pipeline for pre-confirmation alerts."""

    def __init__(
        self,
        invariant_engine: Any = None,
        alert_router: Any = None,
        config: Optional[dict] = None,
    ):
        config = config or {}
        self.invariant_engine = invariant_engine
        self.alert_router = alert_router
        self.enabled: bool = config.get("mempool_alerting_enabled", True)
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._source: Optional[PendingTxSource] = None

        # Recent alerts ring-buffer (for /recent-alerts API)
        self._recent_alerts: deque = deque(maxlen=200)

        # Stats
        self._stats: Dict[str, int] = {
            "txs_scanned": 0,
            "pre_alerts_fired": 0,
            "false_positives": 0,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, mempool_source: PendingTxSource) -> None:
        """Start monitoring *mempool_source* for suspicious transactions."""
        if not self.enabled:
            logger.info("mempool_alerter_disabled")
            return

        self._running = True
        self._source = mempool_source
        logger.info("mempool_alerter_started")

        self._task = asyncio.create_task(self._poll_loop(mempool_source))

    async def stop(self) -> None:
        """Stop the mempool alerter gracefully."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("mempool_alerter_stopped")

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    async def _poll_loop(self, source: PendingTxSource) -> None:
        """Poll the mempool source and process each pending tx."""
        try:
            while self._running:
                try:
                    pending_txs = await source.get_pending_txs(limit=100)
                except Exception as exc:
                    logger.error("mempool_source_get_pending_failed", error=str(exc))
                    await asyncio.sleep(2)
                    continue

                for tx in pending_txs:
                    if not self._running:
                        break
                    await self._process_pending_tx(tx)

                # Avoid busy-looping when the queue is empty
                if not pending_txs:
                    await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("mempool_alerter_loop_error", error=str(exc))

    # ------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------

    async def _process_pending_tx(self, tx: PendingTx) -> None:
        """Run a single pending transaction through the detection pipeline."""
        self._stats["txs_scanned"] += 1

        # Quick heuristic scan
        is_suspicious, reasons = self._quick_scan(tx)

        if not is_suspicious:
            return

        self._stats["pre_alerts_fired"] += 1
        logger.warning(
            "mempool_suspicious_tx",
            tx_hash=tx.tx_hash[:16],
            reasons=reasons,
            from_addr=tx.from_address[:16] if tx.from_address else "",
            to_addr=(tx.to_address or "")[:16],
            value=tx.value,
        )

        # Build a SecurityEvent for the invariant engine
        event = self._tx_to_security_event(tx, reasons)

        # Feed the invariant engine (event-driven evaluation)
        if self.invariant_engine is not None:
            try:
                await self.invariant_engine.process_event(event)
            except Exception as exc:
                logger.debug("mempool_invariant_eval_error", error=str(exc))

        # Fire pre-confirmation alert via pubsub + websocket
        await self._fire_pre_alert(tx, reasons, event)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_event_type(tx: PendingTx) -> EventType:
        """Infer EventType from the function selector."""
        selector = (tx.selector or "")[:10].lower()
        return _SELECTOR_EVENT_TYPE.get(selector, EventType.SUSPICIOUS_CALL)

    def _tx_to_security_event(self, tx: PendingTx, reasons: List[str]) -> SecurityEvent:
        """Convert a PendingTx into a SecurityEvent with PENDING status."""
        return SecurityEvent(
            event_id=f"mempool-{tx.tx_hash}",
            chain_id=tx.chain_id,
            block_number=0,  # not yet mined
            block_timestamp=datetime.now(timezone.utc),
            tx_hash=tx.tx_hash,
            log_index=0,
            event_type=self._detect_event_type(tx),
            severity=Severity.MEDIUM,
            source_address=tx.from_address,
            dest_address=tx.to_address or "",
            contract_address=tx.to_address or "",
            amount=Decimal(str(tx.value)),
            raw_event={
                "status": "PENDING",
                "reasons": reasons,
                "gas_price": tx.gas_price,
                "selector": tx.selector,
            },
        )

    @staticmethod
    def _quick_scan(tx: PendingTx) -> Tuple[bool, List[str]]:
        """Cheap heuristic scan for suspicious patterns."""
        reasons: List[str] = []

        # Large native-value transfer (> ~10 ETH in wei)
        if tx.value > 10 * 10**18:
            reasons.append(f"Large value: {tx.value / 10**18:.2f} ETH")

        # Extremely high gas price (> 500 gwei) -- potential frontrunning
        gas_price = tx.gas_price or 0
        if gas_price > 500 * 10**9:
            reasons.append(f"High gas: {gas_price / 10**9:.0f} gwei")

        # Dangerous function selector
        selector = (tx.selector or "")[:10].lower()
        if selector in _DANGEROUS_SELECTORS:
            reasons.append(f"Dangerous call: {_DANGEROUS_SELECTORS[selector]}")

        # Contract creation with value
        if not tx.to_address and tx.value > 0:
            reasons.append("Contract creation with value")

        return bool(reasons), reasons

    async def _fire_pre_alert(
        self, tx: PendingTx, reasons: List[str], event: SecurityEvent
    ) -> None:
        """Broadcast a pre-confirmation alert via Redis PubSub and WebSocket."""
        alert_payload: Dict[str, Any] = {
            "type": "mempool_alert",
            "severity": "WARNING",
            "tx_hash": tx.tx_hash,
            "chain_id": tx.chain_id,
            "from": tx.from_address,
            "to": tx.to_address or "",
            "value": tx.value,
            "reasons": reasons,
            "status": "PENDING",
            "message": f"Pre-confirmation alert: {'; '.join(reasons)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Store for /recent-alerts
        self._recent_alerts.appendleft(alert_payload)

        # Redis PubSub (consumed by War Room)
        try:
            pubsub = await get_runtime_pubsub()
            await pubsub.publish_threat(
                chain_id=tx.chain_id,
                tx_hash=tx.tx_hash,
                contract=tx.to_address or "",
                protocol="mempool",
                risk_score=0.7,
                details={"reasons": reasons, "status": "PENDING"},
            )
        except Exception:
            pass

        # WebSocket broadcast (best-effort)
        try:
            from ..api.websocket_routes import manager
            await manager.broadcast_alert(alert_payload)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return runtime statistics."""
        return {
            **self._stats,
            "enabled": self.enabled,
            "running": self._running,
        }

    def get_recent_alerts(self, limit: int = 50) -> List[dict]:
        """Return the most recent mempool alerts."""
        return list(self._recent_alerts)[:limit]


# ---------------------------------------------------------------------------
# Module-level singleton (lazily set by worker startup)
# ---------------------------------------------------------------------------
_mempool_alerter: Optional[MempoolAlerter] = None


def get_mempool_alerter() -> Optional[MempoolAlerter]:
    """Return the global MempoolAlerter instance (or None if not started)."""
    return _mempool_alerter


def set_mempool_alerter(alerter: MempoolAlerter) -> None:
    """Register the global MempoolAlerter singleton."""
    global _mempool_alerter
    _mempool_alerter = alerter
