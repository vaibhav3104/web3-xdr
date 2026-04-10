"""
Velocity Invariants - Rate and speed-based detection.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Dict, List, Optional
import structlog

from .base import Invariant, InvariantContext, InvariantRegistry
from ..models.events import EventType, Severity
from ..models.invariants import InvariantResult, InvariantType

logger = structlog.get_logger()


@InvariantRegistry.register("TVL_VELOCITY")
class TVLVelocityInvariant(Invariant):
    """
    TVL should not decrease faster than threshold.
    
    INVARIANT: Δ TVL / Δt < max_drain_rate
    
    Rapid TVL drain indicates:
    - Active exploit draining funds
    - Panic withdrawal (front-running suspected exploit)
    - Coordinated liquidity attack
    """
    
    description = "TVL drain rate must not exceed threshold"
    invariant_type = InvariantType.VELOCITY
    severity = Severity.HIGH
    cooldown_seconds = 300  # 5 minutes between checks
    
    def __init__(
        self,
        bridge_id: str,
        max_drain_percent_per_hour: float = 10.0,
        min_drain_usd: float = 100_000,
        measurement_window: timedelta = timedelta(hours=1)
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.max_drain_rate = max_drain_percent_per_hour / 100
        self.min_drain_usd = min_drain_usd
        self.measurement_window = measurement_window
        
        # Historical TVL snapshots
        self._tvl_history: List[Dict] = []
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check TVL drain velocity.
        """
        # Get current TVL
        current_tvl = await context.get_tvl(self.bridge_id)
        now = datetime.now(timezone.utc)
        
        # Record snapshot
        self._tvl_history.append({
            "timestamp": now,
            "tvl": current_tvl
        })
        
        # Prune old snapshots
        cutoff = now - timedelta(hours=24)
        self._tvl_history = [s for s in self._tvl_history if s["timestamp"] > cutoff]
        
        # Find TVL from measurement window ago
        window_ago = now - self.measurement_window
        historical_tvl = None
        
        for snapshot in self._tvl_history:
            if snapshot["timestamp"] <= window_ago:
                historical_tvl = snapshot["tvl"]
        
        if historical_tvl is None or historical_tvl == 0:
            return InvariantResult(
                violated=False,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                bridge_id=self.bridge_id
            )
        
        # Calculate drain
        drain_amount = float(historical_tvl - current_tvl)
        drain_rate = drain_amount / float(historical_tvl)
        
        # Check thresholds
        if drain_rate > self.max_drain_rate and drain_amount > self.min_drain_usd:
            self.record_violation()
            
            # Calculate drain per block (rough estimate)
            # Assume ~12 second blocks, 300 blocks per hour
            drain_per_block = drain_amount / 300
            time_to_empty = float(current_tvl) / drain_per_block if drain_per_block > 0 else float('inf')
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=Severity.CRITICAL if drain_rate > self.max_drain_rate * 2 else Severity.HIGH,
                violation_amount=Decimal(str(drain_amount)),
                violation_amount_usd=drain_amount,
                bridge_id=self.bridge_id,
                evidence={
                    "tvl_now": float(current_tvl),
                    "tvl_historical": float(historical_tvl),
                    "drain_amount_usd": drain_amount,
                    "drain_rate_percent": drain_rate * 100,
                    "drain_per_block_usd": drain_per_block,
                    "estimated_blocks_to_empty": int(time_to_empty),
                    "measurement_window_hours": self.measurement_window.total_seconds() / 3600
                },
                description=f"TVL draining at {drain_rate*100:.1f}% per hour ({drain_amount:,.0f} USD)"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("TRANSACTION_VELOCITY")
class TransactionVelocityInvariant(Invariant):
    """
    Transaction frequency should not exceed normal patterns.
    
    INVARIANT: tx_count_per_hour < threshold × historical_average
    
    Detects:
    - Automated exploit scripts
    - Bot activity
    - Abnormal usage patterns
    """
    
    description = "Transaction velocity must not exceed threshold"
    invariant_type = InvariantType.VELOCITY
    severity = Severity.MEDIUM
    
    def __init__(
        self,
        bridge_id: str,
        max_tx_per_hour: int = 1000,
        spike_multiplier: float = 5.0  # 5x normal = alert
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.max_tx_per_hour = max_tx_per_hour
        self.spike_multiplier = spike_multiplier
        
        # Track transaction counts
        self._tx_counts: List[Dict] = []  # [{timestamp, count}, ...]
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check transaction velocity.
        """
        # Get transactions in last hour
        events = await context.get_events(
            bridge_id=self.bridge_id,
            window=timedelta(hours=1)
        )
        
        current_count = len(events)
        now = datetime.now(timezone.utc)
        
        # Record
        self._tx_counts.append({"timestamp": now, "count": current_count})
        
        # Prune old data
        cutoff = now - timedelta(days=7)
        self._tx_counts = [c for c in self._tx_counts if c["timestamp"] > cutoff]
        
        # Calculate historical average
        if len(self._tx_counts) < 24:  # Need at least 24 hours of data
            return InvariantResult(
                violated=False,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                bridge_id=self.bridge_id
            )
        
        historical_avg = sum(c["count"] for c in self._tx_counts[:-1]) / (len(self._tx_counts) - 1)
        
        # Check for spike
        is_spike = current_count > historical_avg * self.spike_multiplier
        is_absolute_high = current_count > self.max_tx_per_hour
        
        if is_spike or is_absolute_high:
            self.record_violation()
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=Severity.HIGH if is_spike and is_absolute_high else Severity.MEDIUM,
                bridge_id=self.bridge_id,
                evidence={
                    "current_tx_count": current_count,
                    "historical_avg": historical_avg,
                    "spike_multiplier": current_count / historical_avg if historical_avg > 0 else 0,
                    "max_tx_per_hour": self.max_tx_per_hour
                },
                description=f"Transaction velocity spike: {current_count} tx/hour ({current_count/historical_avg:.1f}x normal)"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("LARGE_TRANSACTION_VELOCITY")
class LargeTransactionVelocityInvariant(Invariant):
    """
    Large transactions should not occur in rapid succession.
    
    INVARIANT: count(tx > threshold) in window < max_count
    
    Detects rapid extraction of funds through multiple large transfers.
    """
    
    description = "Large transactions must not occur in rapid succession"
    invariant_type = InvariantType.VELOCITY
    severity = Severity.HIGH
    
    def __init__(
        self,
        bridge_id: str,
        large_tx_threshold_usd: float = 100_000,
        max_large_tx_per_hour: int = 5,
        window: timedelta = timedelta(hours=1)
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.large_tx_threshold = large_tx_threshold_usd
        self.max_large_tx = max_large_tx_per_hour
        self.window = window
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check for rapid large transactions.
        """
        # Get all events (locks, unlocks, transfers)
        events = await context.get_events(
            bridge_id=self.bridge_id,
            window=self.window
        )
        
        # Filter large transactions
        large_txs = [
            e for e in events
            if float(e.amount_usd) > self.large_tx_threshold
        ]
        
        if len(large_txs) > self.max_large_tx:
            self.record_violation()
            
            total_volume = sum(float(e.amount_usd) for e in large_txs)
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=Severity.CRITICAL if len(large_txs) > self.max_large_tx * 2 else Severity.HIGH,
                violation_amount=Decimal(str(total_volume)),
                violation_amount_usd=total_volume,
                bridge_id=self.bridge_id,
                evidence={
                    "large_tx_count": len(large_txs),
                    "threshold": self.max_large_tx,
                    "total_volume_usd": total_volume,
                    "transactions": [e.to_dict() for e in large_txs[:10]]  # First 10
                },
                description=f"Detected {len(large_txs)} large transactions (>{self.large_tx_threshold:,.0f} USD) in {self.window}"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )


@InvariantRegistry.register("SINGLE_BLOCK_CONCENTRATION")
class SingleBlockConcentrationInvariant(Invariant):
    """
    Suspicious activity concentrated in single block (flash loan pattern).
    
    INVARIANT: High-value operations should not all occur in one block.
    
    Detects:
    - Flash loan attacks
    - MEV extraction
    - Atomic exploits
    """
    
    description = "High-value operations must not concentrate in single block"
    invariant_type = InvariantType.VELOCITY
    severity = Severity.CRITICAL
    
    def __init__(
        self,
        bridge_id: str,
        min_volume_usd: float = 1_000_000,
        min_operations: int = 3
    ):
        super().__init__()
        self.bridge_id = bridge_id
        self.min_volume_usd = min_volume_usd
        self.min_operations = min_operations
    
    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Check for single-block concentration.
        """
        # Get recent events
        events = await context.get_events(
            bridge_id=self.bridge_id,
            window=timedelta(minutes=5)
        )
        
        # Group by block
        blocks: Dict[int, List] = {}
        for event in events:
            if event.block_number not in blocks:
                blocks[event.block_number] = []
            blocks[event.block_number].append(event)
        
        # Check each block
        suspicious_blocks = []
        
        for block_num, block_events in blocks.items():
            if len(block_events) < self.min_operations:
                continue
            
            total_volume = sum(float(e.amount_usd) for e in block_events)
            
            if total_volume >= self.min_volume_usd:
                suspicious_blocks.append({
                    "block_number": block_num,
                    "operation_count": len(block_events),
                    "total_volume_usd": total_volume,
                    "events": [e.to_dict() for e in block_events]
                })
        
        if suspicious_blocks:
            self.record_violation()
            
            return InvariantResult(
                violated=True,
                invariant_name=self.name,
                invariant_type=self.invariant_type,
                severity=self.severity,
                bridge_id=self.bridge_id,
                evidence={
                    "suspicious_blocks": suspicious_blocks,
                    "count": len(suspicious_blocks)
                },
                description=f"Detected {len(suspicious_blocks)} blocks with concentrated high-value operations"
            )
        
        return InvariantResult(
            violated=False,
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            bridge_id=self.bridge_id
        )

