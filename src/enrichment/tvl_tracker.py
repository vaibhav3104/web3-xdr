"""
TVL Tracker
===========

Tracks Total Value Locked (TVL) for protocols to detect:
- Abnormal TVL drains
- Liquidity removal patterns
- Rug pull indicators
"""

from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class TVLSnapshot:
    """TVL snapshot at a point in time."""
    protocol: str
    chain: str
    tvl_usd: float
    timestamp: datetime
    block_number: int


@dataclass
class TVLChange:
    """TVL change event."""
    protocol: str
    chain: str
    old_tvl: float
    new_tvl: float
    change_usd: float
    change_percent: float
    timestamp: datetime
    duration_seconds: int


class TVLTracker:
    """
    Tracks TVL changes for protocols.
    
    Detects:
    - Rapid TVL drains (potential exploits)
    - Large liquidity removals
    - Abnormal withdrawal patterns
    """
    
    # Alert thresholds
    DRAIN_PERCENT_THRESHOLD = 10.0  # 10% drain in 1 hour
    DRAIN_USD_THRESHOLD = 1_000_000  # $1M drain
    RAPID_DRAIN_PERCENT = 50.0  # 50% drain (critical)
    
    def __init__(self, window_hours: int = 24):
        """
        Initialize TVL tracker.
        
        Args:
            window_hours: Hours of history to keep
        """
        self._window_hours = window_hours
        self._snapshots: Dict[str, List[TVLSnapshot]] = defaultdict(list)
        self._current_tvl: Dict[str, float] = {}
        logger.info("tvl_tracker_initialized", window_hours=window_hours)
    
    def _get_key(self, protocol: str, chain: str) -> str:
        """Get unique key for protocol+chain."""
        return f"{protocol}:{chain}"
    
    def record_tvl(
        self, 
        protocol: str, 
        chain: str, 
        tvl_usd: float,
        block_number: int,
        timestamp: Optional[datetime] = None
    ) -> Optional[TVLChange]:
        """
        Record a TVL snapshot and detect changes.
        
        Args:
            protocol: Protocol name
            chain: Chain name
            tvl_usd: Current TVL in USD
            block_number: Block number
            timestamp: Optional timestamp (defaults to now)
            
        Returns:
            TVLChange if significant change detected
        """
        timestamp = timestamp or datetime.utcnow()
        key = self._get_key(protocol, chain)
        
        # Create snapshot
        snapshot = TVLSnapshot(
            protocol=protocol,
            chain=chain,
            tvl_usd=tvl_usd,
            timestamp=timestamp,
            block_number=block_number,
        )
        
        # Get previous TVL
        old_tvl = self._current_tvl.get(key, tvl_usd)
        
        # Calculate change
        change_usd = tvl_usd - old_tvl
        change_percent = ((tvl_usd - old_tvl) / old_tvl * 100) if old_tvl > 0 else 0
        
        # Store snapshot
        self._snapshots[key].append(snapshot)
        self._current_tvl[key] = tvl_usd
        
        # Clean old snapshots
        self._cleanup_old_snapshots(key)
        
        # Check for significant change
        if abs(change_percent) >= self.DRAIN_PERCENT_THRESHOLD or abs(change_usd) >= self.DRAIN_USD_THRESHOLD:
            # Calculate duration since last snapshot
            duration = 0
            if len(self._snapshots[key]) >= 2:
                prev_snapshot = self._snapshots[key][-2]
                duration = int((timestamp - prev_snapshot.timestamp).total_seconds())
            
            return TVLChange(
                protocol=protocol,
                chain=chain,
                old_tvl=old_tvl,
                new_tvl=tvl_usd,
                change_usd=change_usd,
                change_percent=change_percent,
                timestamp=timestamp,
                duration_seconds=duration,
            )
        
        return None
    
    def _cleanup_old_snapshots(self, key: str):
        """Remove snapshots older than window."""
        cutoff = datetime.utcnow() - timedelta(hours=self._window_hours)
        self._snapshots[key] = [
            s for s in self._snapshots[key]
            if s.timestamp > cutoff
        ]
    
    def get_drain_rate(
        self, 
        protocol: str, 
        chain: str, 
        hours: float = 1.0
    ) -> Tuple[float, float]:
        """
        Get TVL drain rate over specified hours.
        
        Args:
            protocol: Protocol name
            chain: Chain name
            hours: Time window in hours
            
        Returns:
            Tuple of (drain_percent_per_hour, drain_amount_usd)
        """
        key = self._get_key(protocol, chain)
        snapshots = self._snapshots.get(key, [])
        
        if len(snapshots) < 2:
            return 0.0, 0.0
        
        # Get snapshots in time window
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        recent = [s for s in snapshots if s.timestamp > cutoff]
        
        if len(recent) < 2:
            return 0.0, 0.0
        
        # Calculate drain
        oldest = recent[0]
        newest = recent[-1]
        
        drain_usd = oldest.tvl_usd - newest.tvl_usd
        drain_percent = (drain_usd / oldest.tvl_usd * 100) if oldest.tvl_usd > 0 else 0
        
        # Normalize to per-hour rate
        actual_hours = (newest.timestamp - oldest.timestamp).total_seconds() / 3600
        if actual_hours > 0:
            drain_percent_per_hour = drain_percent / actual_hours
        else:
            drain_percent_per_hour = drain_percent
        
        return drain_percent_per_hour, drain_usd
    
    def is_draining(
        self, 
        protocol: str, 
        chain: str,
        threshold_percent: float = None,
        threshold_usd: float = None
    ) -> bool:
        """
        Check if protocol is experiencing abnormal drain.
        
        Args:
            protocol: Protocol name
            chain: Chain name
            threshold_percent: Override drain percent threshold
            threshold_usd: Override drain USD threshold
            
        Returns:
            True if draining above threshold
        """
        threshold_percent = threshold_percent or self.DRAIN_PERCENT_THRESHOLD
        threshold_usd = threshold_usd or self.DRAIN_USD_THRESHOLD
        
        drain_rate, drain_usd = self.get_drain_rate(protocol, chain)
        
        return drain_rate >= threshold_percent or drain_usd >= threshold_usd
    
    def get_liquidity_change_percent(
        self,
        protocol: str,
        chain: str,
        hours: float = 1.0
    ) -> float:
        """
        Get liquidity change percentage over time window.
        
        Args:
            protocol: Protocol name
            chain: Chain name
            hours: Time window
            
        Returns:
            Percentage change (negative = decrease)
        """
        key = self._get_key(protocol, chain)
        snapshots = self._snapshots.get(key, [])
        
        if len(snapshots) < 2:
            return 0.0
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        recent = [s for s in snapshots if s.timestamp > cutoff]
        
        if len(recent) < 2:
            return 0.0
        
        oldest = recent[0]
        newest = recent[-1]
        
        if oldest.tvl_usd > 0:
            return ((newest.tvl_usd - oldest.tvl_usd) / oldest.tvl_usd) * 100
        return 0.0
    
    def get_current_tvl(self, protocol: str, chain: str) -> float:
        """Get current TVL for protocol."""
        key = self._get_key(protocol, chain)
        return self._current_tvl.get(key, 0.0)
    
    def get_tvl_history(
        self, 
        protocol: str, 
        chain: str,
        hours: float = 24.0
    ) -> List[TVLSnapshot]:
        """Get TVL history for protocol."""
        key = self._get_key(protocol, chain)
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [
            s for s in self._snapshots.get(key, [])
            if s.timestamp > cutoff
        ]


# Global singleton
_tvl_tracker: Optional[TVLTracker] = None


def get_tvl_tracker() -> TVLTracker:
    """Get global TVL tracker instance."""
    global _tvl_tracker
    if _tvl_tracker is None:
        _tvl_tracker = TVLTracker()
    return _tvl_tracker
