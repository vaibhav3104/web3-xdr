"""
Finality and Reorg Tracker
==========================

Tracks block finality and detects reorgs for all chains.
Ensures events are only marked CONFIRMED after finality threshold.

Chain-specific finality:
- Ethereum: ~12-15 blocks (2-3 minutes)
- Polygon: ~128 blocks (~2 minutes)
- Arbitrum: ~1 block (instant finality)
- BSC: ~15 blocks (~45 seconds)
- Cosmos: ~100 blocks (~2 minutes)
- Solana: ~32 slots (~13 seconds)
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Coroutine, Dict, List, Optional, Any
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)

# Type alias for reorg callbacks
ReorgCallback = Callable[[str, int, List[int]], Coroutine[Any, Any, None]]
# signature: (chain_id, reorg_block, affected_block_numbers) -> None


class FinalityStatus(Enum):
    """Finality status of a block."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REORGED = "reorged"


@dataclass
class BlockInfo:
    """Information about a block."""
    number: int
    hash: str
    parent_hash: Optional[str] = None
    timestamp: Optional[datetime] = None
    status: FinalityStatus = FinalityStatus.PENDING


@dataclass
class ChainFinalityConfig:
    """Finality configuration for a chain."""
    chain_id: str
    confirmations: int  # Blocks needed for finality
    max_reorg_depth: int  # Maximum reorg depth to track
    block_time_seconds: float  # Average block time


# Chain-specific defaults
DEFAULT_FINALITY_CONFIGS = {
    "ethereum": ChainFinalityConfig("ethereum", 12, 12, 12.0),
    "polygon": ChainFinalityConfig("polygon", 128, 128, 2.0),
    "arbitrum": ChainFinalityConfig("arbitrum", 1, 1, 0.25),
    "optimism": ChainFinalityConfig("optimism", 1, 1, 2.0),
    "bsc": ChainFinalityConfig("bsc", 15, 15, 3.0),
    "avalanche": ChainFinalityConfig("avalanche", 1, 1, 2.0),
    "cosmos": ChainFinalityConfig("cosmos", 100, 100, 1.2),
    "solana": ChainFinalityConfig("solana", 32, 32, 0.4),
    "near": ChainFinalityConfig("near", 1, 1, 1.0),
    "aptos": ChainFinalityConfig("aptos", 1, 1, 4.0),
    "sui": ChainFinalityConfig("sui", 1, 1, 3.0),
}


class FinalityTracker:
    """
    Tracks block finality and detects reorgs.
    
    Maintains a sliding window of recent blocks with their hashes.
    When a block is beyond the finality threshold and its hash chain
    is consistent, it's marked as CONFIRMED.
    """
    
    def __init__(self, config: ChainFinalityConfig):
        self.config = config

        # Sliding window: block_number -> BlockInfo
        self.block_window: Dict[int, BlockInfo] = {}

        # Track head block
        self.head_block: Optional[BlockInfo] = None

        # Track last confirmed block
        self.last_confirmed_block: int = 0

        # Track reorgs
        self.reorg_count = 0
        self.last_reorg_at: Optional[datetime] = None

        # Reorg callbacks — called with (chain_id, reorg_block, affected_blocks)
        self._reorg_callbacks: List[ReorgCallback] = []

        logger.info(
            "finality_tracker_initialized",
            chain=self.config.chain_id,
            confirmations=self.config.confirmations,
            max_reorg_depth=self.config.max_reorg_depth
        )

    def on_reorg(self, callback: ReorgCallback):
        """Register a callback to fire when a reorg is detected."""
        self._reorg_callbacks.append(callback)
    
    def update_head(self, block_number: int, block_hash: str, parent_hash: Optional[str] = None):
        """Update the chain head."""
        block_info = BlockInfo(
            number=block_number,
            hash=block_hash,
            parent_hash=parent_hash,
            timestamp=datetime.now(timezone.utc)
        )
        
        self.head_block = block_info
        self.block_window[block_number] = block_info
        
        # Check for reorg
        if parent_hash and block_number > 1:
            prev_block = self.block_window.get(block_number - 1)
            if prev_block and prev_block.hash != parent_hash:
                logger.warning(
                    "reorg_detected",
                    chain=self.config.chain_id,
                    block=block_number,
                    expected_hash=prev_block.hash,
                    actual_parent=parent_hash
                )
                self.reorg_count += 1
                self.last_reorg_at = datetime.now(timezone.utc)
                self._handle_reorg(block_number)
        
        # Prune old blocks
        self._prune_blocks()
        
        # Update confirmed block
        self._update_confirmed_block()
    
    def _handle_reorg(self, reorg_block: int):
        """Handle a detected reorg and notify listeners."""
        # Mark blocks from reorg point as REORGED
        affected_blocks = [
            num for num in self.block_window.keys()
            if num >= reorg_block - self.config.max_reorg_depth
        ]

        for block_num in affected_blocks:
            if block_num in self.block_window:
                self.block_window[block_num].status = FinalityStatus.REORGED

        # Reset last confirmed if it was affected
        if self.last_confirmed_block >= reorg_block - self.config.confirmations:
            self.last_confirmed_block = max(0, reorg_block - self.config.confirmations - 1)
            logger.warning(
                "reorg_affected_confirmed_block",
                chain=self.config.chain_id,
                reset_to=self.last_confirmed_block
            )

        # Fire reorg callbacks to invalidate events/incidents from affected blocks
        for callback in self._reorg_callbacks:
            try:
                asyncio.ensure_future(
                    callback(self.config.chain_id, reorg_block, affected_blocks)
                )
            except Exception as e:
                logger.error("reorg_callback_failed", error=str(e))
    
    def _prune_blocks(self):
        """Remove blocks older than max_reorg_depth."""
        if not self.head_block:
            return
        
        cutoff = self.head_block.number - self.config.max_reorg_depth - self.config.confirmations
        
        blocks_to_remove = [
            num for num in self.block_window.keys()
            if num < cutoff
        ]
        
        for block_num in blocks_to_remove:
            del self.block_window[block_num]
    
    def _update_confirmed_block(self):
        """Update the last confirmed block number."""
        if not self.head_block:
            return
        
        confirmed_candidate = self.head_block.number - self.config.confirmations
        
        if confirmed_candidate <= 0:
            return
        
        # Verify hash chain consistency
        if self._is_hash_chain_consistent(confirmed_candidate):
            if confirmed_candidate > self.last_confirmed_block:
                self.last_confirmed_block = confirmed_candidate
                
                # Mark block as confirmed
                if confirmed_candidate in self.block_window:
                    self.block_window[confirmed_candidate].status = FinalityStatus.CONFIRMED
    
    def _is_hash_chain_consistent(self, block_number: int) -> bool:
        """Check if hash chain is consistent up to block_number."""
        if block_number not in self.block_window:
            return False
        
        # Check parent chain consistency
        current = self.block_window[block_number]
        check_block = block_number - 1
        
        while check_block > max(0, block_number - self.config.confirmations):
            if check_block not in self.block_window:
                return False
            
            prev_block = self.block_window[check_block]
            if current.parent_hash and current.parent_hash != prev_block.hash:
                return False
            
            current = prev_block
            check_block -= 1
        
        return True
    
    def is_confirmed(self, block_number: int) -> bool:
        """Check if a block is confirmed (beyond finality threshold)."""
        return block_number <= self.last_confirmed_block
    
    def get_confirmed_blocks(self) -> List[int]:
        """Get list of confirmed block numbers."""
        return [
            num for num, info in self.block_window.items()
            if info.status == FinalityStatus.CONFIRMED
        ]
    
    def get_status(self) -> Dict[str, any]:
        """Get tracker status."""
        return {
            "chain_id": self.config.chain_id,
            "head_block": self.head_block.number if self.head_block else 0,
            "last_confirmed_block": self.last_confirmed_block,
            "blocks_tracked": len(self.block_window),
            "reorg_count": self.reorg_count,
            "last_reorg_at": self.last_reorg_at.isoformat() if self.last_reorg_at else None,
            "confirmations_required": self.config.confirmations,
            "blocks_behind": (self.head_block.number - self.last_confirmed_block) if self.head_block else 0,
        }


class FinalityTrackerManager:
    """Manages finality trackers for multiple chains."""
    
    def __init__(self):
        self.trackers: Dict[str, FinalityTracker] = {}
        self._global_reorg_callbacks: List[ReorgCallback] = []

    def get_tracker(self, chain_id: str, config: Optional[ChainFinalityConfig] = None) -> FinalityTracker:
        """Get or create a tracker for a chain."""
        if chain_id not in self.trackers:
            if config:
                tracker_config = config
            else:
                tracker_config = DEFAULT_FINALITY_CONFIGS.get(
                    chain_id,
                    ChainFinalityConfig(chain_id, 12, 12, 12.0)  # Safe default
                )
            tracker = FinalityTracker(tracker_config)
            for cb in self._global_reorg_callbacks:
                tracker.on_reorg(cb)
            self.trackers[chain_id] = tracker

        return self.trackers[chain_id]
    
    def update_chain_head(self, chain_id: str, block_number: int, block_hash: str, parent_hash: Optional[str] = None):
        """Update chain head for a specific chain."""
        tracker = self.get_tracker(chain_id)
        tracker.update_head(block_number, block_hash, parent_hash)
    
    def is_block_confirmed(self, chain_id: str, block_number: int) -> bool:
        """Check if a block is confirmed."""
        if chain_id not in self.trackers:
            return False
        return self.trackers[chain_id].is_confirmed(block_number)
    
    def register_reorg_handler(self, callback: ReorgCallback):
        """Register a reorg handler on ALL current and future trackers."""
        self._global_reorg_callbacks.append(callback)
        for tracker in self.trackers.values():
            tracker.on_reorg(callback)

    def get_all_statuses(self) -> Dict[str, Dict[str, any]]:
        """Get status for all trackers."""
        return {
            chain_id: tracker.get_status()
            for chain_id, tracker in self.trackers.items()
        }


async def invalidate_reorged_events(chain_id: str, reorg_block: int, affected_blocks: List[int]):
    """
    Default reorg handler: marks events/incidents from affected blocks as invalidated.

    Logs a critical warning and attempts to update the database to mark
    incidents from reorged blocks as false positives (since the underlying
    transactions may no longer exist on the canonical chain).
    """
    logger.critical(
        "reorg_invalidation_triggered",
        chain_id=chain_id,
        reorg_block=reorg_block,
        affected_block_count=len(affected_blocks),
        affected_range=f"{min(affected_blocks)}-{max(affected_blocks)}" if affected_blocks else "none",
    )

    if not affected_blocks:
        return

    try:
        from ..database.service import DatabaseService

        # Mark incidents from affected blocks as needing re-evaluation
        for block_num in affected_blocks:
            incidents = await DatabaseService.get_incidents_by_block(
                chain_id=chain_id, block_number=block_num
            )
            for incident in (incidents or []):
                await DatabaseService.update_incident_status(
                    incident_id=incident.incident_id,
                    new_status="REORG_INVALIDATED",
                    analyst_id="system",
                    notes=f"Block {block_num} was reorged at block {reorg_block}. "
                          f"Events from this block are no longer on the canonical chain.",
                )
                logger.warning(
                    "incident_invalidated_by_reorg",
                    incident_id=incident.incident_id,
                    block_number=block_num,
                    chain_id=chain_id,
                )
    except ImportError:
        logger.debug("database_service_not_available_for_reorg_invalidation")
    except Exception as e:
        # Best-effort — reorg invalidation should not crash the tracker
        logger.error("reorg_invalidation_error", error=str(e), chain_id=chain_id)

