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
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


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
        
        logger.info(
            "finality_tracker_initialized",
            chain=self.config.chain_id,
            confirmations=self.config.confirmations,
            max_reorg_depth=self.config.max_reorg_depth
        )
    
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
        """Handle a detected reorg."""
        # Mark blocks from reorg point as REORGED
        blocks_to_mark = [
            num for num in self.block_window.keys()
            if num >= reorg_block - self.config.max_reorg_depth
        ]
        
        for block_num in blocks_to_mark:
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
            self.trackers[chain_id] = FinalityTracker(tracker_config)
        
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
    
    def get_all_statuses(self) -> Dict[str, Dict[str, any]]:
        """Get status for all trackers."""
        return {
            chain_id: tracker.get_status()
            for chain_id, tracker in self.trackers.items()
        }

