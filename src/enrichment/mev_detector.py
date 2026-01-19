"""
MEV Detector
============

Detects MEV (Maximal Extractable Value) patterns:
- Sandwich attacks
- Front-running
- Back-running
- JIT (Just-In-Time) liquidity
- Arbitrage
"""

from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class MEVType(Enum):
    """MEV attack types."""
    SANDWICH = "sandwich"
    FRONTRUN = "frontrun"
    BACKRUN = "backrun"
    JIT_LIQUIDITY = "jit_liquidity"
    ARBITRAGE = "arbitrage"
    LIQUIDATION = "liquidation"


@dataclass
class Transaction:
    """Transaction for MEV analysis."""
    tx_hash: str
    block_number: int
    tx_index: int  # Position in block
    from_address: str
    to_address: str
    event_type: str
    amount_usd: float
    gas_price: int
    timestamp: datetime
    contract_address: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class MEVDetection:
    """MEV detection result."""
    mev_type: MEVType
    block_number: int
    transactions: List[Transaction]
    profit_usd: float
    victim_loss_usd: float
    attacker_address: str
    confidence: float  # 0-1
    details: Dict = field(default_factory=dict)


class MEVDetector:
    """
    Detects MEV patterns in blockchain transactions.
    
    Analyzes:
    - Same-block transaction patterns
    - Gas price anomalies
    - Liquidity add/remove patterns
    - Swap sequences
    """
    
    # Thresholds
    SANDWICH_MIN_PROFIT_USD = 100  # Minimum profit to flag
    FRONTRUN_GAS_RATIO = 1.5  # Gas price 50% higher than average
    JIT_TIME_WINDOW_BLOCKS = 1  # Add and remove in same block
    
    def __init__(self, block_window: int = 100):
        """
        Initialize MEV detector.
        
        Args:
            block_window: Number of blocks to keep in memory
        """
        self._block_window = block_window
        self._transactions: Dict[int, List[Transaction]] = defaultdict(list)
        self._block_gas_prices: Dict[int, List[int]] = defaultdict(list)
        self._detections: List[MEVDetection] = []
        logger.info("mev_detector_initialized", block_window=block_window)
    
    def add_transaction(self, tx: Transaction) -> List[MEVDetection]:
        """
        Add a transaction and check for MEV patterns.
        
        Args:
            tx: Transaction to analyze
            
        Returns:
            List of MEV detections (if any)
        """
        # Store transaction
        self._transactions[tx.block_number].append(tx)
        self._block_gas_prices[tx.block_number].append(tx.gas_price)
        
        # Cleanup old blocks
        self._cleanup_old_blocks(tx.block_number)
        
        # Analyze for MEV patterns
        detections = []
        
        # Check sandwich attack
        sandwich = self._detect_sandwich(tx)
        if sandwich:
            detections.append(sandwich)
        
        # Check front-running
        frontrun = self._detect_frontrun(tx)
        if frontrun:
            detections.append(frontrun)
        
        # Check JIT liquidity
        jit = self._detect_jit_liquidity(tx)
        if jit:
            detections.append(jit)
        
        self._detections.extend(detections)
        return detections
    
    def _cleanup_old_blocks(self, current_block: int):
        """Remove transactions from old blocks."""
        cutoff = current_block - self._block_window
        old_blocks = [b for b in self._transactions.keys() if b < cutoff]
        for block in old_blocks:
            del self._transactions[block]
            if block in self._block_gas_prices:
                del self._block_gas_prices[block]
    
    def _detect_sandwich(self, tx: Transaction) -> Optional[MEVDetection]:
        """
        Detect sandwich attack pattern.
        
        Pattern: 
        1. Attacker buys (front-run)
        2. Victim swaps (target)
        3. Attacker sells (back-run)
        
        All in same block, attacker txs have higher gas price.
        """
        block_txs = self._transactions.get(tx.block_number, [])
        
        if len(block_txs) < 3:
            return None
        
        # Look for swap sequences
        swaps = [t for t in block_txs if t.event_type.lower() in ("swap", "transfer")]
        
        if len(swaps) < 3:
            return None
        
        # Sort by tx_index
        swaps.sort(key=lambda t: t.tx_index)
        
        # Look for pattern: same token, buy-swap-sell
        for i in range(len(swaps) - 2):
            front = swaps[i]
            victim = swaps[i + 1]
            back = swaps[i + 2]
            
            # Check if same attacker
            if front.from_address != back.from_address:
                continue
            
            # Check if different from victim
            if front.from_address == victim.from_address:
                continue
            
            # Check if same contract (same pool)
            if front.contract_address != victim.contract_address:
                continue
            if victim.contract_address != back.contract_address:
                continue
            
            # Check gas prices (attacker should pay more)
            if front.gas_price <= victim.gas_price:
                continue
            
            # Calculate estimated profit
            # Simplified: assume profit is difference between back and front
            profit = back.amount_usd - front.amount_usd
            
            if profit > self.SANDWICH_MIN_PROFIT_USD:
                return MEVDetection(
                    mev_type=MEVType.SANDWICH,
                    block_number=tx.block_number,
                    transactions=[front, victim, back],
                    profit_usd=profit,
                    victim_loss_usd=profit * 0.5,  # Estimate
                    attacker_address=front.from_address,
                    confidence=0.8,
                    details={
                        "front_tx": front.tx_hash,
                        "victim_tx": victim.tx_hash,
                        "back_tx": back.tx_hash,
                        "pool": front.contract_address,
                    }
                )
        
        return None
    
    def _detect_frontrun(self, tx: Transaction) -> Optional[MEVDetection]:
        """
        Detect front-running pattern.
        
        Pattern:
        1. Pending tx detected in mempool
        2. Attacker submits same tx with higher gas
        3. Attacker tx executes first
        """
        block_txs = self._transactions.get(tx.block_number, [])
        
        # Get average gas price for block
        gas_prices = self._block_gas_prices.get(tx.block_number, [])
        if not gas_prices:
            return None
        
        avg_gas = sum(gas_prices) / len(gas_prices)
        
        # Check if this tx has significantly higher gas
        if tx.gas_price < avg_gas * self.FRONTRUN_GAS_RATIO:
            return None
        
        # Look for similar tx that came after
        similar_txs = [
            t for t in block_txs
            if t.tx_hash != tx.tx_hash
            and t.tx_index > tx.tx_index
            and t.to_address == tx.to_address
            and t.event_type == tx.event_type
            and abs(t.amount_usd - tx.amount_usd) / max(tx.amount_usd, 1) < 0.1  # Within 10%
        ]
        
        if similar_txs:
            victim = similar_txs[0]
            profit = tx.amount_usd * 0.01  # Estimate 1% profit
            
            return MEVDetection(
                mev_type=MEVType.FRONTRUN,
                block_number=tx.block_number,
                transactions=[tx, victim],
                profit_usd=profit,
                victim_loss_usd=profit,
                attacker_address=tx.from_address,
                confidence=0.6,
                details={
                    "attacker_tx": tx.tx_hash,
                    "victim_tx": victim.tx_hash,
                    "gas_ratio": tx.gas_price / avg_gas,
                }
            )
        
        return None
    
    def _detect_jit_liquidity(self, tx: Transaction) -> Optional[MEVDetection]:
        """
        Detect JIT (Just-In-Time) liquidity pattern.
        
        Pattern:
        1. Add liquidity just before large swap
        2. Earn fees from swap
        3. Remove liquidity immediately after
        
        All in same block.
        """
        if tx.event_type.lower() not in ("liquidityremove", "liquidity_remove", "burn"):
            return None
        
        block_txs = self._transactions.get(tx.block_number, [])
        
        # Look for add liquidity from same address earlier in block
        add_txs = [
            t for t in block_txs
            if t.from_address == tx.from_address
            and t.tx_index < tx.tx_index
            and t.event_type.lower() in ("liquidityadd", "liquidity_add", "mint")
            and t.contract_address == tx.contract_address
        ]
        
        if not add_txs:
            return None
        
        add_tx = add_txs[0]
        
        # Look for swap between add and remove
        swap_txs = [
            t for t in block_txs
            if t.tx_index > add_tx.tx_index
            and t.tx_index < tx.tx_index
            and t.event_type.lower() in ("swap", "swapv3")
            and t.contract_address == tx.contract_address
        ]
        
        if swap_txs:
            # Calculate profit (fees earned)
            total_swap_volume = sum(t.amount_usd for t in swap_txs)
            profit = total_swap_volume * 0.003  # Assume 0.3% fee
            
            return MEVDetection(
                mev_type=MEVType.JIT_LIQUIDITY,
                block_number=tx.block_number,
                transactions=[add_tx] + swap_txs + [tx],
                profit_usd=profit,
                victim_loss_usd=0,  # JIT doesn't directly harm others
                attacker_address=tx.from_address,
                confidence=0.9,
                details={
                    "add_tx": add_tx.tx_hash,
                    "remove_tx": tx.tx_hash,
                    "swap_count": len(swap_txs),
                    "swap_volume_usd": total_swap_volume,
                }
            )
        
        return None
    
    def get_block_mev_stats(self, block_number: int) -> Dict:
        """Get MEV statistics for a block."""
        block_detections = [
            d for d in self._detections
            if d.block_number == block_number
        ]
        
        return {
            "block_number": block_number,
            "mev_count": len(block_detections),
            "total_profit_usd": sum(d.profit_usd for d in block_detections),
            "total_victim_loss_usd": sum(d.victim_loss_usd for d in block_detections),
            "types": [d.mev_type.value for d in block_detections],
        }
    
    def is_same_block(self, tx1: Transaction, tx2: Transaction) -> bool:
        """Check if two transactions are in the same block."""
        return tx1.block_number == tx2.block_number
    
    def get_block_operation_count(self, block_number: int) -> int:
        """Get number of operations in a block."""
        return len(self._transactions.get(block_number, []))
    
    def get_block_volume_usd(self, block_number: int) -> float:
        """Get total volume in a block."""
        txs = self._transactions.get(block_number, [])
        return sum(t.amount_usd for t in txs)


# Global singleton
_mev_detector: Optional[MEVDetector] = None


def get_mev_detector() -> MEVDetector:
    """Get global MEV detector instance."""
    global _mev_detector
    if _mev_detector is None:
        _mev_detector = MEVDetector()
    return _mev_detector
