"""
Stargate Bridge Adapter
=======================

Handles Stargate Finance liquidity bridge events:
- Swap: Deposit into liquidity pool
- SwapRemote: Withdraw from liquidity pool on dest chain

Stargate is a LIQUIDITY bridge (not mint/burn):
- Uses existing liquidity pools
- Fees are deducted from amount
- No canonical mint/burn - uses pool reserves

Correlation Key: (srcChainId, dstChainId, srcPoolId, dstPoolId, nonce)
"""

from decimal import Decimal
from typing import Optional
import structlog

from ...models.events import SecurityEvent, EventType
from .base import (
    BridgeAdapter,
    BridgeProtocol,
    BridgeEventSemantic,
    CorrelationKey,
    ExpectedAmounts
)
from typing import List

logger = structlog.get_logger(__name__)

# Stargate contract addresses
STARGATE_ROUTER = "0x8731d54E9D02c286767d56ac03e8037C07e01e98"
STARGATE_POOL_USDC = "0xdf0770dF86a8034b3EFEf0A1Bb3c889B8332FF56"
STARGATE_POOL_USDT = "0x38EA452219524Bb87e18dE1C24D3bB59510BD783"

# Event signatures
SWAP_SIG = "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f"
SWAP_REMOTE_SIG = "0x" + "SwapRemote".encode().hex()[:64]  # Placeholder - need actual sig


class StargateAdapter(BridgeAdapter):
    """
    Adapter for Stargate Finance liquidity bridge.
    
    Stargate uses liquidity pools (not mint/burn):
    - Source: Deposit into pool → Swap event
    - Dest: Withdraw from pool → SwapRemote event
    
    IMPORTANT: This is NOT a lock/mint bridge. It's a liquidity bridge.
    Do NOT apply mint/lock parity invariants.
    """
    
    def __init__(self):
        super().__init__(BridgeProtocol.STARGATE)
    
    def identify_protocol(self, event: SecurityEvent) -> bool:
        """Check if event is from Stargate."""
        contract = event.contract_address.lower()
        if contract in [
            STARGATE_ROUTER.lower(),
            STARGATE_POOL_USDC.lower(),
            STARGATE_POOL_USDT.lower()
        ]:
            return True
        
        raw_event = event.raw_event
        if not raw_event:
            return False
        
        topics = raw_event.get("topics", [])
        if not topics:
            return False
        
        event_sig = topics[0].lower()
        if event_sig == SWAP_SIG.lower():
            return True
        
        if event.bridge_id and "stargate" in event.bridge_id.lower():
            return True
        
        return False
    
    def classify_event(self, event: SecurityEvent) -> Optional[BridgeEventSemantic]:
        """Classify Stargate event semantic type."""
        raw_event = event.raw_event
        if not raw_event:
            return None
        
        topics = raw_event.get("topics", [])
        if not topics:
            return None
        
        event_sig = topics[0].lower()
        
        if event_sig == SWAP_SIG.lower():
            # Swap = DEPOSIT (adding liquidity/initiating swap)
            return BridgeEventSemantic.DEPOSIT
        
        # SwapRemote would be WITHDRAW/FILL
        # For now, classify based on event type
        if event.event_type == EventType.BRIDGE_WITHDRAW:
            return BridgeEventSemantic.WITHDRAW
        elif event.event_type == EventType.BRIDGE_DEPOSIT:
            return BridgeEventSemantic.DEPOSIT
        
        return None
    
    def extract_correlation_key(self, event: SecurityEvent) -> Optional[CorrelationKey]:
        """
        Extract Stargate correlation key.
        
        Format: (srcChainId, dstChainId, srcPoolId, dstPoolId, nonce)
        Or fallback: (tx_hash, log_index) for lower confidence
        """
        raw_event = event.raw_event
        if not raw_event:
            return None
        
        topics = raw_event.get("topics", [])
        if not topics:
            return None
        
        event_sig = topics[0].lower()
        
        if event_sig == SWAP_SIG.lower():
            # Swap(uint16 chainId, uint256 dstPoolId, address from, ...)
            # Decode from data (requires ABI)
            # For now, use fallback correlation
            try:
                # Extract from topics if available
                src_chain = event.chain_id
                
                # Use tx hash + log index as correlation key (lower confidence)
                key = f"{src_chain}:{event.tx_hash}:{event.log_index}"
                
                return CorrelationKey(
                    protocol_id=self.protocol_id.value,
                    key=key,
                    src_chain=src_chain,
                    dst_chain=None,  # Will be in decoded data
                    confidence=0.6  # Lower confidence - fallback method
                )
            except Exception as e:
                logger.warning("stargate_correlation_key_extraction_failed", error=str(e))
                return None
        
        return None
    
    def expected_amounts(
        self,
        source_event: SecurityEvent,
        dest_event: Optional[SecurityEvent] = None
    ) -> Optional[ExpectedAmounts]:
        """
        Calculate expected amounts for Stargate.
        
        Stargate fees are deducted from the swap amount:
        - Protocol fee: ~6 bps
        - LP fee: ~1-4 bps
        - Total: ~10 bps (0.1%)
        """
        if not source_event.amount or source_event.amount <= 0:
            return None
        
        source_amount = source_event.amount
        
        # Stargate fees: ~10 bps (0.1%)
        fee_bps = 10
        fee_amount = source_amount * Decimal(fee_bps) / Decimal(10000)
        dest_amount = source_amount - fee_amount
        
        if dest_event and dest_event.amount:
            dest_amount = dest_event.amount
        
        return ExpectedAmounts(
            source_amount=source_amount,
            dest_amount=dest_amount,
            fee_amount=fee_amount,
            fee_bps=fee_bps,
            tolerance_bps=self.get_tolerance_bps()
        )
    
    def supported_invariants(self) -> List[str]:
        """
        Stargate supports liquidity invariants, NOT mint/lock parity.
        
        Important: Do NOT use MINT_LOCK_PARITY for Stargate!
        """
        return [
            "LIQUIDITY_PARITY",  # Deposit vs Fill parity
            "POOL_RESERVE_CHECK",  # Ensure pool has liquidity
            "FEE_CONSISTENCY"  # Fees match expected
        ]
    
    def get_tolerance_bps(self, route: Optional[str] = None, token: Optional[str] = None) -> int:
        """Stargate tolerance: 50 bps (0.5%) for fees and slippage."""
        return 50
    
    def get_max_latency_seconds(self, route: Optional[str] = None) -> int:
        """Stargate: Fast finality (~minutes)."""
        return 300  # 5 minutes

