"""
Wormhole Bridge Adapter
=======================

Handles Wormhole Token Bridge events:
- LogMessagePublished: Message sent with sequence number
- TransferRedeemed: Message received and redeemed

Wormhole uses a canonical mint/burn model:
- Lock on source chain → Mint wrapped token on dest chain
- Burn wrapped token on dest chain → Unlock on source chain

Correlation Key: (emitterChainId, emitterAddress, sequence)
"""

from decimal import Decimal
from typing import Optional
import structlog

from ...models.events import SecurityEvent
from .base import (
    BridgeAdapter,
    BridgeProtocol,
    BridgeEventSemantic,
    CorrelationKey,
    ExpectedAmounts
)
from typing import List

logger = structlog.get_logger(__name__)

# Wormhole contract addresses (mainnet)
WORMHOLE_CORE_BRIDGE = "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"
WORMHOLE_TOKEN_BRIDGE = "0x3ee18B2214AFF97000D974cf647E7C347E8fa585"

# Event signatures
LOG_MESSAGE_PUBLISHED_SIG = "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"
TRANSFER_REDEEMED_SIG = "0xcaf280c8cfeba144da67230d9b009c8f868a75bac9a528fa0474be1ba317c169"

# Chain ID mapping (Wormhole chain IDs)
WORMHOLE_CHAIN_IDS = {
    1: "ethereum",
    2: "terra",
    3: "bsc",
    4: "polygon",
    5: "avalanche",
    6: "oasis",
    7: "algorand",
    8: "aurora",
    9: "fantom",
    10: "karura",
    11: "acala",
    12: "klaytn",
    13: "celo",
    14: "near",
    15: "moonbeam",
    16: "neon",
    18: "terra2",
    19: "injective",
    20: "sui",
    21: "aptos",
    22: "arbitrum",
    23: "optimism",
    24: "base",
    25: "sei",
    26: "rootstock",
    28: "scroll",
    30: "mantle",
    3104: "wormchain",
}


class WormholeAdapter(BridgeAdapter):
    """
    Adapter for Wormhole Token Bridge.
    
    Wormhole uses a canonical mint/burn model:
    - Source chain: Lock tokens → Publish message with sequence
    - Dest chain: Receive message → Mint wrapped tokens
    
    Correlation: Uses (emitterChainId, emitterAddress, sequence) as unique key.
    """
    
    def __init__(self):
        super().__init__(BridgeProtocol.WORMHOLE)
    
    def identify_protocol(self, event: SecurityEvent) -> bool:
        """Check if event is from Wormhole."""
        # Check contract address
        contract = event.contract_address.lower()
        if contract in [WORMHOLE_CORE_BRIDGE.lower(), WORMHOLE_TOKEN_BRIDGE.lower()]:
            return True
        
        # Check event signature
        raw_event = event.raw_event
        if not raw_event:
            return False
        
        topics = raw_event.get("topics", [])
        if not topics:
            return False
        
        event_sig = topics[0].lower()
        if event_sig in [LOG_MESSAGE_PUBLISHED_SIG.lower(), TRANSFER_REDEEMED_SIG.lower()]:
            return True
        
        # Check bridge_id field
        if event.bridge_id and "wormhole" in event.bridge_id.lower():
            return True
        
        return False
    
    def classify_event(self, event: SecurityEvent) -> Optional[BridgeEventSemantic]:
        """Classify Wormhole event semantic type."""
        raw_event = event.raw_event
        if not raw_event:
            return None
        
        topics = raw_event.get("topics", [])
        if not topics:
            return None
        
        event_sig = topics[0].lower()
        
        if event_sig == LOG_MESSAGE_PUBLISHED_SIG.lower():
            # Check if it's a lock (token transfer before message) or just a message
            # For simplicity, assume LogMessagePublished = LOCK if amount > 0
            if event.amount and event.amount > 0:
                return BridgeEventSemantic.LOCK
            return BridgeEventSemantic.MESSAGE_SENT
        
        elif event_sig == TRANSFER_REDEEMED_SIG.lower():
            # TransferRedeemed = MINT (tokens minted on dest chain)
            return BridgeEventSemantic.MINT
        
        return None
    
    def extract_correlation_key(self, event: SecurityEvent) -> Optional[CorrelationKey]:
        """
        Extract Wormhole correlation key.
        
        Format: (emitterChainId, emitterAddress, sequence)
        """
        raw_event = event.raw_event
        if not raw_event:
            return None
        
        topics = raw_event.get("topics", [])
        if len(topics) < 3:
            return None
        
        event_sig = topics[0].lower()
        
        if event_sig == LOG_MESSAGE_PUBLISHED_SIG.lower():
            # LogMessagePublished(address indexed sender, uint64 sequence, ...)
            # topics[1] = sender (padded)
            # topics[2] = sequence (padded)
            try:
                sequence = int(topics[2], 16)
                emitter_address = topics[1]  # Already indexed
                emitter_chain_id = event.chain_id
                
                # Extract destination chain from payload if available
                # For now, use None (will be set when message is received)
                dst_chain = None
                
                key = f"{emitter_chain_id}:{emitter_address}:{sequence}"
                
                return CorrelationKey(
                    protocol_id=self.protocol_id.value,
                    key=key,
                    src_chain=emitter_chain_id,
                    dst_chain=dst_chain,
                    confidence=1.0  # High confidence - sequence is unique
                )
            except (ValueError, IndexError) as e:
                logger.warning("wormhole_correlation_key_extraction_failed", error=str(e))
                return None
        
        elif event_sig == TRANSFER_REDEEMED_SIG.lower():
            # TransferRedeemed(uint16 indexed emitterChainId, bytes32 indexed emitterAddress, uint64 indexed sequence)
            # topics[1] = emitterChainId (padded)
            # topics[2] = emitterAddress (padded)
            # topics[3] = sequence (padded)
            try:
                if len(topics) < 4:
                    return None
                
                emitter_chain_id_raw = int(topics[1], 16)
                emitter_address = topics[2]
                sequence = int(topics[3], 16)
                
                # Map Wormhole chain ID to chain name
                emitter_chain_id = WORMHOLE_CHAIN_IDS.get(emitter_chain_id_raw, f"chain_{emitter_chain_id_raw}")
                dst_chain = event.chain_id
                
                key = f"{emitter_chain_id}:{emitter_address}:{sequence}"
                
                return CorrelationKey(
                    protocol_id=self.protocol_id.value,
                    key=key,
                    src_chain=emitter_chain_id,
                    dst_chain=dst_chain,
                    confidence=1.0  # High confidence
                )
            except (ValueError, IndexError) as e:
                logger.warning("wormhole_correlation_key_extraction_failed", error=str(e))
                return None
        
        return None
    
    def expected_amounts(
        self,
        source_event: SecurityEvent,
        dest_event: Optional[SecurityEvent] = None
    ) -> Optional[ExpectedAmounts]:
        """
        Calculate expected amounts for Wormhole.
        
        Wormhole typically has minimal fees (or zero fees for native tokens).
        For wrapped tokens, mint amount should equal lock amount.
        """
        if not source_event.amount or source_event.amount <= 0:
            return None
        
        source_amount = source_event.amount
        
        # Wormhole has minimal fees (usually 0 for native, small for wrapped)
        # Default: 0.1% fee (10 bps)
        fee_bps = 10
        fee_amount = source_amount * Decimal(fee_bps) / Decimal(10000)
        dest_amount = source_amount - fee_amount
        
        # If dest event provided, use actual amount
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
        """Wormhole supports mint/lock parity."""
        return [
            "MINT_LOCK_PARITY",
            "SEQUENCE_CONTINUITY",
            "MESSAGE_VERIFICATION"
        ]
    
    def get_tolerance_bps(self, route: Optional[str] = None, token: Optional[str] = None) -> int:
        """Wormhole tolerance: 50 bps (0.5%) for fees."""
        return 50
    
    def get_max_latency_seconds(self, route: Optional[str] = None) -> int:
        """Wormhole finality: ~15 minutes for guardian signatures."""
        return 900  # 15 minutes

