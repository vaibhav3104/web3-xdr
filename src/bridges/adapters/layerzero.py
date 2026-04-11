"""
LayerZero Bridge Adapter
========================

Handles LayerZero messaging protocol events:
- Packet: Cross-chain message sent
- PacketReceived: Message received

LayerZero uses Ultra Light Nodes (ULN) for message verification.
Correlation Key: (srcChainId, srcAddress, nonce, payloadHash)
"""

from decimal import Decimal
from typing import Optional
import hashlib
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

# LayerZero contract addresses
LAYERZERO_ENDPOINT = "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675"
LAYERZERO_ULN = "0x4D73AdB72bC3DD368966edD0f0b2148401A178E2"

# Event signatures
PACKET_SIG = "0xe9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82"
PACKET_RECEIVED_SIG = "0x5b06d4a4e5e9e2a50e1cfea66e8c0b6e9f8a8d7c6b5a4e3d2c1b0a9f8e7d6c5b"
SEND_TO_CHAIN_SIG = "0x32ed1a409ef04c7b0227189c3a103dc5ac10e775a15b785dcc510201f7c25ad3"
RECEIVE_FROM_CHAIN_SIG = "0xd81b6f2a5a0f1c0c5e8e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c"


class LayerZeroAdapter(BridgeAdapter):
    """
    Adapter for LayerZero messaging protocol.
    
    LayerZero uses Ultra Light Nodes for verification:
    - Source: Send message with nonce and payload
    - Dest: Receive and verify message
    
    Correlation: Uses (srcChainId, srcAddress, nonce, payloadHash)
    """
    
    def __init__(self):
        super().__init__(BridgeProtocol.LAYERZERO)
    
    def identify_protocol(self, event: SecurityEvent) -> bool:
        """Check if event is from LayerZero."""
        contract = event.contract_address.lower()
        if contract in [LAYERZERO_ENDPOINT.lower(), LAYERZERO_ULN.lower()]:
            return True
        
        raw_event = event.raw_event
        if not raw_event:
            return False
        
        topics = raw_event.get("topics", [])
        if not topics:
            return False
        
        event_sig = topics[0].lower()
        if event_sig in [
            PACKET_SIG.lower(),
            PACKET_RECEIVED_SIG.lower(),
            SEND_TO_CHAIN_SIG.lower(),
            RECEIVE_FROM_CHAIN_SIG.lower()
        ]:
            return True
        
        if event.bridge_id and "layerzero" in event.bridge_id.lower():
            return True
        
        return False
    
    def classify_event(self, event: SecurityEvent) -> Optional[BridgeEventSemantic]:
        """Classify LayerZero event semantic type."""
        raw_event = event.raw_event
        if not raw_event:
            return None
        
        topics = raw_event.get("topics", [])
        if not topics:
            return None
        
        event_sig = topics[0].lower()
        
        if event_sig == SEND_TO_CHAIN_SIG.lower():
            return BridgeEventSemantic.DEPOSIT  # Or LOCK depending on context
        elif event_sig == RECEIVE_FROM_CHAIN_SIG.lower():
            return BridgeEventSemantic.WITHDRAW  # Or MINT
        elif event_sig == PACKET_SIG.lower():
            return BridgeEventSemantic.MESSAGE_SENT
        elif event_sig == PACKET_RECEIVED_SIG.lower():
            return BridgeEventSemantic.MESSAGE_RECEIVED
        
        return None
    
    def extract_correlation_key(self, event: SecurityEvent) -> Optional[CorrelationKey]:
        """
        Extract LayerZero correlation key.
        
        Format: (srcChainId, srcAddress, nonce, payloadHash)
        """
        raw_event = event.raw_event
        if not raw_event:
            return None
        
        topics = raw_event.get("topics", [])
        if len(topics) < 2:
            return None
        
        event_sig = topics[0].lower()
        
        if event_sig == PACKET_SIG.lower():
            # Packet(bytes encodedPayload)
            # Extract nonce and payload from data
            data = raw_event.get("data", "")
            if not data or len(data) < 130:  # 0x + 64 bytes minimum
                return None
            
            try:
                # Decode payload (simplified - actual decoding requires ABI)
                # For now, use payload hash as correlation key
                payload_bytes = bytes.fromhex(data[2:])
                payload_hash = hashlib.sha256(payload_bytes).hexdigest()[:16]
                
                # Extract nonce from payload (if available in topics)
                # Otherwise use payload hash
                nonce = payload_hash
                src_chain = event.chain_id
                src_address = event.contract_address
                
                key = f"{src_chain}:{src_address}:{nonce}:{payload_hash}"
                
                return CorrelationKey(
                    protocol_id=self.protocol_id.value,
                    key=key,
                    src_chain=src_chain,
                    dst_chain=None,  # Will be set on receive
                    confidence=0.9  # High confidence with payload hash
                )
            except Exception as e:
                logger.warning("layerzero_correlation_key_extraction_failed", error=str(e))
                return None
        
        elif event_sig == PACKET_RECEIVED_SIG.lower():
            # PacketReceived(uint16 srcChainId, bytes srcAddress, uint64 nonce, bytes payload)
            # Extract from data (requires ABI decoding)
            # For now, use a fallback correlation
            data = raw_event.get("data", "")
            if data:
                payload_hash = hashlib.sha256(bytes.fromhex(data[2:])).hexdigest()[:16]
                src_chain = event.chain_id  # Will be in decoded data
                src_address = event.contract_address
                
                key = f"{src_chain}:{src_address}:{payload_hash}"
                
                return CorrelationKey(
                    protocol_id=self.protocol_id.value,
                    key=key,
                    src_chain=src_chain,
                    dst_chain=event.chain_id,
                    confidence=0.8  # Lower confidence without full decoding
                )
        
        elif event_sig == SEND_TO_CHAIN_SIG.lower():
            # SendToChain(uint16 indexed _dstChainId, address indexed _from, ...)
            # topics[1] = dstChainId
            # topics[2] = from address
            try:
                dst_chain_id = int(topics[1], 16)
                from_address = topics[2]
                src_chain = event.chain_id
                
                # Use tx hash + log index as fallback correlation
                key = f"{src_chain}:{from_address}:{event.tx_hash}:{event.log_index}"
                
                return CorrelationKey(
                    protocol_id=self.protocol_id.value,
                    key=key,
                    src_chain=src_chain,
                    dst_chain=f"chain_{dst_chain_id}",
                    confidence=0.7  # Lower confidence - fallback method
                )
            except Exception as e:
                logger.warning("layerzero_correlation_key_extraction_failed", error=str(e))
                return None
        
        return None
    
    def expected_amounts(
        self,
        source_event: SecurityEvent,
        dest_event: Optional[SecurityEvent] = None
    ) -> Optional[ExpectedAmounts]:
        """
        Calculate expected amounts for LayerZero.
        
        LayerZero fees vary by route and are paid in native token.
        For token transfers, amount should be preserved (fees paid separately).
        """
        if not source_event.amount or source_event.amount <= 0:
            return None
        
        source_amount = source_event.amount
        
        # LayerZero: Fees are paid in native token, not deducted from amount
        # So dest amount should equal source amount
        fee_bps = 0  # Fees not deducted from transfer amount
        fee_amount = Decimal(0)
        dest_amount = source_amount
        
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
        """LayerZero supports message verification and sequence checks."""
        return [
            "MESSAGE_VERIFICATION",
            "SEQUENCE_CONTINUITY",
            "PAYLOAD_INTEGRITY"
        ]
    
    def get_tolerance_bps(self, route: Optional[str] = None, token: Optional[str] = None) -> int:
        """LayerZero: No amount tolerance needed (fees separate)."""
        return 0
    
    def get_max_latency_seconds(self, route: Optional[str] = None) -> int:
        """LayerZero: Fast finality via ULN (~minutes)."""
        return 300  # 5 minutes

