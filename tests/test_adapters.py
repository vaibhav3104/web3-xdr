"""
Test Bridge Adapters
====================

Phase 3: Tests for protocol adapters with real log payloads.
"""

import pytest
from decimal import Decimal
from datetime import datetime, timezone

from src.models.events import SecurityEvent, EventType, EventStatus, Severity
from src.bridges.adapters.wormhole import WormholeAdapter
from src.bridges.adapters.stargate import StargateAdapter
from src.bridges.adapters.layerzero import LayerZeroAdapter
from src.bridges.adapters.base import BridgeEventSemantic, CorrelationKey


class TestWormholeAdapter:
    """Test Wormhole adapter."""
    
    def test_identify_wormhole_event(self):
        """Test Wormhole event identification."""
        adapter = WormholeAdapter()
        
        # Create mock LogMessagePublished event
        event = SecurityEvent(
            chain_id="ethereum",
            contract_address="0x3ee18B2214AFF97000D974cf647E7C347E8fa585",  # Wormhole Token Bridge
            tx_hash="0x1234",
            block_number=18000000,
            log_index=0,
            event_type=EventType.MESSAGE_SENT,
            raw_event={
                "topics": [
                    "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2",  # LogMessagePublished
                    "0x000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",  # sender
                    "0x0000000000000000000000000000000000000000000000000000000000000123",  # sequence
                ],
                "data": "0x..."
            }
        )
        
        assert adapter.identify_protocol(event), "Should identify as Wormhole"
    
    def test_extract_wormhole_correlation_key(self):
        """Test correlation key extraction from Wormhole LogMessagePublished."""
        adapter = WormholeAdapter()
        
        event = SecurityEvent(
            chain_id="ethereum",
            contract_address="0x3ee18B2214AFF97000D974cf647E7C347E8fa585",
            tx_hash="0xabcd",
            block_number=18000000,
            log_index=0,
            raw_event={
                "topics": [
                    "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2",
                    "0x000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",  # sender
                    "0x0000000000000000000000000000000000000000000000000000000000000123",  # sequence = 291
                ]
            }
        )
        
        corr_key = adapter.extract_correlation_key(event)
        assert corr_key is not None, "Should extract correlation key"
        assert corr_key.protocol_id == "wormhole", "Protocol should be wormhole"
        assert "291" in corr_key.key, "Key should contain sequence"
        assert corr_key.confidence == 1.0, "Should have high confidence"
    
    def test_classify_wormhole_lock(self):
        """Test classifying Wormhole LogMessagePublished as LOCK."""
        adapter = WormholeAdapter()
        
        event = SecurityEvent(
            chain_id="ethereum",
            amount=Decimal("1000"),
            raw_event={
                "topics": [
                    "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2",
                ]
            }
        )
        
        semantic = adapter.classify_event(event)
        assert semantic == BridgeEventSemantic.LOCK, "Should classify as LOCK"
    
    def test_classify_wormhole_mint(self):
        """Test classifying TransferRedeemed as MINT."""
        adapter = WormholeAdapter()
        
        event = SecurityEvent(
            chain_id="solana",
            raw_event={
                "topics": [
                    "0xcaf280c8cfeba144da67230d9b009c8f868a75bac9a528fa0474be1ba317c169",  # TransferRedeemed
                    "0x0000000000000000000000000000000000000000000000000000000000000002",  # emitterChainId = 2 (Terra)
                    "0x000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",  # emitterAddress
                    "0x0000000000000000000000000000000000000000000000000000000000000456",  # sequence = 1110
                ]
            }
        )
        
        semantic = adapter.classify_event(event)
        assert semantic == BridgeEventSemantic.MINT, "Should classify as MINT"
    
    def test_wormhole_expected_amounts(self):
        """Test expected amounts calculation for Wormhole."""
        adapter = WormholeAdapter()
        
        source_event = SecurityEvent(
            chain_id="ethereum",
            amount=Decimal("1000")
        )
        
        expected = adapter.expected_amounts(source_event)
        assert expected is not None, "Should calculate expected amounts"
        assert expected.source_amount == Decimal("1000"), "Source amount should match"
        assert expected.fee_bps == 10, "Wormhole fee should be 10 bps"
        assert expected.dest_amount < source_event.amount, "Dest amount should be less (fee deducted)"


class TestStargateAdapter:
    """Test Stargate adapter."""
    
    def test_identify_stargate_event(self):
        """Test Stargate event identification."""
        adapter = StargateAdapter()
        
        event = SecurityEvent(
            chain_id="ethereum",
            contract_address="0x8731d54E9D02c286767d56ac03e8037C07e01e98",  # Stargate Router
            raw_event={
                "topics": [
                    "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f",  # Swap
                ]
            }
        )
        
        assert adapter.identify_protocol(event), "Should identify as Stargate"
    
    def test_stargate_is_not_lock_mint(self):
        """Test that Stargate events are NOT classified as LOCK/MINT."""
        adapter = StargateAdapter()
        
        event = SecurityEvent(
            chain_id="ethereum",
            event_type=EventType.BRIDGE_DEPOSIT,
            raw_event={
                "topics": [
                    "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f",
                ]
            }
        )
        
        semantic = adapter.classify_event(event)
        assert semantic == BridgeEventSemantic.DEPOSIT, "Should be DEPOSIT, not LOCK"
        assert semantic != BridgeEventSemantic.LOCK, "Stargate is NOT a lock/mint bridge"
    
    def test_stargate_supported_invariants(self):
        """Test that Stargate does NOT support MINT_LOCK_PARITY."""
        adapter = StargateAdapter()
        
        invariants = adapter.supported_invariants()
        assert "MINT_LOCK_PARITY" not in invariants, "Stargate should NOT support mint/lock parity"
        assert "LIQUIDITY_PARITY" in invariants, "Stargate should support liquidity parity"
    
    def test_stargate_expected_amounts(self):
        """Test expected amounts for Stargate (with fees)."""
        adapter = StargateAdapter()
        
        source_event = SecurityEvent(
            chain_id="ethereum",
            amount=Decimal("1000")
        )
        
        expected = adapter.expected_amounts(source_event)
        assert expected is not None, "Should calculate expected amounts"
        assert expected.fee_bps == 10, "Stargate fee should be 10 bps"
        assert expected.dest_amount < source_event.amount, "Dest amount should be less (fee deducted)"


class TestLayerZeroAdapter:
    """Test LayerZero adapter."""
    
    def test_identify_layerzero_event(self):
        """Test LayerZero event identification."""
        adapter = LayerZeroAdapter()
        
        event = SecurityEvent(
            chain_id="ethereum",
            contract_address="0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675",  # LayerZero Endpoint
            raw_event={
                "topics": [
                    "0xe9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82",  # Packet
                ]
            }
        )
        
        assert adapter.identify_protocol(event), "Should identify as LayerZero"
    
    def test_layerzero_message_classification(self):
        """Test LayerZero message classification."""
        adapter = LayerZeroAdapter()
        
        event = SecurityEvent(
            chain_id="ethereum",
            raw_event={
                "topics": [
                    "0xe9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82",
                ],
                "data": "0x" + "0" * 200  # Mock payload
            }
        )
        
        semantic = adapter.classify_event(event)
        assert semantic == BridgeEventSemantic.MESSAGE_SENT, "Should classify as MESSAGE_SENT"


class TestAdapterRegistry:
    """Test adapter registry."""
    
    def test_registry_auto_detection(self):
        """Test automatic protocol detection."""
        from src.bridges.registry import BridgeAdapterRegistry
        
        registry = BridgeAdapterRegistry()
        
        # Wormhole event
        wormhole_event = SecurityEvent(
            chain_id="ethereum",
            contract_address="0x3ee18B2214AFF97000D974cf647E7C347E8fa585",
            raw_event={
                "topics": [
                    "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2",
                ]
            }
        )
        
        adapter = registry.get_adapter(wormhole_event)
        assert adapter is not None, "Should detect Wormhole"
        assert isinstance(adapter, WormholeAdapter), "Should return WormholeAdapter"
        
        # Stargate event
        stargate_event = SecurityEvent(
            chain_id="ethereum",
            contract_address="0x8731d54E9D02c286767d56ac03e8037C07e01e98",
            raw_event={
                "topics": [
                    "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f",
                ]
            }
        )
        
        adapter = registry.get_adapter(stargate_event)
        assert adapter is not None, "Should detect Stargate"
        assert isinstance(adapter, StargateAdapter), "Should return StargateAdapter"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

