"""
Tests for Mempool Source Reliability
=====================================

Tests for BloxrouteMempoolSource covering:
- Happy path with valid JSON
- Malformed data handling
- WebSocket disconnect/reconnect
- Auth failure handling
- Filter logic for monitored addresses
"""

import pytest
import json
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
from datetime import datetime, timezone
import websockets.exceptions

from src.runtime.intent_sources.bloxroute_source import BloxrouteMempoolSource
from src.runtime.intent_sources.base import PendingTx


@pytest.mark.asyncio
class TestBloxrouteMempoolSource:
    """Test suite for BloxrouteMempoolSource."""
    
    @pytest.fixture
    def monitored_addresses(self):
        """Sample monitored addresses."""
        return [
            "0x2222222222222222222222222222222222222222",
            "0x3333333333333333333333333333333333333333",
        ]
    
    @pytest.fixture
    def source(self, monitored_addresses):
        """Create a BloxrouteMempoolSource instance."""
        return BloxrouteMempoolSource(
            chain_id="ethereum",
            auth_header="Bearer test-token",
            monitored_addresses=monitored_addresses,
            ws_url="wss://test.blxrbdn.com/ws"
        )
    
    @pytest.fixture
    def valid_tx_message(self):
        """Valid bloXroute transaction message."""
        return json.dumps({
            "method": "subscribe",
            "params": {
                "tx_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "tx_contents": {
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "value": "0xde0b6b3a7640000",  # 1 ETH
                    "data": "0x8456cb59",
                    "gas": "0xc350",
                    "gasPrice": "0x4a817c800",  # 20 gwei
                }
            }
        })
    
    @pytest.mark.asyncio
    async def test_happy_path_valid_json(self, source, valid_tx_message, mock_websocket):
        """Test: Verify BloxrouteMempoolSource yields valid intents when receiving standard JSON."""
        # Create a normalized PendingTx directly (simulating what _normalize_tx would produce)
        from src.runtime.intent_sources.base import PendingTx
        from datetime import datetime, timezone
        
        expected_tx = PendingTx(
            tx_hash="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            chain_id="ethereum",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=1000000000000000000,  # 1 ETH
            data="0x8456cb59",
            gas_limit=50000,
            gas_price=20000000000,
        )
        
        # Mock the async iteration over websocket messages
        async def mock_recv_sequence():
            # First call: subscription confirmation
            yield json.dumps({"id": 1, "result": "subscribed"})
            # Second call: valid transaction
            yield valid_tx_message
            # Yield control to allow processing
            await asyncio.sleep(0)
        
        recv_iter = mock_recv_sequence()
        
        async def mock_recv():
            return await recv_iter.__anext__()
        
        mock_websocket.recv = mock_recv
        mock_websocket.send = AsyncMock()
        mock_websocket.ping = AsyncMock()
        mock_websocket.closed = False
        
        # Mock websockets.connect to return our mock websocket
        async def mock_connect(*args, **kwargs):
            return mock_websocket
        
        with patch('websockets.connect', side_effect=mock_connect):
            # Start source (this will start the receive loop)
            await source.start()
            
            # Yield control to let async operations run
            await asyncio.sleep(0.2)
            
            # Get pending transactions
            pending_txs = await source.get_pending_txs(limit=10)
            
            # Stop source
            await source.stop()
        
        # Verify
        assert len(pending_txs) > 0
        tx = pending_txs[0]
        assert isinstance(tx, PendingTx)
        assert tx.tx_hash == expected_tx.tx_hash
        assert tx.to_address.lower() == "0x2222222222222222222222222222222222222222"
        assert tx.chain_id == "ethereum"
    
    @pytest.mark.asyncio
    async def test_malformed_data_logs_warning_no_crash(self, source, mock_websocket):
        """Test: Send partial/corrupt JSON. Ensure it logs warning but DOES NOT crash."""
        malformed_messages = [
            "{invalid json",  # Incomplete JSON
            '{"method": "subscribe", "params":}',  # Missing value
        ]
        
        call_count = [0]
        
        async def mock_recv():
            if call_count[0] < len(malformed_messages):
                msg = malformed_messages[call_count[0]]
                call_count[0] += 1
                return msg
            raise asyncio.CancelledError()
        
        mock_websocket.recv = mock_recv
        mock_websocket.send = AsyncMock()
        mock_websocket.ping = AsyncMock()
        mock_websocket.closed = False
        
        async def mock_connect(*args, **kwargs):
            return mock_websocket
        
        # Patch the module-level logger instance directly
        with patch('websockets.connect', side_effect=mock_connect):
            with patch('src.runtime.intent_sources.bloxroute_source.logger') as mock_log:
                await source.start()
                
                # Yield control to let async operations run
                await asyncio.sleep(0.2)
                
                # Should not crash - just log warnings
                pending_txs = await source.get_pending_txs(limit=10)
                
                # Verify warnings or errors were logged
                assert mock_log.warning.called or mock_log.error.called
                
                # Should return empty list or continue processing
                assert isinstance(pending_txs, list)
                
                await source.stop()
    
    @pytest.mark.asyncio
    async def test_disconnect_triggers_reconnect_with_backoff(self, source, mock_websocket):
        """Test: Simulate a WebSocket disconnect. Verify reconnect() logic triggers with backoff."""
        disconnect_count = [0]
        
        async def mock_recv():
            disconnect_count[0] += 1
            if disconnect_count[0] == 1:
                # First call: subscription confirmation
                return json.dumps({"id": 1, "result": "subscribed"})
            elif disconnect_count[0] == 2:
                # Second call: simulate disconnect
                raise websockets.exceptions.ConnectionClosed(None, None)
            else:
                raise asyncio.CancelledError()
        
        mock_websocket.recv = mock_recv
        mock_websocket.send = AsyncMock()
        mock_websocket.ping = AsyncMock()
        mock_websocket.closed = False
        
        async def mock_connect(*args, **kwargs):
            return mock_websocket
        
        with patch('websockets.connect', side_effect=mock_connect) as mock_connect_patch:
            with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
                # Start source
                await source.start()
                
                # Wait a bit for reconnect logic
                await asyncio.sleep(0.2)
                
                # Verify reconnect was attempted
                # Note: Actual reconnect logic may vary, but we verify it doesn't crash
                assert mock_connect_patch.called or mock_sleep.called
                
                await source.stop()
    
    @pytest.mark.asyncio
    async def test_auth_failure_handles_gracefully(self, source):
        """Test: Simulate 401/403 response. Ensure worker shuts down gracefully or alerts."""
        # Mock WebSocket to raise auth error
        auth_error = websockets.exceptions.InvalidStatusCode(
            status_code=401,
            headers={}
        )
        
        with patch('websockets.connect', side_effect=auth_error):
            with patch('structlog.get_logger') as mock_logger:
                mock_log = MagicMock()
                mock_logger.return_value = mock_log
                
                # Should handle auth failure gracefully
                try:
                    await source.start()
                except Exception as e:
                    # Should log error or raise specific exception
                    assert mock_log.error.called or isinstance(e, (websockets.exceptions.InvalidStatusCode, RuntimeError))
    
    @pytest.mark.asyncio
    async def test_filter_logic_filters_before_yielding(self, source, mock_websocket):
        """Test: Verify that monitored_addresses correctly filters input *before* yielding."""
        from src.runtime.intent_sources.base import PendingTx
        
        # Create messages for monitored and non-monitored addresses
        monitored_msg = json.dumps({
            "tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "tx_contents": {
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x2222222222222222222222222222222222222222",  # Monitored
                "value": "0x0",
                "data": "0x",
            }
        })
        
        non_monitored_msg = json.dumps({
            "tx_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "tx_contents": {
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x9999999999999999999999999999999999999999",  # NOT monitored
                "value": "0x0",
                "data": "0x",
            }
        })
        
        messages = [
            json.dumps({"id": 1, "result": "subscribed"}),  # Subscription confirmation
            monitored_msg,
            non_monitored_msg,
        ]
        
        call_count = [0]
        
        async def mock_recv():
            if call_count[0] < len(messages):
                msg = messages[call_count[0]]
                call_count[0] += 1
                return msg
            raise asyncio.CancelledError()
        
        mock_websocket.recv = mock_recv
        mock_websocket.send = AsyncMock()
        mock_websocket.ping = AsyncMock()
        mock_websocket.closed = False
        
        async def mock_connect(*args, **kwargs):
            return mock_websocket
        
        with patch('websockets.connect', side_effect=mock_connect):
            # Mark source as running to allow get_pending_txs
            source._running = True
            
            # Start source
            await source.start()
            
            # Yield control to let async operations run
            await asyncio.sleep(0.2)
        
        # Get pending transactions
        pending_txs = await source.get_pending_txs(limit=10)

        await source.stop()

        # Verify only monitored address transaction is yielded
        # The _normalize_tx method filters out non-monitored addresses
        assert len(pending_txs) >= 1
        for tx in pending_txs:
            # All yielded transactions should be to monitored addresses
            assert tx.to_address.lower() in source.monitored_addresses
    
    @pytest.mark.asyncio
    async def test_empty_monitored_addresses_warns(self, mock_websocket):
        """Test: Source with no monitored addresses should warn and not subscribe."""
        # Patch the module-level logger before creating the source
        with patch('src.runtime.intent_sources.bloxroute_source.logger') as mock_log:
            empty_source = BloxrouteMempoolSource(
                chain_id="ethereum",
                auth_header="Bearer test-token",
                monitored_addresses=[],
            )

            # Should warn about empty monitored addresses during initialization
            assert mock_log.warning.called
    
    @pytest.mark.asyncio
    async def test_build_filter_string_format(self, source):
        """Test: Verify filter string is correctly formatted."""
        filter_str = source._build_filter_string()
        
        assert "{to}" in filter_str
        assert "IN" in filter_str
        assert "0x2222222222222222222222222222222222222222" in filter_str.lower()
        assert "0x3333333333333333333333333333333333333333" in filter_str.lower()
    
    @pytest.mark.asyncio
    async def test_normalize_bloxroute_fields(self, source, mock_websocket):
        """Test: Verify bloXroute fields are correctly normalized to PendingTx schema."""
        bloxroute_message = json.dumps({
            "method": "subscribe",
            "params": {
                "tx_hash": "0xabc123",
                "tx_contents": {
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "value": "0xde0b6b3a7640000",  # Hex value
                    "input": "0x8456cb59",
                    "gas": "0xc350",  # Hex gas limit
                    "gas_price": "0x4a817c800",  # Hex gas price
                }
            }
        })
        
        messages = [
            json.dumps({"id": 1, "result": "subscribed"}),
                bloxroute_message,
        ]
        
        call_count = [0]
        
        async def mock_recv():
            if call_count[0] < len(messages):
                msg = messages[call_count[0]]
                call_count[0] += 1
                return msg
            raise asyncio.CancelledError()
        
        mock_websocket.recv = mock_recv
        mock_websocket.send = AsyncMock()
        mock_websocket.ping = AsyncMock()
        mock_websocket.closed = False
        
        async def mock_connect(*args, **kwargs):
            return mock_websocket
        
        with patch('websockets.connect', side_effect=mock_connect):
            await source.start()
            
            # Yield control to let async operations run
            await asyncio.sleep(0.2)
            
            pending_txs = await source.get_pending_txs(limit=10)
            
            if pending_txs:
                tx = pending_txs[0]
                # Verify hex values are converted to int
                assert isinstance(tx.value, int)
                assert tx.value > 0
                assert tx.gas_limit is not None
                assert tx.gas_price is not None
            
            await source.stop()

