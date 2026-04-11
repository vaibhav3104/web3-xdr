"""
Bloxroute Mempool Source - Real-time mempool feed
=================================================

Streams pending transactions from bloXroute Cloud-API WebSocket feed.
Provides "0-block" detection by monitoring transactions before they're mined.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import List, Optional
import structlog
import websockets
from websockets.exceptions import ConnectionClosed, WebSocketException

from .base import PendingTx, PendingTxSource

logger = structlog.get_logger(__name__)


class BloxrouteMempoolSource(PendingTxSource):
    """
    bloXroute Cloud-API mempool feed source.
    
    Features:
    - Real-time WebSocket stream
    - Filtered by monitored addresses
    - Auto-reconnect on connection drops
    - Field normalization to PendingTx schema
    """
    
    def __init__(
        self,
        chain_id: str,
        auth_header: str,
        monitored_addresses: List[str],
        ws_url: str = "wss://api.blxrbdn.com/ws"
    ):
        super().__init__(chain_id)
        self.auth_header = auth_header
        self.monitored_addresses = [addr.lower() for addr in monitored_addresses if addr]
        self.ws_url = ws_url
        
        self._websocket: Optional[websockets.WebSocketClientProtocol] = None
        self._pending_txs_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._reconnect_delay = 5.0
        self._max_reconnect_delay = 60.0
        
        if not self.monitored_addresses:
            logger.warning(
                "bloxroute_no_monitored_addresses",
                chain_id=chain_id,
                message="No monitored addresses provided. Subscription will fail."
            )
        
        logger.info(
            "bloxroute_source_initialized",
            chain_id=chain_id,
            monitored_addresses_count=len(self.monitored_addresses),
            ws_url=ws_url
        )
    
    def _build_filter_string(self) -> str:
        """
        Build bloXroute filter string for monitored addresses.
        
        Format: "{to} IN ['0xContractA', '0xContractB', ...]"
        """
        if not self.monitored_addresses:
            return ""
        
        # Format addresses with single quotes
        address_list = ", ".join([f"'{addr}'" for addr in self.monitored_addresses])
        filter_str = f"{{to}} IN [{address_list}]"
        
        logger.debug("bloxroute_filter_built", filter=filter_str, count=len(self.monitored_addresses))
        return filter_str
    
    async def _subscribe(self):
        """Subscribe to bloXroute newTxs feed."""
        if not self.monitored_addresses:
            logger.error("bloxroute_subscription_skipped", reason="no_monitored_addresses")
            return
        
        filter_str = self._build_filter_string()
        
        subscribe_payload = {
            "method": "subscribe",
            "feed": "newTxs",
            "params": {
                "include": ["tx_hash", "tx_contents"],
                "filters": filter_str
            },
            "id": 1  # Request ID for tracking
        }
        
        try:
            await self._websocket.send(json.dumps(subscribe_payload))
            logger.info("bloxroute_subscribed", filter=filter_str)
        except Exception as e:
            logger.error("bloxroute_subscription_failed", error=str(e))
            raise
    
    async def _connect(self):
        """Establish WebSocket connection to bloXroute."""
        headers = {
            "Authorization": self.auth_header
        }
        
        try:
            logger.info("bloxroute_connecting", ws_url=self.ws_url)
            self._websocket = await websockets.connect(
                self.ws_url,
                extra_headers=headers,
                ping_interval=30,
                ping_timeout=10
            )
            logger.info("bloxroute_connected", chain_id=self.chain_id)
            return True
        except Exception as e:
            logger.error("bloxroute_connection_failed", error=str(e))
            return False
    
    def _normalize_tx(self, bloxroute_tx: dict) -> Optional[PendingTx]:
        """
        Normalize bloXroute transaction format to PendingTx schema.
        
        bloXroute fields (snake_case):
        - tx_hash
        - tx_contents.to
        - tx_contents.from
        - tx_contents.input (calldata)
        - tx_contents.value
        - tx_contents.gas_price
        - tx_contents.gas_limit
        - tx_contents.max_fee_per_gas
        """
        try:
            tx_hash = bloxroute_tx.get("tx_hash", "")
            if not tx_hash:
                return None
            
            tx_contents = bloxroute_tx.get("tx_contents", {})
            if not tx_contents:
                return None
            
            # Extract addresses
            to_address = tx_contents.get("to")
            from_address = tx_contents.get("from", "")
            
            # Normalize addresses
            if to_address:
                to_address = to_address.lower()
            if from_address:
                from_address = from_address.lower()
            
            # Validate to_address is in monitored list (filter should prevent this, but double-check)
            if not to_address or to_address not in self.monitored_addresses:
                logger.debug(
                    "bloxroute_tx_filtered_out",
                    to=to_address[:16] if to_address else None,
                    reason="not_in_monitored_addresses"
                )
                return None
            
            # Extract value (convert to int)
            value = tx_contents.get("value", 0)
            if isinstance(value, str):
                value = int(value, 16) if value.startswith("0x") else int(value)
            elif not isinstance(value, int):
                value = 0
            
            # Extract calldata
            data = tx_contents.get("input", "0x")
            if not data.startswith("0x"):
                data = "0x" + data
            
            # Extract gas info
            gas_limit = tx_contents.get("gas_limit") or tx_contents.get("gas")
            gas_price = tx_contents.get("gas_price")
            max_fee_per_gas = tx_contents.get("max_fee_per_gas")
            
            # Convert gas values to int if needed
            if gas_limit and isinstance(gas_limit, str):
                gas_limit = int(gas_limit, 16) if gas_limit.startswith("0x") else int(gas_limit)
            if gas_price and isinstance(gas_price, str):
                gas_price = int(gas_price, 16) if gas_price.startswith("0x") else int(gas_price)
            if max_fee_per_gas and isinstance(max_fee_per_gas, str):
                max_fee_per_gas = int(max_fee_per_gas, 16) if max_fee_per_gas.startswith("0x") else int(max_fee_per_gas)
            
            pending_tx = PendingTx(
                tx_hash=tx_hash.lower() if isinstance(tx_hash, str) else tx_hash.hex(),
                chain_id=self.chain_id,
                from_address=from_address or "",
                to_address=to_address,
                value=value,
                data=data,
                block_number=None,  # Mempool tx, no block yet
                block_hash=None,
                seen_at=datetime.now(timezone.utc),
                gas_limit=gas_limit,
                gas_price=gas_price,
                max_fee_per_gas=max_fee_per_gas,
            )
            
            return pending_tx
        
        except Exception as e:
            logger.warning("bloxroute_tx_normalization_failed", error=str(e), tx_hash=bloxroute_tx.get("tx_hash", "unknown")[:16])
            return None
    
    async def _receive_loop(self):
        """Receive messages from WebSocket and queue pending transactions."""
        while self._running:
            try:
                if not self._websocket or self._websocket.closed:
                    break
                
                message = await asyncio.wait_for(self._websocket.recv(), timeout=30.0)
                data = json.loads(message)
                
                # Check for subscription confirmation
                if data.get("id") == 1:  # Match our subscription request ID
                    if data.get("result") == "subscribed" or data.get("result") == "ok":
                        logger.info("bloxroute_subscription_confirmed")
                        continue
                    elif data.get("error"):
                        logger.error("bloxroute_subscription_error", error=data.get("error"))
                        # Don't break - might still receive transactions
                        continue
                
                # Check for general errors
                if data.get("error") and data.get("id") != 1:
                    logger.error("bloxroute_error", error=data.get("error"))
                    continue
                
                # Process transaction (bloXroute sends transactions in various formats)
                tx_data = None
                if "tx_hash" in data or "tx_contents" in data:
                    # Direct transaction object
                    tx_data = data
                elif "result" in data and isinstance(data["result"], dict):
                    # Some bloXroute responses wrap in "result"
                    if "tx_hash" in data["result"] or "tx_contents" in data["result"]:
                        tx_data = data["result"]
                elif "params" in data and isinstance(data["params"], dict):
                    # Some bloXroute feeds send in "params"
                    if "tx_hash" in data["params"] or "tx_contents" in data["params"]:
                        tx_data = data["params"]
                
                if tx_data:
                    pending_tx = self._normalize_tx(tx_data)
                    if pending_tx:
                        try:
                            self._pending_txs_queue.put_nowait(pending_tx)
                            logger.debug(
                                "bloxroute_tx_received",
                                tx_hash=pending_tx.tx_hash[:16],
                                to=pending_tx.to_address[:16] if pending_tx.to_address else None
                            )
                        except asyncio.QueueFull:
                            logger.warning("bloxroute_queue_full", message="Pending tx queue is full, dropping transaction")
            
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                if self._websocket and not self._websocket.closed:
                    try:
                        await self._websocket.ping()
                    except:
                        pass
                continue
            
            except (ConnectionClosed, WebSocketException) as e:
                logger.warning("bloxroute_connection_lost", error=str(e))
                break
            
            except Exception as e:
                logger.error("bloxroute_receive_error", error=str(e))
                await asyncio.sleep(1.0)
    
    async def _reconnect_loop(self):
        """Auto-reconnect loop with exponential backoff."""
        reconnect_attempts = 0
        
        while self._running:
            try:
                if await self._connect():
                    reconnect_attempts = 0
                    self._reconnect_delay = 5.0
                    
                    # Subscribe
                    await self._subscribe()
                    
                    # Start receive loop
                    await self._receive_loop()
                else:
                    reconnect_attempts += 1
                    logger.warning(
                        "bloxroute_reconnect_failed",
                        attempt=reconnect_attempts,
                        delay=self._reconnect_delay
                    )
                    await asyncio.sleep(self._reconnect_delay)
                    
                    # Exponential backoff
                    self._reconnect_delay = min(self._reconnect_delay * 2, self._max_reconnect_delay)
            
            except Exception as e:
                logger.error("bloxroute_reconnect_loop_error", error=str(e))
                await asyncio.sleep(self._reconnect_delay)
    
    async def start(self):
        """Start the bloXroute source."""
        if not self.monitored_addresses:
            logger.error("bloxroute_start_failed", reason="no_monitored_addresses")
            return
        
        self._running = True
        
        # Start reconnect loop in background
        asyncio.create_task(self._reconnect_loop())
        
        logger.info("bloxroute_source_started", chain_id=self.chain_id)
    
    async def stop(self):
        """Stop the bloXroute source."""
        self._running = False
        
        if self._websocket and not self._websocket.closed:
            try:
                await self._websocket.close()
            except:
                pass
        
        logger.info("bloxroute_source_stopped", chain_id=self.chain_id)
    
    async def get_pending_txs(self, limit: int = 100) -> List[PendingTx]:
        """
        Get pending transactions from the queue.
        
        Args:
            limit: Maximum number of transactions to return
        
        Returns:
            List of pending transactions
        """
        if not self._running:
            return []
        
        pending_txs: List[PendingTx] = []
        
        # Drain queue up to limit
        while len(pending_txs) < limit:
            try:
                tx = await asyncio.wait_for(self._pending_txs_queue.get(), timeout=0.1)
                pending_txs.append(tx)
            except asyncio.TimeoutError:
                break
        
        if pending_txs:
            logger.debug("bloxroute_txs_retrieved", count=len(pending_txs), chain_id=self.chain_id)
        
        return pending_txs

