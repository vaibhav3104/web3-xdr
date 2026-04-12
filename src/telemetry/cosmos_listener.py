"""
Cosmos/IBC Chain Listener (Robust)
==================================
Monitors Cosmos SDK chains via Tendermint RPC for bridge events.

Features:
- Multi-RPC failover with health tracking
- Automatic reconnection
- Heartbeat logging
- IBC transfer monitoring
- CosmWasm bridge contract detection

Supported Chains:
- Cosmos Hub (ATOM)
- Osmosis (OSMO)
- Injective (INJ)
- Sei (SEI)
- Celestia (TIA)
- dYdX (DYDX)
- Any IBC-enabled chain

Bridge Protocols Monitored:
- IBC (Inter-Blockchain Communication)
- Gravity Bridge
- Axelar
- Wormhole Gateway
"""

import asyncio
import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import AsyncGenerator, Optional, Dict, Any, List
from dataclasses import dataclass, field

import structlog
import aiohttp
from websockets import connect as ws_connect
from websockets.exceptions import ConnectionClosed

from .robust_non_evm import RobustNonEVMListener, NonEVMConfig
from ..models.events import SecurityEvent, EventType, Severity

logger = structlog.get_logger(__name__)


@dataclass
class CosmosConfig(NonEVMConfig):
    """Configuration for Cosmos chain listener with failover support."""
    tendermint_rpc: str = ""  # Primary Tendermint RPC
    rest_api: str = ""  # LCD REST API
    chain_prefix: str = "cosmos"  # Bech32 prefix
    ibc_channels: List[str] = field(default_factory=list)  # IBC channel IDs to monitor
    bridge_contracts: List[str] = field(default_factory=list)  # CosmWasm contract addresses
    
    def get_all_rpc_urls(self) -> List[str]:
        """Get all RPC URLs including tendermint_rpc."""
        urls = []
        if self.tendermint_rpc:
            urls.append(self.tendermint_rpc)
        if self.rpc_url:
            urls.append(self.rpc_url)
        urls.extend(self.rpc_urls)
        urls.extend(self.fallback_rpcs)
        seen = set()
        return [x for x in urls if not (x in seen or seen.add(x))]


# IBC Message Types
IBC_MSG_TYPES = {
    "/ibc.core.channel.v1.MsgRecvPacket": "IBC_RECV",
    "/ibc.core.channel.v1.MsgAcknowledgement": "IBC_ACK",
    "/ibc.core.channel.v1.MsgTimeout": "IBC_TIMEOUT",
    "/ibc.applications.transfer.v1.MsgTransfer": "IBC_TRANSFER",
    "/cosmwasm.wasm.v1.MsgExecuteContract": "CONTRACT_EXEC",
    "/cosmos.bank.v1beta1.MsgSend": "BANK_SEND",
}

# Known Bridge Contract Patterns
BRIDGE_PATTERNS = {
    "gravity": ["gravity", "peggy", "orchestrator"],
    "axelar": ["axelar", "gateway", "gmp"],
    "wormhole": ["wormhole", "guardian", "vaa"],
}


class CosmosListener(RobustNonEVMListener):
    """
    Robust listener for Cosmos SDK chains via Tendermint RPC.
    
    Monitors:
    - IBC transfers and packet events
    - CosmWasm bridge contract executions
    - Gravity Bridge events
    - Axelar GMP messages
    - Large token movements
    
    Includes multi-RPC failover and automatic reconnection.
    """
    
    def __init__(self, config: CosmosConfig):
        super().__init__(config)
        self.config: CosmosConfig = config
        self.ws_client = None
        self.ibc_channels = set(config.ibc_channels or [])
        self.bridge_contracts = set(config.bridge_contracts or [])
        
    async def _make_chain_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        params: Any,
        is_json_rpc: bool
    ) -> Optional[Dict]:
        """Make a Tendermint RPC request."""
        # Tendermint RPC uses path-based endpoints
        endpoint_url = f"{url}/{method}"
        
        if params:
            # Add query params
            query_params = "&".join(f"{k}={v}" for k, v in params.items())
            endpoint_url = f"{endpoint_url}?{query_params}"
        
        async with session.get(endpoint_url) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("result", data)
            elif resp.status >= 500:
                raise aiohttp.ClientResponseError(
                    resp.request_info,
                    resp.history,
                    status=resp.status,
                    message=f"Server error {resp.status}"
                )
            else:
                return None
    
    async def _get_latest_block_height(self) -> int:
        """Get the latest block height from Tendermint."""
        result = await self._make_request("status")
        
        if result:
            sync_info = result.get("sync_info", {})
            return int(sync_info.get("latest_block_height", 0))
        return 0
    
    async def _process_block_impl(self, height: int) -> List[SecurityEvent]:
        """Process a Cosmos block and extract security events."""
        events = []
        
        # Get block results (contains transaction events)
        block_results = await self._make_request(
            "block_results",
            {"height": str(height)}
        )
        
        if not block_results:
            return events
        
        # Process transaction results
        txs_results = block_results.get("txs_results", [])
        
        for tx_idx, tx_result in enumerate(txs_results or []):
            if tx_result is None:
                continue
                
            # Get transaction hash from block
            block_data = await self._make_request(
                "block",
                {"height": str(height)}
            )
            
            if block_data:
                txs = block_data.get("block", {}).get("data", {}).get("txs", [])
                tx_hash = self._compute_tx_hash(txs[tx_idx]) if tx_idx < len(txs) else f"tx_{height}_{tx_idx}"
            else:
                tx_hash = f"tx_{height}_{tx_idx}"
            
            # Parse events from transaction
            tx_events = await self._parse_tx_events(
                tx_result.get("events", []),
                tx_hash,
                height
            )
            events.extend(tx_events)
        
        return events
    
    def _compute_tx_hash(self, tx_base64: str) -> str:
        """Compute transaction hash from base64-encoded transaction."""
        import base64
        import hashlib
        
        try:
            tx_bytes = base64.b64decode(tx_base64)
            return hashlib.sha256(tx_bytes).hexdigest().upper()
        except:
            return tx_base64[:64]
    
    async def _parse_tx_events(
        self,
        tx_events: List[Dict],
        tx_hash: str,
        height: int
    ) -> List[SecurityEvent]:
        """Parse transaction events into security events."""
        events = []
        
        for event in tx_events:
            event_type = event.get("type", "")
            attributes = {}
            
            # Parse attributes (may be base64 encoded)
            for attr in event.get("attributes", []):
                key = attr.get("key", "")
                value = attr.get("value", "")
                
                # Try to decode base64
                try:
                    import base64
                    key = base64.b64decode(key).decode() if key else ""
                    value = base64.b64decode(value).decode() if value else ""
                except:
                    pass
                
                attributes[key] = value
            
            # Check for IBC events
            if event_type.startswith("ibc_"):
                security_event = self._create_ibc_event(
                    event_type, attributes, tx_hash, height
                )
                if security_event:
                    events.append(security_event)
                    
            # Check for transfer events
            elif event_type == "transfer":
                security_event = self._check_large_transfer(
                    attributes, tx_hash, height
                )
                if security_event:
                    events.append(security_event)
                    
            # Check for wasm contract events
            elif event_type == "wasm":
                security_event = self._check_bridge_contract(
                    attributes, tx_hash, height
                )
                if security_event:
                    events.append(security_event)
        
        return events
    
    def _create_ibc_event(
        self,
        event_type: str,
        attributes: Dict,
        tx_hash: str,
        height: int
    ) -> Optional[SecurityEvent]:
        """Create security event from IBC activity."""
        
        # Extract IBC packet details
        packet_data = attributes.get("packet_data", "{}")
        try:
            packet = json.loads(packet_data) if isinstance(packet_data, str) else packet_data
        except:
            packet = {}
        
        amount = packet.get("amount", "0")
        denom = packet.get("denom", "unknown")
        sender = packet.get("sender", "")
        receiver = packet.get("receiver", "")
        
        # Calculate value in USD (simplified)
        try:
            amount_float = float(amount) / 1e6  # Most Cosmos tokens use 6 decimals
        except:
            amount_float = 0
        
        # Determine severity based on amount
        if amount_float > 10_000_000:
            severity = Severity.CRITICAL
        elif amount_float > 1_000_000:
            severity = Severity.HIGH
        elif amount_float > 100_000:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        return SecurityEvent(
            event_id=f"cosmos_{tx_hash}_{event_type}",
            chain_id=self.config.chain_id,
            event_type=EventType.CROSS_CHAIN_TRANSFER,
            severity=severity,
            block_timestamp=datetime.now(timezone.utc),
            tx_hash=tx_hash,
            block_number=height,
            source_address=sender,
            dest_address=receiver,
            amount=Decimal(str(amount)),
            contract_address="ibc",
            raw_event={
                "event_type": event_type,
                "packet": packet,
                "attributes": attributes,
                "denom": denom,
                "method_name": event_type,
                "chain_type": "cosmos",
                "protocol": "IBC",
                "amount_normalized": amount_float
            }
        )
    
    def _check_large_transfer(
        self,
        attributes: Dict,
        tx_hash: str,
        height: int
    ) -> Optional[SecurityEvent]:
        """Check for suspicious large transfers."""
        
        amount = attributes.get("amount", "0")
        sender = attributes.get("sender", "")
        recipient = attributes.get("recipient", "")
        
        # Parse amount (format: "1000000uatom")
        try:
            amount_str = amount.split("u")[0] if "u" in amount else amount
            amount_float = float(amount_str) / 1e6
        except:
            return None
        
        # Only flag very large transfers
        if amount_float < 1_000_000:
            return None
        
        return SecurityEvent(
            event_id=f"cosmos_{tx_hash}_transfer",
            chain_id=self.config.chain_id,
            event_type=EventType.LARGE_TRANSFER,
            severity=Severity.MEDIUM,
            block_timestamp=datetime.now(timezone.utc),
            tx_hash=tx_hash,
            block_number=height,
            source_address=sender,
            dest_address=recipient,
            amount=Decimal(str(amount_float)),
            raw_event={
                **attributes,
                "chain_type": "cosmos",
                "amount_normalized": amount_float
            }
        )
    
    def _check_bridge_contract(
        self,
        attributes: Dict,
        tx_hash: str,
        height: int
    ) -> Optional[SecurityEvent]:
        """Check for bridge contract interactions."""
        
        contract = attributes.get("_contract_address", "")
        action = attributes.get("action", "")
        
        # Check if this is a known bridge contract
        is_bridge = contract in self.bridge_contracts
        
        # Check if action matches bridge patterns
        action_lower = action.lower()
        bridge_type = None
        for btype, patterns in BRIDGE_PATTERNS.items():
            if any(p in action_lower for p in patterns):
                bridge_type = btype
                is_bridge = True
                break
        
        if not is_bridge:
            return None
        
        return SecurityEvent(
            event_id=f"cosmos_{tx_hash}_bridge",
            chain_id=self.config.chain_id,
            event_type=EventType.BRIDGE_CALL,
            severity=Severity.MEDIUM,
            block_timestamp=datetime.now(timezone.utc),
            tx_hash=tx_hash,
            block_number=height,
            contract_address=contract,
            raw_event={
                **attributes,
                "method_name": action,
                "chain_type": "cosmos",
                "bridge_type": bridge_type or "unknown",
                "protocol": "CosmWasm"
            }
        )
    
    async def listen_events_ws(self) -> AsyncGenerator[SecurityEvent, None]:
        """
        Alternative: Subscribe to Tendermint WebSocket events.
        
        Uses WebSocket for real-time events instead of polling.
        Falls back to polling on connection issues.
        """
        ws_url = self.config.ws_url or self.config.rpc_url.replace("http", "ws") + "/websocket"
        
        while self._connected and self._running:
            try:
                async with ws_connect(ws_url) as websocket:
                    self.ws_client = websocket
                    
                    # Subscribe to new transactions
                    await websocket.send(json.dumps({
                        "jsonrpc": "2.0",
                        "method": "subscribe",
                        "id": 1,
                        "params": {"query": "tm.event='Tx'"}
                    }))
                    
                    logger.info("cosmos_ws_subscribed", chain=self.chain_id)
                    
                    async for message in websocket:
                        try:
                            data = json.loads(message)
                            events = await self._process_ws_event(data)
                            for event in events:
                                yield event
                        except json.JSONDecodeError:
                            continue
                        
            except ConnectionClosed:
                logger.warning("cosmos_ws_disconnected", chain=self.chain_id)
                await asyncio.sleep(5)
            except Exception as e:
                logger.error("cosmos_ws_error", chain=self.chain_id, error=str(e))
                await asyncio.sleep(5)
    
    async def _process_ws_event(self, data: Dict) -> List[SecurityEvent]:
        """Process a WebSocket transaction event."""
        events = []
        
        result = data.get("result", {})
        tx_result = result.get("data", {}).get("value", {}).get("TxResult", {})
        
        if not tx_result:
            return events
        
        tx_hash = tx_result.get("tx", "")[:64]
        height = tx_result.get("height", 0)
        
        # Parse transaction events
        tx_events = tx_result.get("result", {}).get("events", [])
        
        return await self._parse_tx_events(tx_events, tx_hash, int(height))
    
    async def get_block(self, height: int) -> Optional[Dict]:
        """Fetch a specific block by height."""
        return await self._make_request("block", {"height": str(height)})
    
    async def get_tx(self, tx_hash: str) -> Optional[Dict]:
        """Fetch transaction by hash."""
        return await self._make_request("tx", {"hash": f"0x{tx_hash}"})
