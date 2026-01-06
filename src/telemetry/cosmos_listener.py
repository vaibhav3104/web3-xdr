"""
Cosmos/IBC Chain Listener
=========================
Monitors Cosmos SDK chains via Tendermint RPC for bridge events.

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
import hashlib
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional, Dict, Any, List
from dataclasses import dataclass

import structlog
import aiohttp
from websockets import connect as ws_connect
from websockets.exceptions import ConnectionClosed

from .base import ChainListener, ListenerConfig
from ..models.events import SecurityEvent, EventType, Severity

logger = structlog.get_logger(__name__)


@dataclass
class CosmosConfig(ListenerConfig):
    """Configuration for Cosmos chain listener"""
    tendermint_rpc: str = ""  # http://localhost:26657
    rest_api: str = ""  # http://localhost:1317
    chain_prefix: str = "cosmos"  # Bech32 prefix
    ibc_channels: List[str] = None  # IBC channel IDs to monitor
    bridge_contracts: List[str] = None  # CosmWasm contract addresses


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


class CosmosListener(ChainListener):
    """
    Listens to Cosmos SDK chains via Tendermint RPC/WebSocket.
    
    Monitors:
    - IBC transfers and packet events
    - CosmWasm bridge contract executions
    - Gravity Bridge events
    - Axelar GMP messages
    - Large token movements
    """
    
    def __init__(self, config: CosmosConfig):
        super().__init__(config)
        self.config: CosmosConfig = config
        self.ws_client = None
        self.http_session = None
        self.latest_height = 0
        self.ibc_channels = set(config.ibc_channels or [])
        self.bridge_contracts = set(config.bridge_contracts or [])
        
    async def connect(self) -> bool:
        """Connect to Tendermint RPC"""
        try:
            self.http_session = aiohttp.ClientSession()
            
            # Test connection by getting latest block
            async with self.http_session.get(
                f"{self.config.tendermint_rpc}/status"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.latest_height = int(
                        data.get("result", {}).get("sync_info", {}).get("latest_block_height", 0)
                    )
                    logger.info(
                        "cosmos_connected",
                        chain=self.config.chain_id,
                        height=self.latest_height
                    )
                    self._connected = True
                    return True
                    
        except Exception as e:
            logger.error("cosmos_connection_failed", chain=self.config.chain_id, error=str(e))
            
        return False
        
    async def disconnect(self):
        """Disconnect from Tendermint"""
        if self.ws_client:
            await self.ws_client.close()
        if self.http_session:
            await self.http_session.close()
        self._connected = False
        logger.info("cosmos_disconnected", chain=self.config.chain_id)
        
    async def listen_events(self) -> AsyncGenerator[SecurityEvent, None]:
        """Subscribe to Tendermint WebSocket events"""
        ws_url = self.config.ws_url or self.config.tendermint_rpc.replace("http", "ws") + "/websocket"
        
        while self._connected:
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
                    
                    logger.info("cosmos_ws_subscribed", chain=self.config.chain_id)
                    
                    async for message in websocket:
                        try:
                            data = json.loads(message)
                            events = await self._process_tx_event(data)
                            for event in events:
                                yield event
                        except json.JSONDecodeError:
                            continue
                            
            except ConnectionClosed:
                logger.warning("cosmos_ws_disconnected", chain=self.config.chain_id)
                await asyncio.sleep(5)
            except Exception as e:
                logger.error("cosmos_ws_error", chain=self.config.chain_id, error=str(e))
                await asyncio.sleep(5)
                
    async def _process_tx_event(self, data: Dict) -> List[SecurityEvent]:
        """Process a Tendermint transaction event"""
        events = []
        
        result = data.get("result", {})
        tx_result = result.get("data", {}).get("value", {}).get("TxResult", {})
        
        if not tx_result:
            return events
            
        tx_hash = tx_result.get("tx", "")[:64]  # First 64 chars as hash
        height = tx_result.get("height", 0)
        
        # Parse transaction events
        tx_events = tx_result.get("result", {}).get("events", [])
        
        for event in tx_events:
            event_type = event.get("type", "")
            attributes = {
                attr.get("key", ""): attr.get("value", "")
                for attr in event.get("attributes", [])
            }
            
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
        """Create security event from IBC activity"""
        
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
        if amount_float > 10_000_000:  # $10M+
            severity = Severity.CRITICAL
        elif amount_float > 1_000_000:  # $1M+
            severity = Severity.HIGH
        elif amount_float > 100_000:  # $100K+
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
            
        return SecurityEvent(
            event_id=f"cosmos_{tx_hash}_{event_type}",
            chain_id=self.config.chain_id,
            event_type=EventType.CROSS_CHAIN_TRANSFER,
            severity=severity,
            timestamp=datetime.now(timezone.utc),
            transaction_hash=tx_hash,
            block_number=height,
            from_address=sender,
            to_address=receiver,
            value=str(amount),
            contract_address="ibc",
            method_name=event_type,
            raw_data={
                "event_type": event_type,
                "packet": packet,
                "attributes": attributes,
                "denom": denom
            },
            metadata={
                "chain_type": "cosmos",
                "protocol": "IBC",
                "denom": denom,
                "amount_normalized": amount_float
            }
        )
        
    def _check_large_transfer(
        self,
        attributes: Dict,
        tx_hash: str,
        height: int
    ) -> Optional[SecurityEvent]:
        """Check for suspicious large transfers"""
        
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
            timestamp=datetime.now(timezone.utc),
            transaction_hash=tx_hash,
            block_number=height,
            from_address=sender,
            to_address=recipient,
            value=amount,
            raw_data=attributes,
            metadata={
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
        """Check for bridge contract interactions"""
        
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
            timestamp=datetime.now(timezone.utc),
            transaction_hash=tx_hash,
            block_number=height,
            contract_address=contract,
            method_name=action,
            raw_data=attributes,
            metadata={
                "chain_type": "cosmos",
                "bridge_type": bridge_type or "unknown",
                "protocol": "CosmWasm"
            }
        )
        
    async def get_block(self, height: int) -> Optional[Dict]:
        """Fetch a specific block by height"""
        try:
            async with self.http_session.get(
                f"{self.config.tendermint_rpc}/block?height={height}"
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.error("cosmos_get_block_failed", height=height, error=str(e))
        return None
        
    async def get_tx(self, tx_hash: str) -> Optional[Dict]:
        """Fetch transaction by hash"""
        try:
            async with self.http_session.get(
                f"{self.config.tendermint_rpc}/tx?hash=0x{tx_hash}"
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.error("cosmos_get_tx_failed", tx_hash=tx_hash, error=str(e))
        return None

