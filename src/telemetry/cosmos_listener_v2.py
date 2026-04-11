"""
Cosmos/IBC Chain Listener (Passive - Phase 6)
==============================================

Refactored to be passive - no loops, no threading.
Worker calls poll_logs(block_number) to get events.
"""

import base64
import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Dict
from dataclasses import dataclass, field

import structlog
import aiohttp

from .non_evm_base import PassiveNonEVMListener
from .base import ListenerConfig
from ..models.events import SecurityEvent, EventType, Severity

logger = structlog.get_logger(__name__)


@dataclass
class CosmosListenerConfig(ListenerConfig):
    """Configuration for Cosmos chain listener."""
    tendermint_rpc: str = ""  # Primary Tendermint RPC
    rest_api: str = ""  # LCD REST API
    chain_prefix: str = "cosmos"  # Bech32 prefix
    ibc_channels: List[str] = field(default_factory=list)  # IBC channel IDs to monitor
    bridge_contracts: List[str] = field(default_factory=list)  # CosmWasm contract addresses
    
    def __post_init__(self):
        """Set rpc_url from tendermint_rpc if not provided."""
        if not self.rpc_url and self.tendermint_rpc:
            self.rpc_url = self.tendermint_rpc


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


class CosmosListener(PassiveNonEVMListener):
    """
    Passive Cosmos/IBC listener.
    
    Phase 6: No loops, no threading - just poll_logs(block_number).
    """
    
    def __init__(self, config: CosmosListenerConfig):
        super().__init__(config)
        self.config: CosmosListenerConfig = config
        self.ibc_channels = set(config.ibc_channels or [])
        self.bridge_contracts = set(config.bridge_contracts or [])
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30.0)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session
    
    async def _make_request(self, method: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make a Tendermint RPC request."""
        url = self.config.rpc_url or self.config.tendermint_rpc
        if not url:
            logger.error("cosmos_no_rpc_url", chain_id=self.chain_id)
            return None
        
        endpoint_url = f"{url}/{method}"
        if params:
            query_params = "&".join(f"{k}={v}" for k, v in params.items())
            endpoint_url = f"{endpoint_url}?{query_params}"
        
        try:
            session = await self._get_session()
            async with session.get(endpoint_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("result", data)
                else:
                    logger.warning("cosmos_request_failed", method=method, status=resp.status)
                    return None
        except Exception as e:
            logger.error("cosmos_request_error", method=method, error=str(e))
            return None
    
    async def get_latest_block(self) -> int:
        """Get the latest block height."""
        result = await self._make_request("status")
        if result:
            sync_info = result.get("sync_info", {})
            return int(sync_info.get("latest_block_height", 0))
        return 0
    
    async def poll_logs(self, block_number: int) -> List[SecurityEvent]:
        """
        Poll logs for a specific block number.
        
        Phase 6: Passive method - no loops, no threading.
        Worker calls this for each block.
        """
        events = []
        
        # Get block results (contains transaction events)
        block_results = await self._make_request("block_results", {"height": str(block_number)})
        if not block_results:
            return events
        
        # Get block data for transaction hashes
        block_data = await self._make_request("block", {"height": str(block_number)})
        txs = []
        if block_data:
            txs = block_data.get("block", {}).get("data", {}).get("txs", [])
        
        # Process transaction results
        txs_results = block_results.get("txs_results", [])
        
        for tx_idx, tx_result in enumerate(txs_results or []):
            if tx_result is None:
                continue
            
            # Get transaction hash
            if tx_idx < len(txs):
                tx_hash = self._compute_tx_hash(txs[tx_idx])
            else:
                tx_hash = f"tx_{block_number}_{tx_idx}"
            
            # Parse events from transaction
            tx_events = self._parse_tx_events(
                tx_result.get("events", []),
                tx_hash,
                block_number
            )
            events.extend(tx_events)
        
        logger.debug(
            "cosmos_block_polled",
            chain_id=self.chain_id,
            block_number=block_number,
            events_found=len(events)
        )
        
        return events
    
    def _compute_tx_hash(self, tx_base64: str) -> str:
        """Compute transaction hash from base64-encoded transaction."""
        try:
            tx_bytes = base64.b64decode(tx_base64)
            return hashlib.sha256(tx_bytes).hexdigest().upper()
        except:
            return tx_base64[:64]
    
    def _parse_tx_events(
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
            
            # Check for bridge contract executions
            elif event_type == "wasm" or event_type.startswith("cosmwasm"):
                security_event = self._check_bridge_contract(
                    attributes, tx_hash, height
                )
                if security_event:
                    events.append(security_event)
        
        return events
    
    def _create_ibc_event(
        self,
        event_type: str,
        attributes: Dict[str, str],
        tx_hash: str,
        height: int
    ) -> Optional[SecurityEvent]:
        """Create security event from IBC event."""
        # Extract IBC channel and packet info
        channel_id = attributes.get("packet_src_channel") or attributes.get("packet_dst_channel")
        packet_sequence = attributes.get("packet_sequence")
        
        if not channel_id:
            return None
        
        # Check if this is a monitored channel
        if self.ibc_channels and channel_id not in self.ibc_channels:
            return None
        
        # Extract amount if available
        amount_str = attributes.get("amount") or attributes.get("packet_data")
        amount = None
        if amount_str:
            try:
                # Try to parse amount (format: "1000uatom")
                import re
                match = re.search(r'(\d+)', amount_str)
                if match:
                    amount = int(match.group(1))
            except:
                pass
        
        return SecurityEvent(
            event_id=f"cosmos_{self.chain_id}_{height}_{tx_hash}_{packet_sequence}",
            chain_id=self.chain_id,
            event_type=EventType.BRIDGE_TRANSFER,
            tx_hash=tx_hash,
            block_number=height,
            block_timestamp=datetime.now(timezone.utc),  # Would get from block header
            contract_address=channel_id,
            severity=Severity.MEDIUM,
            amount=amount,
            raw_data={
                "event_type": event_type,
                "attributes": attributes,
                "protocol": "IBC"
            }
        )
    
    def _check_large_transfer(
        self,
        attributes: Dict[str, str],
        tx_hash: str,
        height: int
    ) -> Optional[SecurityEvent]:
        """Check for large token transfers."""
        amount_str = attributes.get("amount")
        if not amount_str:
            return None
        
        try:
            # Parse amount (format: "1000000uatom")
            import re
            match = re.search(r'(\d+)', amount_str)
            if match:
                amount = int(match.group(1))
                # Threshold: 1M tokens (adjust based on chain)
                if amount >= 1_000_000:
                    return SecurityEvent(
                        event_id=f"cosmos_{self.chain_id}_{height}_{tx_hash}_transfer",
                        chain_id=self.chain_id,
                        event_type=EventType.LARGE_TRANSFER,
                        tx_hash=tx_hash,
                        block_number=height,
                        block_timestamp=datetime.now(timezone.utc),
                        severity=Severity.LOW,
                        amount=amount,
                        raw_data={"attributes": attributes}
                    )
        except:
            pass
        
        return None
    
    def _check_bridge_contract(
        self,
        attributes: Dict[str, str],
        tx_hash: str,
        height: int
    ) -> Optional[SecurityEvent]:
        """Check for bridge contract executions."""
        contract = attributes.get("_contract_address") or attributes.get("contract_address")
        if not contract:
            return None
        
        # Check if this is a monitored bridge contract
        if self.bridge_contracts and contract not in self.bridge_contracts:
            return None
        
        # Identify bridge protocol
        protocol = "UNKNOWN"
        for bridge_name, patterns in BRIDGE_PATTERNS.items():
            if any(pattern in contract.lower() for pattern in patterns):
                protocol = bridge_name.upper()
                break
        
        return SecurityEvent(
            event_id=f"cosmos_{self.chain_id}_{height}_{tx_hash}_{contract}",
            chain_id=self.chain_id,
            event_type=EventType.BRIDGE_TRANSFER,
            tx_hash=tx_hash,
            block_number=height,
            block_timestamp=datetime.now(timezone.utc),
            contract_address=contract,
            severity=Severity.MEDIUM,
            raw_data={
                "attributes": attributes,
                "protocol": protocol
            }
        )
    
    async def get_block_info(self, block_number: int) -> Optional[dict]:
        """Get block metadata."""
        block_data = await self._make_request("block", {"height": str(block_number)})
        if block_data:
            block = block_data.get("block", {})
            header = block.get("header", {})
            return {
                "height": int(header.get("height", block_number)),
                "hash": block.get("last_commit", {}).get("block_id", {}).get("hash", ""),
                "time": header.get("time", ""),
                "tx_count": len(block.get("data", {}).get("txs", []))
            }
        return None

