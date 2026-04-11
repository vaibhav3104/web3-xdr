"""
Aptos/Sui Listener (Passive - Phase 6)
======================================

Refactored to be passive - no loops, no threading.
Worker calls poll_logs(block_number) to get events.
"""

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
class AptosListenerConfig(ListenerConfig):
    """Configuration for Aptos/Sui listener."""
    rest_api: str = "https://fullnode.mainnet.aptoslabs.com/v1"
    indexer_api: str = ""  # GraphQL indexer
    chain_type: str = "aptos"  # "aptos" or "sui"
    bridge_modules: List[str] = field(default_factory=list)  # Move module addresses
    
    def __post_init__(self):
        """Set rpc_url from rest_api if not provided."""
        if not self.rpc_url and self.rest_api:
            self.rpc_url = self.rest_api


# Known Aptos Bridge Addresses
APTOS_BRIDGES = {
    "0x54ad3d30af77b60d939ae356e6606de9a4da67583f02b962d2d3f2e481484e90": "LayerZero",
    "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa": "LayerZero Executor",
    "0x5bc11445584a763c1fa7ed39081f1b920954da14e04b32440cba863d03e19625": "Wormhole",
    "0x576410486a2da45eee6c949c995670112ddf2fbeedab20350d506328eefc9d4f": "Wormhole Token Bridge",
    "0x8d87a65ba30e09357fa2edea2c80dbac296e5dec2b18287113500b902942929d": "Celer cBridge",
    "0x9770fa9c725cbd97eb50b2be5f7416efdfd1f1554beb0750d4dae4c64e860da3": "Multichain",
}

# Sui Bridge Addresses
SUI_BRIDGES = {
    "0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d": "Wormhole",
    "0x5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a": "LayerZero",
}


class AptosListener(PassiveNonEVMListener):
    """
    Passive Aptos/Sui listener.
    
    Phase 6: No loops, no threading - just poll_logs(block_number).
    """
    
    def __init__(self, config: AptosListenerConfig):
        super().__init__(config)
        self.config: AptosListenerConfig = config
        self.bridge_modules = set(config.bridge_modules or [])
        
        # Add known bridges based on chain type
        if config.chain_type == "aptos":
            self.bridge_modules.update(APTOS_BRIDGES.keys())
            self.bridge_names = APTOS_BRIDGES
        else:
            self.bridge_modules.update(SUI_BRIDGES.keys())
            self.bridge_names = SUI_BRIDGES
        
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30.0)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session
    
    async def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make an Aptos REST API request."""
        url = self.config.rpc_url or self.config.rest_api
        if not url:
            logger.error("aptos_no_rpc_url", chain_id=self.chain_id)
            return None
        
        endpoint_url = f"{url}/{endpoint}"
        if params:
            query_params = "&".join(f"{k}={v}" for k, v in params.items())
            endpoint_url = f"{endpoint_url}?{query_params}"
        
        try:
            session = await self._get_session()
            async with session.get(endpoint_url) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    logger.warning("aptos_request_failed", endpoint=endpoint, status=resp.status)
                    return None
        except Exception as e:
            logger.error("aptos_request_error", endpoint=endpoint, error=str(e))
            return None
    
    async def get_latest_block(self) -> int:
        """Get the latest block height (version for Aptos)."""
        if self.config.chain_type == "aptos":
            result = await self._make_request("")
            if result:
                # Aptos uses "ledger_info" endpoint
                ledger_info = await self._make_request("")
                if ledger_info:
                    return int(ledger_info.get("block_height", 0))
        else:
            # Sui uses different endpoint
            result = await self._make_request("sui_getLatestCheckpointSequenceNumber")
            if result:
                return int(result.get("result", 0))
        return 0
    
    async def poll_logs(self, block_number: int) -> List[SecurityEvent]:
        """
        Poll logs for a specific block number (version for Aptos).
        
        Phase 6: Passive method - no loops, no threading.
        Worker calls this for each block.
        """
        events = []
        
        if self.config.chain_type == "aptos":
            # Aptos uses "version" instead of "block_number"
            transactions = await self._make_request("transactions", {"start": str(block_number), "limit": "100"})
            if transactions:
                for tx in transactions.get("result", []):
                    tx_events = self._parse_aptos_tx(tx, block_number)
                    events.extend(tx_events)
        else:
            # Sui uses checkpoint-based model
            checkpoint = await self._make_request(f"checkpoint/{block_number}")
            if checkpoint:
                transactions = checkpoint.get("transactions", [])
                for tx in transactions:
                    tx_events = self._parse_sui_tx(tx, block_number)
                    events.extend(tx_events)
        
        logger.debug(
            "aptos_block_polled",
            chain_id=self.chain_id,
            block_number=block_number,
            events_found=len(events)
        )
        
        return events
    
    def _parse_aptos_tx(self, tx: Dict, version: int) -> List[SecurityEvent]:
        """Parse Aptos transaction into security events."""
        events = []
        
        tx_hash = tx.get("hash", "")
        tx_type = tx.get("type", "")
        
        # Check for bridge transactions
        if tx_type == "user_transaction":
            payload = tx.get("payload", {})
            function = payload.get("function", "")
            
            # Check if this is a bridge module
            for bridge_addr, bridge_name in self.bridge_names.items():
                if bridge_addr in function:
                    events.append(SecurityEvent(
                        event_id=f"aptos_{self.chain_id}_{version}_{tx_hash}",
                        chain_id=self.chain_id,
                        event_type=EventType.BRIDGE_TRANSFER,
                        tx_hash=tx_hash,
                        block_number=version,
                        block_timestamp=datetime.now(timezone.utc),
                        contract_address=bridge_addr,
                        severity=Severity.MEDIUM,
                        raw_data={
                            "function": function,
                            "protocol": bridge_name,
                            "tx": tx
                        }
                    ))
                    break
        
        return events
    
    def _parse_sui_tx(self, tx: Dict, checkpoint: int) -> List[SecurityEvent]:
        """Parse Sui transaction into security events."""
        events = []
        
        tx_digest = tx.get("transaction", {}).get("data", {}).get("digest", "")
        
        # Check for bridge transactions
        for bridge_addr, bridge_name in self.bridge_names.items():
            if bridge_addr in str(tx):
                events.append(SecurityEvent(
                    event_id=f"sui_{self.chain_id}_{checkpoint}_{tx_digest}",
                    chain_id=self.chain_id,
                    event_type=EventType.BRIDGE_TRANSFER,
                    tx_hash=tx_digest,
                    block_number=checkpoint,
                    block_timestamp=datetime.now(timezone.utc),
                    contract_address=bridge_addr,
                    severity=Severity.MEDIUM,
                    raw_data={
                        "protocol": bridge_name,
                        "tx": tx
                    }
                ))
                break
        
        return events
    
    async def get_block_info(self, block_number: int) -> Optional[dict]:
        """Get block metadata."""
        if self.config.chain_type == "aptos":
            result = await self._make_request(f"transactions/{block_number}")
            if result:
                return {
                    "version": block_number,
                    "hash": result.get("hash", ""),
                    "timestamp": result.get("timestamp", "")
                }
        else:
            checkpoint = await self._make_request(f"checkpoint/{block_number}")
            if checkpoint:
                return {
                    "checkpoint": block_number,
                    "digest": checkpoint.get("digest", ""),
                    "timestamp": checkpoint.get("timestamp_ms", "")
                }
        return None

