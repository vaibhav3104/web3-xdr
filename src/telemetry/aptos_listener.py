"""
Aptos/Sui Listener (Move-based Chains)
======================================
Monitors Move-based blockchains for bridge events.

Supported Chains:
- Aptos
- Sui
- Movement (Aptos-compatible)

Bridge Protocols Monitored:
- LayerZero on Aptos
- Wormhole on Aptos/Sui
- Celer cBridge
- Multichain (compromised - forensic)
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional, Dict, Any, List
from dataclasses import dataclass, field

import structlog
import aiohttp

from .base import ChainListener, ListenerConfig
from ..models.events import SecurityEvent, EventType, EventSeverity

logger = structlog.get_logger(__name__)


@dataclass
class AptosConfig(ListenerConfig):
    """Configuration for Aptos/Sui listener"""
    rest_api: str = "https://fullnode.mainnet.aptoslabs.com/v1"
    indexer_api: str = ""  # GraphQL indexer
    chain_type: str = "aptos"  # "aptos" or "sui"
    bridge_modules: List[str] = field(default_factory=list)  # Move module addresses


# Known Aptos Bridge Addresses
APTOS_BRIDGES = {
    # LayerZero
    "0x54ad3d30af77b60d939ae356e6606de9a4da67583f02b962d2d3f2e481484e90": "LayerZero",
    "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa": "LayerZero Executor",
    # Wormhole
    "0x5bc11445584a763c1fa7ed39081f1b920954da14e04b32440cba863d03e19625": "Wormhole",
    "0x576410486a2da45eee6c949c995670112ddf2fbeedab20350d506328eefc9d4f": "Wormhole Token Bridge",
    # Celer
    "0x8d87a65ba30e09357fa2edea2c80dbac296e5dec2b18287113500b902942929d": "Celer cBridge",
    # Multichain (compromised)
    "0x9770fa9c725cbd97eb50b2be5f7416efdfd1f1554beb0750d4dae4c64e860da3": "Multichain",
}

# Sui Bridge Addresses
SUI_BRIDGES = {
    "0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d": "Wormhole",
    "0x5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a": "LayerZero",
}

# Suspicious Move module patterns
SUSPICIOUS_PATTERNS = [
    "flash_loan",
    "flash_swap",
    "emergency_withdraw",
    "admin_withdraw",
    "upgrade_module",
    "transfer_ownership",
]


class AptosListener(ChainListener):
    """
    Listens to Aptos/Sui chains via REST API.
    
    Move-based chains have unique security properties:
    - Formal verification support
    - Resource-oriented programming
    - Strong type system
    
    But still vulnerable to:
    - Bridge logic errors
    - Oracle manipulation
    - Access control bugs
    """
    
    def __init__(self, config: AptosConfig):
        super().__init__(config)
        self.config: AptosConfig = config
        self.http_session = None
        self.latest_version = 0
        self.bridge_modules = set(config.bridge_modules or [])
        
        # Add known bridges
        if config.chain_type == "aptos":
            self.bridge_modules.update(APTOS_BRIDGES.keys())
            self.bridge_names = APTOS_BRIDGES
        else:
            self.bridge_modules.update(SUI_BRIDGES.keys())
            self.bridge_names = SUI_BRIDGES
            
    async def connect(self) -> bool:
        """Connect to Aptos/Sui REST API"""
        try:
            self.http_session = aiohttp.ClientSession()
            
            if self.config.chain_type == "aptos":
                # Get ledger info for Aptos
                async with self.http_session.get(
                    f"{self.config.rest_api}"
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.latest_version = int(data.get("ledger_version", 0))
                        logger.info(
                            "aptos_connected",
                            chain=self.config.chain_id,
                            version=self.latest_version
                        )
                        self._connected = True
                        return True
            else:
                # Sui connection
                async with self.http_session.post(
                    self.config.rest_api,
                    json={"jsonrpc": "2.0", "method": "sui_getLatestCheckpointSequenceNumber", "id": 1}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.latest_version = int(data.get("result", 0))
                        logger.info(
                            "sui_connected",
                            chain=self.config.chain_id,
                            checkpoint=self.latest_version
                        )
                        self._connected = True
                        return True
                        
        except Exception as e:
            logger.error(
                f"{self.config.chain_type}_connection_failed",
                chain=self.config.chain_id,
                error=str(e)
            )
            
        return False
        
    async def disconnect(self):
        """Disconnect from API"""
        if self.http_session:
            await self.http_session.close()
        self._connected = False
        logger.info(f"{self.config.chain_type}_disconnected", chain=self.config.chain_id)
        
    async def listen_events(self) -> AsyncGenerator[SecurityEvent, None]:
        """Poll for new transactions"""
        poll_interval = 2  # seconds
        
        while self._connected:
            try:
                if self.config.chain_type == "aptos":
                    events = await self._poll_aptos_transactions()
                else:
                    events = await self._poll_sui_transactions()
                    
                for event in events:
                    yield event
                    
                await asyncio.sleep(poll_interval)
                
            except Exception as e:
                logger.error(
                    f"{self.config.chain_type}_poll_error",
                    chain=self.config.chain_id,
                    error=str(e)
                )
                await asyncio.sleep(5)
                
    async def _poll_aptos_transactions(self) -> List[SecurityEvent]:
        """Poll Aptos for new transactions"""
        events = []
        
        try:
            # Get recent transactions
            async with self.http_session.get(
                f"{self.config.rest_api}/transactions",
                params={"limit": 100, "start": self.latest_version}
            ) as resp:
                if resp.status != 200:
                    return events
                    
                transactions = await resp.json()
                
                for tx in transactions:
                    tx_events = self._process_aptos_tx(tx)
                    events.extend(tx_events)
                    
                    # Update latest version
                    version = int(tx.get("version", 0))
                    if version > self.latest_version:
                        self.latest_version = version
                        
        except Exception as e:
            logger.error("aptos_poll_failed", error=str(e))
            
        return events
        
    def _process_aptos_tx(self, tx: Dict) -> List[SecurityEvent]:
        """Process an Aptos transaction"""
        events = []
        
        if tx.get("type") != "user_transaction":
            return events
            
        tx_hash = tx.get("hash", "")
        version = tx.get("version", 0)
        sender = tx.get("sender", "")
        payload = tx.get("payload", {})
        
        # Check for bridge interactions
        function = payload.get("function", "")
        module_address = function.split("::")[0] if "::" in function else ""
        
        if module_address in self.bridge_modules:
            bridge_name = self.bridge_names.get(module_address, "Unknown Bridge")
            
            # Parse arguments for value
            args = payload.get("arguments", [])
            value = self._extract_value(args)
            
            severity = self._calculate_severity(value)
            
            events.append(SecurityEvent(
                event_id=f"aptos_{tx_hash}",
                chain_id=self.config.chain_id,
                event_type=EventType.BRIDGE_CALL,
                severity=severity,
                timestamp=datetime.now(timezone.utc),
                transaction_hash=tx_hash,
                block_number=int(version),
                from_address=sender,
                contract_address=module_address,
                method_name=function,
                value=str(value),
                raw_data=tx,
                metadata={
                    "chain_type": "aptos",
                    "bridge_name": bridge_name,
                    "function": function,
                    "value_usd": value
                }
            ))
            
        # Check for suspicious patterns
        function_lower = function.lower()
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in function_lower:
                events.append(SecurityEvent(
                    event_id=f"aptos_{tx_hash}_suspicious",
                    chain_id=self.config.chain_id,
                    event_type=EventType.SUSPICIOUS_CALL,
                    severity=EventSeverity.HIGH,
                    timestamp=datetime.now(timezone.utc),
                    transaction_hash=tx_hash,
                    block_number=int(version),
                    from_address=sender,
                    contract_address=module_address,
                    method_name=function,
                    raw_data=tx,
                    metadata={
                        "chain_type": "aptos",
                        "suspicious_pattern": pattern,
                        "function": function
                    }
                ))
                break
                
        # Check for events in the transaction
        for event in tx.get("events", []):
            event_type = event.get("type", "")
            
            # Look for bridge-related events
            if any(bridge in event_type.lower() for bridge in ["transfer", "deposit", "withdraw", "bridge"]):
                event_data = event.get("data", {})
                
                events.append(SecurityEvent(
                    event_id=f"aptos_{tx_hash}_{event.get('sequence_number', 0)}",
                    chain_id=self.config.chain_id,
                    event_type=EventType.TOKEN_TRANSFER,
                    severity=EventSeverity.LOW,
                    timestamp=datetime.now(timezone.utc),
                    transaction_hash=tx_hash,
                    block_number=int(version),
                    from_address=sender,
                    raw_data=event,
                    metadata={
                        "chain_type": "aptos",
                        "event_type": event_type,
                        "event_data": event_data
                    }
                ))
                
        return events
        
    async def _poll_sui_transactions(self) -> List[SecurityEvent]:
        """Poll Sui for new transactions"""
        events = []
        
        try:
            # Get recent transactions using JSON-RPC
            async with self.http_session.post(
                self.config.rest_api,
                json={
                    "jsonrpc": "2.0",
                    "method": "suix_queryTransactionBlocks",
                    "params": [{
                        "filter": None,
                        "options": {"showInput": True, "showEffects": True, "showEvents": True}
                    }, None, 50, True],
                    "id": 1
                }
            ) as resp:
                if resp.status != 200:
                    return events
                    
                data = await resp.json()
                transactions = data.get("result", {}).get("data", [])
                
                for tx in transactions:
                    tx_events = self._process_sui_tx(tx)
                    events.extend(tx_events)
                    
        except Exception as e:
            logger.error("sui_poll_failed", error=str(e))
            
        return events
        
    def _process_sui_tx(self, tx: Dict) -> List[SecurityEvent]:
        """Process a Sui transaction"""
        events = []
        
        digest = tx.get("digest", "")
        checkpoint = tx.get("checkpoint", 0)
        
        # Get transaction input
        tx_input = tx.get("transaction", {}).get("data", {}).get("transaction", {})
        kind = tx_input.get("kind", "")
        
        if kind == "ProgrammableTransaction":
            # Check for bridge package calls
            for command in tx_input.get("commands", []):
                if command.get("MoveCall"):
                    move_call = command["MoveCall"]
                    package = move_call.get("package", "")
                    module = move_call.get("module", "")
                    function = move_call.get("function", "")
                    
                    if package in self.bridge_modules:
                        bridge_name = self.bridge_names.get(package, "Unknown Bridge")
                        
                        events.append(SecurityEvent(
                            event_id=f"sui_{digest}",
                            chain_id=self.config.chain_id,
                            event_type=EventType.BRIDGE_CALL,
                            severity=EventSeverity.MEDIUM,
                            timestamp=datetime.now(timezone.utc),
                            transaction_hash=digest,
                            block_number=int(checkpoint) if checkpoint else 0,
                            contract_address=package,
                            method_name=f"{module}::{function}",
                            raw_data=tx,
                            metadata={
                                "chain_type": "sui",
                                "bridge_name": bridge_name,
                                "package": package,
                                "module": module,
                                "function": function
                            }
                        ))
                        
        # Process emitted events
        for event in tx.get("events", []):
            event_type = event.get("type", "")
            
            if "bridge" in event_type.lower() or "transfer" in event_type.lower():
                events.append(SecurityEvent(
                    event_id=f"sui_{digest}_{event.get('id', {}).get('eventSeq', 0)}",
                    chain_id=self.config.chain_id,
                    event_type=EventType.TOKEN_TRANSFER,
                    severity=EventSeverity.LOW,
                    timestamp=datetime.now(timezone.utc),
                    transaction_hash=digest,
                    block_number=int(checkpoint) if checkpoint else 0,
                    raw_data=event,
                    metadata={
                        "chain_type": "sui",
                        "event_type": event_type
                    }
                ))
                
        return events
        
    def _extract_value(self, args: List) -> float:
        """Extract USD value from transaction arguments"""
        for arg in args:
            if isinstance(arg, (int, str)):
                try:
                    # Assume 8 decimals for most Aptos tokens
                    val = float(arg) / 1e8
                    if val > 100:  # Likely a meaningful value
                        return val
                except:
                    continue
        return 0
        
    def _calculate_severity(self, value: float) -> EventSeverity:
        """Calculate severity based on value"""
        if value > 10_000_000:
            return EventSeverity.CRITICAL
        elif value > 1_000_000:
            return EventSeverity.HIGH
        elif value > 100_000:
            return EventSeverity.MEDIUM
        return EventSeverity.LOW
        
    async def get_account_resources(self, address: str) -> Optional[List[Dict]]:
        """Get account resources (for investigation)"""
        try:
            async with self.http_session.get(
                f"{self.config.rest_api}/accounts/{address}/resources"
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.error("aptos_get_resources_failed", address=address, error=str(e))
        return None

