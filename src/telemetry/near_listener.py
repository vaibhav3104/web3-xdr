"""
Near Protocol Listener
======================
Monitors Near Protocol for bridge events via RPC.

Key Features:
- Rainbow Bridge monitoring (ETH <-> Near)
- Aurora (EVM on Near) bridge events
- Octopus Network appchains
- Near native token transfers

Near-Specific Vulnerabilities:
- Rainbow Bridge relay attacks
- Aurora EVM exploits
- Access key abuse
- Sharded execution timing
"""

import asyncio
import json
import base64
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional, Dict, Any, List
from dataclasses import dataclass, field

import structlog
import aiohttp

from .base import ChainListener, ListenerConfig
from ..models.events import SecurityEvent, EventType, Severity

logger = structlog.get_logger(__name__)


@dataclass
class NearConfig(ListenerConfig):
    """Configuration for Near Protocol listener"""
    rpc_url: str = "https://rpc.mainnet.near.org"
    archival_rpc: str = ""  # For historical queries
    indexer_url: str = ""  # Near Indexer for Explorer
    bridge_accounts: List[str] = field(default_factory=list)


# Known Near Bridge Accounts
NEAR_BRIDGES = {
    # Rainbow Bridge
    "factory.bridge.near": "Rainbow Bridge Factory",
    "aurora": "Aurora Engine",
    "relay.aurora": "Aurora Relay",
    "client.bridge.near": "Rainbow Light Client",
    "prover.bridge.near": "Rainbow Prover",
    # Octopus Network
    "octopus-registry.near": "Octopus Registry",
    # Allbridge
    "allbridge.near": "Allbridge",
    # Wormhole
    "contract.wormhole_crypto.near": "Wormhole",
}

# Suspicious method patterns
SUSPICIOUS_METHODS = [
    "withdraw_all",
    "emergency",
    "admin_",
    "upgrade",
    "set_owner",
    "add_key",
    "delete_key",
    "deploy_code",
]


class NearListener(ChainListener):
    """
    Listens to Near Protocol via JSON-RPC.
    
    Near has unique properties:
    - Account-based (not address-based)
    - Sharded execution
    - Named accounts
    - Access keys with function call permissions
    
    Attack vectors specific to Near:
    - Rainbow Bridge relay manipulation
    - Aurora EVM escape
    - Access key compromise
    - Sharding timing attacks
    """
    
    def __init__(self, config: NearConfig):
        super().__init__(config)
        self.config: NearConfig = config
        self.http_session = None
        self.latest_block_height = 0
        self.bridge_accounts = set(config.bridge_accounts or [])
        self.bridge_accounts.update(NEAR_BRIDGES.keys())
        
    async def connect(self) -> bool:
        """Connect to Near RPC"""
        try:
            self.http_session = aiohttp.ClientSession()
            
            # Get latest block
            result = await self._rpc_call("status", [])
            
            if result:
                sync_info = result.get("sync_info", {})
                self.latest_block_height = sync_info.get("latest_block_height", 0)
                
                logger.info(
                    "near_connected",
                    chain=self.config.chain_id,
                    height=self.latest_block_height,
                    syncing=sync_info.get("syncing", False)
                )
                self._connected = True
                return True
                
        except Exception as e:
            logger.error("near_connection_failed", chain=self.config.chain_id, error=str(e))
            
        return False
        
    async def disconnect(self):
        """Disconnect from Near RPC"""
        if self.http_session:
            await self.http_session.close()
        self._connected = False
        logger.info("near_disconnected", chain=self.config.chain_id)
        
    async def _rpc_call(self, method: str, params: Any) -> Optional[Dict]:
        """Make a JSON-RPC call to Near"""
        try:
            async with self.http_session.post(
                self.config.rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": "web3-xdr",
                    "method": method,
                    "params": params
                }
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("result")
        except Exception as e:
            logger.error("near_rpc_failed", method=method, error=str(e))
        return None
        
    async def listen_events(self) -> AsyncGenerator[SecurityEvent, None]:
        """Poll for new blocks and transactions"""
        poll_interval = 1  # Near has ~1s block time
        
        while self._connected:
            try:
                # Get latest block
                result = await self._rpc_call("status", [])
                if not result:
                    await asyncio.sleep(poll_interval)
                    continue
                    
                current_height = result.get("sync_info", {}).get("latest_block_height", 0)
                
                # Process new blocks
                while self.latest_block_height < current_height:
                    self.latest_block_height += 1
                    
                    events = await self._process_block(self.latest_block_height)
                    for event in events:
                        yield event
                        
                await asyncio.sleep(poll_interval)
                
            except Exception as e:
                logger.error("near_poll_error", chain=self.config.chain_id, error=str(e))
                await asyncio.sleep(5)
                
    async def _process_block(self, height: int) -> List[SecurityEvent]:
        """Process a Near block"""
        events = []
        
        # Get block details
        block = await self._rpc_call("block", {"block_id": height})
        if not block:
            return events
            
        block_hash = block.get("header", {}).get("hash", "")
        
        # Get chunks (Near is sharded)
        for chunk_header in block.get("chunks", []):
            chunk_hash = chunk_header.get("chunk_hash", "")
            
            # Get chunk details with transactions
            chunk = await self._rpc_call("chunk", {"chunk_id": chunk_hash})
            if not chunk:
                continue
                
            # Process transactions in chunk
            for tx in chunk.get("transactions", []):
                tx_events = await self._process_transaction(tx, height, block_hash)
                events.extend(tx_events)
                
        return events
        
    async def _process_transaction(
        self,
        tx: Dict,
        height: int,
        block_hash: str
    ) -> List[SecurityEvent]:
        """Process a Near transaction"""
        events = []
        
        tx_hash = tx.get("hash", "")
        signer_id = tx.get("signer_id", "")
        receiver_id = tx.get("receiver_id", "")
        
        # Get full transaction outcome
        outcome = await self._rpc_call("tx", [tx_hash, signer_id])
        if not outcome:
            return events
            
        # Process each action in the transaction
        for action in tx.get("actions", []):
            action_events = self._process_action(
                action, tx_hash, height, signer_id, receiver_id, outcome
            )
            events.extend(action_events)
            
        # Check receipts for cross-contract calls
        for receipt in outcome.get("receipts_outcome", []):
            receipt_events = self._process_receipt(receipt, tx_hash, height)
            events.extend(receipt_events)
            
        return events
        
    def _process_action(
        self,
        action: Dict,
        tx_hash: str,
        height: int,
        signer: str,
        receiver: str,
        outcome: Dict
    ) -> List[SecurityEvent]:
        """Process a single Near action"""
        events = []
        
        # Transfer action
        if "Transfer" in action:
            amount = int(action["Transfer"].get("deposit", 0))
            amount_near = amount / 1e24  # Near uses 24 decimals
            
            # Check if receiver is a bridge
            is_bridge = receiver in self.bridge_accounts
            bridge_name = NEAR_BRIDGES.get(receiver)
            
            if is_bridge or amount_near > 100000:  # Large transfer or bridge
                severity = self._calculate_severity(amount_near, is_bridge)
                
                events.append(SecurityEvent(
                    event_id=f"near_{tx_hash}_transfer",
                    chain_id=self.config.chain_id,
                    event_type=EventType.BRIDGE_DEPOSIT if is_bridge else EventType.LARGE_TRANSFER,
                    severity=severity,
                    timestamp=datetime.now(timezone.utc),
                    transaction_hash=tx_hash,
                    block_number=height,
                    from_address=signer,
                    to_address=receiver,
                    value=str(amount),
                    raw_data={"action": action, "outcome": outcome},
                    metadata={
                        "chain_type": "near",
                        "amount_near": amount_near,
                        "bridge_name": bridge_name,
                        "is_bridge": is_bridge
                    }
                ))
                
        # Function call action
        elif "FunctionCall" in action:
            fc = action["FunctionCall"]
            method_name = fc.get("method_name", "")
            args_raw = fc.get("args", "")
            deposit = int(fc.get("deposit", 0))
            
            # Decode args if base64
            try:
                if args_raw:
                    args = json.loads(base64.b64decode(args_raw))
                else:
                    args = {}
            except:
                args = {"raw": args_raw}
                
            # Check if calling a bridge
            is_bridge = receiver in self.bridge_accounts
            bridge_name = NEAR_BRIDGES.get(receiver)
            
            # Check for suspicious methods
            is_suspicious = any(
                pattern in method_name.lower()
                for pattern in SUSPICIOUS_METHODS
            )
            
            if is_bridge:
                events.append(SecurityEvent(
                    event_id=f"near_{tx_hash}_bridge_call",
                    chain_id=self.config.chain_id,
                    event_type=EventType.BRIDGE_CALL,
                    severity=Severity.MEDIUM,
                    timestamp=datetime.now(timezone.utc),
                    transaction_hash=tx_hash,
                    block_number=height,
                    from_address=signer,
                    to_address=receiver,
                    contract_address=receiver,
                    method_name=method_name,
                    value=str(deposit),
                    raw_data={"action": action, "args": args},
                    metadata={
                        "chain_type": "near",
                        "bridge_name": bridge_name,
                        "method": method_name,
                        "deposit_near": deposit / 1e24
                    }
                ))
                
            if is_suspicious:
                events.append(SecurityEvent(
                    event_id=f"near_{tx_hash}_suspicious",
                    chain_id=self.config.chain_id,
                    event_type=EventType.SUSPICIOUS_CALL,
                    severity=Severity.HIGH,
                    timestamp=datetime.now(timezone.utc),
                    transaction_hash=tx_hash,
                    block_number=height,
                    from_address=signer,
                    to_address=receiver,
                    contract_address=receiver,
                    method_name=method_name,
                    raw_data={"action": action, "args": args},
                    metadata={
                        "chain_type": "near",
                        "suspicious_method": method_name,
                        "reason": "Matches suspicious pattern"
                    }
                ))
                
        # Add/Delete key actions (access key manipulation)
        elif "AddKey" in action or "DeleteKey" in action:
            key_action = "AddKey" if "AddKey" in action else "DeleteKey"
            key_data = action[key_action]
            
            # Key manipulation on bridge accounts is critical
            if receiver in self.bridge_accounts:
                events.append(SecurityEvent(
                    event_id=f"near_{tx_hash}_key_{key_action.lower()}",
                    chain_id=self.config.chain_id,
                    event_type=EventType.ACCESS_CONTROL_CHANGE,
                    severity=Severity.CRITICAL,
                    timestamp=datetime.now(timezone.utc),
                    transaction_hash=tx_hash,
                    block_number=height,
                    from_address=signer,
                    to_address=receiver,
                    contract_address=receiver,
                    method_name=key_action,
                    raw_data={"action": action},
                    metadata={
                        "chain_type": "near",
                        "key_action": key_action,
                        "bridge_name": NEAR_BRIDGES.get(receiver),
                        "key_data": key_data
                    }
                ))
                
        # Deploy contract action
        elif "DeployContract" in action:
            events.append(SecurityEvent(
                event_id=f"near_{tx_hash}_deploy",
                chain_id=self.config.chain_id,
                event_type=EventType.CONTRACT_DEPLOYED,
                severity=Severity.MEDIUM,
                timestamp=datetime.now(timezone.utc),
                transaction_hash=tx_hash,
                block_number=height,
                from_address=signer,
                to_address=receiver,
                contract_address=receiver,
                method_name="deploy_contract",
                raw_data={"action": "DeployContract"},
                metadata={
                    "chain_type": "near",
                    "deployed_to": receiver
                }
            ))
            
        return events
        
    def _process_receipt(
        self,
        receipt: Dict,
        tx_hash: str,
        height: int
    ) -> List[SecurityEvent]:
        """Process a Near receipt (cross-contract call result)"""
        events = []
        
        outcome = receipt.get("outcome", {})
        executor_id = outcome.get("executor_id", "")
        
        # Check for bridge interactions in cross-contract calls
        if executor_id in self.bridge_accounts:
            logs = outcome.get("logs", [])
            
            # Parse logs for transfer events
            for log in logs:
                if "transfer" in log.lower() or "deposit" in log.lower():
                    events.append(SecurityEvent(
                        event_id=f"near_{tx_hash}_{receipt.get('id', '')}",
                        chain_id=self.config.chain_id,
                        event_type=EventType.BRIDGE_EVENT,
                        severity=Severity.LOW,
                        timestamp=datetime.now(timezone.utc),
                        transaction_hash=tx_hash,
                        block_number=height,
                        contract_address=executor_id,
                        raw_data={"receipt": receipt, "log": log},
                        metadata={
                            "chain_type": "near",
                            "bridge_name": NEAR_BRIDGES.get(executor_id),
                            "log": log
                        }
                    ))
                    
        return events
        
    def _calculate_severity(self, amount_near: float, is_bridge: bool) -> Severity:
        """Calculate severity based on amount and context"""
        if is_bridge:
            if amount_near > 1_000_000:
                return Severity.CRITICAL
            elif amount_near > 100_000:
                return Severity.HIGH
            elif amount_near > 10_000:
                return Severity.MEDIUM
        else:
            if amount_near > 10_000_000:
                return Severity.CRITICAL
            elif amount_near > 1_000_000:
                return Severity.HIGH
        return Severity.LOW
        
    async def get_account(self, account_id: str) -> Optional[Dict]:
        """Get account details"""
        return await self._rpc_call("query", {
            "request_type": "view_account",
            "finality": "final",
            "account_id": account_id
        })
        
    async def get_access_keys(self, account_id: str) -> Optional[List[Dict]]:
        """Get account access keys (for investigation)"""
        result = await self._rpc_call("query", {
            "request_type": "view_access_key_list",
            "finality": "final",
            "account_id": account_id
        })
        return result.get("keys", []) if result else None

