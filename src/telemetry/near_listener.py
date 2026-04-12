"""
Near Protocol Listener (Robust)
================================
Monitors Near Protocol for bridge events via RPC with failover support.

Features:
- Multi-RPC failover with health tracking
- Automatic reconnection
- Heartbeat logging
- Rainbow Bridge monitoring
- Aurora EVM bridge events
- Access key abuse detection

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

import json
import base64
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

import structlog
import aiohttp

from .robust_non_evm import RobustNonEVMListener, NonEVMConfig
from ..models.events import SecurityEvent, EventType, Severity

logger = structlog.get_logger(__name__)


@dataclass
class NearConfig(NonEVMConfig):
    """Configuration for Near Protocol listener with failover support."""
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


class NearListener(RobustNonEVMListener):
    """
    Robust listener for Near Protocol via JSON-RPC.
    
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
    
    Includes multi-RPC failover and automatic reconnection.
    """
    
    def __init__(self, config: NearConfig):
        super().__init__(config)
        self.config: NearConfig = config
        self.bridge_accounts = set(config.bridge_accounts or [])
        self.bridge_accounts.update(NEAR_BRIDGES.keys())
    
    async def _make_chain_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        params: Any,
        is_json_rpc: bool
    ) -> Optional[Dict]:
        """Make a Near JSON-RPC request."""
        async with session.post(
            url,
            json={
                "jsonrpc": "2.0",
                "id": "sentinel3",
                "method": method,
                "params": params or {}
            }
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                if "error" in data:
                    logger.warning(
                        "near_rpc_error",
                        method=method,
                        error=data["error"]
                    )
                    raise Exception(f"Near RPC error: {data['error']}")
                return data.get("result")
            else:
                raise aiohttp.ClientResponseError(
                    resp.request_info,
                    resp.history,
                    status=resp.status,
                    message=f"HTTP {resp.status}"
                )
    
    async def _get_latest_block_height(self) -> int:
        """Get the latest block height from Near."""
        result = await self._make_request("status", [])
        
        if result:
            sync_info = result.get("sync_info", {})
            return sync_info.get("latest_block_height", 0)
        return 0
    
    async def _process_block_impl(self, height: int) -> List[SecurityEvent]:
        """Process a Near block."""
        events = []
        
        # Get block details
        block = await self._make_request("block", {"block_id": height})
        if not block:
            return events
        
        block_hash = block.get("header", {}).get("hash", "")
        
        # Get chunks (Near is sharded)
        for chunk_header in block.get("chunks", []):
            chunk_hash = chunk_header.get("chunk_hash", "")
            
            # Get chunk details with transactions
            chunk = await self._make_request("chunk", {"chunk_id": chunk_hash})
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
        """Process a Near transaction."""
        events = []
        
        tx_hash = tx.get("hash", "")
        signer_id = tx.get("signer_id", "")
        receiver_id = tx.get("receiver_id", "")
        
        # Get full transaction outcome
        outcome = await self._make_request("tx", [tx_hash, signer_id])
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
        """Process a single Near action."""
        events = []
        
        # Transfer action
        if "Transfer" in action:
            amount = int(action["Transfer"].get("deposit", 0))
            amount_near = amount / 1e24  # Near uses 24 decimals
            
            is_bridge = receiver in self.bridge_accounts
            bridge_name = NEAR_BRIDGES.get(receiver)
            
            if is_bridge or amount_near > 100000:
                severity = self._calculate_severity(amount_near, is_bridge)
                
                events.append(SecurityEvent(
                    event_id=f"near_{tx_hash}_transfer",
                    chain_id=self.config.chain_id,
                    event_type=EventType.BRIDGE_DEPOSIT if is_bridge else EventType.LARGE_TRANSFER,
                    severity=severity,
                    block_timestamp=datetime.now(timezone.utc),
                    tx_hash=tx_hash,
                    block_number=height,
                    source_address=signer,
                    dest_address=receiver,
                    amount=Decimal(str(amount_near)),
                    raw_event={
                        "action": action,
                        "outcome": outcome,
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
                    block_timestamp=datetime.now(timezone.utc),
                    tx_hash=tx_hash,
                    block_number=height,
                    source_address=signer,
                    dest_address=receiver,
                    contract_address=receiver,
                    amount=Decimal(str(deposit / 1e24)),
                    raw_event={
                        "action": action,
                        "args": args,
                        "method_name": method_name,
                        "chain_type": "near",
                        "bridge_name": bridge_name,
                        "deposit_near": deposit / 1e24
                    }
                ))
            
            if is_suspicious:
                events.append(SecurityEvent(
                    event_id=f"near_{tx_hash}_suspicious",
                    chain_id=self.config.chain_id,
                    event_type=EventType.SUSPICIOUS_CALL,
                    severity=Severity.HIGH,
                    block_timestamp=datetime.now(timezone.utc),
                    tx_hash=tx_hash,
                    block_number=height,
                    source_address=signer,
                    dest_address=receiver,
                    contract_address=receiver,
                    raw_event={
                        "action": action,
                        "args": args,
                        "method_name": method_name,
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
                    block_timestamp=datetime.now(timezone.utc),
                    tx_hash=tx_hash,
                    block_number=height,
                    source_address=signer,
                    dest_address=receiver,
                    contract_address=receiver,
                    raw_event={
                        "action": action,
                        "method_name": key_action,
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
                block_timestamp=datetime.now(timezone.utc),
                tx_hash=tx_hash,
                block_number=height,
                source_address=signer,
                dest_address=receiver,
                contract_address=receiver,
                raw_event={
                    "action": "DeployContract",
                    "method_name": "deploy_contract",
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
        """Process a Near receipt (cross-contract call result)."""
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
                        block_timestamp=datetime.now(timezone.utc),
                        tx_hash=tx_hash,
                        block_number=height,
                        contract_address=executor_id,
                        raw_event={
                            "receipt": receipt,
                            "log": log,
                            "chain_type": "near",
                            "bridge_name": NEAR_BRIDGES.get(executor_id)
                        }
                    ))
        
        return events
    
    def _calculate_severity(self, amount_near: float, is_bridge: bool) -> Severity:
        """Calculate severity based on amount and context."""
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
        """Get account details."""
        return await self._make_request("query", {
            "request_type": "view_account",
            "finality": "final",
            "account_id": account_id
        })
    
    async def get_access_keys(self, account_id: str) -> Optional[List[Dict]]:
        """Get account access keys (for investigation)."""
        result = await self._make_request("query", {
            "request_type": "view_access_key_list",
            "finality": "final",
            "account_id": account_id
        })
        return result.get("keys", []) if result else None
