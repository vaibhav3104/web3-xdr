"""
Solana Chain Listener - For Solana mainnet and devnet.
"""

from datetime import datetime, timezone
from decimal import Decimal
from typing import AsyncIterator, Dict, List, Optional, Set
import asyncio
import structlog

from .base import ChainListener, ListenerConfig, BlockMetadata
from ..models.events import SecurityEvent, EventType, Severity

logger = structlog.get_logger()


# Solana program IDs
SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
WORMHOLE_BRIDGE_PROGRAM = "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth"


class SolanaListener(ChainListener):
    """
    Listener for Solana blockchain.
    
    Uses Solana RPC API to monitor:
    - SPL Token transfers
    - Program invocations (bridges)
    - Account changes
    """
    
    def __init__(self, config: ListenerConfig):
        super().__init__(config)
        self._http_client = None
        self._last_signature: Optional[str] = None
        
        # Track processed signatures to avoid duplicates
        self._processed_signatures: Set[str] = set()
        
        # Program ID to bridge mapping
        self._program_bridges: Dict[str, str] = {}
    
    async def connect(self):
        """Connect to Solana RPC."""
        import httpx
        self._http_client = httpx.AsyncClient(timeout=30.0)
        
        # Test connection
        response = await self._rpc_call("getHealth")
        if response.get("result") != "ok":
            logger.warning("solana_node_not_healthy", response=response)
        
        logger.info(
            "solana_connected",
            chain_id=self.chain_id,
            rpc_url=self.config.rpc_url[:50] + "..."
        )
    
    async def disconnect(self):
        """Disconnect from Solana RPC."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
    
    async def _rpc_call(self, method: str, params: List = None) -> dict:
        """Make an RPC call to Solana node."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or []
        }
        
        response = await self._http_client.post(
            self.config.rpc_url,
            json=payload
        )
        return response.json()
    
    async def get_latest_block(self) -> int:
        """Get latest slot number."""
        response = await self._rpc_call("getSlot")
        return response.get("result", 0)
    
    async def process_block(self, block_number: int) -> BlockMetadata:
        """
        Process a Solana slot and extract security events.
        """
        try:
            # Get block (slot) data
            response = await self._rpc_call(
                "getBlock",
                [
                    block_number,
                    {
                        "encoding": "jsonParsed",
                        "transactionDetails": "full",
                        "rewards": False,
                        "maxSupportedTransactionVersion": 0
                    }
                ]
            )
            
            if "error" in response or not response.get("result"):
                return BlockMetadata(
                    chain_id=self.chain_id,
                    block_number=block_number,
                    block_hash="",
                    timestamp=datetime.now(timezone.utc),
                    tx_count=0,
                    events_extracted=0
                )
            
            block = response["result"]
            block_timestamp = datetime.utcfromtimestamp(block.get("blockTime", 0))
            events_count = 0
            
            # Process transactions
            for tx in block.get("transactions", []):
                events = await self._parse_transaction(tx, block_number, block_timestamp)
                for event in events:
                    await self.emit_event(event)
                    events_count += 1
            
            return BlockMetadata(
                chain_id=self.chain_id,
                block_number=block_number,
                block_hash=block.get("blockhash", ""),
                timestamp=block_timestamp,
                tx_count=len(block.get("transactions", [])),
                events_extracted=events_count
            )
            
        except Exception as e:
            logger.error("solana_block_error", slot=block_number, error=str(e))
            return BlockMetadata(
                chain_id=self.chain_id,
                block_number=block_number,
                block_hash="",
                timestamp=datetime.now(timezone.utc),
                tx_count=0,
                events_extracted=0
            )
    
    async def _parse_transaction(
        self,
        tx: dict,
        slot: int,
        block_timestamp: datetime
    ) -> List[SecurityEvent]:
        """
        Parse a Solana transaction into SecurityEvents.
        """
        events = []
        
        transaction = tx.get("transaction", {})
        meta = tx.get("meta", {})
        
        if meta.get("err"):
            return events  # Skip failed transactions
        
        # Get transaction signature
        message = transaction.get("message", {})
        signatures = transaction.get("signatures", [])
        tx_signature = signatures[0] if signatures else ""
        
        # Skip if already processed
        if tx_signature in self._processed_signatures:
            return events
        self._processed_signatures.add(tx_signature)
        
        # Limit cache size
        if len(self._processed_signatures) > 10000:
            self._processed_signatures = set(list(self._processed_signatures)[-5000:])
        
        # Parse inner instructions (includes token transfers)
        meta.get("innerInstructions", [])
        
        # Check for token transfers in pre/post token balances
        pre_balances = meta.get("preTokenBalances", [])
        post_balances = meta.get("postTokenBalances", [])
        
        balance_changes = self._calculate_token_balance_changes(pre_balances, post_balances)
        
        for account, change in balance_changes.items():
            if abs(change["amount"]) > 0:
                event_type = EventType.TRANSFER
                
                # Check if involves bridge
                if self._is_bridge_account(account):
                    if change["amount"] > 0:
                        event_type = EventType.LOCK  # Funds going to bridge
                    else:
                        event_type = EventType.UNLOCK  # Funds leaving bridge
                
                events.append(SecurityEvent(
                    chain_id=self.chain_id,
                    block_number=slot,
                    block_timestamp=block_timestamp,
                    tx_hash=tx_signature,
                    event_type=event_type,
                    severity=self._calculate_severity(abs(change["amount"])),
                    source_address=account if change["amount"] < 0 else "",
                    dest_address=account if change["amount"] > 0 else "",
                    contract_address=change["mint"],
                    asset_type="SPL",
                    asset_address=change["mint"],
                    amount=Decimal(str(abs(change["amount"]))),
                    bridge_id=self._get_bridge_id(account),
                    raw_event={
                        "signature": tx_signature,
                        "slot": slot,
                        "account": account,
                        "change": change
                    }
                ))
        
        # Parse program invocations for bridge-specific events
        account_keys = message.get("accountKeys", [])
        instructions = message.get("instructions", [])
        
        for ix in instructions:
            program_id = self._get_program_id(ix, account_keys)
            
            if program_id in self.config.bridge_contracts:
                event = self._parse_bridge_instruction(
                    ix, program_id, tx_signature, slot, block_timestamp, account_keys
                )
                if event:
                    events.append(event)
        
        return events
    
    def _calculate_token_balance_changes(
        self,
        pre_balances: List[dict],
        post_balances: List[dict]
    ) -> Dict[str, dict]:
        """
        Calculate token balance changes from pre/post balances.
        """
        changes = {}
        
        # Build pre-balance map
        pre_map = {}
        for bal in pre_balances:
            key = f"{bal.get('owner', '')}:{bal.get('mint', '')}"
            amount = float(bal.get("uiTokenAmount", {}).get("uiAmount", 0) or 0)
            pre_map[key] = {
                "owner": bal.get("owner", ""),
                "mint": bal.get("mint", ""),
                "amount": amount
            }
        
        # Calculate changes from post balances
        for bal in post_balances:
            owner = bal.get("owner", "")
            mint = bal.get("mint", "")
            key = f"{owner}:{mint}"
            post_amount = float(bal.get("uiTokenAmount", {}).get("uiAmount", 0) or 0)
            pre_amount = pre_map.get(key, {}).get("amount", 0)
            
            change = post_amount - pre_amount
            if change != 0:
                changes[owner] = {
                    "mint": mint,
                    "amount": change
                }
        
        return changes
    
    def _get_program_id(self, instruction: dict, account_keys: List) -> str:
        """Get program ID from instruction."""
        if isinstance(instruction.get("programId"), str):
            return instruction["programId"]
        
        program_idx = instruction.get("programIdIndex", 0)
        if program_idx < len(account_keys):
            key = account_keys[program_idx]
            if isinstance(key, dict):
                return key.get("pubkey", "")
            return key
        return ""
    
    def _is_bridge_account(self, account: str) -> bool:
        """Check if account is a known bridge."""
        return account in self.config.bridge_contracts
    
    def _get_bridge_id(self, account: str) -> Optional[str]:
        """Get bridge ID from account."""
        for i, bridge in enumerate(self.config.bridge_contracts):
            if account == bridge:
                return f"solana_bridge_{i}"
        return None
    
    def _parse_bridge_instruction(
        self,
        instruction: dict,
        program_id: str,
        tx_signature: str,
        slot: int,
        block_timestamp: datetime,
        account_keys: List
    ) -> Optional[SecurityEvent]:
        """
        Parse bridge-specific instruction.
        """
        # Determine event type from instruction data
        # This is bridge-specific and would need to decode the instruction
        
        # For Wormhole, check if this is a message publication
        if program_id == WORMHOLE_BRIDGE_PROGRAM:
            return SecurityEvent(
                chain_id=self.chain_id,
                block_number=slot,
                block_timestamp=block_timestamp,
                tx_hash=tx_signature,
                event_type=EventType.MESSAGE_SENT,
                severity=Severity.HIGH,
                contract_address=program_id,
                bridge_id="wormhole",
                raw_event={
                    "signature": tx_signature,
                    "program_id": program_id,
                    "instruction": instruction
                }
            )
        
        return None
    
    def _calculate_severity(self, amount: float) -> Severity:
        """Calculate severity based on amount."""
        if amount > 1000000:
            return Severity.CRITICAL
        elif amount > 100000:
            return Severity.HIGH
        elif amount > 10000:
            return Severity.MEDIUM
        elif amount > 1000:
            return Severity.LOW
        return Severity.INFO
    
    async def subscribe_to_events(self) -> AsyncIterator[SecurityEvent]:
        """
        Subscribe to real-time events.
        
        Uses polling since WebSocket subscription requires different client.
        """
        while self.is_running:
            try:
                latest = await self.get_latest_block()
                if latest > self.last_processed_block:
                    # Process in batches
                    start = self.last_processed_block + 1
                    end = min(latest, start + self.config.max_blocks_per_batch)
                    
                    for slot in range(start, end + 1):
                        await self.process_block(slot)
                        self.last_processed_block = slot
                
                await asyncio.sleep(self.config.poll_interval_seconds)
                yield  # Required for async generator
                
            except Exception as e:
                logger.error("solana_subscription_error", error=str(e))
                await asyncio.sleep(5)
                yield

