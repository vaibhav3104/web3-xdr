"""
Security Event Model - Unified schema for all blockchain events.
"""

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Optional
import uuid


class EventType(Enum):
    """Classification of security-relevant blockchain events."""
    
    # Asset movements
    TRANSFER = "transfer"
    LOCK = "lock"
    UNLOCK = "unlock"
    MINT = "mint"
    BURN = "burn"
    
    # Bridge operations
    BRIDGE_DEPOSIT = "bridge_deposit"
    BRIDGE_WITHDRAW = "bridge_withdraw"
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    MESSAGE_VERIFIED = "message_verified"
    
    # Governance
    PROPOSAL_CREATED = "proposal_created"
    PROPOSAL_EXECUTED = "proposal_executed"
    ADMIN_ACTION = "admin_action"
    ROLE_GRANTED = "role_granted"
    ROLE_REVOKED = "role_revoked"
    
    # Validator operations
    SIGNATURE_SUBMIT = "signature_submit"
    VALIDATOR_SET_UPDATE = "validator_set_update"
    
    # Flash loans
    FLASH_BORROW = "flash_borrow"
    FLASH_REPAY = "flash_repay"
    
    # DeFi operations
    SWAP = "swap"
    LIQUIDITY_ADD = "liquidity_add"
    LIQUIDITY_REMOVE = "liquidity_remove"
    
    # Contract operations
    CONTRACT_DEPLOY = "contract_deploy"
    CONTRACT_UPGRADE = "contract_upgrade"
    
    # Unknown / Other
    UNKNOWN = "unknown"


class Severity(Enum):
    """Event severity levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def __lt__(self, other: "Severity") -> bool:
        return self.value < other.value
    
    def __gt__(self, other: "Severity") -> bool:
        return self.value > other.value


@dataclass
class SecurityEvent:
    """
    Unified security event schema.
    
    All chain-specific events are normalized to this schema for
    cross-chain correlation and invariant checking.
    """
    
    # Identity
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""  # "ethereum", "solana", "polygon", etc.
    block_number: int = 0
    block_timestamp: datetime = field(default_factory=datetime.utcnow)
    tx_hash: str = ""
    log_index: int = 0
    
    # Classification
    event_type: EventType = EventType.UNKNOWN
    severity: Severity = Severity.INFO
    
    # Entities
    source_address: str = ""
    dest_address: str = ""
    contract_address: str = ""
    
    # Asset information
    asset_type: str = ""  # Token symbol or "NATIVE"
    asset_address: str = ""  # Token contract address
    amount: Decimal = Decimal("0")
    amount_usd: Decimal = Decimal("0")
    
    # Bridge-specific fields
    bridge_id: Optional[str] = None
    message_hash: Optional[str] = None
    message_nonce: Optional[int] = None
    source_chain: Optional[str] = None
    dest_chain: Optional[str] = None
    
    # Governance-specific fields
    proposal_id: Optional[str] = None
    
    # Validator-specific fields
    validator_address: Optional[str] = None
    signature_count: Optional[int] = None
    threshold: Optional[int] = None
    
    # Raw data
    raw_event: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "block_timestamp": self.block_timestamp.isoformat(),
            "tx_hash": self.tx_hash,
            "log_index": self.log_index,
            "event_type": self.event_type.value,
            "severity": self.severity.name,
            "source_address": self.source_address,
            "dest_address": self.dest_address,
            "contract_address": self.contract_address,
            "asset_type": self.asset_type,
            "asset_address": self.asset_address,
            "amount": str(self.amount),
            "amount_usd": str(self.amount_usd),
            "bridge_id": self.bridge_id,
            "message_hash": self.message_hash,
            "source_chain": self.source_chain,
            "dest_chain": self.dest_chain,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "SecurityEvent":
        """Create from dictionary."""
        return cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            chain_id=data.get("chain_id", ""),
            block_number=data.get("block_number", 0),
            block_timestamp=datetime.fromisoformat(data["block_timestamp"]) 
                if "block_timestamp" in data else datetime.utcnow(),
            tx_hash=data.get("tx_hash", ""),
            log_index=data.get("log_index", 0),
            event_type=EventType(data.get("event_type", "unknown")),
            severity=Severity[data.get("severity", "INFO")],
            source_address=data.get("source_address", ""),
            dest_address=data.get("dest_address", ""),
            contract_address=data.get("contract_address", ""),
            asset_type=data.get("asset_type", ""),
            asset_address=data.get("asset_address", ""),
            amount=Decimal(data.get("amount", "0")),
            amount_usd=Decimal(data.get("amount_usd", "0")),
            bridge_id=data.get("bridge_id"),
            message_hash=data.get("message_hash"),
            source_chain=data.get("source_chain"),
            dest_chain=data.get("dest_chain"),
        )
    
    def __hash__(self) -> int:
        return hash(self.event_id)
    
    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, SecurityEvent):
            return False
        return self.event_id == other.event_id

