"""
Event Type Normalizer
=====================

Normalizes event types from various sources to match YAML rule expectations.

The telemetry layer produces event types in different formats:
- lowercase: "transfer", "swap", "mint"
- Protocol-prefixed: "Wormhole:MessagePublished", "LayerZero:SendToChain"
- Contract-prefixed: "ContractDeploy:Safe", "ContractDeploy:Suspicious"

YAML rules expect standardized event types:
- PascalCase: "Transfer", "Swap", "Mint"
- Protocol-specific: "FlashLoan", "LiquidationCall"

This module provides bidirectional mapping and normalization.
"""

from typing import Optional, Set


# Mapping from ingested event types to rule-expected types
EVENT_TYPE_MAP = {
    # Basic transfers
    "transfer": "Transfer",
    "Transfer": "Transfer",
    
    # Swaps
    "swap": "Swap",
    "Swap": "Swap",
    "SwapV3": "Swap",
    "TokenExchange": "Swap",
    "Stargate:Swap": "Swap",
    
    # Minting
    "mint": "Mint",
    "Mint": "Mint",
    
    # Burning
    "burn": "Burn",
    "Burn": "Burn",
    
    # Liquidity
    "liquidity_add": "LiquidityAdd",
    "liquidity_remove": "LiquidityRemove",
    "RemoveLiquidity": "LiquidityRemove",
    
    # Bridge events
    "bridge_deposit": "Lock",
    "Lock": "Lock",
    "message_sent": "LogMessagePublished",
    "Wormhole:MessagePublished": "LogMessagePublished",
    "LayerZero:SendToChain": "SendToChain",
    "Wormhole:TransferRedeemed": "TransferRedeemed",
    "Synapse:TokenDeposit": "Lock",
    "Stargate:SendCredits": "SendToChain",
    "Stargate:CreditChainPath": "SendToChain",
    
    # Contract deployments
    "contract_deploy": "ContractDeploy",
    "ContractDeploy:Safe": "ContractDeploy",
    "ContractDeploy:Suspicious": "ContractDeploy",
    "ContractDeploy:reentrancy_exploit": "ContractDeploy",
    
    # Flash loans
    "flash_borrow": "FlashLoan",
    "flash_repay": "FlashLoan",
    "FlashLoan": "FlashLoan",
    
    # Approvals
    "Approval": "Approval",
    
    # Withdrawals
    "Withdrawal": "Withdrawal",
    "Withdraw": "Withdrawal",
    "Withdrawn": "Withdrawal",
    
    # Liquidations
    "LiquidationCall": "LiquidationCall",
    "Liquidate": "LiquidationCall",
    "LiquidateBorrow": "LiquidationCall",
    "LiquidatePosition": "LiquidationCall",
    "Bite": "LiquidationCall",  # MakerDAO
    "Bark": "LiquidationCall",  # MakerDAO
    
    # Governance
    "ProposalCreated": "ProposalCreated",
    "VoteCast": "VoteCast",
    "QueueTransaction": "QueueTransaction",
    
    # Admin events
    "OwnershipTransferred": "AdminAction",
    "AdminChanged": "AdminAction",
    "RoleGranted": "AdminAction",
    "Paused": "AdminAction",
    "Unpaused": "AdminAction",
    
    # Oracle
    "PriceUpdated": "PriceUpdated",
    
    # Unknown/generic
    "unknown": "Unknown",
    "Event": "Unknown",
}

# Reverse mapping for rules that use multiple event types
RULE_TO_INGESTED_MAP = {
    "Transfer": {"transfer", "Transfer"},
    "Swap": {"swap", "Swap", "SwapV3", "TokenExchange", "Stargate:Swap"},
    "Mint": {"mint", "Mint"},
    "Burn": {"burn", "Burn"},
    "Lock": {"bridge_deposit", "Lock", "Synapse:TokenDeposit"},
    "FlashLoan": {"flash_borrow", "flash_repay", "FlashLoan"},
    "LiquidationCall": {"LiquidationCall", "Liquidate", "LiquidateBorrow", "Bite", "Bark"},
    "Withdrawal": {"Withdrawal", "Withdraw", "Withdrawn"},
    "LogMessagePublished": {"message_sent", "Wormhole:MessagePublished"},
    "SendToChain": {"LayerZero:SendToChain", "Stargate:SendCredits", "Stargate:CreditChainPath"},
    "ContractDeploy": {"contract_deploy", "ContractDeploy:Safe", "ContractDeploy:Suspicious", "ContractDeploy:reentrancy_exploit"},
}


def normalize_event_type(event_type: str) -> str:
    """
    Normalize an event type to match YAML rule expectations.
    
    Args:
        event_type: The raw event type from telemetry
        
    Returns:
        Normalized event type for rule matching
    """
    if not event_type:
        return "Unknown"
    
    # Direct mapping
    if event_type in EVENT_TYPE_MAP:
        return EVENT_TYPE_MAP[event_type]
    
    # Check if it's already normalized
    if event_type in RULE_TO_INGESTED_MAP:
        return event_type
    
    # Handle protocol-prefixed events
    if ":" in event_type:
        prefix, suffix = event_type.split(":", 1)
        # Try suffix directly
        if suffix in EVENT_TYPE_MAP:
            return EVENT_TYPE_MAP[suffix]
        # Return suffix as-is (PascalCase expected)
        return suffix
    
    # Default: capitalize first letter
    return event_type.capitalize() if event_type else "Unknown"


def get_matching_event_types(rule_event_type: str) -> Set[str]:
    """
    Get all ingested event types that match a rule's expected type.
    
    Args:
        rule_event_type: The event type specified in a YAML rule
        
    Returns:
        Set of ingested event types that should match this rule
    """
    if rule_event_type == "any":
        return set(EVENT_TYPE_MAP.keys())
    
    # Check reverse mapping
    if rule_event_type in RULE_TO_INGESTED_MAP:
        return RULE_TO_INGESTED_MAP[rule_event_type]
    
    # Check direct mapping
    matching = set()
    for ingested, normalized in EVENT_TYPE_MAP.items():
        if normalized == rule_event_type:
            matching.add(ingested)
    
    # If no mapping found, return the rule type itself
    if not matching:
        matching.add(rule_event_type)
        matching.add(rule_event_type.lower())
    
    return matching


def event_type_matches(
    ingested_type: str, 
    rule_types: list[str]
) -> bool:
    """
    Check if an ingested event type matches any of the rule's expected types.
    
    Args:
        ingested_type: The event type from the ingested event
        rule_types: List of event types the rule expects
        
    Returns:
        True if the ingested type matches any rule type
    """
    if not rule_types or "any" in rule_types:
        return True
    
    normalized = normalize_event_type(ingested_type)
    
    for rule_type in rule_types:
        # Direct match
        if rule_type == normalized:
            return True
        if rule_type == ingested_type:
            return True
        
        # Check if ingested type is in the matching set
        matching = get_matching_event_types(rule_type)
        if ingested_type in matching or normalized in matching:
            return True
    
    return False


# Protocol-specific event type detection
def get_protocol_from_event(event_type: str) -> Optional[str]:
    """
    Extract protocol name from event type if present.
    
    Args:
        event_type: Event type string
        
    Returns:
        Protocol name or None
    """
    if ":" in event_type:
        return event_type.split(":")[0]
    
    # Known protocol prefixes
    protocol_prefixes = {
        "Wormhole": "wormhole",
        "LayerZero": "layerzero",
        "Stargate": "stargate",
        "Synapse": "synapse",
        "Aave": "aave",
        "Compound": "compound",
        "Uniswap": "uniswap",
        "MakerDAO": "makerdao",
        "Curve": "curve",
    }
    
    for prefix, protocol in protocol_prefixes.items():
        if event_type.startswith(prefix):
            return protocol
    
    return None


# Severity calculation helpers
def get_event_base_severity(event_type: str) -> str:
    """
    Get base severity for an event type.
    
    Args:
        event_type: Normalized event type
        
    Returns:
        Base severity level
    """
    critical_types = {
        "FlashLoan", "LiquidationCall", "AdminAction", 
        "SelfDestruct", "ContractUpgraded"
    }
    high_types = {
        "LiquidityRemove", "Withdrawal", "ProposalCreated"
    }
    medium_types = {
        "Transfer", "Swap", "Lock", "Mint", "Burn"
    }
    
    normalized = normalize_event_type(event_type)
    
    if normalized in critical_types:
        return "CRITICAL"
    elif normalized in high_types:
        return "HIGH"
    elif normalized in medium_types:
        return "MEDIUM"
    else:
        return "LOW"
