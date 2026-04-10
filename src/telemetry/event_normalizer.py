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
    # =========================================================================
    # Basic ERC20 Events
    # =========================================================================
    "transfer": "Transfer",
    "Transfer": "Transfer",
    "Approval": "Approval",
    "Permit": "Permit",
    
    # =========================================================================
    # Swaps / DEX
    # =========================================================================
    "swap": "Swap",
    "Swap": "Swap",
    "SwapV3": "Swap",
    "TokenExchange": "Swap",  # Curve
    "Stargate:Swap": "Swap",
    "SynthExchange": "Swap",  # Synthetix
    
    # =========================================================================
    # Minting / Burning
    # =========================================================================
    "mint": "Mint",
    "Mint": "Mint",
    "burn": "Burn",
    "Burn": "Burn",
    "TokensBurned": "Burn",  # Rocket Pool
    
    # =========================================================================
    # Liquidity Events
    # =========================================================================
    "liquidity_add": "LiquidityAdd",
    "liquidity_remove": "LiquidityRemove",
    "RemoveLiquidity": "RemoveLiquidity",  # Curve, GMX
    "AddLiquidity": "LiquidityAdd",
    "Supply": "LiquidityAdd",  # Aave
    "Redeem": "LiquidityRemove",  # Compound
    
    # =========================================================================
    # Bridge Events
    # =========================================================================
    "bridge_deposit": "Lock",
    "Lock": "Lock",
    "Locked": "Locked",  # Convex
    "message_sent": "LogMessagePublished",
    "LogMessagePublished": "LogMessagePublished",  # Wormhole
    "Wormhole:MessagePublished": "LogMessagePublished",
    "SendToChain": "SendToChain",  # LayerZero
    "LayerZero:SendToChain": "SendToChain",
    "TransferRedeemed": "TransferRedeemed",  # Wormhole
    "Wormhole:TransferRedeemed": "TransferRedeemed",
    "Synapse:TokenDeposit": "Lock",
    "Stargate:SendCredits": "SendToChain",
    "Stargate:CreditChainPath": "SendToChain",
    "FundsDeposited": "FundsDeposited",  # Across
    "RootBundleExecuted": "RootBundleExecuted",  # Across
    "SetTrustedRemote": "SetTrustedRemote",  # LayerZero
    "TransferInitiated": "TransferInitiated",
    
    # =========================================================================
    # Contract Deployments
    # =========================================================================
    "contract_deploy": "ContractDeploy",
    "ContractDeploy:Safe": "ContractDeploy",
    "ContractDeploy:Suspicious": "ContractDeploy",
    "ContractDeploy:reentrancy_exploit": "ContractDeploy",
    "SelfDestruct": "SelfDestruct",
    
    # =========================================================================
    # Flash Loans
    # =========================================================================
    "flash_borrow": "FlashLoan",
    "flash_repay": "FlashLoan",
    "FlashLoan": "FlashLoan",
    "Flash": "FlashLoan",  # Uniswap V3
    "flash_loan": "FlashLoan",
    "flashloan": "FlashLoan",
    
    # =========================================================================
    # Borrowing / Lending
    # =========================================================================
    "Borrow": "Borrow",
    "Repay": "Repay",
    "RepayBorrow": "Repay",  # Compound
    
    # =========================================================================
    # Withdrawals
    # =========================================================================
    "Withdrawal": "Withdrawal",
    "Withdraw": "Withdraw",
    "Withdrawn": "Withdrawn",  # Convex
    "WithdrawalRequested": "WithdrawalRequested",  # Lido
    "WithdrawalQueued": "WithdrawalQueued",  # EigenLayer
    "WithdrawalChallenged": "WithdrawalChallenged",  # Optimism
    "LogWithdrawalPerformed": "LogWithdrawalPerformed",  # dYdX
    
    # =========================================================================
    # Liquidations
    # =========================================================================
    "liquidation_call": "LiquidationCall",  # From event_signatures.py
    "LiquidationCall": "LiquidationCall",  # Aave
    "Liquidate": "LiquidationCall",  # Morpho - map to common type
    "LiquidateBorrow": "LiquidationCall",  # Compound - map to common type
    "LiquidatePosition": "LiquidationCall",  # GMX - map to common type
    "Bite": "LiquidationCall",  # MakerDAO - map to common type
    "Bark": "LiquidationCall",  # MakerDAO - map to common type
    "AccountLiquidated": "LiquidationCall",  # Synthetix - map to common type
    
    # =========================================================================
    # Governance
    # =========================================================================
    "ProposalCreated": "ProposalCreated",
    "ProposalSubmitted": "ProposalSubmitted",  # Cosmos
    "VoteCast": "VoteCast",
    "QueueTransaction": "QueueTransaction",
    
    # =========================================================================
    # Admin / Security Events
    # =========================================================================
    "admin_changed": "AdminChanged",  # From event_signatures.py
    "admin_action": "AdminAction",  # From event_signatures.py
    "OwnershipTransferred": "OwnershipTransferred",
    "AdminChanged": "AdminChanged",
    "RoleGranted": "RoleGranted",
    "Paused": "Paused",
    "Unpaused": "Unpaused",
    "NewAdmin": "NewAdmin",  # Curve
    "AuthorizerChanged": "AuthorizerChanged",  # Balancer
    "GuardianSetAdded": "GuardianSetAdded",  # Wormhole
    "ContractUpgraded": "ContractUpgraded",  # Wormhole
    "Upgraded": "Upgraded",  # Proxy
    
    # =========================================================================
    # MakerDAO Specific
    # =========================================================================
    "Cage": "Cage",  # Emergency shutdown
    "File": "File",  # Parameter change
    
    # =========================================================================
    # Lido Specific
    # =========================================================================
    "ValidatorExitRequest": "ValidatorExitRequest",
    
    # =========================================================================
    # EigenLayer Specific
    # =========================================================================
    "OperatorSlashed": "OperatorSlashed",
    
    # =========================================================================
    # Rocket Pool Specific
    # =========================================================================
    "MinipoolDestroyed": "MinipoolDestroyed",
    
    # =========================================================================
    # dYdX Specific
    # =========================================================================
    "LogForcedTradeRequest": "LogForcedTradeRequest",
    
    # =========================================================================
    # Yearn Specific
    # =========================================================================
    "EmergencyShutdown": "EmergencyShutdown",
    "StrategyRevoked": "StrategyRevoked",
    
    # =========================================================================
    # GMX Specific
    # =========================================================================
    "IncreasePosition": "IncreasePosition",
    "DecreasePosition": "DecreasePosition",
    
    # =========================================================================
    # Oracle Events
    # =========================================================================
    "price_update": "PriceUpdated",  # From event_signatures.py
    "PriceUpdated": "PriceUpdated",
    "AnswerUpdated": "PriceUpdated",  # Chainlink
    
    # =========================================================================
    # Chain-Specific Events
    # =========================================================================
    "BlockReorg": "BlockReorg",  # Ethereum
    "ExitStarted": "ExitStarted",  # Polygon
    "ProposerFault": "ProposerFault",  # Optimism
    "ValidatorSlashed": "ValidatorSlashed",  # BSC
    "IBCTimeout": "IBCTimeout",  # Cosmos
    
    # =========================================================================
    # Unknown / Generic
    # =========================================================================
    "unknown": "Unknown",
    "Unknown": "Unknown",
    "Event": "Unknown",
}

# Reverse mapping for rules that use multiple event types
RULE_TO_INGESTED_MAP = {
    # Basic events
    "Transfer": {"transfer", "Transfer"},
    "Approval": {"Approval"},
    "Permit": {"Permit"},
    
    # Swaps
    "Swap": {"swap", "Swap", "SwapV3", "TokenExchange", "Stargate:Swap", "SynthExchange"},
    
    # Minting/Burning
    "Mint": {"mint", "Mint"},
    "Burn": {"burn", "Burn", "TokensBurned"},
    
    # Liquidity
    "LiquidityAdd": {"liquidity_add", "AddLiquidity", "Supply"},
    "LiquidityRemove": {"liquidity_remove", "RemoveLiquidity", "Redeem"},
    "RemoveLiquidity": {"RemoveLiquidity"},
    
    # Bridge events
    "Lock": {"bridge_deposit", "Lock", "Synapse:TokenDeposit"},
    "Locked": {"Locked"},
    "LogMessagePublished": {"message_sent", "LogMessagePublished", "Wormhole:MessagePublished"},
    "SendToChain": {"SendToChain", "LayerZero:SendToChain", "Stargate:SendCredits", "Stargate:CreditChainPath"},
    "TransferRedeemed": {"TransferRedeemed", "Wormhole:TransferRedeemed"},
    "FundsDeposited": {"FundsDeposited"},
    "RootBundleExecuted": {"RootBundleExecuted"},
    "SetTrustedRemote": {"SetTrustedRemote"},
    "TransferInitiated": {"TransferInitiated"},
    
    # Contract events
    "ContractDeploy": {"contract_deploy", "ContractDeploy:Safe", "ContractDeploy:Suspicious", "ContractDeploy:reentrancy_exploit"},
    "SelfDestruct": {"SelfDestruct"},
    
    # Flash loans
    "FlashLoan": {"flash_borrow", "flash_repay", "FlashLoan", "Flash", "flash_loan", "flashloan"},
    
    # Borrowing
    "Borrow": {"Borrow"},
    
    # Withdrawals
    "Withdrawal": {"Withdrawal"},
    "Withdraw": {"Withdraw"},
    "Withdrawn": {"Withdrawn"},
    "WithdrawalRequested": {"WithdrawalRequested"},
    "WithdrawalQueued": {"WithdrawalQueued"},
    "WithdrawalChallenged": {"WithdrawalChallenged"},
    "LogWithdrawalPerformed": {"LogWithdrawalPerformed"},
    
    # Liquidations (comprehensive) - all map to LiquidationCall
    "LiquidationCall": {"liquidation_call", "LiquidationCall", "Liquidate", "LiquidateBorrow", "LiquidatePosition", "Bite", "Bark", "AccountLiquidated"},
    "Liquidate": {"liquidation_call", "Liquidate"},
    "LiquidateBorrow": {"liquidation_call", "LiquidateBorrow"},
    "LiquidatePosition": {"liquidation_call", "LiquidatePosition"},
    "Bite": {"liquidation_call", "Bite"},
    "Bark": {"liquidation_call", "Bark"},
    "AccountLiquidated": {"liquidation_call", "AccountLiquidated"},
    
    # Governance
    "ProposalCreated": {"ProposalCreated"},
    "ProposalSubmitted": {"ProposalSubmitted"},
    "VoteCast": {"VoteCast"},
    "QueueTransaction": {"QueueTransaction"},
    
    # Admin events
    "OwnershipTransferred": {"OwnershipTransferred"},
    "AdminChanged": {"AdminChanged"},
    "RoleGranted": {"RoleGranted"},
    "Paused": {"Paused"},
    "Unpaused": {"Unpaused"},
    "NewAdmin": {"NewAdmin"},
    "AuthorizerChanged": {"AuthorizerChanged"},
    "GuardianSetAdded": {"GuardianSetAdded"},
    "ContractUpgraded": {"ContractUpgraded"},
    "Upgraded": {"Upgraded"},
    
    # MakerDAO
    "Cage": {"Cage"},
    "File": {"File"},
    
    # Lido
    "ValidatorExitRequest": {"ValidatorExitRequest"},
    
    # EigenLayer
    "OperatorSlashed": {"OperatorSlashed"},
    
    # Rocket Pool
    "MinipoolDestroyed": {"MinipoolDestroyed"},
    "TokensBurned": {"TokensBurned"},
    
    # dYdX
    "LogForcedTradeRequest": {"LogForcedTradeRequest"},
    
    # Yearn
    "EmergencyShutdown": {"EmergencyShutdown"},
    "StrategyRevoked": {"StrategyRevoked"},
    
    # GMX
    "IncreasePosition": {"IncreasePosition"},
    "DecreasePosition": {"DecreasePosition"},
    
    # Oracle
    "PriceUpdated": {"price_update", "PriceUpdated", "AnswerUpdated"},
    
    # Chain-specific
    "BlockReorg": {"BlockReorg"},
    "ExitStarted": {"ExitStarted"},
    "ProposerFault": {"ProposerFault"},
    "ValidatorSlashed": {"ValidatorSlashed"},
    "IBCTimeout": {"IBCTimeout"},
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
