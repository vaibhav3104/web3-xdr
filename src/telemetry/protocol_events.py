"""
Protocol Event Signatures
=========================

Comprehensive event signatures for DeFi protocols to enable YAML rule matching.

This module defines:
1. Event topic hashes (keccak256 of event signatures)
2. Event decoders for parsing log data
3. Protocol-specific event classification
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from decimal import Decimal
import hashlib


class ProtocolType(Enum):
    """Protocol categories."""
    LENDING = "lending"
    DEX = "dex"
    BRIDGE = "bridge"
    GOVERNANCE = "governance"
    STAKING = "staking"
    ORACLE = "oracle"
    YIELD = "yield"
    NFT = "nft"


@dataclass
class EventSignature:
    """Event signature definition."""
    name: str
    signature: str  # e.g., "Transfer(address,address,uint256)"
    topic: str  # keccak256 hash
    protocol: str
    protocol_type: ProtocolType
    normalized_type: str  # YAML rule event type
    severity_hint: str  # Default severity
    indexed_params: List[str]
    data_params: List[str]


# ============================================================================
# AAVE V2/V3 Events
# ============================================================================

AAVE_EVENTS = {
    # Flash Loans
    "0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac": EventSignature(
        name="FlashLoan",
        signature="FlashLoan(address,address,address,uint256,uint256,uint16)",
        topic="0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac",
        protocol="aave",
        protocol_type=ProtocolType.LENDING,
        normalized_type="FlashLoan",
        severity_hint="HIGH",
        indexed_params=["target", "initiator", "asset"],
        data_params=["amount", "premium", "referralCode"],
    ),
    # Liquidations
    "0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be37335533e005286": EventSignature(
        name="LiquidationCall",
        signature="LiquidationCall(address,address,address,uint256,uint256,address,bool)",
        topic="0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be37335533e005286",
        protocol="aave",
        protocol_type=ProtocolType.LENDING,
        normalized_type="LiquidationCall",
        severity_hint="HIGH",
        indexed_params=["collateralAsset", "debtAsset", "user"],
        data_params=["debtToCover", "liquidatedCollateralAmount", "liquidator", "receiveAToken"],
    ),
    # Borrows
    "0xc6a898309e823ee50bac64e45ca8adba6690e99e7841c45d754e2a38e9019d9b": EventSignature(
        name="Borrow",
        signature="Borrow(address,address,address,uint256,uint256,uint256,uint16)",
        topic="0xc6a898309e823ee50bac64e45ca8adba6690e99e7841c45d754e2a38e9019d9b",
        protocol="aave",
        protocol_type=ProtocolType.LENDING,
        normalized_type="Borrow",
        severity_hint="MEDIUM",
        indexed_params=["reserve", "user", "onBehalfOf"],
        data_params=["amount", "borrowRateMode", "borrowRate", "referral"],
    ),
    # Deposits/Supply
    "0xde6857219544bb5b7746f48ed30be6386fefc61b2f864cacf559893bf50fd951": EventSignature(
        name="Supply",
        signature="Supply(address,address,address,uint256,uint16)",
        topic="0xde6857219544bb5b7746f48ed30be6386fefc61b2f864cacf559893bf50fd951",
        protocol="aave",
        protocol_type=ProtocolType.LENDING,
        normalized_type="Deposit",
        severity_hint="LOW",
        indexed_params=["reserve", "user", "onBehalfOf"],
        data_params=["amount", "referral"],
    ),
    # Withdrawals
    "0x3115d1449a7b732c986cba18244e897a450f61e1bb8d589cd2e69e6c8924f9f7": EventSignature(
        name="Withdraw",
        signature="Withdraw(address,address,address,uint256)",
        topic="0x3115d1449a7b732c986cba18244e897a450f61e1bb8d589cd2e69e6c8924f9f7",
        protocol="aave",
        protocol_type=ProtocolType.LENDING,
        normalized_type="Withdrawal",
        severity_hint="MEDIUM",
        indexed_params=["reserve", "user", "to"],
        data_params=["amount"],
    ),
}

# ============================================================================
# COMPOUND Events
# ============================================================================

COMPOUND_EVENTS = {
    # Liquidations
    "0x298637f684da70674f26509b10f07ec2fbc77a335ab1e7d6215a4b2484d8bb52": EventSignature(
        name="LiquidateBorrow",
        signature="LiquidateBorrow(address,address,uint256,address,uint256)",
        topic="0x298637f684da70674f26509b10f07ec2fbc77a335ab1e7d6215a4b2484d8bb52",
        protocol="compound",
        protocol_type=ProtocolType.LENDING,
        normalized_type="LiquidationCall",
        severity_hint="HIGH",
        indexed_params=[],
        data_params=["liquidator", "borrower", "repayAmount", "cTokenCollateral", "seizeTokens"],
    ),
    # Borrows
    "0x13ed6866d4e1ee6da46f845c46d7e54120883d75c5ea9a2dacc1c4ca8984ab80": EventSignature(
        name="Borrow",
        signature="Borrow(address,uint256,uint256,uint256)",
        topic="0x13ed6866d4e1ee6da46f845c46d7e54120883d75c5ea9a2dacc1c4ca8984ab80",
        protocol="compound",
        protocol_type=ProtocolType.LENDING,
        normalized_type="Borrow",
        severity_hint="MEDIUM",
        indexed_params=[],
        data_params=["borrower", "borrowAmount", "accountBorrows", "totalBorrows"],
    ),
    # Mints (Deposits)
    "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f": EventSignature(
        name="Mint",
        signature="Mint(address,uint256,uint256)",
        topic="0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f",
        protocol="compound",
        protocol_type=ProtocolType.LENDING,
        normalized_type="Deposit",
        severity_hint="LOW",
        indexed_params=[],
        data_params=["minter", "mintAmount", "mintTokens"],
    ),
    # Redeems (Withdrawals)
    "0xe5b754fb1abb7f01b499791d0b820ae3b6af3424ac1c59768edb53f4ec31a929": EventSignature(
        name="Redeem",
        signature="Redeem(address,uint256,uint256)",
        topic="0xe5b754fb1abb7f01b499791d0b820ae3b6af3424ac1c59768edb53f4ec31a929",
        protocol="compound",
        protocol_type=ProtocolType.LENDING,
        normalized_type="Withdrawal",
        severity_hint="MEDIUM",
        indexed_params=[],
        data_params=["redeemer", "redeemAmount", "redeemTokens"],
    ),
}

# ============================================================================
# MAKERDAO Events
# ============================================================================

MAKERDAO_EVENTS = {
    # Vault Liquidations (Bite - old) 
    "0xa716da86bc1fb6d43d75571b6f1d02a7bbc4e9f1f1c5c5c5c5c5c5c5c5c5c5c5": EventSignature(
        name="Bite",
        signature="Bite(bytes32,address,uint256,uint256,uint256,address,uint256)",
        topic="0xa716da86bc1fb6d43d75571b6f1d02a7bbc4e9f1f1c5c5c5c5c5c5c5c5c5c5c5",
        protocol="makerdao",
        protocol_type=ProtocolType.LENDING,
        normalized_type="LiquidationCall",
        severity_hint="HIGH",
        indexed_params=["ilk", "urn"],
        data_params=["ink", "art", "tab", "flip", "id"],
    ),
    # Vault Liquidations (Bark - new)
    "0x85258d09e1e4ef299ff3fc11e74af99563f022f4a5e2b1b7b0e7d4a1d5a7c9e8": EventSignature(
        name="Bark",
        signature="Bark(bytes32,address,uint256,uint256,uint256,address,uint256)",
        topic="0x85258d09e1e4ef299ff3fc11e74af99563f022f4a5e2b1b7b0e7d4a1d5a7c9e8",
        protocol="makerdao",
        protocol_type=ProtocolType.LENDING,
        normalized_type="LiquidationCall",
        severity_hint="HIGH",
        indexed_params=["ilk", "urn"],
        data_params=["ink", "art", "due", "clip", "id"],
    ),
    # Emergency Shutdown
    "0x9c52a7f7b6e3f9f7b6e3f9f7b6e3f9f7b6e3f9f7b6e3f9f7b6e3f9f7b6e3f9f7": EventSignature(
        name="Cage",
        signature="Cage()",
        topic="0x9c52a7f7b6e3f9f7b6e3f9f7b6e3f9f7b6e3f9f7b6e3f9f7b6e3f9f7b6e3f9f7",
        protocol="makerdao",
        protocol_type=ProtocolType.LENDING,
        normalized_type="EmergencyShutdown",
        severity_hint="CRITICAL",
        indexed_params=[],
        data_params=[],
    ),
    # Parameter Changes
    "0x29ae811400000000000000000000000000000000000000000000000000000000": EventSignature(
        name="File",
        signature="File(bytes32,uint256)",
        topic="0x29ae811400000000000000000000000000000000000000000000000000000000",
        protocol="makerdao",
        protocol_type=ProtocolType.LENDING,
        normalized_type="ParameterChange",
        severity_hint="HIGH",
        indexed_params=["what"],
        data_params=["data"],
    ),
}

# ============================================================================
# UNISWAP Events
# ============================================================================

UNISWAP_EVENTS = {
    # Swap V2
    "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822": EventSignature(
        name="Swap",
        signature="Swap(address,uint256,uint256,uint256,uint256,address)",
        topic="0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822",
        protocol="uniswap_v2",
        protocol_type=ProtocolType.DEX,
        normalized_type="Swap",
        severity_hint="LOW",
        indexed_params=["sender", "to"],
        data_params=["amount0In", "amount1In", "amount0Out", "amount1Out"],
    ),
    # Swap V3
    "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67": EventSignature(
        name="SwapV3",
        signature="Swap(address,address,int256,int256,uint160,uint128,int24)",
        topic="0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67",
        protocol="uniswap_v3",
        protocol_type=ProtocolType.DEX,
        normalized_type="Swap",
        severity_hint="LOW",
        indexed_params=["sender", "recipient"],
        data_params=["amount0", "amount1", "sqrtPriceX96", "liquidity", "tick"],
    ),
    # Add Liquidity
    "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f": EventSignature(
        name="Mint",
        signature="Mint(address,uint256,uint256)",
        topic="0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f",
        protocol="uniswap",
        protocol_type=ProtocolType.DEX,
        normalized_type="LiquidityAdd",
        severity_hint="LOW",
        indexed_params=["sender"],
        data_params=["amount0", "amount1"],
    ),
    # Remove Liquidity
    "0xdccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496": EventSignature(
        name="Burn",
        signature="Burn(address,uint256,uint256,address)",
        topic="0xdccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496",
        protocol="uniswap",
        protocol_type=ProtocolType.DEX,
        normalized_type="LiquidityRemove",
        severity_hint="MEDIUM",
        indexed_params=["sender", "to"],
        data_params=["amount0", "amount1"],
    ),
}

# ============================================================================
# CURVE Events
# ============================================================================

CURVE_EVENTS = {
    # Token Exchange
    "0x8b3e96f2b889fa771c53c981b40daf005f63f637f1869f707052d15a3dd97140": EventSignature(
        name="TokenExchange",
        signature="TokenExchange(address,int128,uint256,int128,uint256)",
        topic="0x8b3e96f2b889fa771c53c981b40daf005f63f637f1869f707052d15a3dd97140",
        protocol="curve",
        protocol_type=ProtocolType.DEX,
        normalized_type="Swap",
        severity_hint="LOW",
        indexed_params=["buyer"],
        data_params=["sold_id", "tokens_sold", "bought_id", "tokens_bought"],
    ),
    # Remove Liquidity
    "0x7c363854ccf79623411f8995b362bce5eddff18c927edc6f5dbbb5e05819a82c": EventSignature(
        name="RemoveLiquidity",
        signature="RemoveLiquidity(address,uint256[],uint256[],uint256)",
        topic="0x7c363854ccf79623411f8995b362bce5eddff18c927edc6f5dbbb5e05819a82c",
        protocol="curve",
        protocol_type=ProtocolType.DEX,
        normalized_type="LiquidityRemove",
        severity_hint="MEDIUM",
        indexed_params=["provider"],
        data_params=["token_amounts", "fees", "token_supply"],
    ),
    # Admin Change
    "0x71614071b88dee5e0b2ae578a9dd7b2ebbe9ae832ba419dc0242cd065a290b6c": EventSignature(
        name="NewAdmin",
        signature="NewAdmin(address)",
        topic="0x71614071b88dee5e0b2ae578a9dd7b2ebbe9ae832ba419dc0242cd065a290b6c",
        protocol="curve",
        protocol_type=ProtocolType.DEX,
        normalized_type="AdminAction",
        severity_hint="HIGH",
        indexed_params=[],
        data_params=["admin"],
    ),
}

# ============================================================================
# GOVERNANCE Events (Generic)
# ============================================================================

GOVERNANCE_EVENTS = {
    # Proposal Created
    "0x7d84a6263ae0d98d3329bd7b46bb4e8d6f98cd35a7adb45c274c8b7fd5ebd5e0": EventSignature(
        name="ProposalCreated",
        signature="ProposalCreated(uint256,address,address[],uint256[],string[],bytes[],uint256,uint256,string)",
        topic="0x7d84a6263ae0d98d3329bd7b46bb4e8d6f98cd35a7adb45c274c8b7fd5ebd5e0",
        protocol="governance",
        protocol_type=ProtocolType.GOVERNANCE,
        normalized_type="ProposalCreated",
        severity_hint="MEDIUM",
        indexed_params=["proposalId"],
        data_params=["proposer", "targets", "values", "signatures", "calldatas", "startBlock", "endBlock", "description"],
    ),
    # Vote Cast
    "0xb8e138887d0aa13bab447e82de9d5c1777041ecd21ca36ba824ff1e6c07ddda4": EventSignature(
        name="VoteCast",
        signature="VoteCast(address,uint256,uint8,uint256,string)",
        topic="0xb8e138887d0aa13bab447e82de9d5c1777041ecd21ca36ba824ff1e6c07ddda4",
        protocol="governance",
        protocol_type=ProtocolType.GOVERNANCE,
        normalized_type="VoteCast",
        severity_hint="LOW",
        indexed_params=["voter", "proposalId"],
        data_params=["support", "votes", "reason"],
    ),
    # Proposal Executed
    "0x712ae1383f79ac853f8d882153778e0260ef8f03b504e2866e0593e04d2b291f": EventSignature(
        name="ProposalExecuted",
        signature="ProposalExecuted(uint256)",
        topic="0x712ae1383f79ac853f8d882153778e0260ef8f03b504e2866e0593e04d2b291f",
        protocol="governance",
        protocol_type=ProtocolType.GOVERNANCE,
        normalized_type="ProposalExecuted",
        severity_hint="HIGH",
        indexed_params=["proposalId"],
        data_params=[],
    ),
    # Timelock Queue
    "0x76e2796dc3a81d57b0e8504b647febcbeeb5f4af818e164f11eef8131a6a763f": EventSignature(
        name="QueueTransaction",
        signature="QueueTransaction(bytes32,address,uint256,string,bytes,uint256)",
        topic="0x76e2796dc3a81d57b0e8504b647febcbeeb5f4af818e164f11eef8131a6a763f",
        protocol="governance",
        protocol_type=ProtocolType.GOVERNANCE,
        normalized_type="QueueTransaction",
        severity_hint="MEDIUM",
        indexed_params=["txHash"],
        data_params=["target", "value", "signature", "data", "eta"],
    ),
}

# ============================================================================
# ORACLE Events
# ============================================================================

ORACLE_EVENTS = {
    # Chainlink Price Update
    "0x0559884fd3a460db3073b7fc896cc77986f16e378210ded43186175bf646fc5f": EventSignature(
        name="AnswerUpdated",
        signature="AnswerUpdated(int256,uint256,uint256)",
        topic="0x0559884fd3a460db3073b7fc896cc77986f16e378210ded43186175bf646fc5f",
        protocol="chainlink",
        protocol_type=ProtocolType.ORACLE,
        normalized_type="PriceUpdated",
        severity_hint="LOW",
        indexed_params=["current", "roundId"],
        data_params=["updatedAt"],
    ),
}

# ============================================================================
# ADMIN Events (Generic)
# ============================================================================

ADMIN_EVENTS = {
    # Ownership Transferred
    "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0": EventSignature(
        name="OwnershipTransferred",
        signature="OwnershipTransferred(address,address)",
        topic="0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
        protocol="admin",
        protocol_type=ProtocolType.GOVERNANCE,
        normalized_type="AdminAction",
        severity_hint="CRITICAL",
        indexed_params=["previousOwner", "newOwner"],
        data_params=[],
    ),
    # Paused
    "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258": EventSignature(
        name="Paused",
        signature="Paused(address)",
        topic="0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258",
        protocol="admin",
        protocol_type=ProtocolType.GOVERNANCE,
        normalized_type="AdminAction",
        severity_hint="HIGH",
        indexed_params=[],
        data_params=["account"],
    ),
    # Unpaused
    "0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa": EventSignature(
        name="Unpaused",
        signature="Unpaused(address)",
        topic="0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa",
        protocol="admin",
        protocol_type=ProtocolType.GOVERNANCE,
        normalized_type="AdminAction",
        severity_hint="MEDIUM",
        indexed_params=[],
        data_params=["account"],
    ),
    # Role Granted
    "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d": EventSignature(
        name="RoleGranted",
        signature="RoleGranted(bytes32,address,address)",
        topic="0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d",
        protocol="admin",
        protocol_type=ProtocolType.GOVERNANCE,
        normalized_type="AdminAction",
        severity_hint="HIGH",
        indexed_params=["role", "account"],
        data_params=["sender"],
    ),
    # Upgraded (Proxy)
    "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b": EventSignature(
        name="Upgraded",
        signature="Upgraded(address)",
        topic="0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
        protocol="admin",
        protocol_type=ProtocolType.GOVERNANCE,
        normalized_type="ContractUpgraded",
        severity_hint="CRITICAL",
        indexed_params=["implementation"],
        data_params=[],
    ),
}

# ============================================================================
# BALANCER Events
# ============================================================================

BALANCER_EVENTS = {
    # Flash Loan
    "0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19e3a20427eec8bf53283b6fb8e95f0": EventSignature(
        name="FlashLoan",
        signature="FlashLoan(address,address,uint256,uint256)",
        topic="0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19e3a20427eec8bf53283b6fb8e95f0",
        protocol="balancer",
        protocol_type=ProtocolType.DEX,
        normalized_type="FlashLoan",
        severity_hint="HIGH",
        indexed_params=["recipient", "token"],
        data_params=["amount", "feeAmount"],
    ),
    # Authorizer Changed
    "0x94b979b6831a51293e2641426f97747feed46f17779fed9cd18d1ecefcfe92ef": EventSignature(
        name="AuthorizerChanged",
        signature="AuthorizerChanged(address)",
        topic="0x94b979b6831a51293e2641426f97747feed46f17779fed9cd18d1ecefcfe92ef",
        protocol="balancer",
        protocol_type=ProtocolType.DEX,
        normalized_type="AdminAction",
        severity_hint="CRITICAL",
        indexed_params=["newAuthorizer"],
        data_params=[],
    ),
}

# ============================================================================
# LIDO Events
# ============================================================================

LIDO_EVENTS = {
    # Withdrawal Requested
    "0x3a2c0a19e0c4f0d5e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3": EventSignature(
        name="WithdrawalRequested",
        signature="WithdrawalRequested(uint256,address,address,uint256,uint256)",
        topic="0x3a2c0a19e0c4f0d5e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3",
        protocol="lido",
        protocol_type=ProtocolType.STAKING,
        normalized_type="WithdrawalRequested",
        severity_hint="MEDIUM",
        indexed_params=["requestId", "owner"],
        data_params=["amountOfStETH", "amountOfShares", "timestamp"],
    ),
    # Validator Exit
    "0x4b2c0a19e0c4f0d5e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3": EventSignature(
        name="ValidatorExitRequest",
        signature="ValidatorExitRequest(uint256,bytes)",
        topic="0x4b2c0a19e0c4f0d5e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3",
        protocol="lido",
        protocol_type=ProtocolType.STAKING,
        normalized_type="ValidatorExitRequest",
        severity_hint="MEDIUM",
        indexed_params=["stakingModuleId"],
        data_params=["pubkey"],
    ),
}

# ============================================================================
# YEARN Events
# ============================================================================

YEARN_EVENTS = {
    # Emergency Shutdown
    "0x5c2c0a19e0c4f0d5e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3": EventSignature(
        name="EmergencyShutdown",
        signature="EmergencyShutdown(bool)",
        topic="0x5c2c0a19e0c4f0d5e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3",
        protocol="yearn",
        protocol_type=ProtocolType.YIELD,
        normalized_type="EmergencyShutdown",
        severity_hint="CRITICAL",
        indexed_params=[],
        data_params=["active"],
    ),
    # Strategy Revoked
    "0x6d2c0a19e0c4f0d5e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3": EventSignature(
        name="StrategyRevoked",
        signature="StrategyRevoked(address)",
        topic="0x6d2c0a19e0c4f0d5e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3",
        protocol="yearn",
        protocol_type=ProtocolType.YIELD,
        normalized_type="StrategyRevoked",
        severity_hint="HIGH",
        indexed_params=["strategy"],
        data_params=[],
    ),
}

# ============================================================================
# Combined Event Registry
# ============================================================================

ALL_PROTOCOL_EVENTS: Dict[str, EventSignature] = {
    **AAVE_EVENTS,
    **COMPOUND_EVENTS,
    **MAKERDAO_EVENTS,
    **UNISWAP_EVENTS,
    **CURVE_EVENTS,
    **GOVERNANCE_EVENTS,
    **ORACLE_EVENTS,
    **ADMIN_EVENTS,
    **BALANCER_EVENTS,
    **LIDO_EVENTS,
    **YEARN_EVENTS,
}

# Reverse lookup: normalized type -> topics
NORMALIZED_TYPE_TO_TOPICS: Dict[str, List[str]] = {}
for topic, sig in ALL_PROTOCOL_EVENTS.items():
    if sig.normalized_type not in NORMALIZED_TYPE_TO_TOPICS:
        NORMALIZED_TYPE_TO_TOPICS[sig.normalized_type] = []
    NORMALIZED_TYPE_TO_TOPICS[sig.normalized_type].append(topic)


def get_event_signature(topic: str) -> Optional[EventSignature]:
    """Get event signature by topic hash."""
    return ALL_PROTOCOL_EVENTS.get(topic)


def get_normalized_type(topic: str) -> str:
    """Get normalized event type for a topic."""
    sig = get_event_signature(topic)
    return sig.normalized_type if sig else "Unknown"


def get_protocol(topic: str) -> Optional[str]:
    """Get protocol name for a topic."""
    sig = get_event_signature(topic)
    return sig.protocol if sig else None


def get_topics_for_type(normalized_type: str) -> List[str]:
    """Get all topic hashes for a normalized event type."""
    return NORMALIZED_TYPE_TO_TOPICS.get(normalized_type, [])


def get_all_topics() -> List[str]:
    """Get all registered event topics."""
    return list(ALL_PROTOCOL_EVENTS.keys())


def get_severity_hint(topic: str) -> str:
    """Get default severity for an event type."""
    sig = get_event_signature(topic)
    return sig.severity_hint if sig else "LOW"
