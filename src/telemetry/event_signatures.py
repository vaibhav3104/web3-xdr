"""
Event Signatures - Comprehensive mapping of event signatures to types.
Used to decode and classify blockchain events.
"""

from ..models.events import EventType

# =============================================================================
# ERC20 / Token Events
# =============================================================================
ERC20_SIGNATURES = {
    # Transfer(address indexed from, address indexed to, uint256 value)
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": {
        "name": "Transfer",
        "type": EventType.TRANSFER,
        "params": ["from", "to", "value"]
    },
    # Approval(address indexed owner, address indexed spender, uint256 value)
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": {
        "name": "Approval",
        "type": EventType.UNKNOWN,
        "params": ["owner", "spender", "value"]
    },
}

# =============================================================================
# Bridge Protocol Events
# =============================================================================
BRIDGE_SIGNATURES = {
    # -------------------------------------------------------------------------
    # WORMHOLE
    # -------------------------------------------------------------------------
    # LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel)
    "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2": {
        "name": "LogMessagePublished",
        "type": EventType.MESSAGE_SENT,
        "protocol": "wormhole",
        "severity": "high"
    },
    # TransferRedeemed(uint16 indexed emitterChainId, bytes32 indexed emitterAddress, uint64 indexed sequence)
    "0xcaf280c8cfeba144da67230d9b009c8f868a75bac9a528fa0474be1ba317c169": {
        "name": "TransferRedeemed",
        "type": EventType.MESSAGE_RECEIVED,
        "protocol": "wormhole",
        "severity": "high"
    },
    
    # -------------------------------------------------------------------------
    # LAYERZERO
    # -------------------------------------------------------------------------
    # Packet(bytes encodedPayload)
    "0xe9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82": {
        "name": "Packet",
        "type": EventType.MESSAGE_SENT,
        "protocol": "layerzero",
        "severity": "high"
    },
    # PacketReceived(uint16 srcChainId, bytes srcAddress, uint64 nonce, bytes payload)
    "0x5b06d4a4e5e9e2a50e1cfea66e8c0b6e9f8a8d7c6b5a4e3d2c1b0a9f8e7d6c5b": {
        "name": "PacketReceived",
        "type": EventType.MESSAGE_RECEIVED,
        "protocol": "layerzero",
        "severity": "high"
    },
    # SendToChain(uint16 indexed _dstChainId, address indexed _from, bytes _toAddress, uint _amount)
    "0x32ed1a409ef04c7b0227189c3a103dc5ac10e775a15b785dcc510201f7c25ad3": {
        "name": "SendToChain",
        "type": EventType.BRIDGE_DEPOSIT,
        "protocol": "layerzero",
        "severity": "high"
    },
    # ReceiveFromChain(uint16 indexed _srcChainId, bytes _srcAddress, address indexed _toAddress, uint _amount)
    "0xd81b6f2a5a0f1c0c5e8e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c": {
        "name": "ReceiveFromChain",
        "type": EventType.BRIDGE_WITHDRAW,
        "protocol": "layerzero",
        "severity": "high"
    },
    
    # -------------------------------------------------------------------------
    # STARGATE
    # -------------------------------------------------------------------------
    # Swap(uint16 chainId, uint256 dstPoolId, address from, uint256 amountSD, uint256 eqReward, uint256 eqFee, uint256 protocolFee, uint256 lpFee)
    "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f": {
        "name": "Swap",
        "type": EventType.BRIDGE_DEPOSIT,
        "protocol": "stargate",
        "severity": "high"
    },
    # SendCredits(uint16 dstChainId, uint256 credits)
    "0x44b559f101f8fbcc8a0ea43fa91a05a729a5ea6e14a7c75aa750374690137208": {
        "name": "SendCredits",
        "type": EventType.MESSAGE_SENT,
        "protocol": "stargate",
        "severity": "medium"
    },
    # CreditChainPath(uint16 chainId, uint256 srcPoolId, uint256 dstPoolId, uint256 credits)
    "0xf4ad92585b1bc117fbdd644990adf0827bc4c95baeae8a23322af807b6d0020e": {
        "name": "CreditChainPath",
        "type": EventType.MESSAGE_RECEIVED,
        "protocol": "stargate",
        "severity": "medium"
    },
    
    # -------------------------------------------------------------------------
    # ACROSS PROTOCOL
    # -------------------------------------------------------------------------
    # FilledRelay(uint256 amount, uint256 totalFilledAmount, uint256 fillAmount, uint256 repaymentChainId, ...)
    "0x8ab9dc6c19fe88e69bc70221b339c84332752fdd49591b7c51e66bae3947b73c": {
        "name": "FilledRelay",
        "type": EventType.BRIDGE_WITHDRAW,
        "protocol": "across",
        "severity": "high"
    },
    # FundsDeposited(uint256 amount, uint256 originChainId, uint256 destinationChainId, ...)
    "0xafc4df6845a4ab948b492800d3d8a25d538a102a2bc07cd01f1cfa097fddcff6": {
        "name": "FundsDeposited",
        "type": EventType.BRIDGE_DEPOSIT,
        "protocol": "across",
        "severity": "high"
    },
    # V3FundsDeposited - newer version
    "0xa123dc29aebf7d0c3322c8eeb5b999e859f39937950ed31056532713d0de396f": {
        "name": "V3FundsDeposited",
        "type": EventType.BRIDGE_DEPOSIT,
        "protocol": "across",
        "severity": "high"
    },
    
    # -------------------------------------------------------------------------
    # HOP PROTOCOL
    # -------------------------------------------------------------------------
    # TransferSent(bytes32 indexed transferId, uint256 chainId, address recipient, uint256 amount, ...)
    "0xe35dddd4ea75d7e9b3fe93af4f4e40e778c3da4074c9d93e7c6f3f94a7d0ec34": {
        "name": "TransferSent",
        "type": EventType.BRIDGE_DEPOSIT,
        "protocol": "hop",
        "severity": "high"
    },
    # TransferFromL1Completed(address indexed recipient, uint256 amount, uint256 amountOutMin, ...)
    "0x320958176930804eb66c2343c7343fc0367dc16249590c0f195783bee199d094": {
        "name": "TransferFromL1Completed",
        "type": EventType.BRIDGE_WITHDRAW,
        "protocol": "hop",
        "severity": "high"
    },
    
    # -------------------------------------------------------------------------
    # SYNAPSE
    # -------------------------------------------------------------------------
    # TokenDeposit(address indexed to, uint256 chainId, address token, uint256 amount)
    "0xda5273705dbef4bf1b902a131c2eac086b7e1476a8ab0cb4da08af1fe1bd8e3b": {
        "name": "TokenDeposit",
        "type": EventType.BRIDGE_DEPOSIT,
        "protocol": "synapse",
        "severity": "high"
    },
    # TokenRedeem(address indexed to, uint256 chainId, address token, uint256 amount)
    "0xdc5bad4651c5fbe9977a696aadc65996c468cde1448dd468ec0d83bf61c4b57c": {
        "name": "TokenRedeem",
        "type": EventType.BRIDGE_WITHDRAW,
        "protocol": "synapse",
        "severity": "high"
    },
    
    # -------------------------------------------------------------------------
    # CELER cBRIDGE
    # -------------------------------------------------------------------------
    # Send(bytes32 transferId, address sender, address receiver, address token, uint256 amount, uint64 dstChainId, ...)
    "0x89d8051e597ab4178a863a5190407b98abfeff406aa8db90c59af76612e58f01": {
        "name": "Send",
        "type": EventType.BRIDGE_DEPOSIT,
        "protocol": "celer",
        "severity": "high"
    },
    # Relay(bytes32 transferId, address sender, address receiver, address token, uint256 amount, ...)
    "0x79fa08de5149d912dce8e5e8da7a7c17ccdf23dd5d3bfe196802f6c6d471f3f9": {
        "name": "Relay",
        "type": EventType.BRIDGE_WITHDRAW,
        "protocol": "celer",
        "severity": "high"
    },
}

# =============================================================================
# DeFi Protocol Events
# =============================================================================
DEFI_SIGNATURES = {
    # -------------------------------------------------------------------------
    # AAVE V3
    # -------------------------------------------------------------------------
    # Supply(address indexed reserve, address user, address indexed onBehalfOf, uint256 amount, ...)
    "0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61": {
        "name": "Supply",
        "type": EventType.LIQUIDITY_ADD,
        "protocol": "aave",
        "severity": "low"
    },
    # Withdraw(address indexed reserve, address indexed user, address indexed to, uint256 amount)
    "0x3115d1449a7b732c986cba18244e897a450f61e1bb8d589cd2e69e6c8924f9f7": {
        "name": "Withdraw",
        "type": EventType.LIQUIDITY_REMOVE,
        "protocol": "aave",
        "severity": "medium"
    },
    # Borrow(address indexed reserve, address user, address indexed onBehalfOf, uint256 amount, ...)
    "0xb3d084820fb1a9decffb176436bd02558d15fac9b0ddfed8c465bc7359d7dce0": {
        "name": "Borrow",
        "type": EventType.FLASH_BORROW,
        "protocol": "aave",
        "severity": "medium"
    },
    # Repay(address indexed reserve, address indexed user, address indexed repayer, uint256 amount, ...)
    "0xa534c8dbe71f871f9f3530e97a74601fea17b426cae02e1c5aee42c96c784051": {
        "name": "Repay",
        "type": EventType.FLASH_REPAY,
        "protocol": "aave",
        "severity": "medium"
    },
    # FlashLoan(address indexed target, address initiator, address indexed asset, uint256 amount, ...)
    "0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac": {
        "name": "FlashLoan",
        "type": EventType.FLASH_BORROW,
        "protocol": "aave",
        "severity": "critical"
    },
    # LiquidationCall(address indexed collateralAsset, address indexed debtAsset, address indexed user, ...)
    "0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be37335533e005286": {
        "name": "LiquidationCall",
        "type": EventType.UNKNOWN,
        "protocol": "aave",
        "severity": "high"
    },
    
    # -------------------------------------------------------------------------
    # UNISWAP V3
    # -------------------------------------------------------------------------
    # Swap(address indexed sender, address indexed recipient, int256 amount0, int256 amount1, ...)
    "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67": {
        "name": "Swap",
        "type": EventType.SWAP,
        "protocol": "uniswap",
        "severity": "low"
    },
    # Mint(address sender, address indexed owner, int24 indexed tickLower, int24 indexed tickUpper, ...)
    "0x7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde": {
        "name": "Mint",
        "type": EventType.LIQUIDITY_ADD,
        "protocol": "uniswap",
        "severity": "low"
    },
    # Burn(address indexed owner, int24 indexed tickLower, int24 indexed tickUpper, uint128 amount, ...)
    "0x0c396cd989a39f4459b5fa1aed6a9a8dcdbc45908acfd67e028cd568da98982c": {
        "name": "Burn",
        "type": EventType.LIQUIDITY_REMOVE,
        "protocol": "uniswap",
        "severity": "medium"
    },
    # Flash(address indexed sender, address indexed recipient, uint256 amount0, uint256 amount1, ...)
    "0xbdbdb71d7860376ba52b25a5028beea23581364a40522f6bcfb86bb1f2dca633": {
        "name": "Flash",
        "type": EventType.FLASH_BORROW,
        "protocol": "uniswap",
        "severity": "critical"
    },
    
    # -------------------------------------------------------------------------
    # UNISWAP V2
    # -------------------------------------------------------------------------
    # Swap(address indexed sender, uint amount0In, uint amount1In, uint amount0Out, uint amount1Out, address indexed to)
    "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822": {
        "name": "Swap",
        "type": EventType.SWAP,
        "protocol": "uniswap_v2",
        "severity": "low"
    },
    # Sync(uint112 reserve0, uint112 reserve1)
    "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1": {
        "name": "Sync",
        "type": EventType.UNKNOWN,
        "protocol": "uniswap_v2",
        "severity": "low"
    },
    
    # -------------------------------------------------------------------------
    # COMPOUND V2
    # -------------------------------------------------------------------------
    # Mint(address minter, uint mintAmount, uint mintTokens)
    "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f": {
        "name": "Mint",
        "type": EventType.LIQUIDITY_ADD,
        "protocol": "compound",
        "severity": "low"
    },
    # Redeem(address redeemer, uint redeemAmount, uint redeemTokens)
    "0xe5b754fb1abb7f01b499791d0b820ae3b6af3424ac1c59768edb53f4ec31a929": {
        "name": "Redeem",
        "type": EventType.LIQUIDITY_REMOVE,
        "protocol": "compound",
        "severity": "medium"
    },
    # Borrow(address borrower, uint borrowAmount, uint accountBorrows, uint totalBorrows)
    "0x13ed6866d4e1ee6da46f845c46d7e54120883d75c5ea9a2dacc1c4ca8984ab80": {
        "name": "Borrow",
        "type": EventType.FLASH_BORROW,
        "protocol": "compound",
        "severity": "medium"
    },
    # RepayBorrow(address payer, address borrower, uint repayAmount, uint accountBorrows, uint totalBorrows)
    "0x1a2a22cb034d26d1854bdc6666a5b91fe25efbbb5dcad3b0355478d6f5c362a1": {
        "name": "RepayBorrow",
        "type": EventType.FLASH_REPAY,
        "protocol": "compound",
        "severity": "medium"
    },
    # LiquidateBorrow(address liquidator, address borrower, uint repayAmount, address cTokenCollateral, uint seizeTokens)
    "0x298637f684da70674f26509b10f07ec2fbc77a335ab1e7d6215a4b2484d8bb52": {
        "name": "LiquidateBorrow",
        "type": EventType.UNKNOWN,
        "protocol": "compound",
        "severity": "high"
    },
    
    # -------------------------------------------------------------------------
    # CURVE FINANCE
    # -------------------------------------------------------------------------
    # TokenExchange(address indexed buyer, int128 sold_id, uint256 tokens_sold, int128 bought_id, uint256 tokens_bought)
    "0x8b3e96f2b889fa771c53c981b40daf005f63f637f1869f707052d15a3dd97140": {
        "name": "TokenExchange",
        "type": EventType.SWAP,
        "protocol": "curve",
        "severity": "low"
    },
    # AddLiquidity(address indexed provider, uint256[2] token_amounts, uint256[2] fees, uint256 invariant, uint256 token_supply)
    "0x26f55a85081d24974e85c6c00045d0f0453991e95873f52bff0d21af4079a768": {
        "name": "AddLiquidity",
        "type": EventType.LIQUIDITY_ADD,
        "protocol": "curve",
        "severity": "low"
    },
    # RemoveLiquidity(address indexed provider, uint256[2] token_amounts, uint256[2] fees, uint256 token_supply)
    "0x7c363854ccf79623411f8995b362bce5eddff18c927edc6f5dbbb5e05819a82c": {
        "name": "RemoveLiquidity",
        "type": EventType.LIQUIDITY_REMOVE,
        "protocol": "curve",
        "severity": "medium"
    },
    
    # -------------------------------------------------------------------------
    # BALANCER
    # -------------------------------------------------------------------------
    # Swap(bytes32 indexed poolId, address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut)
    "0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b": {
        "name": "Swap",
        "type": EventType.SWAP,
        "protocol": "balancer",
        "severity": "low"
    },
    # FlashLoan(address indexed recipient, address indexed token, uint256 amount, uint256 feeAmount)
    "0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19f3f93ce64d5e2b7c60e9e0e2b4a3f": {
        "name": "FlashLoan",
        "type": EventType.FLASH_BORROW,
        "protocol": "balancer",
        "severity": "critical"
    },
}

# =============================================================================
# Governance Events
# =============================================================================
GOVERNANCE_SIGNATURES = {
    # ProposalCreated(uint256 proposalId, address proposer, ...)
    "0x7d84a6263ae0d98d3329bd7b46bb4e8d6f98cd35a7adb45c274c8b7fd5ebd5e0": {
        "name": "ProposalCreated",
        "type": EventType.PROPOSAL_CREATED,
        "severity": "medium"
    },
    # ProposalExecuted(uint256 proposalId)
    "0x712ae1383f79ac853f8d882153778e0260ef8f03b504e2866e0593e04d2b291f": {
        "name": "ProposalExecuted",
        "type": EventType.PROPOSAL_EXECUTED,
        "severity": "high"
    },
    # VoteCast(address indexed voter, uint256 proposalId, uint8 support, uint256 weight, string reason)
    "0xb8e138887d0aa13bab447e82de9d5c1777041ecd21ca36ba824ff1e6c07ddda4": {
        "name": "VoteCast",
        "type": EventType.UNKNOWN,
        "severity": "low"
    },
}

# =============================================================================
# Combined Signature Lookup
# =============================================================================
ALL_SIGNATURES = {
    **ERC20_SIGNATURES,
    **BRIDGE_SIGNATURES,
    **DEFI_SIGNATURES,
    **GOVERNANCE_SIGNATURES,
}


def get_event_info(topic0: str) -> dict:
    """
    Get event information from topic0 (event signature).
    
    Args:
        topic0: The first topic (event signature hash)
        
    Returns:
        Event info dict with name, type, protocol, severity
    """
    # Normalize topic0
    if not topic0.startswith("0x"):
        topic0 = "0x" + topic0
    topic0 = topic0.lower()
    
    # Look up in all signatures
    for sig, info in ALL_SIGNATURES.items():
        if sig.lower() == topic0:
            return info
    
    # Unknown event
    return {
        "name": "Unknown",
        "type": EventType.UNKNOWN,
        "protocol": "unknown",
        "severity": "low"
    }


def identify_event_type(topic0: str) -> EventType:
    """Get EventType from topic0."""
    info = get_event_info(topic0)
    return info.get("type", EventType.UNKNOWN)


def get_protocol_name(topic0: str) -> str:
    """Get protocol name from topic0."""
    info = get_event_info(topic0)
    return info.get("protocol", "unknown")


def get_event_severity(topic0: str) -> str:
    """Get event severity from topic0."""
    info = get_event_info(topic0)
    return info.get("severity", "low")

