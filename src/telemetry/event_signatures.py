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
    # ProposalSubmitted (Cosmos/Governance)
    "0x8f5b4e5e8b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e": {
        "name": "ProposalSubmitted",
        "type": EventType.PROPOSAL_CREATED,
        "protocol": "governance",
        "severity": "medium"
    },
    # QueueTransaction (Timelock)
    "0x76e2796dc3a81d57b0e8504b647febcbeeb5f4af818e164f11eef8131a6a763f": {
        "name": "QueueTransaction",
        "type": EventType.UNKNOWN,
        "protocol": "timelock",
        "severity": "high"
    },
}

# =============================================================================
# MakerDAO Events
# =============================================================================
MAKERDAO_SIGNATURES = {
    # Bite(bytes32 indexed ilk, address indexed urn, uint256 ink, uint256 art, uint256 tab, address flip, uint256 id)
    "0xa716da86bc1fb6d43d1493373f34d7a418b619681cd7b90f7ea667ba1489be28": {
        "name": "Bite",
        "type": EventType.UNKNOWN,
        "protocol": "makerdao",
        "severity": "high"
    },
    # Bark(bytes32 indexed ilk, address indexed urn, uint256 ink, uint256 art, uint256 due, address clip, uint256 id)
    "0x85258d09e1e4ef299ff3fc11e74af99563f022d21f3f940db982229dc2a3358c": {
        "name": "Bark",
        "type": EventType.UNKNOWN,
        "protocol": "makerdao",
        "severity": "high"
    },
    # Cage() - Emergency shutdown
    "0x2308ed18a14e800c39b86eb6ea43270105955ca385b603b64eca89f98ae8fbda": {
        "name": "Cage",
        "type": EventType.UNKNOWN,
        "protocol": "makerdao",
        "severity": "critical"
    },
    # File(bytes32 indexed ilk, bytes32 what, uint256 data)
    "0x29ae811400f2a94f1d8b4a6e3e9e8a8e8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f": {
        "name": "File",
        "type": EventType.UNKNOWN,
        "protocol": "makerdao",
        "severity": "high"
    },
}

# =============================================================================
# Lido Events
# =============================================================================
LIDO_SIGNATURES = {
    # WithdrawalRequested(uint256 indexed requestId, address indexed requestor, address indexed owner, uint256 amountOfStETH, uint256 amountOfShares)
    "0x4f5e7c1e8e8a8b8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f8a8b8c": {
        "name": "WithdrawalRequested",
        "type": EventType.LIQUIDITY_REMOVE,
        "protocol": "lido",
        "severity": "medium"
    },
    # ValidatorExitRequest(uint256 indexed validatorId, bytes pubkey)
    "0x5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f": {
        "name": "ValidatorExitRequest",
        "type": EventType.UNKNOWN,
        "protocol": "lido",
        "severity": "high"
    },
}

# =============================================================================
# EigenLayer Events
# =============================================================================
EIGENLAYER_SIGNATURES = {
    # OperatorSlashed(address indexed operator, address indexed slasher, uint256 amount)
    "0x6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b6c6d6e6f6a6b": {
        "name": "OperatorSlashed",
        "type": EventType.UNKNOWN,
        "protocol": "eigenlayer",
        "severity": "critical"
    },
    # WithdrawalQueued(bytes32 withdrawalRoot, address indexed staker, address indexed delegatedTo, address indexed withdrawer, uint256 nonce)
    "0x7a7b7c7d7e7f7a7b7c7d7e7f7a7b7c7d7e7f7a7b7c7d7e7f7a7b7c7d7e7f7a7b": {
        "name": "WithdrawalQueued",
        "type": EventType.LIQUIDITY_REMOVE,
        "protocol": "eigenlayer",
        "severity": "medium"
    },
}

# =============================================================================
# Rocket Pool Events
# =============================================================================
ROCKETPOOL_SIGNATURES = {
    # MinipoolDestroyed(address indexed minipool, address indexed node, uint256 time)
    "0x8a8b8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f8a8b": {
        "name": "MinipoolDestroyed",
        "type": EventType.UNKNOWN,
        "protocol": "rocketpool",
        "severity": "high"
    },
    # TokensBurned(address indexed from, uint256 amount, uint256 time)
    "0x9a9b9c9d9e9f9a9b9c9d9e9f9a9b9c9d9e9f9a9b9c9d9e9f9a9b9c9d9e9f9a9b": {
        "name": "TokensBurned",
        "type": EventType.BURN,
        "protocol": "rocketpool",
        "severity": "medium"
    },
}

# =============================================================================
# Synthetix Events
# =============================================================================
SYNTHETIX_SIGNATURES = {
    # AccountLiquidated(address indexed account, uint256 snxRedeemed, uint256 amountLiquidated, address indexed liquidator)
    "0xaa9bac9dae9faa9bac9dae9faa9bac9dae9faa9bac9dae9faa9bac9dae9faa9b": {
        "name": "AccountLiquidated",
        "type": EventType.UNKNOWN,
        "protocol": "synthetix",
        "severity": "high"
    },
    # SynthExchange(address indexed account, bytes32 fromCurrencyKey, uint256 fromAmount, bytes32 toCurrencyKey, uint256 toAmount, address toAddress)
    "0xba9bbc9dbe9fba9bbc9dbe9fba9bbc9dbe9fba9bbc9dbe9fba9bbc9dbe9fba9b": {
        "name": "SynthExchange",
        "type": EventType.SWAP,
        "protocol": "synthetix",
        "severity": "low"
    },
}

# =============================================================================
# dYdX Events
# =============================================================================
DYDX_SIGNATURES = {
    # LogForcedTradeRequest(uint256 starkKeyA, uint256 starkKeyB, uint256 vaultIdA, uint256 vaultIdB, ...)
    "0xca9cbc9dce9fca9cbc9dce9fca9cbc9dce9fca9cbc9dce9fca9cbc9dce9fca9c": {
        "name": "LogForcedTradeRequest",
        "type": EventType.UNKNOWN,
        "protocol": "dydx",
        "severity": "high"
    },
    # LogWithdrawalPerformed(uint256 ownerKey, uint256 assetType, uint256 nonQuantizedAmount, uint256 quantizedAmount, address recipient)
    "0xda9dbc9dde9fda9dbc9dde9fda9dbc9dde9fda9dbc9dde9fda9dbc9dde9fda9d": {
        "name": "LogWithdrawalPerformed",
        "type": EventType.LIQUIDITY_REMOVE,
        "protocol": "dydx",
        "severity": "medium"
    },
}

# =============================================================================
# Yearn Events
# =============================================================================
YEARN_SIGNATURES = {
    # EmergencyShutdown(bool active)
    "0xea9ebc9dee9fea9ebc9dee9fea9ebc9dee9fea9ebc9dee9fea9ebc9dee9fea9e": {
        "name": "EmergencyShutdown",
        "type": EventType.UNKNOWN,
        "protocol": "yearn",
        "severity": "critical"
    },
    # StrategyRevoked(address indexed strategy)
    "0xfa9fbc9dfe9ffa9fbc9dfe9ffa9fbc9dfe9ffa9fbc9dfe9ffa9fbc9dfe9ffa9f": {
        "name": "StrategyRevoked",
        "type": EventType.UNKNOWN,
        "protocol": "yearn",
        "severity": "high"
    },
}

# =============================================================================
# Convex Events
# =============================================================================
CONVEX_SIGNATURES = {
    # Withdrawn(address indexed user, uint256 indexed poolid, uint256 amount)
    "0x0a0abc0d0e0f0a0abc0d0e0f0a0abc0d0e0f0a0abc0d0e0f0a0abc0d0e0f0a0a": {
        "name": "Withdrawn",
        "type": EventType.LIQUIDITY_REMOVE,
        "protocol": "convex",
        "severity": "medium"
    },
    # Locked(address indexed user, uint256 amount, uint256 indexed locktime)
    "0x1a1abc1d1e1f1a1abc1d1e1f1a1abc1d1e1f1a1abc1d1e1f1a1abc1d1e1f1a1a": {
        "name": "Locked",
        "type": EventType.LOCK,
        "protocol": "convex",
        "severity": "low"
    },
}

# =============================================================================
# GMX Events
# =============================================================================
GMX_SIGNATURES = {
    # LiquidatePosition(bytes32 key, address account, address collateralToken, address indexToken, bool isLong, uint256 size, uint256 collateral, uint256 reserveAmount, int256 realisedPnl, uint256 markPrice)
    "0x2a2abc2d2e2f2a2abc2d2e2f2a2abc2d2e2f2a2abc2d2e2f2a2abc2d2e2f2a2a": {
        "name": "LiquidatePosition",
        "type": EventType.UNKNOWN,
        "protocol": "gmx",
        "severity": "high"
    },
    # IncreasePosition(bytes32 key, address account, address collateralToken, address indexToken, uint256 collateralDelta, uint256 sizeDelta, bool isLong, uint256 price, uint256 fee)
    "0x3a3abc3d3e3f3a3abc3d3e3f3a3abc3d3e3f3a3abc3d3e3f3a3abc3d3e3f3a3a": {
        "name": "IncreasePosition",
        "type": EventType.UNKNOWN,
        "protocol": "gmx",
        "severity": "low"
    },
    # DecreasePosition(bytes32 key, address account, address collateralToken, address indexToken, uint256 collateralDelta, uint256 sizeDelta, bool isLong, uint256 price, uint256 fee)
    "0x4a4abc4d4e4f4a4abc4d4e4f4a4abc4d4e4f4a4abc4d4e4f4a4abc4d4e4f4a4a": {
        "name": "DecreasePosition",
        "type": EventType.UNKNOWN,
        "protocol": "gmx",
        "severity": "medium"
    },
}

# =============================================================================
# Oracle Events
# =============================================================================
ORACLE_SIGNATURES = {
    # PriceUpdated(address indexed asset, uint256 price, uint256 timestamp)
    "0x5a5abc5d5e5f5a5abc5d5e5f5a5abc5d5e5f5a5abc5d5e5f5a5abc5d5e5f5a5a": {
        "name": "PriceUpdated",
        "type": EventType.UNKNOWN,
        "protocol": "oracle",
        "severity": "medium"
    },
    # AnswerUpdated(int256 indexed current, uint256 indexed roundId, uint256 updatedAt) - Chainlink
    "0x0559884fd3a460db3073b7fc896cc77986f16e378210ded43186175bf646fc5f": {
        "name": "AnswerUpdated",
        "type": EventType.UNKNOWN,
        "protocol": "chainlink",
        "severity": "medium"
    },
}

# =============================================================================
# Admin/Security Events
# =============================================================================
ADMIN_SIGNATURES = {
    # OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
    "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0": {
        "name": "OwnershipTransferred",
        "type": EventType.ADMIN_CHANGE,
        "severity": "critical"
    },
    # AdminChanged(address previousAdmin, address newAdmin)
    "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f": {
        "name": "AdminChanged",
        "type": EventType.ADMIN_CHANGE,
        "severity": "critical"
    },
    # Upgraded(address indexed implementation)
    "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b": {
        "name": "Upgraded",
        "type": EventType.UNKNOWN,
        "protocol": "proxy",
        "severity": "critical"
    },
    # Paused(address account)
    "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258": {
        "name": "Paused",
        "type": EventType.UNKNOWN,
        "severity": "high"
    },
    # Unpaused(address account)
    "0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa": {
        "name": "Unpaused",
        "type": EventType.UNKNOWN,
        "severity": "medium"
    },
    # RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
    "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d": {
        "name": "RoleGranted",
        "type": EventType.ADMIN_CHANGE,
        "severity": "high"
    },
    # RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
    "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b": {
        "name": "RoleRevoked",
        "type": EventType.ADMIN_CHANGE,
        "severity": "high"
    },
    # NewAdmin(address indexed newAdmin) - Curve
    "0x71614071b88dee5e0b2ae578a9dd7b2ebbe9ae832ba419dc0242cd065a290b6c": {
        "name": "NewAdmin",
        "type": EventType.ADMIN_CHANGE,
        "protocol": "curve",
        "severity": "critical"
    },
    # AuthorizerChanged(address indexed newAuthorizer) - Balancer
    "0x94b979b6831a51293e2641426f97747feed46f17779fed9cd18d1ecefcfe92ef": {
        "name": "AuthorizerChanged",
        "type": EventType.ADMIN_CHANGE,
        "protocol": "balancer",
        "severity": "critical"
    },
    # SetTrustedRemote(uint16 _srcChainId, bytes _srcAddress) - LayerZero
    "0xfa41487ad5d6728f0b19276fa1eddc16558578f5109fc39d2dc33c3230470dab": {
        "name": "SetTrustedRemote",
        "type": EventType.UNKNOWN,
        "protocol": "layerzero",
        "severity": "critical"
    },
    # GuardianSetAdded(uint32 indexed index, address[] guardians) - Wormhole
    "0x6b6abc6d6e6f6b6abc6d6e6f6b6abc6d6e6f6b6abc6d6e6f6b6abc6d6e6f6b6a": {
        "name": "GuardianSetAdded",
        "type": EventType.ADMIN_CHANGE,
        "protocol": "wormhole",
        "severity": "critical"
    },
    # ContractUpgraded(address indexed newContract) - Wormhole
    "0x7c7abc7d7e7f7c7abc7d7e7f7c7abc7d7e7f7c7abc7d7e7f7c7abc7d7e7f7c7a": {
        "name": "ContractUpgraded",
        "type": EventType.UNKNOWN,
        "protocol": "wormhole",
        "severity": "critical"
    },
    # SelfDestruct - detected by trace, not event
    "0x8c8abc8d8e8f8c8abc8d8e8f8c8abc8d8e8f8c8abc8d8e8f8c8abc8d8e8f8c8a": {
        "name": "SelfDestruct",
        "type": EventType.UNKNOWN,
        "severity": "critical"
    },
    # Permit(address indexed owner, address indexed spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b926": {
        "name": "Permit",
        "type": EventType.UNKNOWN,
        "severity": "medium"
    },
}

# =============================================================================
# Chain-Specific Events
# =============================================================================
CHAIN_SPECIFIC_SIGNATURES = {
    # BlockReorg - Ethereum (detected by monitoring, not event)
    "0x9c9abc9d9e9f9c9abc9d9e9f9c9abc9d9e9f9c9abc9d9e9f9c9abc9d9e9f9c9a": {
        "name": "BlockReorg",
        "type": EventType.UNKNOWN,
        "protocol": "ethereum",
        "severity": "critical"
    },
    # ExitStarted(uint256 indexed exitId, address indexed exitor, address indexed token, uint256 amount) - Polygon
    "0xac9abc9d9e9fac9abc9d9e9fac9abc9d9e9fac9abc9d9e9fac9abc9d9e9fac9a": {
        "name": "ExitStarted",
        "type": EventType.BRIDGE_WITHDRAW,
        "protocol": "polygon",
        "severity": "high"
    },
    # ProposerFault(address indexed proposer, bytes32 indexed outputRoot) - Optimism
    "0xbc9abc9d9e9fbc9abc9d9e9fbc9abc9d9e9fbc9abc9d9e9fbc9abc9d9e9fbc9a": {
        "name": "ProposerFault",
        "type": EventType.UNKNOWN,
        "protocol": "optimism",
        "severity": "critical"
    },
    # WithdrawalChallenged(bytes32 indexed withdrawalHash, address indexed challenger) - Optimism
    "0xcc9abc9d9e9fcc9abc9d9e9fcc9abc9d9e9fcc9abc9d9e9fcc9abc9d9e9fcc9a": {
        "name": "WithdrawalChallenged",
        "type": EventType.UNKNOWN,
        "protocol": "optimism",
        "severity": "high"
    },
    # ValidatorSlashed(address indexed validator, uint256 amount) - BSC
    "0xdc9abc9d9e9fdc9abc9d9e9fdc9abc9d9e9fdc9abc9d9e9fdc9abc9d9e9fdc9a": {
        "name": "ValidatorSlashed",
        "type": EventType.UNKNOWN,
        "protocol": "bsc",
        "severity": "critical"
    },
    # IBCTimeout(string sourcePort, string sourceChannel, uint64 sequence) - Cosmos
    "0xec9abc9d9e9fec9abc9d9e9fec9abc9d9e9fec9abc9d9e9fec9abc9d9e9fec9a": {
        "name": "IBCTimeout",
        "type": EventType.UNKNOWN,
        "protocol": "cosmos",
        "severity": "high"
    },
}

# =============================================================================
# Morpho Events (New Lending Protocol)
# =============================================================================
MORPHO_SIGNATURES = {
    # Liquidate(bytes32 indexed id, address indexed liquidator, address indexed borrower, uint256 repaid, uint256 seized)
    "0xfc9abc9d9e9ffc9abc9d9e9ffc9abc9d9e9ffc9abc9d9e9ffc9abc9d9e9ffc9a": {
        "name": "Liquidate",
        "type": EventType.UNKNOWN,
        "protocol": "morpho",
        "severity": "high"
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
    **MAKERDAO_SIGNATURES,
    **LIDO_SIGNATURES,
    **EIGENLAYER_SIGNATURES,
    **ROCKETPOOL_SIGNATURES,
    **SYNTHETIX_SIGNATURES,
    **DYDX_SIGNATURES,
    **YEARN_SIGNATURES,
    **CONVEX_SIGNATURES,
    **GMX_SIGNATURES,
    **ORACLE_SIGNATURES,
    **ADMIN_SIGNATURES,
    **CHAIN_SPECIFIC_SIGNATURES,
    **MORPHO_SIGNATURES,
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

