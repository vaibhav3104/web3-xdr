/*
 * Sentinel3 YARA Rules - Malicious Smart Contract Detection
 * ==========================================================
 * Detects malicious patterns in EVM bytecode and Solidity source code.
 * 
 * Usage:
 *   yara -r security/yara/rules/web3/ <contract_bytecode.bin>
 *   yara -r security/yara/rules/web3/ <contract_source.sol>
 *
 * Categories:
 *   - Honeypot contracts
 *   - Rug pull patterns
 *   - Reentrancy vulnerabilities
 *   - Flash loan exploits
 *   - Oracle manipulation
 */

// ============================================================================
// HONEYPOT DETECTION
// ============================================================================

rule Honeypot_Common_Prefix
{
    meta:
        description = "Common honeypot contract bytecode prefix"
        severity = "CRITICAL"
        category = "honeypot"
        confidence = 85
        reference = "Sentinel3 vulnerability_scanner.py"
        author = "Sentinel3 Detection Engineering"
    
    strings:
        $prefix1 = { 60 80 60 40 52 60 04 36 10 61 00 }
        $prefix2 = { 60 80 60 40 52 34 80 15 61 }
        
    condition:
        $prefix1 at 0 or $prefix2 at 0
}

rule Honeypot_Hidden_Transfer_Block
{
    meta:
        description = "Honeypot that blocks transfers after initial buys"
        severity = "CRITICAL"
        category = "honeypot"
        confidence = 90
        mitre_attack = "T1499.004"
    
    strings:
        // Solidity patterns
        $sol_block1 = "require(from == owner" nocase
        $sol_block2 = "require(to == owner" nocase
        $sol_block3 = "if (from != owner) revert" nocase
        $sol_block4 = "onlyOwner" 
        $sol_transfer = "function transfer"
        $sol_approve = "function approve"
        
        // Bytecode: CALLER PUSH owner EQ
        $bytecode_check = { 33 73 [20] 14 }
        
    condition:
        ($sol_transfer and ($sol_block1 or $sol_block2 or $sol_block3)) or
        ($sol_approve and $sol_block4) or
        $bytecode_check
}

rule Honeypot_Max_Transaction_Limit
{
    meta:
        description = "Token with extremely low max transaction limit (honeypot indicator)"
        severity = "HIGH"
        category = "honeypot"
        confidence = 75
    
    strings:
        $max_tx1 = "maxTransactionAmount"
        $max_tx2 = "_maxTxAmount"
        $max_tx3 = "maxTxAmount"
        $very_low = /maxT[xX].*=\s*[1-9]\d{0,5}\s*\*/
        
    condition:
        any of ($max_tx*) and $very_low
}

// ============================================================================
// RUG PULL DETECTION
// ============================================================================

rule Rugpull_Hidden_Mint
{
    meta:
        description = "Hidden mint function that can inflate supply (rug pull)"
        severity = "CRITICAL"
        category = "rugpull"
        confidence = 90
    
    strings:
        // Disguised mint functions
        $mint1 = "function _mint" nocase
        $mint2 = "function mint" nocase
        $mint3 = "_totalSupply +=" 
        $mint4 = "totalSupply = totalSupply.add"
        $mint5 = { 01 90 55 }  // ADD SWAP1 SSTORE (increase storage)
        
        // Owner-only minting
        $owner_mint = /onlyOwner.*_mint|_mint.*onlyOwner/
        
        // Max supply checks (absence indicates risk)
        $has_max_supply = "maxSupply"
        $has_max_supply2 = "MAX_SUPPLY"
        
    condition:
        (any of ($mint*)) and $owner_mint and not ($has_max_supply or $has_max_supply2)
}

rule Rugpull_Liquidity_Removal
{
    meta:
        description = "Contract can remove all liquidity (rug pull)"
        severity = "CRITICAL"
        category = "rugpull"
        confidence = 85
    
    strings:
        $remove_liq1 = "removeLiquidity"
        $remove_liq2 = "removeLiquidityETH"
        $remove_liq3 = "removeLiquidityWithPermit"
        $all_liq = /remove.*100\s*%|remove.*percent.*100/i
        
        // Uniswap router selector for removeLiquidity
        $selector = { ba a2 ab de }  // removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)
        
    condition:
        any of them
}

rule Rugpull_Ownership_Renounce_Fake
{
    meta:
        description = "Fake renounce ownership (still has backdoor)"
        severity = "CRITICAL"
        category = "rugpull"
        confidence = 80
    
    strings:
        $renounce = "renounceOwnership"
        $backdoor1 = "function setOwner" nocase
        $backdoor2 = "function changeOwner" nocase
        $backdoor3 = "function recoverOwnership" nocase
        $backdoor4 = "_owner = " 
        
    condition:
        $renounce and any of ($backdoor*)
}

// ============================================================================
// REENTRANCY VULNERABILITIES
// ============================================================================

rule Reentrancy_Classic
{
    meta:
        description = "Classic reentrancy vulnerability pattern"
        severity = "CRITICAL"
        category = "reentrancy"
        confidence = 85
        mitre_attack = "T1499.004"
    
    strings:
        // State change after external call
        $pattern1 = /\.call\{.*\}\([^)]*\)[^;]*;[^}]*balance.*=/
        $pattern2 = /\.transfer\([^)]*\)[^;]*;[^}]*balance.*=/
        $pattern3 = /\.send\([^)]*\)[^;]*;[^}]*balance.*=/
        
        // Bytecode: CALL followed by SSTORE (dangerous order)
        $bytecode = { F1 [0-20] 55 }  // CALL ... SSTORE
        
    condition:
        any of them
}

rule Reentrancy_Cross_Function
{
    meta:
        description = "Cross-function reentrancy vulnerability"
        severity = "CRITICAL"
        category = "reentrancy"
        confidence = 75
    
    strings:
        $external_call = ".call{"
        $shared_state1 = "balances["
        $shared_state2 = "shares["
        $shared_state3 = "_balances["
        
        // Reentrancy guards (presence = safe)
        $has_nonreentrant = "nonReentrant"
        $has_locked = "locked"
        $has_mutex = "mutex"
        $has_guard = "ReentrancyGuard"
        
    condition:
        $external_call and any of ($shared_state*) and not any of ($has_*)
}

rule Reentrancy_Read_Only
{
    meta:
        description = "Read-only reentrancy (price manipulation via reentrancy)"
        severity = "HIGH"
        category = "reentrancy"
        confidence = 70
    
    strings:
        $callback = "onERC721Received"
        $callback2 = "onERC1155Received"
        $callback3 = "tokensReceived"  // ERC777
        $price_read = /getPrice|getRate|get.*Price|oracle.*price/i
        
    condition:
        any of ($callback*) and $price_read
}

// ============================================================================
// FLASH LOAN EXPLOITS
// ============================================================================

rule FlashLoan_Attack_Pattern
{
    meta:
        description = "Flash loan attack pattern (borrow, manipulate, repay)"
        severity = "CRITICAL"
        category = "flashloan"
        confidence = 80
    
    strings:
        // Flash loan interfaces
        $aave_flash = "executeOperation"
        $uniswap_flash = "uniswapV2Call"
        $uniswap_v3 = "uniswapV3FlashCallback"
        $balancer_flash = "receiveFlashLoan"
        $dydx_flash = "callFunction"
        
        // Manipulation indicators
        $swap = "swapExactTokensForTokens"
        $price_impact = "getAmountOut"
        $price_impact2 = "getAmountsOut"
        
    condition:
        ($aave_flash or $uniswap_flash or $uniswap_v3 or $balancer_flash or $dydx_flash) and 
        ($swap or $price_impact or $price_impact2)
}

rule FlashLoan_Arbitrage_Bot
{
    meta:
        description = "Flash loan arbitrage contract (may be legitimate or malicious)"
        severity = "MEDIUM"
        category = "flashloan"
        confidence = 60
    
    strings:
        $flash1 = "flashLoan"
        $flash2 = "FlashLoan"
        $arb1 = "arbitrage"
        $arb2 = "profit"
        $multi_dex = /uniswap.*sushiswap|pancake.*trader.*joe/i
        
    condition:
        any of ($flash*) and (any of ($arb*) or $multi_dex)
}

// ============================================================================
// ORACLE MANIPULATION
// ============================================================================

rule Oracle_TWAP_Manipulation
{
    meta:
        description = "TWAP oracle manipulation pattern"
        severity = "CRITICAL"
        category = "oracle"
        confidence = 85
    
    strings:
        // Uniswap V3 TWAP functions
        $observe = { 88 3b db fd }  // observe(uint32[])
        $slot0 = { 38 50 c7 bd }    // slot0()
        
        // Manipulation indicators
        $same_block = "block.number"
        $low_cardinality = /cardinality.*[<]=?\s*[1-5]/
        
    condition:
        any of ($observe, $slot0) and ($same_block or $low_cardinality)
}

rule Oracle_Spot_Price_Reliance
{
    meta:
        description = "Dangerous reliance on spot price (manipulation risk)"
        severity = "HIGH"
        category = "oracle"
        confidence = 75
    
    strings:
        // Uniswap V2 reserve-based pricing
        $reserves = "getReserves()"
        $spot_calc = /reserve[01]\s*[*\/]\s*reserve[01]/
        
        // TWAP protection indicators (absence = risk)
        $has_observe = "observe"
        $has_consult = "consult"
        $has_twap = "TWAP"
        
    condition:
        $reserves and $spot_calc and not ($has_observe or $has_consult or $has_twap)
}

// ============================================================================
// DANGEROUS OPCODES
// ============================================================================

rule Dangerous_SelfDestruct
{
    meta:
        description = "Contract contains SELFDESTRUCT opcode"
        severity = "CRITICAL"
        category = "dangerous_opcode"
        confidence = 95
    
    strings:
        $selfdestruct_sol = "selfdestruct("
        $selfdestruct_bytecode = { FF }  // SELFDESTRUCT opcode
        
    condition:
        any of them
}

rule Dangerous_DelegateCall_To_Input
{
    meta:
        description = "DELEGATECALL to user-controlled address"
        severity = "CRITICAL"
        category = "dangerous_opcode"
        confidence = 90
    
    strings:
        // Solidity pattern
        $delegatecall_sol = ".delegatecall("
        $user_input = /delegatecall\([^)]*msg\.(sender|data)|delegatecall\([^)]*_[a-z]/
        
        // Bytecode: CALLDATALOAD followed by DELEGATECALL
        $bytecode = { 35 [0-30] F4 }  // CALLDATALOAD ... DELEGATECALL
        
    condition:
        ($delegatecall_sol and $user_input) or $bytecode
}

rule Dangerous_Arbitrary_Jump
{
    meta:
        description = "Arbitrary JUMP from user input"
        severity = "CRITICAL"
        category = "dangerous_opcode"
        confidence = 85
    
    strings:
        // Bytecode: CALLDATALOAD to JUMP (very dangerous)
        $pattern = { 35 [0-10] 56 }  // CALLDATALOAD ... JUMP
        
    condition:
        $pattern
}

// ============================================================================
// TX.ORIGIN AUTHENTICATION
// ============================================================================

rule TxOrigin_Authentication
{
    meta:
        description = "Using tx.origin for authentication (phishing vulnerability)"
        severity = "HIGH"
        category = "access_control"
        confidence = 90
    
    strings:
        $pattern1 = "require(tx.origin ==" 
        $pattern2 = "require(tx.origin!="
        $pattern3 = "if (tx.origin ==" 
        $pattern4 = "assert(tx.origin"
        
        // Bytecode: ORIGIN PUSH EQ
        $bytecode = { 32 73 [20] 14 }  // ORIGIN PUSH20 addr EQ
        
    condition:
        any of them
}

// ============================================================================
// APPROVAL EXPLOITS
// ============================================================================

rule Unlimited_Approval
{
    meta:
        description = "Contract requests unlimited token approval"
        severity = "HIGH"
        category = "approval"
        confidence = 80
    
    strings:
        // Max uint256 approval
        $max_approval1 = "type(uint256).max"
        $max_approval2 = "uint256(-1)"
        $max_approval3 = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        $max_approval4 = { 7f ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff }
        
        $approve = "approve("
        
    condition:
        $approve and any of ($max_approval*)
}

rule Approval_Frontrun_Vulnerability
{
    meta:
        description = "Approval can be frontrun (use increaseAllowance instead)"
        severity = "MEDIUM"
        category = "approval"
        confidence = 70
    
    strings:
        $approve = "function approve("
        
        // Safe approval patterns (presence = safe)
        $has_increase = "increaseAllowance"
        $has_decrease = "decreaseAllowance"
        
    condition:
        $approve and not ($has_increase or $has_decrease)
}

// ============================================================================
// PHISHING PATTERNS
// ============================================================================

rule Phishing_Permit_Signature
{
    meta:
        description = "Permit signature phishing pattern"
        severity = "HIGH"
        category = "phishing"
        confidence = 75
    
    strings:
        $permit = "permit("
        $deadline_far = /deadline.*[>]\s*block\.timestamp\s*\+\s*\d{8,}/
        $unlimited = "type(uint256).max"
        
    condition:
        $permit and ($deadline_far or $unlimited)
}

rule Phishing_Zero_Transfer_Poisoning
{
    meta:
        description = "Zero-value transfer address poisoning"
        severity = "MEDIUM"
        category = "phishing"
        confidence = 80
    
    strings:
        $transfer = "transfer("
        $zero_amount = /transfer\([^,]+,\s*0\s*\)/
        $zero_value = "amount == 0"
        
    condition:
        $transfer and ($zero_amount or $zero_value)
}

// ============================================================================
// PROXY VULNERABILITIES
// ============================================================================

rule Proxy_Uninitialized
{
    meta:
        description = "Uninitialized proxy (storage collision risk)"
        severity = "CRITICAL"
        category = "proxy"
        confidence = 80
    
    strings:
        // EIP-1167 minimal proxy
        $minimal_proxy = { 36 3d 3d 37 3d 3d 3d 36 3d 73 }
        
        // Initializable pattern
        $initializer = "initializer"
        $initialize_func = "function initialize"
        
        // Initialized check patterns (presence = safe)
        $has_initialized = "initialized"
        $has_init_flag = "_initialized"
        
    condition:
        $minimal_proxy or (($initializer or $initialize_func) and not ($has_initialized or $has_init_flag))
}

rule Proxy_Storage_Collision
{
    meta:
        description = "Proxy storage layout mismatch risk"
        severity = "HIGH"
        category = "proxy"
        confidence = 70
    
    strings:
        $delegatecall = "delegatecall"
        $upgradeable = "Upgradeable"
        
        // Gap pattern (presence = safe)
        $has_gap = "__gap"
        
    condition:
        $delegatecall and $upgradeable and not $has_gap
}

// ============================================================================
// MEV / SANDWICH ATTACK VECTORS
// ============================================================================

rule MEV_Sandwich_Vulnerable
{
    meta:
        description = "Contract vulnerable to sandwich attacks (no slippage protection)"
        severity = "HIGH"
        category = "mev"
        confidence = 75
    
    strings:
        $swap = "swapExactTokensForTokens"
        $swap2 = "swapTokensForExactTokens"
        $no_slippage = /swap.*amountOutMin.*[=]\s*0/
        $hardcoded_slippage = /amountOutMin.*[=]\s*\d{1,3}[^0-9]/  // Very low slippage
        
    condition:
        any of ($swap*) and ($no_slippage or $hardcoded_slippage)
}

// ============================================================================
// GOVERNANCE ATTACKS
// ============================================================================

rule Governance_FlashLoan_Vote
{
    meta:
        description = "Governance vulnerable to flash loan voting"
        severity = "CRITICAL"
        category = "governance"
        confidence = 80
    
    strings:
        $vote = "castVote"
        $delegate = "delegate("
        $same_block = "block.number"
        $has_snapshot = "snapshot"
        $has_prior = "getPriorVotes"
        $has_past = "getPastVotes"
        
    condition:
        ($vote or $delegate) and $same_block and not ($has_snapshot or $has_prior or $has_past)
}
