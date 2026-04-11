/*
 * Sentinel3 YARA Rules - Malicious Event Signatures
 * ==================================================
 * Detects known malicious transaction data and event logs.
 * 
 * Usage:
 *   yara security/yara/rules/web3/event_signatures.yar <tx_calldata.bin>
 *   yara security/yara/rules/web3/event_signatures.yar <event_log.bin>
 */

// ============================================================================
// CRITICAL ADMIN EVENTS (topic0 hashes)
// ============================================================================

rule Event_OwnershipTransferred
{
    meta:
        description = "OwnershipTransferred event detected"
        severity = "HIGH"
        category = "admin_event"
        topic0 = "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"
        confidence = 100
    
    strings:
        $topic0 = { 8b e0 07 9c 53 16 59 14 13 44 cd 1f d0 a4 f2 84 19 49 7f 97 22 a3 da af e3 b4 18 6f 6b 64 57 e0 }
        
    condition:
        $topic0
}

rule Event_AdminChanged
{
    meta:
        description = "AdminChanged event (proxy upgrade)"
        severity = "CRITICAL"
        category = "admin_event"
        topic0 = "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f"
        confidence = 100
    
    strings:
        $topic0 = { 7e 64 4d 79 42 2f 17 c0 1e 48 94 b5 f4 f5 88 d3 31 eb fa 28 65 3d 42 ae 83 2d c5 9e 38 c9 79 8f }
        
    condition:
        $topic0
}

rule Event_Upgraded
{
    meta:
        description = "Upgraded event (implementation change)"
        severity = "CRITICAL"
        category = "admin_event"
        topic0 = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"
        confidence = 100
    
    strings:
        $topic0 = { bc 7c d7 5a 20 ee 27 fd 9a de ba b3 20 41 f7 55 21 4d bc 6b ff a9 0c c0 22 5b 39 da 2e 5c 2d 3b }
        
    condition:
        $topic0
}

rule Event_Paused
{
    meta:
        description = "Paused event (protocol paused)"
        severity = "HIGH"
        category = "admin_event"
        topic0 = "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258"
        confidence = 100
    
    strings:
        $topic0 = { 62 e7 8c ea 01 be e3 20 cd 4e 42 02 70 b5 ea 74 00 0d 11 b0 c9 f7 47 54 eb db fc 54 4b 05 a2 58 }
        
    condition:
        $topic0
}

// ============================================================================
// FLASH LOAN EVENTS
// ============================================================================

rule Event_FlashLoan_AAVE
{
    meta:
        description = "AAVE V3 FlashLoan event"
        severity = "HIGH"
        category = "flashloan"
        topic0 = "0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac"
        confidence = 100
    
    strings:
        $topic0 = { 63 10 42 c8 32 b0 74 52 97 38 31 13 7f 2d 73 e3 95 02 8b 44 b2 50 de dc 5a bb 0e e7 66 e1 68 ac }
        
    condition:
        $topic0
}

rule Event_Flash_UniswapV3
{
    meta:
        description = "Uniswap V3 Flash event"
        severity = "HIGH"
        category = "flashloan"
        topic0 = "0xbdbdb71d7860376ba52b25a5028beea23581364a40522f6bcfb86bb1f2dca633"
        confidence = 100
    
    strings:
        $topic0 = { bd bd b7 1d 78 60 37 6b a5 2b 25 a5 02 8b ee a2 35 81 36 4a 40 52 2f 6b cf b8 6b b1 f2 dc a6 33 }
        
    condition:
        $topic0
}

// ============================================================================
// BRIDGE EVENTS (Cross-Chain)
// ============================================================================

rule Event_Wormhole_MessagePublished
{
    meta:
        description = "Wormhole LogMessagePublished event"
        severity = "MEDIUM"
        category = "bridge"
        topic0 = "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"
        confidence = 100
    
    strings:
        $topic0 = { 6e b2 24 fb 00 1e d2 10 e3 79 b3 35 e3 5e fe 88 67 2a 8c e9 35 d9 81 a6 89 6b 27 ff df 52 a3 b2 }
        
    condition:
        $topic0
}

rule Event_Wormhole_TransferRedeemed
{
    meta:
        description = "Wormhole TransferRedeemed event"
        severity = "HIGH"
        category = "bridge"
        topic0 = "0xcaf280c8cfeba144da67230d9b009c8f868a75bac9a528fa0474be1ba317c169"
        confidence = 100
    
    strings:
        $topic0 = { ca f2 80 c8 cf eb a1 44 da 67 23 0d 9b 00 9c 8f 86 8a 75 ba c9 a5 28 fa 04 74 be 1b a3 17 c1 69 }
        
    condition:
        $topic0
}

rule Event_LayerZero_Packet
{
    meta:
        description = "LayerZero Packet event"
        severity = "MEDIUM"
        category = "bridge"
        confidence = 95
    
    strings:
        // Common LayerZero event patterns
        $lz_send = "SendToChain"
        $lz_receive = "ReceiveFromChain"
        $lz_packet = "Packet("
        
    condition:
        any of them
}

// ============================================================================
// LIQUIDATION EVENTS
// ============================================================================

rule Event_LiquidationCall_AAVE
{
    meta:
        description = "AAVE LiquidationCall event"
        severity = "HIGH"
        category = "liquidation"
        topic0 = "0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be37335533e005286"
        confidence = 100
    
    strings:
        $topic0 = { e4 13 a3 21 e8 68 1d 83 1f 4d bc cb ca 79 0d 29 52 b5 6f 97 79 08 e4 5b e3 73 35 53 3e 00 52 86 }
        
    condition:
        $topic0
}

rule Event_Bite_MakerDAO
{
    meta:
        description = "MakerDAO Bite/Bark liquidation event"
        severity = "HIGH"
        category = "liquidation"
        topic0 = "0xa716da86bc1fb6d43d1493373f34d7a418b619681cd7b90f7ea667ba1489be28"
        confidence = 100
    
    strings:
        $topic0 = { a7 16 da 86 bc 1f b6 d4 3d 14 93 37 3f 34 d7 a4 18 b6 19 68 1c d7 b9 0f 7e a6 67 ba 14 89 be 28 }
        
    condition:
        $topic0
}

// ============================================================================
// DANGEROUS FUNCTION SELECTORS
// ============================================================================

rule Selector_Approve_Unlimited
{
    meta:
        description = "approve() function call (check for unlimited approval)"
        severity = "MEDIUM"
        category = "function_call"
        selector = "0x095ea7b3"
        confidence = 80
    
    strings:
        // approve(address,uint256)
        $selector = { 09 5e a7 b3 }
        // Unlimited approval value (max uint256)
        $unlimited = { ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff }
        
    condition:
        $selector and $unlimited
}

rule Selector_Transfer
{
    meta:
        description = "transfer() function call"
        severity = "LOW"
        category = "function_call"
        selector = "0xa9059cbb"
        confidence = 100
    
    strings:
        // transfer(address,uint256)
        $selector = { a9 05 9c bb }
        
    condition:
        $selector at 0
}

rule Selector_TransferFrom
{
    meta:
        description = "transferFrom() function call"
        severity = "LOW"
        category = "function_call"
        selector = "0x23b872dd"
        confidence = 100
    
    strings:
        // transferFrom(address,address,uint256)
        $selector = { 23 b8 72 dd }
        
    condition:
        $selector at 0
}

rule Selector_Withdraw_Common
{
    meta:
        description = "Common withdraw function calls"
        severity = "MEDIUM"
        category = "function_call"
        confidence = 90
    
    strings:
        // withdraw() - no params
        $withdraw1 = { 3c cf d6 0b }
        // withdraw(uint256)
        $withdraw2 = { 2e 1a 7d 4d }
        // withdraw(uint256,address)
        $withdraw3 = { 00 f7 14 ce }
        
    condition:
        any of them at 0
}

rule Selector_SelfDestruct_Pattern
{
    meta:
        description = "Potential selfdestruct trigger"
        severity = "CRITICAL"
        category = "function_call"
        confidence = 85
    
    strings:
        // Common selfdestruct wrapper function names hashed
        $destroy = { 83 19 75 35 }  // destroy()
        $kill = { 41 c0 e1 b5 }     // kill()
        $suicide = { ff }            // SELFDESTRUCT opcode
        
    condition:
        any of them
}

// ============================================================================
// MEV ATTACK PATTERNS
// ============================================================================

rule MEV_Sandwich_Transaction
{
    meta:
        description = "Potential sandwich attack transaction pattern"
        severity = "HIGH"
        category = "mev"
        confidence = 70
    
    strings:
        // Uniswap V2 Router swaps
        $swap_exact = { 38 ed 17 39 }  // swapExactTokensForTokens
        $swap_eth = { 7f f3 6a b5 }    // swapExactETHForTokens
        
        // Very high gas price indicator (in calldata context)
        $high_gas = /gasPrice.*[1-9]\d{11,}/  // > 100 gwei
        
    condition:
        any of ($swap*) and $high_gas
}

rule MEV_Flashbots_Bundle
{
    meta:
        description = "Flashbots bundle indicator"
        severity = "LOW"
        category = "mev"
        confidence = 60
    
    strings:
        $flashbots = "X-Flashbots-Signature"
        $bundle = "eth_sendBundle"
        $private = "eth_sendPrivateTransaction"
        
    condition:
        any of them
}

// ============================================================================
// KNOWN EXPLOIT SIGNATURES
// ============================================================================

rule Exploit_Ronin_Bridge
{
    meta:
        description = "Ronin Bridge exploit signature pattern"
        severity = "CRITICAL"
        category = "known_exploit"
        incident = "Ronin Bridge Hack - March 2022"
        loss = "$625M"
        confidence = 95
    
    strings:
        // Fake validator signature pattern
        $multi_sig_bypass = { 19 01 }  // EIP-712 prefix with manipulated domain
        $ronin_bridge = "0x8407dc57739bcda7aa53ca6f12f82f9d51c2f21e"
        
    condition:
        $multi_sig_bypass and $ronin_bridge
}

rule Exploit_Wormhole
{
    meta:
        description = "Wormhole exploit pattern (signature verification bypass)"
        severity = "CRITICAL"
        category = "known_exploit"
        incident = "Wormhole Hack - February 2022"
        loss = "$320M"
        confidence = 90
    
    strings:
        // Deprecated secp256k1 instruction ID
        $deprecated_verify = { 00 01 }  // Solana program instruction
        $wormhole_addr = "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth"
        
    condition:
        $deprecated_verify and $wormhole_addr
}

rule Exploit_Nomad_Bridge
{
    meta:
        description = "Nomad Bridge exploit pattern (zero-hash initialization)"
        severity = "CRITICAL"
        category = "known_exploit"
        incident = "Nomad Bridge Hack - August 2022"
        loss = "$190M"
        confidence = 90
    
    strings:
        // Zero hash that bypassed merkle proof
        $zero_root = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $process = "process("
        
    condition:
        $zero_root and $process
}

rule Exploit_Euler_Finance
{
    meta:
        description = "Euler Finance exploit pattern (donation attack)"
        severity = "CRITICAL"
        category = "known_exploit"
        incident = "Euler Finance Hack - March 2023"
        loss = "$197M"
        confidence = 85
    
    strings:
        // donateToReserves exploitation
        $donate = "donateToReserves"
        $etoken = "EToken"
        $dtoken = "DToken"
        $liquidation = "liquidate"
        
    condition:
        $donate and ($etoken or $dtoken) and $liquidation
}

// ============================================================================
// ORACLE MANIPULATION SIGNATURES
// ============================================================================

rule Oracle_Chainlink_Stale
{
    meta:
        description = "Chainlink oracle without staleness check"
        severity = "HIGH"
        category = "oracle"
        confidence = 75
    
    strings:
        // latestRoundData selector
        $latest_round = { fe af 96 8c }
        $latest_round_call = "latestRoundData"
        $answer = "answer"
        
        // Staleness check patterns (presence = safe)
        $has_updated = "updatedAt"
        $has_timestamp_check = "block.timestamp"
        
    condition:
        ($latest_round or $latest_round_call) and $answer and not ($has_updated or $has_timestamp_check)
}

rule Oracle_UniswapV3_TWAP_Short
{
    meta:
        description = "Uniswap V3 TWAP with dangerously short period"
        severity = "HIGH"
        category = "oracle"
        confidence = 70
    
    strings:
        // observe() selector
        $observe = { 88 3b db fd }
        // Very short TWAP window (< 10 minutes = 600 seconds)
        $short_window = /secondsAgo.*[<]\s*(60|120|300|600)\s*[,\]]/
        
    condition:
        $observe and $short_window
}
