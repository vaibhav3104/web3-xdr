"""
Historical Attack Database
Contains all known bridge and DeFi exploits for training
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum

class AttackType(Enum):
    # Bridge Attacks
    SIGNATURE_FORGERY = "signature_forgery"
    VALIDATOR_COMPROMISE = "validator_compromise"
    MESSAGE_REPLAY = "message_replay"
    ADMIN_KEY_THEFT = "admin_key_theft"
    PROOF_FORGERY = "proof_forgery"
    MINT_WITHOUT_LOCK = "mint_without_lock"
    
    # DeFi Attacks
    FLASH_LOAN = "flash_loan"
    REENTRANCY = "reentrancy"
    ORACLE_MANIPULATION = "oracle_manipulation"
    GOVERNANCE_ATTACK = "governance_attack"
    PRICE_MANIPULATION = "price_manipulation"
    SANDWICH_ATTACK = "sandwich_attack"
    LIQUIDATION_CASCADE = "liquidation_cascade"
    
    # Generic
    RUG_PULL = "rug_pull"
    HONEYPOT = "honeypot"
    ACCESS_CONTROL = "access_control"

class ProtocolType(Enum):
    BRIDGE = "bridge"
    DEX = "dex"
    LENDING = "lending"
    STAKING = "staking"
    YIELD = "yield"
    DERIVATIVES = "derivatives"
    OTHER = "other"

@dataclass
class HistoricalAttack:
    """Represents a historical attack for training"""
    id: str
    name: str
    date: datetime
    chain: str
    chains_involved: List[str]
    protocol: str
    protocol_type: ProtocolType
    attack_type: AttackType
    loss_usd: float
    attacker_address: str
    exploit_contract: Optional[str]
    victim_contract: str
    tx_hashes: List[str]
    description: str
    technique_details: str
    
# ============================================================================
# HISTORICAL ATTACK DATABASE
# Source: rekt.news, DeFiLlama, security reports
# ============================================================================

HISTORICAL_ATTACKS: List[Dict] = [
    # ==========================================================================
    # BRIDGE ATTACKS
    # ==========================================================================
    {
        "id": "ronin_bridge_2022",
        "name": "Ronin Bridge Hack",
        "date": "2022-03-23",
        "chain": "ethereum",
        "chains_involved": ["ethereum", "ronin"],
        "protocol": "Ronin Bridge",
        "protocol_type": "bridge",
        "attack_type": "validator_compromise",
        "loss_usd": 625_000_000,
        "attacker_address": "0x098B716B8Aaf21512996dC57EB0615e2383E2f96",
        "exploit_contract": None,  # No exploit contract, key compromise
        "victim_contract": "0x8407dc57739bcda7aa53ca6f12f82f9d51c2f21e",
        "tx_hashes": [
            "0xc28fad5e8d5e0ce6a2eaf67b6687be5d58113e16be590824d6cfa1a94467d0b7",
            "0xed2c72ef1a552ddaec6dd1f5cddf0b59a8f37f82bdda5257d9c7c37db7bb9b08"
        ],
        "description": "Attacker compromised 5 of 9 validator keys to forge withdrawals",
        "technique_details": """
        1. Social engineering to obtain private keys
        2. Compromised 5 validators (out of 9 required)
        3. Forged withdrawal signatures
        4. Drained 173,600 ETH + 25.5M USDC
        """
    },
    {
        "id": "wormhole_2022",
        "name": "Wormhole Bridge Hack",
        "date": "2022-02-02",
        "chain": "solana",
        "chains_involved": ["ethereum", "solana"],
        "protocol": "Wormhole",
        "protocol_type": "bridge",
        "attack_type": "signature_forgery",
        "loss_usd": 320_000_000,
        "attacker_address": "CxegPrfn2ge5dNiQberUrQJkHCcimeR4VXkeawcFBBka",
        "exploit_contract": None,
        "victim_contract": "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth",
        "tx_hashes": [
            "2zCz2GgSoSS68eNJENWrYB48dMM1zmH8SZkgYneVDv2G4gRsVfwu5rNXtK5BKFxn7fSqX9BvrBc1rdPAeBEcD6Es"
        ],
        "description": "Exploited signature verification bug to mint 120,000 wETH without deposit",
        "technique_details": """
        1. Found bug in Solana's secp256k1 signature verification
        2. Crafted malicious SignatureSet account
        3. Called complete_wrapped without valid VAA
        4. Minted 120,000 wETH on Solana without ETH lock on Ethereum
        """
    },
    {
        "id": "nomad_2022",
        "name": "Nomad Bridge Hack",
        "date": "2022-08-01",
        "chain": "ethereum",
        "chains_involved": ["ethereum", "moonbeam", "evmos"],
        "protocol": "Nomad",
        "protocol_type": "bridge",
        "attack_type": "message_replay",
        "loss_usd": 190_000_000,
        "attacker_address": "0x56D8B635A7C88Fd1104D23d632AF40c1C3Aac4e3",
        "exploit_contract": None,
        "victim_contract": "0x88A69B4E698A4B090DF6CF5Bd7B2D47325Ad30A3",
        "tx_hashes": [
            "0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460"
        ],
        "description": "Initialization bug allowed anyone to pass message validation",
        "technique_details": """
        1. Routine upgrade initialized committedRoot to zero
        2. Any message with zero proof passed validation
        3. Attackers could replay any previous valid message
        4. Massive copycat attack - hundreds of addresses drained funds
        """
    },
    {
        "id": "bnb_bridge_2022",
        "name": "BNB Bridge Hack",
        "date": "2022-10-06",
        "chain": "bnb",
        "chains_involved": ["bnb"],
        "protocol": "BNB Bridge",
        "protocol_type": "bridge",
        "attack_type": "proof_forgery",
        "loss_usd": 570_000_000,
        "attacker_address": "0x489a8756c18c0b8b24ec2a2b9ff3d4d447f79bec",
        "exploit_contract": None,
        "victim_contract": "0x0000000000000000000000000000000000001004",
        "tx_hashes": [
            "0xebf83628ba893d35b496121fb8201666b8e09f3cbadf0e269162baa72efe3b8b"
        ],
        "description": "Forged IAVL proof to mint 2M BNB",
        "technique_details": """
        1. Exploited vulnerability in IAVL proof verification
        2. Created valid-looking proof for non-existent deposit
        3. Minted 2M BNB (~$570M)
        4. Chain halted to prevent further damage
        """
    },
    {
        "id": "harmony_2022",
        "name": "Harmony Horizon Bridge",
        "date": "2022-06-23",
        "chain": "ethereum",
        "chains_involved": ["ethereum", "harmony"],
        "protocol": "Horizon Bridge",
        "protocol_type": "bridge",
        "attack_type": "validator_compromise",
        "loss_usd": 100_000_000,
        "attacker_address": "0x0d043128146654c7683fbf30ac98d7b2285ded00",
        "exploit_contract": None,
        "victim_contract": "0xf9fb1c508ff49f78b60d3A96dea99Fa5d7F3A8A6",
        "tx_hashes": [],
        "description": "Compromised 2 of 5 multisig keys",
        "technique_details": """
        1. Social engineering/hack to obtain 2 private keys
        2. 2-of-5 multisig was insufficient security
        3. Drained ETH, USDC, WBTC, others
        """
    },
    {
        "id": "multichain_2023",
        "name": "Multichain Hack",
        "date": "2023-07-06",
        "chain": "ethereum",
        "chains_involved": ["ethereum", "fantom", "moonriver"],
        "protocol": "Multichain",
        "protocol_type": "bridge",
        "attack_type": "admin_key_theft",
        "loss_usd": 130_000_000,
        "attacker_address": "0x027F1571ACA57354223c872366f1B2e67ee6F7F8",
        "exploit_contract": None,
        "victim_contract": "0xC564EE9f21Ed8A2d8E7e76c085740d5e4c5FaFbE",
        "tx_hashes": [],
        "description": "CEO arrested, admin keys compromised",
        "technique_details": """
        1. Multichain CEO arrested in China
        2. Admin/MPC keys seized or compromised
        3. Unauthorized withdrawals from bridge
        4. Project effectively dead
        """
    },
    {
        "id": "poly_network_2021",
        "name": "Poly Network Hack",
        "date": "2021-08-10",
        "chain": "ethereum",
        "chains_involved": ["ethereum", "bsc", "polygon"],
        "protocol": "Poly Network",
        "protocol_type": "bridge",
        "attack_type": "access_control",
        "loss_usd": 610_000_000,
        "attacker_address": "0xC8a65Fadf0e0dDAf421F28FEAb69Bf6E2E589963",
        "exploit_contract": None,
        "victim_contract": "0x250e76987d838a75310c34bf422ea9f1AC4Cc906",
        "tx_hashes": [],
        "description": "Exploited cross-chain message to change keeper",
        "technique_details": """
        1. Found way to craft cross-chain message
        2. Changed keeper address to attacker-controlled
        3. Drained funds across 3 chains
        4. Attacker returned funds (white hat claim)
        """
    },

    # ==========================================================================
    # DEFI ATTACKS
    # ==========================================================================
    {
        "id": "euler_2023",
        "name": "Euler Finance Hack",
        "date": "2023-03-13",
        "chain": "ethereum",
        "chains_involved": ["ethereum"],
        "protocol": "Euler Finance",
        "protocol_type": "lending",
        "attack_type": "flash_loan",
        "loss_usd": 197_000_000,
        "attacker_address": "0xb66cd966670d962C227B3EABA30a872DbFb995db",
        "exploit_contract": "0xeBC29199C817Dc47BA12E3F86102564D640CBf99",
        "victim_contract": "0x27182842E098f60e3D576794A5bFFb0777E025d3",
        "tx_hashes": [
            "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d"
        ],
        "description": "Donation attack via donateToReserves function",
        "technique_details": """
        1. Flash loan large amount of DAI
        2. Deposit to Euler, get eDAI
        3. Self-liquidate at profit using donateToReserves bug
        4. Repeat with leverage
        5. Drain reserves
        """
    },
    {
        "id": "mango_2022",
        "name": "Mango Markets Exploit",
        "date": "2022-10-11",
        "chain": "solana",
        "chains_involved": ["solana"],
        "protocol": "Mango Markets",
        "protocol_type": "derivatives",
        "attack_type": "oracle_manipulation",
        "loss_usd": 114_000_000,
        "attacker_address": "CQvd1KNvfW8oKjsrcwqkgfFdrjMQGrzJ7BxPAsTuwWzZ",
        "exploit_contract": None,
        "victim_contract": "mv3ekLzLbnVPNxjSKvqBpU3ZeZXPQdEC3bp5MDEBG68",
        "tx_hashes": [],
        "description": "Manipulated MNGO perp price to drain treasury",
        "technique_details": """
        1. Opened large MNGO-PERP position
        2. Pumped MNGO spot price on illiquid markets
        3. Oracle reported inflated price
        4. Borrowed against inflated collateral
        5. Drained lending pools
        """
    },
    {
        "id": "beanstalk_2022",
        "name": "Beanstalk Governance Attack",
        "date": "2022-04-17",
        "chain": "ethereum",
        "chains_involved": ["ethereum"],
        "protocol": "Beanstalk",
        "protocol_type": "staking",
        "attack_type": "governance_attack",
        "loss_usd": 182_000_000,
        "attacker_address": "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4",
        "exploit_contract": "0x79224bC0bf70EC34F0ef56ed8251619499a59dEf",
        "victim_contract": "0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5",
        "tx_hashes": [
            "0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7"
        ],
        "description": "Flash loan to pass malicious governance proposal instantly",
        "technique_details": """
        1. Flash loan massive amount
        2. Deposit to get governance tokens
        3. Propose + vote + execute malicious proposal in same TX
        4. Proposal drained all funds to attacker
        """
    },
    {
        "id": "cream_2021",
        "name": "Cream Finance Hack",
        "date": "2021-10-27",
        "chain": "ethereum",
        "chains_involved": ["ethereum"],
        "protocol": "Cream Finance",
        "protocol_type": "lending",
        "attack_type": "flash_loan",
        "loss_usd": 130_000_000,
        "attacker_address": "0x24354D31bC9D90F62FE5f2454709C32049cf866b",
        "exploit_contract": "0x961D2B694D9097f35cfFFa363ef98823928a330D",
        "victim_contract": "0x44fbeBd2F576670a6C33f6Fc0B00aA8c5753b322",
        "tx_hashes": [
            "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92"
        ],
        "description": "Price oracle manipulation via flash loan",
        "technique_details": """
        1. Flash loan to manipulate yUSD price
        2. Mint crYUSD at inflated rate
        3. Borrow other assets against crYUSD
        4. Repeat to drain pools
        """
    },
    {
        "id": "curve_2023",
        "name": "Curve Vyper Reentrancy",
        "date": "2023-07-30",
        "chain": "ethereum",
        "chains_involved": ["ethereum"],
        "protocol": "Curve Finance",
        "protocol_type": "dex",
        "attack_type": "reentrancy",
        "loss_usd": 70_000_000,
        "attacker_address": "0xdce5d6b41c32f578f875efffc0d422c57a75d7d8",
        "exploit_contract": "0x466b85b49ec0c5c1eb402d5ea3c4b88864ea0f04",
        "victim_contract": "0x6A8cbed756804B16E05E741eDaBd5cB544AE21bf",
        "tx_hashes": [
            "0xa84aa065ce61dbb1eb50ab6ae67fc31a9da50dd2c74eefd561661bfce2f1620c"
        ],
        "description": "Vyper compiler bug caused reentrancy in multiple pools",
        "technique_details": """
        1. Vyper 0.2.15-0.3.0 had reentrancy guard bug
        2. remove_liquidity could be reentered
        3. Multiple pools affected (pETH, msETH, alETH)
        4. Drained via repeated withdraw
        """
    },
    {
        "id": "penpie_2024",
        "name": "Penpie Exploit",
        "date": "2024-09-03",
        "chain": "ethereum",
        "chains_involved": ["ethereum", "arbitrum"],
        "protocol": "Penpie",
        "protocol_type": "yield",
        "attack_type": "reentrancy",
        "loss_usd": 28_000_000,
        "attacker_address": "0x7a2f4d625fb21f5e51562ce8dc2e722e12a61d1b",
        "exploit_contract": "0xcde2cd6aeaaf0238f4ce33295be13704e4a97de2",
        "victim_contract": "0x6DB96BBEB081d2a85E0954C252f2c1dC108b3f81",
        "tx_hashes": [],
        "description": "Reentrancy in reward claiming with flash loan",
        "technique_details": """
        1. Flash loan from Balancer
        2. Deposit into Penpie
        3. Exploit reentrancy in claimRewards
        4. Claim rewards multiple times
        5. Repay flash loan, keep profit
        """
    },
    {
        "id": "kyberswap_2023",
        "name": "KyberSwap Exploit",
        "date": "2023-11-22",
        "chain": "ethereum",
        "chains_involved": ["ethereum", "arbitrum", "optimism", "polygon", "base"],
        "protocol": "KyberSwap",
        "protocol_type": "dex",
        "attack_type": "price_manipulation",
        "loss_usd": 48_000_000,
        "attacker_address": "0x50275E0B7261559cE1644014d4b78D4AA63BE836",
        "exploit_contract": "0xaf2acf3d4ab78e4c702256d214a3189a874cdc13",
        "victim_contract": "0x2B1c7b41f6A8F2b2bc45C3233a5d5FB3cD6dC9A8",
        "tx_hashes": [],
        "description": "Tick manipulation in concentrated liquidity",
        "technique_details": """
        1. Manipulate pool to specific tick boundaries
        2. Exploit rounding in tick math
        3. Extract value through repeated swaps
        4. Affected multiple chains simultaneously
        """
    },
]

def get_all_attacks() -> List[Dict]:
    """Return all historical attacks"""
    return HISTORICAL_ATTACKS

def get_attacks_by_type(attack_type: AttackType) -> List[Dict]:
    """Filter attacks by type"""
    return [a for a in HISTORICAL_ATTACKS if a["attack_type"] == attack_type.value]

def get_attacks_by_protocol_type(protocol_type: ProtocolType) -> List[Dict]:
    """Filter attacks by protocol type"""
    return [a for a in HISTORICAL_ATTACKS if a["protocol_type"] == protocol_type.value]

def get_bridge_attacks() -> List[Dict]:
    """Get all bridge attacks"""
    return [a for a in HISTORICAL_ATTACKS if a["protocol_type"] == "bridge"]

def get_defi_attacks() -> List[Dict]:
    """Get all DeFi attacks"""
    return [a for a in HISTORICAL_ATTACKS if a["protocol_type"] != "bridge"]

def get_attack_contracts() -> List[str]:
    """Get all known exploit contract addresses"""
    return [a["exploit_contract"] for a in HISTORICAL_ATTACKS if a["exploit_contract"]]

def get_attacker_addresses() -> List[str]:
    """Get all known attacker addresses"""
    return [a["attacker_address"] for a in HISTORICAL_ATTACKS]

# Statistics
def get_statistics() -> Dict:
    """Get attack statistics"""
    total_loss = sum(a["loss_usd"] for a in HISTORICAL_ATTACKS)
    bridge_loss = sum(a["loss_usd"] for a in get_bridge_attacks())
    defi_loss = sum(a["loss_usd"] for a in get_defi_attacks())
    
    return {
        "total_attacks": len(HISTORICAL_ATTACKS),
        "total_loss_usd": total_loss,
        "bridge_attacks": len(get_bridge_attacks()),
        "bridge_loss_usd": bridge_loss,
        "defi_attacks": len(get_defi_attacks()),
        "defi_loss_usd": defi_loss,
        "average_loss_usd": total_loss / len(HISTORICAL_ATTACKS),
        "attack_types": list(set(a["attack_type"] for a in HISTORICAL_ATTACKS)),
    }

if __name__ == "__main__":
    stats = get_statistics()
    print("=" * 60)
    print("HISTORICAL ATTACK DATABASE STATISTICS")
    print("=" * 60)
    print(f"Total Attacks:     {stats['total_attacks']}")
    print(f"Total Loss:        ${stats['total_loss_usd']:,.0f}")
    print(f"Bridge Attacks:    {stats['bridge_attacks']} (${stats['bridge_loss_usd']:,.0f})")
    print(f"DeFi Attacks:      {stats['defi_attacks']} (${stats['defi_loss_usd']:,.0f})")
    print(f"Average Loss:      ${stats['average_loss_usd']:,.0f}")
    print(f"Attack Types:      {len(stats['attack_types'])}")
    print("=" * 60)
