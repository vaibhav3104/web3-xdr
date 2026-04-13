"""
Real Bytecode Collector
Fetches actual contract bytecode from blockchain for ML training
"""

import os
import json
import asyncio
import aiohttp
from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)

# =============================================================================
# KNOWN CONTRACT ADDRESSES
# =============================================================================

# Exploit contracts (malicious - used in actual attacks)
EXPLOIT_CONTRACTS = {
    "ethereum": [
        # Euler Finance Exploiter
        {"address": "0xeBC29199C817Dc47BA12E3F86102564D640CBf99", "label": "flash_loan_exploit", "attack": "Euler Finance"},
        # Beanstalk Exploiter
        {"address": "0x79224bC0bf70EC34F0ef56ed8251619499a59dEf", "label": "governance_attack", "attack": "Beanstalk"},
        # Cream Finance Exploiter
        {"address": "0x961D2B694D9097f35cfFFa363ef98823928a330D", "label": "flash_loan_exploit", "attack": "Cream Finance"},
        # Curve Vyper Exploiter
        {"address": "0x466b85b49ec0c5c1eb402d5ea3c4b88864ea0f04", "label": "reentrancy_exploit", "attack": "Curve Vyper"},
        # Penpie Exploiter
        {"address": "0xcde2cd6aeaaf0238f4ce33295be13704e4a97de2", "label": "reentrancy_exploit", "attack": "Penpie"},
        # KyberSwap Exploiter
        {"address": "0xaf2acf3d4ab78e4c702256d214a3189a874cdc13", "label": "price_manipulation", "attack": "KyberSwap"},
        # Nomad Bridge Exploiter
        {"address": "0x56D8B635A7C88Fd1104D23d632AF40c1C3Aac4e3", "label": "bridge_exploit", "attack": "Nomad"},
        # Wintermute Exploiter (Profanity vulnerability)
        {"address": "0xe74b28c2eAe8679e3cCc3a94d5d0dE83CCB84705", "label": "unknown_threat", "attack": "Wintermute"},
        # Transit Swap Exploiter
        {"address": "0x75f2aba6a44580d7be2c4e42885d4a1917bffd46", "label": "flash_loan_exploit", "attack": "Transit Swap"},
        # Harvest Finance Exploiter
        {"address": "0xf224ab004461540778a914ea397c589b677e27bb", "label": "oracle_manipulation", "attack": "Harvest Finance"},
        # Alpha Homora Exploiter
        {"address": "0x905315602ed9a854e325f692ff82f58799beab57", "label": "flash_loan_exploit", "attack": "Alpha Homora"},
        # Rari Capital Exploiter (Reentrancy)
        {"address": "0x32075bad9050d4767018084f0cb87b3182d36c45", "label": "reentrancy_exploit", "attack": "Rari Capital"},
        # BadgerDAO Exploiter
        {"address": "0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107", "label": "unknown_threat", "attack": "BadgerDAO"},
        # Saddle Finance Exploiter
        {"address": "0x63341ba917de90498f3903b199df5699b4a55ac0", "label": "flash_loan_exploit", "attack": "Saddle Finance"},
        # Inverse Finance Exploiter
        {"address": "0x2d02fefb43be42f95cdc25c736e3ac3e4d8f25e8", "label": "oracle_manipulation", "attack": "Inverse Finance"},
        # Platypus Finance Exploiter
        {"address": "0x1279cb35fb9370e5143aff8814af1b7dce38859f", "label": "flash_loan_exploit", "attack": "Platypus Finance"},
        # Warp Finance Exploiter
        {"address": "0x8d4aeb80e0b4082c3eb2d414b249f0c8a781c7ae", "label": "flash_loan_exploit", "attack": "Warp Finance"},
        # Pickle Finance Exploiter (Evil Jar)
        {"address": "0xf1D82e6EeD782EFA1D8fa0aCfaA8e280A5430D50", "label": "flash_loan_exploit", "attack": "Pickle Finance"},
        # Value DeFi Exploiter
        {"address": "0x5b3055BdA7b13e8dbF9bD7Ce7F5025c453FF2127", "label": "flash_loan_exploit", "attack": "Value DeFi"},
        # Indexed Finance Exploiter
        {"address": "0xba5ed099633d3B313e4D5F7bdc1305d3c431C4AF", "label": "price_manipulation", "attack": "Indexed Finance"},
        # Visor Finance Exploiter
        {"address": "0x10C509AA9ab291C76c45414e7CdBd375e1D5AcE8", "label": "reentrancy_exploit", "attack": "Visor Finance"},
        # Eminence Finance Exploiter
        {"address": "0x223034edbe95823c1160c16f26e3000315171cc9", "label": "flash_loan_exploit", "attack": "Eminence Finance"},
        # Cheese Bank Exploiter
        {"address": "0x2eDe22e7a08F0A41A685A3CF40e2259137699879", "label": "oracle_manipulation", "attack": "Cheese Bank"},
        # bZx Exploiter (Attack Contract 2)
        {"address": "0xb8c6ad5a72efdd04a86e6B1d0f30fa3c74B9b325", "label": "flash_loan_exploit", "attack": "bZx Protocol"},
        # Poly Network Exploiter
        {"address": "0xC8a65Fadf0e0dDAf421F28FEAb69Bf6E2E589963", "label": "bridge_exploit", "attack": "Poly Network"},
        # Ronin Bridge Exploiter
        {"address": "0x098B716B8Aaf21512996dC57EB0615e2383E2f96", "label": "bridge_exploit", "attack": "Ronin Bridge"},
        # Harmony Horizon Exploiter
        {"address": "0x0d043128146654C7683FBf30ac98D7B2285DeD00", "label": "bridge_exploit", "attack": "Harmony Horizon"},
    ],
    "arbitrum": [
        # Penpie Arbitrum Exploiter
        {"address": "0x7a2f4d625fb21f5e51562ce8dc2e722e12a61d1b", "label": "reentrancy_exploit", "attack": "Penpie Arbitrum"},
        # Radiant Capital Exploiter
        {"address": "0x826d5f4d6293f8b4931c7f5f71e19d3b85e71bd3", "label": "flash_loan_exploit", "attack": "Radiant Capital"},
    ],
    "bsc": [
        # Venus Protocol Exploiter
        {"address": "0x489A8756C18C0b8B24EC2a2b9FF3D4d447F79BEc", "label": "oracle_manipulation", "attack": "Venus Protocol"},
        # PancakeBunny Exploiter
        {"address": "0xa0acc61547f6bd066f7c9663c17a312b6ad7e187", "label": "flash_loan_exploit", "attack": "PancakeBunny"},
        # Uranium Finance Exploiter
        {"address": "0x2b528a28451e9853f51616f3b0f6d82af8bea6ae", "label": "flash_loan_exploit", "attack": "Uranium Finance"},
    ],
    "polygon": [
        # QiDAO Exploiter
        {"address": "0x118203b0f2a3ef9e749d871c8fef5e5e55ef5c91", "label": "flash_loan_exploit", "attack": "QiDAO"},
    ],
    "optimism": [
        {"address": "0x4f3a120E72C76c22ae802D129F599BFDbc31cb81", "label": "reentrancy_exploit", "attack": "Exactly Protocol"},
    ],
    "avalanche": [
        {"address": "0x67afdd6489d40a01dae65f709367e1b1d18a5322", "label": "flash_loan_exploit", "attack": "Platypus Finance AVAX"},
        {"address": "0xB0f8e42F44Ea221bf1e49ee4e4828F1e0f52F6F5", "label": "flash_loan_exploit", "attack": "Nereus Finance"},
    ],
}

# Safe contracts (verified, audited protocols)
SAFE_CONTRACTS = {
    "ethereum": [
        # OpenZeppelin Contracts
        {"address": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "label": "safe", "protocol": "Uniswap UNI Token"},
        {"address": "0x514910771AF9Ca656af840dff83E8264EcF986CA", "label": "safe", "protocol": "Chainlink LINK"},
        {"address": "0x6B175474E89094C44Da98b954EescdeCB5B899AF", "label": "safe", "protocol": "MakerDAO DAI"},
        {"address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "label": "safe", "protocol": "Circle USDC"},
        {"address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "label": "safe", "protocol": "Tether USDT"},
        
        # Uniswap V3 Contracts
        {"address": "0x1F98431c8aD98523631AE4a59f267346ea31F984", "label": "safe", "protocol": "Uniswap V3 Factory"},
        {"address": "0xE592427A0AEce92De3Edee1F18E0157C05861564", "label": "safe", "protocol": "Uniswap V3 Router"},
        {"address": "0xC36442b4a4522E871399CD717aBDD847Ab11FE88", "label": "safe", "protocol": "Uniswap V3 Positions NFT"},
        
        # Aave V3 Contracts
        {"address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "label": "safe", "protocol": "Aave V3 Pool"},
        {"address": "0x64b761D848206f447Fe2dd461b0c635Ec39EbB27", "label": "safe", "protocol": "Aave V3 Pool Configurator"},
        
        # Compound V3
        {"address": "0xc3d688B66703497DAA19211EEdff47f25384cdc3", "label": "safe", "protocol": "Compound V3 USDC"},
        
        # Lido
        {"address": "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "label": "safe", "protocol": "Lido stETH"},
        {"address": "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0", "label": "safe", "protocol": "Lido wstETH"},
        
        # Curve Finance
        {"address": "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", "label": "safe", "protocol": "Curve 3Pool"},
        {"address": "0xD51a44d3FaE010294C616388b506AcdA1bfAAE46", "label": "safe", "protocol": "Curve Tricrypto2"},
        
        # Balancer
        {"address": "0xBA12222222228d8Ba445958a75a0704d566BF2C8", "label": "safe", "protocol": "Balancer Vault"},
        
        # 1inch
        {"address": "0x1111111254EEB25477B68fb85Ed929f73A960582", "label": "safe", "protocol": "1inch Router V5"},
        
        # ENS
        {"address": "0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85", "label": "safe", "protocol": "ENS Base Registrar"},
        
        # OpenSea Seaport
        {"address": "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC", "label": "safe", "protocol": "OpenSea Seaport"},
        
        # Gnosis Safe
        {"address": "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552", "label": "safe", "protocol": "Gnosis Safe Singleton"},
        
        # Bridge Contracts (Safe)
        {"address": "0x3ee18B2214AFF97000D974cf647E7C347E8fa585", "label": "safe", "protocol": "Wormhole Token Bridge"},
        {"address": "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1", "label": "safe", "protocol": "Optimism Gateway"},
        {"address": "0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f", "label": "safe", "protocol": "Arbitrum Inbox"},
        # EigenLayer
        {"address": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A", "label": "safe", "protocol": "EigenLayer StrategyManager"},
        # Morpho
        {"address": "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb", "label": "safe", "protocol": "Morpho"},
        # Pendle
        {"address": "0x0000000001E4ef00d069e71d6bA041b0A16F7eA0", "label": "safe", "protocol": "Pendle Router V4"},
        # Ethena
        {"address": "0x4c9EDD5852cd905f086C759E8383e09bFF1E68B3", "label": "safe", "protocol": "Ethena USDe"},
        # Rocket Pool
        {"address": "0xae78736Cd615f374D3085123A210448E74Fc6393", "label": "safe", "protocol": "Rocket Pool rETH"},
        # Convex
        {"address": "0xF403C135812408BFbE8713b5A23a04b3D48AAE31", "label": "safe", "protocol": "Convex Booster"},
    ],
    "arbitrum": [
        {"address": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "label": "safe", "protocol": "WETH"},
        {"address": "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8", "label": "safe", "protocol": "USDC.e"},
        {"address": "0x912CE59144191C1204E64559FE8253a0e49E6548", "label": "safe", "protocol": "ARB Token"},
        {"address": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", "label": "safe", "protocol": "USDT"},
    ],
    "polygon": [
        {"address": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", "label": "safe", "protocol": "WMATIC"},
        {"address": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "label": "safe", "protocol": "USDC.e"},
        {"address": "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", "label": "safe", "protocol": "WETH"},
    ],
    "bsc": [
        {"address": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "label": "safe", "protocol": "WBNB"},
        {"address": "0x55d398326f99059fF775485246999027B3197955", "label": "safe", "protocol": "BSC-USD"},
        {"address": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", "label": "safe", "protocol": "BUSD"},
    ],
    "optimism": [
        {"address": "0x4200000000000000000000000000000000000006", "label": "safe", "protocol": "WETH"},
        {"address": "0x4200000000000000000000000000000000000042", "label": "safe", "protocol": "OP Token"},
        {"address": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "label": "safe", "protocol": "USDC"},
    ],
    "avalanche": [
        {"address": "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7", "label": "safe", "protocol": "WAVAX"},
        {"address": "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", "label": "safe", "protocol": "USDC"},
    ],
}

# Honeypot/Rug Pull contracts (known scams)
SCAM_CONTRACTS = {
    "ethereum": [
        {"address": "0x6b4c7a5e3f0b99fcd83e9c089bddd6c7fce5c611", "label": "honeypot", "scam": "Known Honeypot"},
        {"address": "0x30f7a0c13b2e1c7a72f7ddb72bd9de4e56f99acd", "label": "rug_pull", "scam": "Squid Game Token"},
        {"address": "0x59068075A799594db03C0255eDd68CbC6c8af4e1", "label": "rug_pull", "scam": "AnubisDAO"},
    ],
    "bsc": [
        {"address": "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82", "label": "honeypot", "scam": "Known BSC Honeypot"},
    ]
}

@dataclass
class CollectedContract:
    """Represents a collected contract with bytecode"""
    address: str
    chain: str
    bytecode: str
    label: str
    source: str  # exploit, safe, scam
    metadata: Dict
    collected_at: str
    bytecode_hash: str
    bytecode_length: int


class BytecodeCollector:
    """
    Collects real bytecode from blockchain for ML training
    """
    
    # RPC endpoints (using public endpoints - for production use Infura/Alchemy)
    RPC_ENDPOINTS = {
        "ethereum": os.getenv("ETH_RPC_URL", "https://eth.llamarpc.com"),
        "arbitrum": os.getenv("ARB_RPC_URL", "https://arb1.arbitrum.io/rpc"),
        "polygon": os.getenv("POLYGON_RPC_URL", "https://polygon-rpc.com"),
        "bsc": os.getenv("BSC_RPC_URL", "https://bsc-dataseed.binance.org"),
        "optimism": os.getenv("OP_RPC_URL", "https://mainnet.optimism.io"),
        "base": os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
        "avalanche": os.getenv("AVAX_RPC_URL", "https://api.avax.network/ext/bc/C/rpc"),
    }
    
    def __init__(self, output_dir: str = "./data/bytecode"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.collected: List[CollectedContract] = []
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Stats
        self.stats = {
            "total_collected": 0,
            "exploits": 0,
            "safe": 0,
            "scams": 0,
            "failed": 0,
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_bytecode(self, address: str, chain: str) -> Optional[str]:
        """Fetch bytecode from blockchain via RPC"""
        rpc_url = self.RPC_ENDPOINTS.get(chain)
        if not rpc_url:
            logger.warning("no_rpc_endpoint", chain=chain)
            return None
        
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": [address, "latest"],
                "id": 1
            }
            
            async with self.session.post(
                rpc_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    bytecode = data.get("result", "0x")
                    
                    # Check if contract exists
                    if bytecode == "0x" or len(bytecode) < 10:
                        logger.warning("empty_bytecode", address=address, chain=chain)
                        return None
                    
                    return bytecode
                else:
                    logger.error("rpc_error", status=response.status, chain=chain)
                    return None
                    
        except Exception as e:
            logger.error("bytecode_fetch_error", address=address, chain=chain, error=str(e))
            return None
    
    async def collect_contract(
        self,
        address: str,
        chain: str,
        label: str,
        source: str,
        metadata: Dict = None
    ) -> Optional[CollectedContract]:
        """Collect a single contract's bytecode"""
        
        bytecode = await self.get_bytecode(address, chain)
        if not bytecode:
            self.stats["failed"] += 1
            return None
        
        # Calculate hash for deduplication
        import hashlib
        bytecode_hash = hashlib.sha256(bytecode.encode()).hexdigest()[:16]
        
        contract = CollectedContract(
            address=address.lower(),
            chain=chain,
            bytecode=bytecode,
            label=label,
            source=source,
            metadata=metadata or {},
            collected_at=datetime.now(timezone.utc).isoformat(),
            bytecode_hash=bytecode_hash,
            bytecode_length=len(bytecode)
        )
        
        self.collected.append(contract)
        self.stats["total_collected"] += 1
        self.stats[source] = self.stats.get(source, 0) + 1
        
        logger.info(
            "contract_collected",
            address=address[:10] + "...",
            chain=chain,
            label=label,
            bytecode_length=len(bytecode)
        )
        
        return contract
    
    async def collect_all_known_contracts(self) -> int:
        """Collect bytecode from all known contracts"""
        
        print("🔍 Collecting real bytecode from blockchain...")
        print("=" * 60)
        
        # Collect exploit contracts
        print("\n🔴 Collecting EXPLOIT contracts...")
        for chain, contracts in EXPLOIT_CONTRACTS.items():
            for contract in contracts:
                await self.collect_contract(
                    address=contract["address"],
                    chain=chain,
                    label=contract["label"],
                    source="exploits",
                    metadata={"attack": contract.get("attack", "Unknown")}
                )
                await asyncio.sleep(0.5)  # Rate limiting
        
        # Collect safe contracts
        print("\n🟢 Collecting SAFE contracts...")
        for chain, contracts in SAFE_CONTRACTS.items():
            for contract in contracts:
                await self.collect_contract(
                    address=contract["address"],
                    chain=chain,
                    label=contract["label"],
                    source="safe",
                    metadata={"protocol": contract.get("protocol", "Unknown")}
                )
                await asyncio.sleep(0.5)
        
        # Collect scam contracts
        print("\n🟡 Collecting SCAM contracts...")
        for chain, contracts in SCAM_CONTRACTS.items():
            for contract in contracts:
                await self.collect_contract(
                    address=contract["address"],
                    chain=chain,
                    label=contract["label"],
                    source="scams",
                    metadata={"scam": contract.get("scam", "Unknown")}
                )
                await asyncio.sleep(0.5)
        
        print("\n" + "=" * 60)
        print("✅ Collection complete!")
        print(f"   Total collected: {self.stats['total_collected']}")
        print(f"   Exploits: {self.stats.get('exploits', 0)}")
        print(f"   Safe: {self.stats.get('safe', 0)}")
        print(f"   Scams: {self.stats.get('scams', 0)}")
        print(f"   Failed: {self.stats['failed']}")
        
        return self.stats["total_collected"]
    
    def save_collected_data(self) -> str:
        """Save collected bytecode to JSON file"""
        
        output_file = self.output_dir / f"bytecode_dataset_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        
        # Convert to serializable format
        data = {
            "metadata": {
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "total_contracts": len(self.collected),
                "stats": self.stats,
            },
            "contracts": [asdict(c) for c in self.collected]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n💾 Data saved to: {output_file}")
        
        # Also save a summary file (without full bytecode for quick loading)
        summary_file = self.output_dir / "bytecode_summary.json"
        summary = {
            "metadata": data["metadata"],
            "contracts": [
                {
                    "address": c.address,
                    "chain": c.chain,
                    "label": c.label,
                    "source": c.source,
                    "bytecode_hash": c.bytecode_hash,
                    "bytecode_length": c.bytecode_length,
                }
                for c in self.collected
            ]
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return str(output_file)
    
    def load_existing_data(self, file_path: str) -> int:
        """Load previously collected bytecode data"""
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        for contract in data.get("contracts", []):
            self.collected.append(CollectedContract(**contract))
        
        print(f"📂 Loaded {len(self.collected)} contracts from {file_path}")
        return len(self.collected)


class RealBytecodeFeatureExtractor:
    """
    Extract features from real bytecode for ML training
    """
    
    # EVM Opcodes we care about
    DANGEROUS_OPCODES = {
        "F1": "CALL",
        "F2": "CALLCODE",
        "F4": "DELEGATECALL",
        "FA": "STATICCALL",
        "FF": "SELFDESTRUCT",
        "55": "SSTORE",
        "54": "SLOAD",
        "31": "BALANCE",
        "3B": "EXTCODESIZE",
        "3C": "EXTCODECOPY",
        "3F": "EXTCODEHASH",
    }
    
    # Known malicious function signatures (4-byte selectors)
    MALICIOUS_SIGNATURES = {
        # Flash loan callbacks
        "23e30c8b": "executeOperation",      # Aave V3
        "ab803a65": "onFlashLoan",           # ERC-3156
        "c72c4d10": "onFlashLoan",           # Balancer
        "ee872558": "uniswapV2Call",         # Uniswap V2 flash
        "84800812": "pancakeCall",           # PancakeSwap flash
        # Reentrancy patterns
        "a9059cbb": "transfer",              # ERC20 transfer
        "23b872dd": "transferFrom",          # ERC20 transferFrom
        # Dangerous admin functions
        "715018a6": "renounceOwnership",
        "f2fde38b": "transferOwnership",
        "8456cb59": "pause",
        "3f4ba83a": "unpause",
        # Token minting
        "40c10f19": "mint",
        "a0712d68": "mint",
        "6a627842": "mint",
        # Proxy patterns
        "5c60da1b": "implementation",
        "f851a440": "admin",
        "3659cfe6": "upgradeTo",
    }
    
    def extract_features(self, bytecode: str) -> Dict:
        """Extract comprehensive features from bytecode"""
        
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        
        features = {
            # Basic metrics
            "bytecode_length": len(bytecode) // 2,  # In bytes
            "bytecode_length_normalized": min(len(bytecode) / 50000, 1.0),
            
            # Opcode counts
            "call_count": 0,
            "delegatecall_count": 0,
            "staticcall_count": 0,
            "selfdestruct_count": 0,
            "sstore_count": 0,
            "sload_count": 0,
            "balance_count": 0,
            "extcode_count": 0,
            
            # Pattern flags
            "has_flash_loan_callback": False,
            "has_reentrancy_pattern": False,
            "has_delegatecall_pattern": False,
            "has_selfdestruct": False,
            "has_mint_function": False,
            "has_admin_functions": False,
            "has_proxy_pattern": False,
            
            # Complexity metrics
            "unique_opcodes": 0,
            "jumps_count": 0,
            "push_count": 0,
            
            # Signature analysis
            "known_signatures_count": 0,
            "flash_loan_signatures": 0,
            "admin_signatures": 0,
        }
        
        # Parse bytecode
        i = 0
        opcodes_seen = set()
        
        while i < len(bytecode):
            try:
                opcode = bytecode[i:i+2].upper()
                opcodes_seen.add(opcode)
                
                # Count dangerous opcodes
                if opcode == "F1":  # CALL
                    features["call_count"] += 1
                elif opcode == "F4":  # DELEGATECALL
                    features["delegatecall_count"] += 1
                    features["has_delegatecall_pattern"] = True
                elif opcode == "FA":  # STATICCALL
                    features["staticcall_count"] += 1
                elif opcode == "FF":  # SELFDESTRUCT
                    features["selfdestruct_count"] += 1
                    features["has_selfdestruct"] = True
                elif opcode == "55":  # SSTORE
                    features["sstore_count"] += 1
                elif opcode == "54":  # SLOAD
                    features["sload_count"] += 1
                elif opcode == "31":  # BALANCE
                    features["balance_count"] += 1
                elif opcode in ["3B", "3C", "3F"]:  # EXTCODE*
                    features["extcode_count"] += 1
                elif opcode in ["56", "57"]:  # JUMP, JUMPI
                    features["jumps_count"] += 1
                elif opcode.startswith("6") or opcode.startswith("7"):  # PUSH
                    features["push_count"] += 1
                
                # Skip PUSH data
                if opcode.startswith("6"):  # PUSH1-PUSH16
                    push_size = int(opcode[1], 16) + 1
                    i += push_size * 2
                elif opcode.startswith("7"):  # PUSH17-PUSH32
                    push_size = int(opcode[1], 16) + 17
                    i += push_size * 2
                else:
                    i += 2
                    
            except Exception:
                i += 2
        
        features["unique_opcodes"] = len(opcodes_seen)
        
        # Check for known function signatures
        for sig, name in self.MALICIOUS_SIGNATURES.items():
            if sig.lower() in bytecode.lower():
                features["known_signatures_count"] += 1
                
                if name in ["executeOperation", "onFlashLoan", "uniswapV2Call", "pancakeCall"]:
                    features["flash_loan_signatures"] += 1
                    features["has_flash_loan_callback"] = True
                elif name in ["mint"]:
                    features["has_mint_function"] = True
                elif name in ["renounceOwnership", "transferOwnership", "pause", "unpause"]:
                    features["admin_signatures"] += 1
                    features["has_admin_functions"] = True
                elif name in ["implementation", "admin", "upgradeTo"]:
                    features["has_proxy_pattern"] = True
        
        # Detect reentrancy pattern: CALL opcode (0xf1) followed by SSTORE (0x55)
        # Parse opcodes properly instead of naive hex string search to avoid
        # matching data bytes embedded in PUSH instructions
        if features["call_count"] > 0 and features["sstore_count"] > 0:
            try:
                bc_bytes = bytes.fromhex(bytecode.lower().replace("0x", ""))
                opcodes_parsed = []
                idx = 0
                while idx < len(bc_bytes):
                    op = bc_bytes[idx]
                    opcodes_parsed.append(op)
                    # Skip PUSH data bytes (0x60-0x7f push 1-32 bytes)
                    if 0x60 <= op <= 0x7F:
                        idx += op - 0x5F
                    idx += 1
                # Check for CALL (0xf1) followed by SSTORE (0x55) within 30 opcodes
                call_indices = [i for i, op in enumerate(opcodes_parsed) if op == 0xF1]
                sstore_indices = [i for i, op in enumerate(opcodes_parsed) if op == 0x55]
                for ci in call_indices:
                    for si in sstore_indices:
                        if ci < si < ci + 30:
                            # Check for reentrancy guard (SLOAD+EQ/ISZERO+JUMPI before CALL)
                            pre = opcodes_parsed[max(0, ci - 30):ci]
                            has_guard = 0x54 in pre and (0x14 in pre or 0x15 in pre) and 0x57 in pre
                            if not has_guard:
                                features["has_reentrancy_pattern"] = True
                            break
                    if features.get("has_reentrancy_pattern"):
                        break
            except (ValueError, IndexError):
                pass
        
        # Normalize counts
        features["call_count_normalized"] = min(features["call_count"] / 50, 1.0)
        features["delegatecall_count_normalized"] = min(features["delegatecall_count"] / 10, 1.0)
        features["sstore_count_normalized"] = min(features["sstore_count"] / 100, 1.0)
        features["sload_count_normalized"] = min(features["sload_count"] / 100, 1.0)
        
        # Calculate risk score
        risk_score = 0.0
        if features["has_flash_loan_callback"]:
            risk_score += 0.3
        if features["has_reentrancy_pattern"]:
            risk_score += 0.25
        if features["has_delegatecall_pattern"]:
            risk_score += 0.15
        if features["has_selfdestruct"]:
            risk_score += 0.15
        if features["delegatecall_count"] > 2:
            risk_score += 0.1
        if features["call_count"] > 10:
            risk_score += 0.05
        
        features["risk_score"] = min(risk_score, 1.0)
        
        return features
    
    def features_to_vector(self, features: Dict) -> List[float]:
        """Convert features dict to ML-ready vector"""
        
        return [
            features["bytecode_length_normalized"],
            features["call_count_normalized"],
            features["delegatecall_count_normalized"],
            min(features["staticcall_count"] / 20, 1.0),
            min(features["selfdestruct_count"] / 5, 1.0),
            features["sstore_count_normalized"],
            features["sload_count_normalized"],
            min(features["balance_count"] / 10, 1.0),
            min(features["extcode_count"] / 10, 1.0),
            min(features["jumps_count"] / 200, 1.0),
            min(features["push_count"] / 500, 1.0),
            float(features["has_flash_loan_callback"]),
            float(features["has_reentrancy_pattern"]),
            float(features["has_delegatecall_pattern"]),
            float(features["has_selfdestruct"]),
            float(features["has_mint_function"]),
            float(features["has_admin_functions"]),
            float(features["has_proxy_pattern"]),
            min(features["unique_opcodes"] / 100, 1.0),
            features["risk_score"],
        ]


async def collect_training_bytecode():
    """Main function to collect bytecode for training"""
    
    async with BytecodeCollector() as collector:
        await collector.collect_all_known_contracts()
        collector.save_collected_data()
        
        # Extract features for all collected contracts
        print("\n🔬 Extracting features from bytecode...")
        extractor = RealBytecodeFeatureExtractor()
        
        training_data = []
        for contract in collector.collected:
            features = extractor.extract_features(contract.bytecode)
            vector = extractor.features_to_vector(features)
            
            training_data.append({
                "address": contract.address,
                "chain": contract.chain,
                "label": contract.label,
                "source": contract.source,
                "features": vector,
                "features_dict": features,
            })
        
        # Save training data
        training_file = collector.output_dir / "training_data_real.json"
        with open(training_file, 'w') as f:
            json.dump(training_data, f, indent=2)
        
        print(f"📊 Training data saved to: {training_file}")
        print(f"   Total samples: {len(training_data)}")
        
        return training_data


if __name__ == "__main__":
    asyncio.run(collect_training_bytecode())

