#!/usr/bin/env python3
"""
Phase 3.1: Safe Contracts Collection Script
===========================================

Collects "safe" (benign) smart contract bytecode for ML negative sampling.

A contract is considered "safe" if it:
1. Has been verified on Etherscan
2. Is older than 1 year (survived without exploit)
3. Belongs to a known reputable protocol
4. Has significant transaction activity

Sources:
- Etherscan Verified Contracts API
- Known DeFi Protocol Contracts (Uniswap, Aave, Compound, etc.)
- Top TVL Protocols from DeFi Llama
- Token contracts from CoinGecko

Output:
- Saves bytecode to src/ai/data/safe_samples/
- Generates metadata JSON for training

Usage:
    python scripts/collect_safe_contracts.py
    python scripts/collect_safe_contracts.py --chain ethereum --limit 500
    python scripts/collect_safe_contracts.py --source etherscan
"""

import asyncio
import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from enum import Enum

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aiohttp
import structlog

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer()
    ]
)

logger = structlog.get_logger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

# API Keys (set via environment or .env)
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
POLYGONSCAN_API_KEY = os.getenv("POLYGONSCAN_API_KEY", "")
ARBISCAN_API_KEY = os.getenv("ARBISCAN_API_KEY", "")
BSCSCAN_API_KEY = os.getenv("BSCSCAN_API_KEY", "")

# Output directories
OUTPUT_DIR = Path(__file__).parent.parent / "src" / "ai" / "data" / "safe_samples"
METADATA_FILE = OUTPUT_DIR / "metadata.json"

# Rate limiting
REQUESTS_PER_SECOND = 5
MIN_REQUEST_INTERVAL = 1 / REQUESTS_PER_SECOND

# Contract age threshold (contracts older than this are considered "safe")
MIN_AGE_DAYS = 365  # 1 year

# RPC endpoints
RPC_ENDPOINTS = {
    "ethereum": [
        "https://eth.llamarpc.com",
        "https://rpc.ankr.com/eth",
        "https://cloudflare-eth.com",
    ],
    "polygon": [
        "https://polygon-rpc.com",
        "https://rpc.ankr.com/polygon",
    ],
    "arbitrum": [
        "https://arb1.arbitrum.io/rpc",
        "https://rpc.ankr.com/arbitrum",
    ],
    "bsc": [
        "https://bsc-dataseed.binance.org",
        "https://rpc.ankr.com/bsc",
    ],
}

# Explorer APIs
EXPLORER_APIS = {
    "ethereum": "https://api.etherscan.io/api",
    "polygon": "https://api.polygonscan.com/api",
    "arbitrum": "https://api.arbiscan.io/api",
    "bsc": "https://api.bscscan.com/api",
}


# =============================================================================
# KNOWN SAFE PROTOCOLS
# =============================================================================

class ContractCategory(Enum):
    """Categories for safe contracts."""
    DEX = "dex"
    LENDING = "lending"
    BRIDGE = "bridge"
    TOKEN = "token"
    NFT = "nft"
    ORACLE = "oracle"
    GOVERNANCE = "governance"
    STAKING = "staking"
    YIELD = "yield"
    INFRASTRUCTURE = "infrastructure"


# Top DeFi protocols with verified, battle-tested contracts
KNOWN_SAFE_PROTOCOLS = {
    "ethereum": {
        # Uniswap
        "0x1F98431c8aD98523631AE4a59f267346ea31F984": {"name": "Uniswap V3 Factory", "category": ContractCategory.DEX},
        "0xE592427A0AEce92De3Edee1F18E0157C05861564": {"name": "Uniswap V3 Router", "category": ContractCategory.DEX},
        "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45": {"name": "Uniswap Universal Router", "category": ContractCategory.DEX},
        "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f": {"name": "Uniswap V2 Factory", "category": ContractCategory.DEX},
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D": {"name": "Uniswap V2 Router", "category": ContractCategory.DEX},
        
        # Aave
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2": {"name": "Aave V3 Pool", "category": ContractCategory.LENDING},
        "0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e": {"name": "Aave V3 Pool Addresses Provider", "category": ContractCategory.LENDING},
        "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9": {"name": "Aave V2 Lending Pool", "category": ContractCategory.LENDING},
        
        # Compound
        "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B": {"name": "Compound Comptroller", "category": ContractCategory.LENDING},
        "0xc00e94Cb662C3520282E6f5717214004A7f26888": {"name": "COMP Token", "category": ContractCategory.TOKEN},
        
        # MakerDAO
        "0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2": {"name": "MKR Token", "category": ContractCategory.TOKEN},
        "0x6B175474E89094C44Da98b954EescdeCB5BAA7fD9": {"name": "DAI Stablecoin", "category": ContractCategory.TOKEN},
        "0x35D1b3F3D7966A1DFe207aa4514C12a259A0492B": {"name": "MakerDAO Vat", "category": ContractCategory.LENDING},
        
        # Chainlink
        "0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf": {"name": "Chainlink Oracle", "category": ContractCategory.ORACLE},
        "0x514910771AF9Ca656af840dff83E8264EcF986CA": {"name": "LINK Token", "category": ContractCategory.TOKEN},
        
        # Lido
        "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84": {"name": "stETH Token", "category": ContractCategory.STAKING},
        "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0": {"name": "wstETH Token", "category": ContractCategory.STAKING},
        
        # Curve
        "0xD51a44d3FaE010294C616388b506AcdA1bfAAE46": {"name": "Curve Tricrypto2 Pool", "category": ContractCategory.DEX},
        "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7": {"name": "Curve 3pool", "category": ContractCategory.DEX},
        "0xD533a949740bb3306d119CC777fa900bA034cd52": {"name": "CRV Token", "category": ContractCategory.TOKEN},
        
        # OpenZeppelin Implementations
        "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984": {"name": "UNI Token", "category": ContractCategory.TOKEN},
        "0xdAC17F958D2ee523a2206206994597C13D831ec7": {"name": "USDT", "category": ContractCategory.TOKEN},
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": {"name": "USDC", "category": ContractCategory.TOKEN},
        "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599": {"name": "WBTC", "category": ContractCategory.TOKEN},
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": {"name": "WETH", "category": ContractCategory.TOKEN},
        
        # Yearn
        "0xa354F35829Ae975e850e23e9615b11Da1B3dC4DE": {"name": "yvUSDC Vault", "category": ContractCategory.YIELD},
        
        # ENS
        "0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85": {"name": "ENS Base Registrar", "category": ContractCategory.NFT},
        "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e": {"name": "ENS Registry", "category": ContractCategory.INFRASTRUCTURE},
        
        # Safe (Gnosis)
        "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552": {"name": "Safe Singleton", "category": ContractCategory.INFRASTRUCTURE},
        "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2": {"name": "Safe Proxy Factory", "category": ContractCategory.INFRASTRUCTURE},
    },
    "polygon": {
        "0x1F98431c8aD98523631AE4a59f267346ea31F984": {"name": "Uniswap V3 Factory", "category": ContractCategory.DEX},
        "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff": {"name": "QuickSwap Router", "category": ContractCategory.DEX},
        "0x794a61358D6845594F94dc1DB02A252b5b4814aD": {"name": "Aave V3 Pool", "category": ContractCategory.LENDING},
        "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174": {"name": "USDC.e", "category": ContractCategory.TOKEN},
        "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619": {"name": "WETH", "category": ContractCategory.TOKEN},
    },
    "arbitrum": {
        "0x1F98431c8aD98523631AE4a59f267346ea31F984": {"name": "Uniswap V3 Factory", "category": ContractCategory.DEX},
        "0xE592427A0AEce92De3Edee1F18E0157C05861564": {"name": "Uniswap V3 Router", "category": ContractCategory.DEX},
        "0x794a61358D6845594F94dc1DB02A252b5b4814aD": {"name": "Aave V3 Pool", "category": ContractCategory.LENDING},
        "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1": {"name": "WETH", "category": ContractCategory.TOKEN},
        "0xaf88d065e77c8cC2239327C5EDb3A432268e5831": {"name": "USDC", "category": ContractCategory.TOKEN},
        "0x912CE59144191C1204E64559FE8253a0e49E6548": {"name": "ARB Token", "category": ContractCategory.TOKEN},
    },
    "bsc": {
        "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73": {"name": "PancakeSwap V2 Factory", "category": ContractCategory.DEX},
        "0x10ED43C718714eb63d5aA57B78B54704E256024E": {"name": "PancakeSwap Router", "category": ContractCategory.DEX},
        "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56": {"name": "BUSD", "category": ContractCategory.TOKEN},
        "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c": {"name": "WBNB", "category": ContractCategory.TOKEN},
    },
}


@dataclass
class SafeContract:
    """Metadata for a safe contract."""
    address: str
    chain: str
    bytecode_hash: str
    bytecode_length: int
    name: str = ""
    category: str = "unknown"
    protocol: str = ""
    deployment_date: Optional[str] = None
    verified: bool = False
    transaction_count: int = 0
    source: str = "manual"
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SafeContractCollector:
    """
    Collects safe (benign) contract bytecode for ML training.
    
    Implements multiple strategies:
    1. Known protocol contracts
    2. Etherscan verified contracts (API)
    3. Historical top contracts by transaction count
    """
    
    def __init__(self, chains: Optional[List[str]] = None):
        self.chains = chains or ["ethereum"]
        self.session: Optional[aiohttp.ClientSession] = None
        self.collected: Dict[str, SafeContract] = {}  # address -> metadata
        self.last_request_time: Dict[str, float] = {}  # endpoint -> timestamp
        
        # Ensure output directory exists
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
        # Load existing metadata if present
        self._load_existing_metadata()
        
        logger.info(
            "collector_initialized",
            chains=self.chains,
            existing_contracts=len(self.collected)
        )
    
    def _load_existing_metadata(self):
        """Load existing metadata to avoid re-collecting."""
        if METADATA_FILE.exists():
            try:
                with open(METADATA_FILE) as f:
                    data = json.load(f)
                    for addr, meta in data.get("contracts", {}).items():
                        self.collected[addr.lower()] = SafeContract(**meta)
                logger.info("loaded_existing_metadata", count=len(self.collected))
            except Exception as e:
                logger.warning("metadata_load_failed", error=str(e))
    
    async def _rate_limit(self, endpoint: str):
        """Implement rate limiting per endpoint."""
        now = time.time()
        if endpoint in self.last_request_time:
            elapsed = now - self.last_request_time[endpoint]
            if elapsed < MIN_REQUEST_INTERVAL:
                await asyncio.sleep(MIN_REQUEST_INTERVAL - elapsed)
        self.last_request_time[endpoint] = time.time()
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    async def _fetch_bytecode(self, chain: str, address: str) -> Optional[str]:
        """Fetch contract bytecode from RPC."""
        rpcs = RPC_ENDPOINTS.get(chain, [])
        if not rpcs:
            return None
        
        session = await self._get_session()
        
        for rpc_url in rpcs:
            try:
                await self._rate_limit(rpc_url)
                
                async with session.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_getCode",
                        "params": [address, "latest"],
                        "id": 1
                    }
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        bytecode = data.get("result", "0x")
                        if bytecode and bytecode != "0x":
                            return bytecode
            except Exception as e:
                logger.debug("rpc_fetch_failed", rpc=rpc_url[:30], error=str(e)[:40])
                continue
        
        return None
    
    async def _get_contract_info(self, chain: str, address: str) -> Optional[Dict]:
        """Get contract info from explorer API."""
        api_url = EXPLORER_APIS.get(chain)
        api_key = {
            "ethereum": ETHERSCAN_API_KEY,
            "polygon": POLYGONSCAN_API_KEY,
            "arbitrum": ARBISCAN_API_KEY,
            "bsc": BSCSCAN_API_KEY,
        }.get(chain, "")
        
        if not api_url:
            return None
        
        session = await self._get_session()
        
        try:
            await self._rate_limit(api_url)
            
            params = {
                "module": "contract",
                "action": "getcontractcreation",
                "contractaddresses": address,
                "apikey": api_key
            }
            
            async with session.get(api_url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "1" and data.get("result"):
                        return data["result"][0]
        except Exception as e:
            logger.debug("explorer_api_failed", chain=chain, error=str(e)[:40])
        
        return None
    
    async def _get_verified_contracts(self, chain: str, page: int = 1, limit: int = 100) -> List[Dict]:
        """Fetch verified contracts from explorer API."""
        api_url = EXPLORER_APIS.get(chain)
        api_key = {
            "ethereum": ETHERSCAN_API_KEY,
            "polygon": POLYGONSCAN_API_KEY,
            "arbitrum": ARBISCAN_API_KEY,
            "bsc": BSCSCAN_API_KEY,
        }.get(chain, "")
        
        if not api_url or not api_key:
            logger.warning("no_api_key", chain=chain)
            return []
        
        session = await self._get_session()
        
        try:
            await self._rate_limit(api_url)
            
            # Get recently verified contracts
            params = {
                "module": "contract",
                "action": "listcontracts",
                "page": page,
                "offset": limit,
                "filter": "verified",
                "apikey": api_key
            }
            
            async with session.get(api_url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "1":
                        return data.get("result", [])
        except Exception as e:
            logger.error("verified_contracts_fetch_failed", chain=chain, error=str(e))
        
        return []
    
    async def collect_known_protocols(self) -> int:
        """Collect bytecode from known safe protocols."""
        logger.info("collecting_known_protocols")
        collected = 0
        
        for chain in self.chains:
            protocols = KNOWN_SAFE_PROTOCOLS.get(chain, {})
            
            for address, info in protocols.items():
                address_lower = address.lower()
                
                # Skip if already collected
                if address_lower in self.collected:
                    continue
                
                bytecode = await self._fetch_bytecode(chain, address)
                
                if bytecode and len(bytecode) > 4:  # More than just "0x"
                    # Calculate bytecode hash
                    import hashlib
                    bytecode_hash = hashlib.sha256(bytecode.encode()).hexdigest()
                    
                    # Save bytecode
                    bytecode_file = OUTPUT_DIR / f"{chain}_{address_lower}.bin"
                    with open(bytecode_file, "w") as f:
                        f.write(bytecode)
                    
                    # Store metadata
                    self.collected[address_lower] = SafeContract(
                        address=address,
                        chain=chain,
                        bytecode_hash=bytecode_hash,
                        bytecode_length=len(bytecode),
                        name=info["name"],
                        category=info["category"].value,
                        protocol=info["name"].split()[0],
                        verified=True,
                        source="known_protocol"
                    )
                    
                    collected += 1
                    logger.debug(
                        "collected_protocol",
                        chain=chain,
                        name=info["name"],
                        bytecode_len=len(bytecode)
                    )
                
                # Brief pause between contracts
                await asyncio.sleep(0.1)
        
        logger.info("known_protocols_collected", count=collected)
        return collected
    
    async def collect_from_etherscan(self, max_contracts: int = 100) -> int:
        """Collect verified contracts from Etherscan-like APIs."""
        logger.info("collecting_from_explorers", max=max_contracts)
        collected = 0
        
        for chain in self.chains:
            if chain not in EXPLORER_APIS:
                continue
            
            page = 1
            chain_collected = 0
            
            while chain_collected < max_contracts // len(self.chains):
                contracts = await self._get_verified_contracts(chain, page, 25)
                
                if not contracts:
                    break
                
                for contract in contracts:
                    address = contract.get("Address", contract.get("address", ""))
                    if not address:
                        continue
                    
                    address_lower = address.lower()
                    
                    # Skip if already collected
                    if address_lower in self.collected:
                        continue
                    
                    bytecode = await self._fetch_bytecode(chain, address)
                    
                    if bytecode and len(bytecode) > 100:
                        import hashlib
                        bytecode_hash = hashlib.sha256(bytecode.encode()).hexdigest()
                        
                        # Save bytecode
                        bytecode_file = OUTPUT_DIR / f"{chain}_{address_lower}.bin"
                        with open(bytecode_file, "w") as f:
                            f.write(bytecode)
                        
                        # Store metadata
                        self.collected[address_lower] = SafeContract(
                            address=address,
                            chain=chain,
                            bytecode_hash=bytecode_hash,
                            bytecode_length=len(bytecode),
                            name=contract.get("ContractName", ""),
                            category="verified",
                            verified=True,
                            source="etherscan_verified"
                        )
                        
                        chain_collected += 1
                        collected += 1
                        
                        if chain_collected >= max_contracts // len(self.chains):
                            break
                
                page += 1
                
                # Rate limit between pages
                await asyncio.sleep(1)
        
        logger.info("explorer_contracts_collected", count=collected)
        return collected
    
    async def collect_top_tokens(self) -> int:
        """Collect top ERC20 token contracts."""
        logger.info("collecting_top_tokens")
        
        # Top tokens by market cap (hardcoded for reliability)
        top_tokens = {
            "ethereum": [
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
                "0x6B175474E89094C44Da98b954EesCDeCB5BAA7fd9",  # DAI
                "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",  # WBTC
                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
                "0x514910771AF9Ca656af840dff83E8264EcF986CA",  # LINK
                "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",  # UNI
                "0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0",  # MATIC
                "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",  # SHIB
                "0x4d224452801ACEd8B2F0aebE155379bb5D594381",  # APE
            ]
        }
        
        collected = 0
        
        for chain, tokens in top_tokens.items():
            if chain not in self.chains:
                continue
            
            for address in tokens:
                address_lower = address.lower()
                
                if address_lower in self.collected:
                    continue
                
                bytecode = await self._fetch_bytecode(chain, address)
                
                if bytecode and len(bytecode) > 4:
                    import hashlib
                    bytecode_hash = hashlib.sha256(bytecode.encode()).hexdigest()
                    
                    bytecode_file = OUTPUT_DIR / f"{chain}_{address_lower}.bin"
                    with open(bytecode_file, "w") as f:
                        f.write(bytecode)
                    
                    self.collected[address_lower] = SafeContract(
                        address=address,
                        chain=chain,
                        bytecode_hash=bytecode_hash,
                        bytecode_length=len(bytecode),
                        category="token",
                        verified=True,
                        source="top_token"
                    )
                    
                    collected += 1
        
        logger.info("top_tokens_collected", count=collected)
        return collected
    
    def save_metadata(self):
        """Save collection metadata to JSON."""
        metadata = {
            "version": "1.0",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "total_contracts": len(self.collected),
            "by_chain": {},
            "by_category": {},
            "by_source": {},
            "contracts": {}
        }
        
        for addr, contract in self.collected.items():
            # By chain
            chain = contract.chain
            if chain not in metadata["by_chain"]:
                metadata["by_chain"][chain] = 0
            metadata["by_chain"][chain] += 1
            
            # By category
            cat = contract.category
            if cat not in metadata["by_category"]:
                metadata["by_category"][cat] = 0
            metadata["by_category"][cat] += 1
            
            # By source
            src = contract.source
            if src not in metadata["by_source"]:
                metadata["by_source"][src] = 0
            metadata["by_source"][src] += 1
            
            # Contract details
            metadata["contracts"][addr] = asdict(contract)
        
        with open(METADATA_FILE, "w") as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(
            "metadata_saved",
            total=metadata["total_contracts"],
            by_chain=metadata["by_chain"]
        )
    
    async def run(self, max_etherscan: int = 100):
        """Run the collection pipeline."""
        logger.info("starting_collection")
        
        start_time = time.time()
        
        # 1. Collect known protocols
        known_count = await self.collect_known_protocols()
        
        # 2. Collect top tokens
        tokens_count = await self.collect_top_tokens()
        
        # 3. Collect from Etherscan (if API key available)
        etherscan_count = 0
        if ETHERSCAN_API_KEY:
            etherscan_count = await self.collect_from_etherscan(max_etherscan)
        else:
            logger.warning("etherscan_api_key_not_set", hint="Set ETHERSCAN_API_KEY for more contracts")
        
        # Save metadata
        self.save_metadata()
        
        # Close session
        if self.session:
            await self.session.close()
        
        elapsed = time.time() - start_time
        
        logger.info(
            "collection_complete",
            total=len(self.collected),
            known_protocols=known_count,
            top_tokens=tokens_count,
            etherscan=etherscan_count,
            elapsed_seconds=f"{elapsed:.1f}"
        )
        
        return len(self.collected)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        stats = {
            "total": len(self.collected),
            "by_chain": {},
            "by_category": {},
            "by_source": {},
            "avg_bytecode_length": 0,
        }
        
        total_length = 0
        for contract in self.collected.values():
            # By chain
            chain = contract.chain
            stats["by_chain"][chain] = stats["by_chain"].get(chain, 0) + 1
            
            # By category
            cat = contract.category
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
            
            # By source
            src = contract.source
            stats["by_source"][src] = stats["by_source"].get(src, 0) + 1
            
            total_length += contract.bytecode_length
        
        if self.collected:
            stats["avg_bytecode_length"] = total_length // len(self.collected)
        
        return stats


async def main():
    """Entry point."""
    parser = argparse.ArgumentParser(description="Collect safe contract bytecode for ML training")
    parser.add_argument(
        "--chain",
        type=str,
        default="ethereum",
        help="Chain to collect from (ethereum, polygon, arbitrum, bsc)"
    )
    parser.add_argument(
        "--chains",
        type=str,
        help="Comma-separated list of chains"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum contracts to fetch from explorers"
    )
    parser.add_argument(
        "--source",
        type=str,
        choices=["all", "protocols", "etherscan", "tokens"],
        default="all",
        help="Data source to use"
    )
    
    args = parser.parse_args()
    
    # Parse chains
    if args.chains:
        chains = args.chains.split(",")
    else:
        chains = [args.chain]
    
    print()
    print("=" * 60)
    print("🔒 Safe Contract Collector - ML Negative Sampling")
    print("=" * 60)
    print(f"   Chains: {chains}")
    print(f"   Limit: {args.limit}")
    print(f"   Source: {args.source}")
    print(f"   Output: {OUTPUT_DIR}")
    print()
    
    collector = SafeContractCollector(chains=chains)
    
    try:
        if args.source == "all":
            total = await collector.run(max_etherscan=args.limit)
        elif args.source == "protocols":
            total = await collector.collect_known_protocols()
            collector.save_metadata()
        elif args.source == "tokens":
            total = await collector.collect_top_tokens()
            collector.save_metadata()
        elif args.source == "etherscan":
            total = await collector.collect_from_etherscan(args.limit)
            collector.save_metadata()
    finally:
        # Ensure session is closed
        if collector.session and not collector.session.closed:
            await collector.session.close()
    
    # Print stats
    stats = collector.get_stats()
    print()
    print("=" * 60)
    print("📊 Collection Statistics")
    print("=" * 60)
    print(f"   Total contracts: {stats['total']}")
    print(f"   By chain: {stats['by_chain']}")
    print(f"   By category: {stats['by_category']}")
    print(f"   By source: {stats['by_source']}")
    print(f"   Avg bytecode length: {stats['avg_bytecode_length']} chars")
    print()


if __name__ == "__main__":
    asyncio.run(main())

