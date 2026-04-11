"""
Price Feed Service for USD Conversion
=====================================

Provides real-time token prices from multiple sources:
1. DeFiLlama (free, no API key required)
2. CoinGecko (free tier, rate-limited)
3. Static fallback for common tokens

Usage:
    price_feed = PriceFeed()
    price = await price_feed.get_price("ethereum", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
    # Returns: 3200.0 (USD)
"""

import aiohttp
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class TokenPrice:
    """Cached token price"""
    price_usd: float
    symbol: str
    timestamp: datetime
    source: str


class PriceFeed:
    """
    Multi-source price feed with caching.
    
    Priority:
    1. Cache (if fresh)
    2. DeFiLlama (free, reliable)
    3. CoinGecko (free, rate-limited)
    4. Static fallback
    """
    
    # Cache TTL in seconds
    CACHE_TTL = 60
    
    # Common token addresses (checksummed and lowercase)
    KNOWN_TOKENS: Dict[str, Dict[str, str]] = {
        # Ethereum
        "ethereum": {
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",  # WETH
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",  # USDC
            "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",  # USDT
            "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",   # DAI
            "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",  # WBTC
            "0x514910771af9ca656af840dff83e8264ecf986ca": "LINK",  # LINK
            "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": "UNI",   # UNI
            "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9": "AAVE",  # AAVE
            "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": "stETH", # stETH
            "0xbe9895146f7af43049ca1c1ae358b0541ea49704": "cbETH", # cbETH
            # Additional common tokens
            "0x4d224452801aced8b2f0aebe155379bb5d594381": "APE",   # ApeCoin
            "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce": "SHIB",  # Shiba Inu
            "0x6982508145454ce325ddbe47a25d4ec3d2311933": "PEPE",  # Pepe
            "0x5a98fcbea516cf06857215779fd812ca3bef1b32": "LDO",   # Lido DAO
            "0xd533a949740bb3306d119cc777fa900ba034cd52": "CRV",   # Curve DAO
            "0x4e3fbd56cd56c3e72c1403e103b45db9da5b9d2b": "CVX",   # Convex
            "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2": "MKR",   # Maker
            "0xc00e94cb662c3520282e6f5717214004a7f26888": "COMP",  # Compound
            "0xba100000625a3754423978a60c9317c58a424e3d": "BAL",   # Balancer
            "0x111111111117dc0aa78b770fa6a738034120c302": "1INCH", # 1inch
            "0x0bc529c00c6401aef6d220be8c6ea1667f6ad93e": "YFI",   # Yearn
            "0x6810e776880c02933d47db1b9fc05908e5386b96": "GNO",   # Gnosis
            "0x853d955acef822db058eb8505911ed77f175b99e": "FRAX",  # Frax
            "0x3432b6a60d23ca0dfca7761b7ab56459d9c964d0": "FXS",   # Frax Share
            "0x5f98805a4e8be255a32880fdec7f6728c6568ba0": "LUSD",  # Liquity USD
            "0x6dea81c8171d0ba574754ef6f8b412f2ed88c54d": "LQTY",  # Liquity
            "0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f": "SNX",   # Synthetix
            "0x4691937a7508860f876c9c0a2a617e7d9e945d4b": "WOO",   # WOO Network
            "0x0d8775f648430679a709e98d2b0cb6250d2887ef": "BAT",   # Basic Attention
            "0x0f5d2fb29fb7d3cfee444a200298f468908cc942": "MANA",  # Decentraland
            "0x3845badade8e6dff049820680d1f14bd3903a5d0": "SAND",  # Sandbox
            "0xbb0e17ef65f82ab018d8edd776e8dd940327b28b": "AXS",   # Axie Infinity
            "0x4c19596f5aaff459fa38b0f7ed92f11ae6543784": "TRU",   # TrueFi
            "0x090185f2135308bad17527004364ebcc2d37e5f6": "SPELL", # Spell Token
        },
        # Polygon
        "polygon": {
            "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619": "WETH",
            "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": "USDC",
            "0xc2132d05d31c914a87c6611c10748aeb04b58e8f": "USDT",
            "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063": "DAI",
            "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270": "WMATIC",
            "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6": "WBTC",
            # Native USDC (Circle) on Polygon
            "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": "USDC",
        },
        # Arbitrum
        "arbitrum": {
            "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": "WETH",
            "0xaf88d065e77c8cc2239327c5edb3a432268e5831": "USDC",
            "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": "USDT",
            "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1": "DAI",
            "0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f": "WBTC",
            "0x912ce59144191c1204e64559fe8253a0e49e6548": "ARB",
        },
        # Optimism
        "optimism": {
            "0x4200000000000000000000000000000000000006": "WETH",
            "0x7f5c764cbc14f9669b88837ca1490cca17c31607": "USDC",
            "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58": "USDT",
            "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1": "DAI",
            "0x4200000000000000000000000000000000000042": "OP",
            # Native USDC (Circle) on Optimism
            "0x0b2c639c533813f4aa9d7837caf62653d097ff85": "USDC",
        },
        # Base
        "base": {
            "0x4200000000000000000000000000000000000006": "WETH",
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": "USDC",
            "0x50c5725949a6f0c72e6c4a641f24049a917db0cb": "DAI",
            "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca": "USDbC",
        },
        # Avalanche
        "avalanche": {
            "0x49d5c2bdffac6ce2bfdb6640f4f80f226bc10bab": "WETH.e",
            "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e": "USDC",
            "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7": "USDT",
            "0xd586e7f844cea2f87f50152665bcbc2c279d8d70": "DAI.e",
            "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7": "WAVAX",
        },
        # BSC
        "bsc": {
            "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": "WBNB",
            "0x55d398326f99059ff775485246999027b3197955": "USDT",
            "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "USDC",
            "0xe9e7cea3dedca5984780bafc599bd69add087d56": "BUSD",
            "0x2170ed0880ac9a755fd29b2688956bd959f933f8": "WETH",
            "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c": "WBTC",
        },
    }
    
    # Static fallback prices (updated periodically)
    STATIC_PRICES: Dict[str, float] = {
        "WETH": 3200.0,
        "ETH": 3200.0,
        "WBTC": 95000.0,
        "BTC": 95000.0,
        "USDC": 1.0,
        "USDT": 1.0,
        "DAI": 1.0,
        "LINK": 22.0,
        "UNI": 12.0,
        "AAVE": 280.0,
        "stETH": 3180.0,
        "cbETH": 3150.0,
        "WMATIC": 0.45,
        "MATIC": 0.45,
        "ARB": 0.80,
        "OP": 2.50,
        "WAVAX": 35.0,
        "AVAX": 35.0,
        "WETH.e": 3200.0,
        "DAI.e": 1.0,
        # Additional tokens
        "APE": 1.50,
        "SHIB": 0.000025,
        "PEPE": 0.000015,
        "LDO": 2.50,
        "CRV": 0.80,
        "CVX": 4.50,
        "MKR": 2000.0,
        "COMP": 80.0,
        "BAL": 4.0,
        "1INCH": 0.50,
        "YFI": 8000.0,
        "GNO": 300.0,
        "FRAX": 1.0,
        "FXS": 5.0,
        "LUSD": 1.0,
        "LQTY": 1.50,
        "SNX": 3.0,
        "WOO": 0.25,
        "BAT": 0.25,
        "MANA": 0.50,
        "SAND": 0.60,
        "AXS": 8.0,
        "TRU": 0.10,
        "SPELL": 0.001,
        # BSC tokens
        "BNB": 600.0,
        "WBNB": 600.0,
        "CAKE": 2.50,
        "BUSD": 1.0,
        "USDbC": 1.0,
    }
    
    # Token decimals mapping (most tokens use 18, but stablecoins often use 6)
    TOKEN_DECIMALS: Dict[str, int] = {
        # 6 decimal tokens (stablecoins)
        "USDC": 6,
        "USDT": 6,
        "USDbC": 6,
        "BUSD": 6,  # Some versions
        # 8 decimal tokens
        "WBTC": 8,
        "renBTC": 8,
        # 18 decimal tokens (default for most ERC20)
        "WETH": 18,
        "ETH": 18,
        "DAI": 18,
        "LINK": 18,
        "UNI": 18,
        "AAVE": 18,
        "stETH": 18,
        "cbETH": 18,
        "WMATIC": 18,
        "MATIC": 18,
        "ARB": 18,
        "OP": 18,
        "WAVAX": 18,
        "AVAX": 18,
        "BNB": 18,
        "WBNB": 18,
        "FRAX": 18,
        "LUSD": 18,
    }
    
    # Default decimals for unknown tokens
    DEFAULT_DECIMALS = 18
    
    # CoinGecko ID mapping
    COINGECKO_IDS: Dict[str, str] = {
        "WETH": "weth",
        "ETH": "ethereum",
        "WBTC": "wrapped-bitcoin",
        "BTC": "bitcoin",
        "USDC": "usd-coin",
        "USDT": "tether",
        "DAI": "dai",
        "LINK": "chainlink",
        "UNI": "uniswap",
        "AAVE": "aave",
        "stETH": "staked-ether",
        "cbETH": "coinbase-wrapped-staked-eth",
        "WMATIC": "wmatic",
        "MATIC": "matic-network",
        "ARB": "arbitrum",
        "OP": "optimism",
        "WAVAX": "wrapped-avax",
        "AVAX": "avalanche-2",
    }
    
    def __init__(self):
        self._cache: Dict[str, TokenPrice] = {}
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_bulk_update: Optional[datetime] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )
        return self._session
    
    async def close(self):
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def get_token_symbol(self, chain: str, token_address: str) -> Optional[str]:
        """Get token symbol from address."""
        chain_tokens = self.KNOWN_TOKENS.get(chain.lower(), {})
        return chain_tokens.get(token_address.lower())
    
    async def get_price(
        self, 
        chain: str, 
        token_address: str,
        use_cache: bool = True
    ) -> float:
        """
        Get token price in USD.
        
        Args:
            chain: Chain name (ethereum, polygon, etc.)
            token_address: Token contract address
            use_cache: Whether to use cached price
            
        Returns:
            Price in USD, or 0.0 if not found
        """
        token_address = token_address.lower()
        cache_key = f"{chain}:{token_address}"
        
        # Check cache
        if use_cache and cache_key in self._cache:
            cached = self._cache[cache_key]
            if datetime.now(timezone.utc) - cached.timestamp < timedelta(seconds=self.CACHE_TTL):
                return cached.price_usd
        
        # Get token symbol
        symbol = self.get_token_symbol(chain, token_address)
        
        if not symbol:
            # Unknown token - try to fetch from DeFiLlama by address
            price = await self._fetch_price_by_address(chain, token_address)
            if price > 0:
                self._cache[cache_key] = TokenPrice(
                    price_usd=price,
                    symbol="UNKNOWN",
                    timestamp=datetime.now(timezone.utc),
                    source="defillama"
                )
                logger.debug("unknown_token_price_found", chain=chain, address=token_address[:10], price=price)
                return price
            # For unknown tokens with no price, return 0 but don't spam logs
            return 0.0
        
        # Try DeFiLlama first
        price = await self._fetch_defillama_price(chain, token_address)
        if price > 0:
            self._cache[cache_key] = TokenPrice(
                price_usd=price,
                symbol=symbol,
                timestamp=datetime.now(timezone.utc),
                source="defillama"
            )
            return price
        
        # Try CoinGecko
        price = await self._fetch_coingecko_price(symbol)
        if price > 0:
            self._cache[cache_key] = TokenPrice(
                price_usd=price,
                symbol=symbol,
                timestamp=datetime.now(timezone.utc),
                source="coingecko"
            )
            return price
        
        # Fallback to static price
        static_price = self.STATIC_PRICES.get(symbol, 0.0)
        if static_price > 0:
            self._cache[cache_key] = TokenPrice(
                price_usd=static_price,
                symbol=symbol,
                timestamp=datetime.now(timezone.utc),
                source="static"
            )
            logger.debug("using_static_price", symbol=symbol, price=static_price)
        
        return static_price
    
    async def _fetch_defillama_price(self, chain: str, token_address: str) -> float:
        """Fetch price from DeFiLlama."""
        try:
            session = await self._get_session()
            
            # DeFiLlama uses chain:address format
            chain_map = {
                "ethereum": "ethereum",
                "polygon": "polygon",
                "arbitrum": "arbitrum",
                "optimism": "optimism",
                "base": "base",
                "avalanche": "avax",
                "bsc": "bsc",
            }
            
            llama_chain = chain_map.get(chain.lower(), chain.lower())
            url = f"https://coins.llama.fi/prices/current/{llama_chain}:{token_address}"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    coins = data.get("coins", {})
                    key = f"{llama_chain}:{token_address}"
                    if key in coins:
                        price = coins[key].get("price", 0)
                        logger.debug("defillama_price_fetched", chain=chain, address=token_address[:10], price=price)
                        return float(price)
        except Exception as e:
            logger.debug("defillama_fetch_error", error=str(e))
        
        return 0.0
    
    async def _fetch_price_by_address(self, chain: str, token_address: str) -> float:
        """Fetch price by address from DeFiLlama."""
        return await self._fetch_defillama_price(chain, token_address)
    
    async def _fetch_coingecko_price(self, symbol: str) -> float:
        """Fetch price from CoinGecko."""
        try:
            coingecko_id = self.COINGECKO_IDS.get(symbol)
            if not coingecko_id:
                return 0.0
            
            session = await self._get_session()
            url = f"https://api.coingecko.com/api/v3/simple/price?ids={coingecko_id}&vs_currencies=usd"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if coingecko_id in data:
                        price = data[coingecko_id].get("usd", 0)
                        logger.debug("coingecko_price_fetched", symbol=symbol, price=price)
                        return float(price)
        except Exception as e:
            logger.debug("coingecko_fetch_error", error=str(e))
        
        return 0.0
    
    async def get_prices_batch(
        self, 
        tokens: list[Tuple[str, str]]
    ) -> Dict[str, float]:
        """
        Get prices for multiple tokens efficiently.
        
        Args:
            tokens: List of (chain, token_address) tuples
            
        Returns:
            Dict mapping "chain:address" to price
        """
        results = {}
        
        # Group by chain for efficient DeFiLlama batch request
        by_chain: Dict[str, list[str]] = {}
        for chain, address in tokens:
            chain = chain.lower()
            address = address.lower()
            if chain not in by_chain:
                by_chain[chain] = []
            by_chain[chain].append(address)
        
        # Fetch from DeFiLlama in batch
        for chain, addresses in by_chain.items():
            try:
                session = await self._get_session()
                
                chain_map = {
                    "ethereum": "ethereum",
                    "polygon": "polygon",
                    "arbitrum": "arbitrum",
                    "optimism": "optimism",
                    "base": "base",
                    "avalanche": "avax",
                    "bsc": "bsc",
                }
                llama_chain = chain_map.get(chain, chain)
                
                # Build comma-separated list
                coins = ",".join([f"{llama_chain}:{addr}" for addr in addresses])
                url = f"https://coins.llama.fi/prices/current/{coins}"
                
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for addr in addresses:
                            key = f"{llama_chain}:{addr}"
                            if key in data.get("coins", {}):
                                price = data["coins"][key].get("price", 0)
                                results[f"{chain}:{addr}"] = float(price)
            except Exception as e:
                logger.debug("batch_fetch_error", chain=chain, error=str(e))
        
        # Fill in missing with static prices
        for chain, address in tokens:
            key = f"{chain.lower()}:{address.lower()}"
            if key not in results:
                symbol = self.get_token_symbol(chain, address)
                if symbol:
                    results[key] = self.STATIC_PRICES.get(symbol, 0.0)
                else:
                    results[key] = 0.0
        
        return results
    
    async def update_static_prices(self):
        """Update static fallback prices from CoinGecko."""
        try:
            session = await self._get_session()
            
            ids = ",".join(self.COINGECKO_IDS.values())
            url = f"https://api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=usd"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Update static prices
                    for symbol, cg_id in self.COINGECKO_IDS.items():
                        if cg_id in data:
                            self.STATIC_PRICES[symbol] = data[cg_id].get("usd", self.STATIC_PRICES.get(symbol, 0))
                    
                    self._last_bulk_update = datetime.now(timezone.utc)
                    logger.info("static_prices_updated", count=len(data))
        except Exception as e:
            logger.warning("static_prices_update_failed", error=str(e))
    
    def get_token_decimals(self, chain: str, token_address: str) -> int:
        """
        Get token decimals for proper amount conversion.
        
        Most ERC20 tokens use 18 decimals, but stablecoins (USDC, USDT) use 6.
        This is critical for correct USD value calculation.
        """
        # First, get the symbol
        symbol = self.get_token_symbol(chain, token_address)
        
        if symbol:
            return self.TOKEN_DECIMALS.get(symbol, self.DEFAULT_DECIMALS)
        
        # Check if it's a known stablecoin address (6 decimals)
        stablecoin_addresses = {
            # Ethereum USDC/USDT
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 6,  # USDC
            "0xdac17f958d2ee523a2206206994597c13d831ec7": 6,  # USDT
            # Polygon USDC/USDT
            "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": 6,  # USDC
            "0xc2132d05d31c914a87c6611c10748aeb04b58e8f": 6,  # USDT
            # Arbitrum USDC/USDT
            "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": 6,  # USDC
            "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": 6,  # USDT
            # Optimism USDC/USDT
            "0x7f5c764cbc14f9669b88837ca1490cca17c31607": 6,  # USDC
            "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58": 6,  # USDT
            # Avalanche USDC/USDT
            "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e": 6,  # USDC
            "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7": 6,  # USDT
            # BSC USDC/USDT/BUSD (18 decimals on BSC, unlike other chains)
            "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": 18, # USDC (18 on BSC)
            "0x55d398326f99059ff775485246999027b3197955": 18, # USDT (18 on BSC)
            "0xe9e7cea3dedca5984780bafc599bd69add087d56": 18, # BUSD
            # Native USDC (Circle) — 6 decimals
            "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": 6,  # Polygon native USDC
            "0x0b2c639c533813f4aa9d7837caf62653d097ff85": 6,  # Optimism native USDC
            # Base
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": 6,  # Base USDC
            "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca": 6,  # Base USDbC
        }
        
        if token_address:
            decimals = stablecoin_addresses.get(token_address.lower())
            if decimals is not None:
                return decimals
        
        return self.DEFAULT_DECIMALS
    
    def calculate_usd_value(
        self, 
        amount: Decimal, 
        price: float,
        decimals: int = 18
    ) -> Decimal:
        """
        Calculate USD value from token amount and price.
        
        IMPORTANT: The 'amount' should already be in human-readable format
        (i.e., already divided by 10^decimals). If you have raw wei amount,
        use calculate_usd_value_from_raw() instead.
        """
        if price <= 0:
            return Decimal("0")
        
        usd_value = amount * Decimal(str(price))
        
        # Sanity check: Cap at $10 billion (no single tx should be more)
        MAX_USD = Decimal("10000000000")  # $10B
        if usd_value > MAX_USD:
            logger.warning("usd_value_capped", 
                          original=str(usd_value)[:20], 
                          capped=str(MAX_USD),
                          amount=str(amount)[:20],
                          price=price)
            return MAX_USD
        
        return usd_value
    
    def calculate_usd_value_from_raw(
        self,
        raw_amount: int,
        price: float,
        decimals: int = 18
    ) -> Decimal:
        """
        Calculate USD value from RAW token amount (in smallest units like wei).
        
        This handles the decimal conversion automatically.
        """
        if price <= 0 or raw_amount <= 0:
            return Decimal("0")
        
        # Convert raw amount to human-readable
        human_amount = Decimal(raw_amount) / Decimal(10 ** decimals)
        
        return self.calculate_usd_value(human_amount, price, decimals)
    
    def get_native_token_symbol(self, chain: str) -> str:
        """Get native token symbol for a chain."""
        native_tokens = {
            "ethereum": "ETH",
            "polygon": "MATIC",
            "arbitrum": "ETH",
            "optimism": "ETH",
            "base": "ETH",
            "avalanche": "AVAX",
            "bsc": "BNB",
        }
        return native_tokens.get(chain.lower(), "ETH")
    
    async def get_native_price(self, chain: str) -> float:
        """Get native token price for a chain."""
        symbol = self.get_native_token_symbol(chain)
        
        # Map to wrapped version for price lookup
        wrapped_map = {
            "ETH": ("ethereum", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            "MATIC": ("polygon", "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"),
            "AVAX": ("avalanche", "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7"),
            "BNB": ("bsc", "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"),
        }
        
        if symbol in wrapped_map:
            chain_for_price, address = wrapped_map[symbol]
            return await self.get_price(chain_for_price, address)
        
        return self.STATIC_PRICES.get(symbol, 0.0)


# Global singleton
_price_feed: Optional[PriceFeed] = None


def get_price_feed() -> PriceFeed:
    """Get global price feed instance."""
    global _price_feed
    if _price_feed is None:
        _price_feed = PriceFeed()
    return _price_feed
