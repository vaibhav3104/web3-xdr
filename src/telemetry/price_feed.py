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

import asyncio
import aiohttp
from datetime import datetime, timedelta
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
        },
        # Polygon
        "polygon": {
            "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619": "WETH",
            "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": "USDC",
            "0xc2132d05d31c914a87c6611c10748aeb04b58e8f": "USDT",
            "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063": "DAI",
            "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270": "WMATIC",
            "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6": "WBTC",
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
        },
        # Base
        "base": {
            "0x4200000000000000000000000000000000000006": "WETH",
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": "USDC",
            "0x50c5725949a6f0c72e6c4a641f24049a917db0cb": "DAI",
        },
        # Avalanche
        "avalanche": {
            "0x49d5c2bdffac6ce2bfdb6640f4f80f226bc10bab": "WETH.e",
            "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e": "USDC",
            "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7": "USDT",
            "0xd586e7f844cea2f87f50152665bcbc2c279d8d70": "DAI.e",
            "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7": "WAVAX",
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
    }
    
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
            if datetime.utcnow() - cached.timestamp < timedelta(seconds=self.CACHE_TTL):
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
                    timestamp=datetime.utcnow(),
                    source="defillama"
                )
                return price
            return 0.0
        
        # Try DeFiLlama first
        price = await self._fetch_defillama_price(chain, token_address)
        if price > 0:
            self._cache[cache_key] = TokenPrice(
                price_usd=price,
                symbol=symbol,
                timestamp=datetime.utcnow(),
                source="defillama"
            )
            return price
        
        # Try CoinGecko
        price = await self._fetch_coingecko_price(symbol)
        if price > 0:
            self._cache[cache_key] = TokenPrice(
                price_usd=price,
                symbol=symbol,
                timestamp=datetime.utcnow(),
                source="coingecko"
            )
            return price
        
        # Fallback to static price
        static_price = self.STATIC_PRICES.get(symbol, 0.0)
        if static_price > 0:
            self._cache[cache_key] = TokenPrice(
                price_usd=static_price,
                symbol=symbol,
                timestamp=datetime.utcnow(),
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
                    
                    self._last_bulk_update = datetime.utcnow()
                    logger.info("static_prices_updated", count=len(data))
        except Exception as e:
            logger.warning("static_prices_update_failed", error=str(e))
    
    def calculate_usd_value(
        self, 
        amount: Decimal, 
        price: float
    ) -> Decimal:
        """Calculate USD value from token amount and price."""
        if price <= 0:
            return Decimal("0")
        return amount * Decimal(str(price))
    
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
