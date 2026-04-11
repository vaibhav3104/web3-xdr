"""
Financial Impact Calculator
============================

Calculates the financial impact (loss) from simulation results.
Uses state diffs to determine token balance changes and converts to USD.
"""

from decimal import Decimal
from typing import Dict, List, Optional
import structlog
import aiohttp

from ...models.predicted_incidents import StateDiffFingerprint

logger = structlog.get_logger(__name__)


class PriceOracle:
    """Simple price oracle for token USD conversion."""
    
    # Hardcoded prices from chains.yaml or API
    DEFAULT_PRICES: Dict[str, Decimal] = {
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": Decimal("2000.0"),  # WETH
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": Decimal("1.0"),  # USDC
        "0xdAC17F958D2ee523a2206206994597C13D831ec7": Decimal("1.0"),  # USDT
        "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599": Decimal("40000.0"),  # WBTC
        "0x6B175474E89094C44Da98b954EedeCB4957d9B2": Decimal("1.0"),  # DAI
    }
    
    @classmethod
    async def get_price_usd(cls, token_address: str, chain_id: str = "ethereum") -> Optional[Decimal]:
        """
        Get USD price for a token.
        
        First checks hardcoded prices, then tries API if available.
        """
        token_lower = token_address.lower()
        
        # Check hardcoded prices
        if token_lower in cls.DEFAULT_PRICES:
            return cls.DEFAULT_PRICES[token_lower]
        
        # Try CoinGecko API (free tier)
        try:
            async with aiohttp.ClientSession() as session:
                # Map token address to CoinGecko ID (simplified)
                coingecko_id = cls._get_coingecko_id(token_address, chain_id)
                if coingecko_id:
                    url = f"https://api.coingecko.com/api/v3/simple/price?ids={coingecko_id}&vs_currencies=usd"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if coingecko_id in data and "usd" in data[coingecko_id]:
                                price = Decimal(str(data[coingecko_id]["usd"]))
                                logger.debug("price_fetched_from_api", token=token_address[:16], price=price)
                                return price
        except Exception as e:
            logger.warning("price_api_failed", token=token_address[:16], error=str(e))
        
        # Default to 0 if price unavailable
        logger.warning("price_unavailable", token=token_address[:16])
        return None
    
    @staticmethod
    def _get_coingecko_id(token_address: str, chain_id: str) -> Optional[str]:
        """Map token address to CoinGecko ID (simplified mapping)."""
        # Common tokens mapping
        mapping = {
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "ethereum",  # WETH
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "usd-coin",  # USDC
            "0xdac17f958d2ee523a2206206994597c13d831ec7": "tether",  # USDT
            "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "wrapped-bitcoin",  # WBTC
        }
        return mapping.get(token_address.lower())


class FinancialImpactCalculator:
    """Calculates financial impact from state diffs."""
    
    def __init__(self, price_oracle: Optional[PriceOracle] = None):
        self.price_oracle = price_oracle or PriceOracle()
    
    async def calculate_loss(
        self,
        state_diff: StateDiffFingerprint,
        protected_addresses: List[str],
        chain_id: str = "ethereum"
    ) -> Dict[str, any]:
        """
        Calculate financial loss from state diff.
        
        Returns:
            {
                "loss_usd": Decimal,
                "loss_by_token": {token_address: {"amount": Decimal, "usd": Decimal, "symbol": str}},
                "primary_token": str,  # Token with largest loss
                "primary_token_symbol": str,
            }
        """
        loss_by_token: Dict[str, Dict[str, any]] = {}
        total_loss_usd = Decimal("0.0")
        
        # Check token balance deltas for protected addresses
        for address in protected_addresses:
            address_lower = address.lower()
            if address_lower not in state_diff.token_balance_deltas:
                continue
            
            token_deltas = state_diff.token_balance_deltas[address_lower]
            
            for token_address, delta in token_deltas.items():
                # Negative delta = loss
                if delta < 0:
                    loss_amount = abs(delta)
                    
                    # Get USD price
                    price_usd = await self.price_oracle.get_price_usd(token_address, chain_id)
                    loss_usd = loss_amount * price_usd if price_usd else Decimal("0.0")
                    
                    # Get token symbol (simplified - would need contract call in real implementation)
                    token_symbol = self._get_token_symbol(token_address)
                    
                    if token_address not in loss_by_token:
                        loss_by_token[token_address] = {
                            "amount": Decimal("0.0"),
                            "usd": Decimal("0.0"),
                            "symbol": token_symbol,
                        }
                    
                    loss_by_token[token_address]["amount"] += loss_amount
                    loss_by_token[token_address]["usd"] += loss_usd
                    total_loss_usd += loss_usd
        
        # Check total supply deltas (for mint/burn exploits)
        for token_address, delta in state_diff.total_supply_deltas.items():
            if delta > 0:  # Increase in supply = potential exploit
                # Estimate loss as a percentage of supply (simplified)
                # In real implementation, would check actual balances
                price_usd = await self.price_oracle.get_price_usd(token_address, chain_id)
                if price_usd:
                    # Assume 10% of supply increase is exploitable (conservative)
                    estimated_loss = delta * Decimal("0.1") * price_usd
                    total_loss_usd += estimated_loss
                    
                    if token_address not in loss_by_token:
                        token_symbol = self._get_token_symbol(token_address)
                        loss_by_token[token_address] = {
                            "amount": delta * Decimal("0.1"),
                            "usd": estimated_loss,
                            "symbol": token_symbol,
                        }
        
        # Find primary token (largest loss)
        primary_token = None
        primary_token_symbol = None
        if loss_by_token:
            primary_token = max(loss_by_token.items(), key=lambda x: x[1]["usd"])[0]
            primary_token_symbol = loss_by_token[primary_token]["symbol"]
        
        return {
            "loss_usd": total_loss_usd,
            "loss_by_token": {
                token: {
                    "amount": str(amount_info["amount"]),
                    "usd": str(amount_info["usd"]),
                    "symbol": amount_info["symbol"],
                }
                for token, amount_info in loss_by_token.items()
            },
            "primary_token": primary_token,
            "primary_token_symbol": primary_token_symbol,
        }
    
    @staticmethod
    def _get_token_symbol(token_address: str) -> str:
        """Get token symbol (simplified - would need contract call in real implementation)."""
        mapping = {
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
            "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
            "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
            "0x6b175474e89094c44da98b954eedecb4957d9b2": "DAI",
        }
        return mapping.get(token_address.lower(), "UNKNOWN")

