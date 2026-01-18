"""
Protocol-specific Monitoring Module
===================================

Deep integration with major DeFi protocols:
- Aave: Lending/borrowing, liquidations, health factors
- Uniswap: Swaps, liquidity, price impact
- Compound: Supply/borrow rates, liquidations
- MakerDAO: CDP management, stability fees
- Curve: Stable swaps, gauge rewards
- Lido: Staking, withdrawals

Features:
- TVL monitoring
- Liquidation alerts
- Large transaction detection
- Protocol-specific risk scoring
"""

from .base import ProtocolMonitor, ProtocolConfig
from .aave import AaveMonitor
from .uniswap import UniswapMonitor
from .compound import CompoundMonitor

__all__ = [
    "ProtocolMonitor",
    "ProtocolConfig",
    "AaveMonitor",
    "UniswapMonitor",
    "CompoundMonitor",
]
