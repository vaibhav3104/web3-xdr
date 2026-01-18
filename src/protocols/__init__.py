"""
Protocol-specific Monitoring Module
===================================

Deep integration with major DeFi protocols:

LENDING:
- Aave V3: Lending/borrowing, liquidations, health factors
- Compound: Supply/borrow rates, liquidations
- MakerDAO: CDP management, DAI stability, emergency shutdown
- Spark: DAI-focused lending (MakerDAO ecosystem)
- Morpho: P2P lending optimizer

DEX:
- Uniswap: Swaps, liquidity, price impact
- Curve: Stablecoin swaps, gauge rewards
- Balancer: Multi-asset pools, flash loans
- SushiSwap: Swaps, MasterChef rewards
- PancakeSwap: BSC/multi-chain DEX

LIQUID STAKING:
- Lido: stETH minting, withdrawals, oracle reports
- Rocket Pool: rETH, minipool management
- EigenLayer: Restaking, operator slashing

BRIDGES:
- Wormhole: Cross-chain messaging, guardian monitoring
- LayerZero: Omnichain messaging, OFT transfers
- Stargate: Native asset bridge, pool liquidity
- Across: Fast bridge, relayer monitoring

DERIVATIVES:
- GMX: Perpetuals, GLP, liquidations
- dYdX: Perpetuals, forced trades
- Synthetix: Synth exchanges, liquidations

YIELD:
- Yearn: Vault strategies, emergency shutdown
- Convex: Curve yield boosting, CVX locking

Features:
- TVL monitoring
- Liquidation alerts
- Large transaction detection
- Protocol-specific risk scoring
- Governance action monitoring
"""

from .base import ProtocolMonitor, ProtocolConfig, ProtocolType, AlertType

# Lending
from .aave import AaveMonitor, aave_monitor
from .compound import CompoundMonitor, compound_monitor
from .makerdao import MakerDAOMonitor, makerdao_monitor
from .spark import SparkMonitor, spark_monitor
from .morpho import MorphoMonitor, morpho_monitor

# DEX
from .uniswap import UniswapMonitor, uniswap_monitor
from .curve import CurveMonitor, curve_monitor
from .balancer import BalancerMonitor, balancer_monitor
from .sushiswap import SushiSwapMonitor, sushiswap_monitor
from .pancakeswap import PancakeSwapMonitor, pancakeswap_monitor

# Liquid Staking
from .lido import LidoMonitor, lido_monitor
from .rocketpool import RocketPoolMonitor, rocketpool_monitor
from .eigenlayer import EigenLayerMonitor, eigenlayer_monitor

# Bridges
from .wormhole import WormholeMonitor, wormhole_monitor
from .layerzero import LayerZeroMonitor, layerzero_monitor
from .stargate import StargateMonitor, stargate_monitor
from .across import AcrossMonitor, across_monitor

# Derivatives
from .gmx import GMXMonitor, gmx_monitor
from .dydx import DYDXMonitor, dydx_monitor
from .synthetix import SynthetixMonitor, synthetix_monitor

# Yield
from .yearn import YearnMonitor, yearn_monitor
from .convex import ConvexMonitor, convex_monitor


__all__ = [
    # Base
    "ProtocolMonitor",
    "ProtocolConfig",
    "ProtocolType",
    "AlertType",
    
    # Lending
    "AaveMonitor", "aave_monitor",
    "CompoundMonitor", "compound_monitor",
    "MakerDAOMonitor", "makerdao_monitor",
    "SparkMonitor", "spark_monitor",
    "MorphoMonitor", "morpho_monitor",
    
    # DEX
    "UniswapMonitor", "uniswap_monitor",
    "CurveMonitor", "curve_monitor",
    "BalancerMonitor", "balancer_monitor",
    "SushiSwapMonitor", "sushiswap_monitor",
    "PancakeSwapMonitor", "pancakeswap_monitor",
    
    # Liquid Staking
    "LidoMonitor", "lido_monitor",
    "RocketPoolMonitor", "rocketpool_monitor",
    "EigenLayerMonitor", "eigenlayer_monitor",
    
    # Bridges
    "WormholeMonitor", "wormhole_monitor",
    "LayerZeroMonitor", "layerzero_monitor",
    "StargateMonitor", "stargate_monitor",
    "AcrossMonitor", "across_monitor",
    
    # Derivatives
    "GMXMonitor", "gmx_monitor",
    "DYDXMonitor", "dydx_monitor",
    "SynthetixMonitor", "synthetix_monitor",
    
    # Yield
    "YearnMonitor", "yearn_monitor",
    "ConvexMonitor", "convex_monitor",
]
