"""
Uniswap Protocol Monitor
========================

Deep integration with Uniswap V2/V3:
- Large swap detection
- Price impact alerts
- Liquidity changes
- Pool imbalance detection
- MEV/sandwich attack detection
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import structlog

from .base import (
    ProtocolMonitor,
    ProtocolConfig,
    ProtocolType,
    ProtocolMetrics,
    ProtocolAlert,
    AlertType,
)

logger = structlog.get_logger(__name__)


# Uniswap V3 Event Signatures
UNISWAP_V3_EVENTS = {
    # Swap
    "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67": "Swap",
    # Mint (add liquidity)
    "0x7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde": "Mint",
    # Burn (remove liquidity)
    "0x0c396cd989a39f4459b5fa1aed6a9a8dcdbc45908acfd67e028cd568da98982c": "Burn",
    # Collect (fees)
    "0x70935338e69775456a85ddef226c395fb668b63fa0115f5f20610b388e6ca9c0": "Collect",
    # Flash
    "0xbdbdb71d7860376ba52b25a5028beea23581364a40522f6bcfb86bb1f2dca633": "Flash",
    # PoolCreated
    "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118": "PoolCreated",
}

# Uniswap V2 Event Signatures
UNISWAP_V2_EVENTS = {
    # Swap
    "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822": "Swap",
    # Mint
    "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f": "Mint",
    # Burn
    "0xdccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496": "Burn",
    # Sync
    "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1": "Sync",
}

# Uniswap Factory/Router addresses
UNISWAP_CONTRACTS = {
    "ethereum": {
        "v3_factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "v3_router": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
        "v2_factory": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
        "v2_router": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    },
    "polygon": {
        "v3_factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "v3_router": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    },
    "arbitrum": {
        "v3_factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "v3_router": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    },
    "optimism": {
        "v3_factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "v3_router": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    },
    "base": {
        "v3_factory": "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
        "v3_router": "0x2626664c2603336E57B271c5C0b26F421741e481",
    },
}


class UniswapMonitor(ProtocolMonitor):
    """
    Uniswap Protocol Monitor.
    
    Monitors:
    - Large swaps
    - High price impact trades
    - Liquidity additions/removals
    - Pool imbalances
    - Potential sandwich attacks
    """
    
    def __init__(self):
        config = ProtocolConfig(
            protocol_id="uniswap",
            protocol_name="Uniswap",
            protocol_type=ProtocolType.DEX,
            chains=["ethereum", "polygon", "arbitrum", "optimism", "base"],
            contracts=UNISWAP_CONTRACTS,
            large_tx_threshold_usd=50000,
            price_impact_warning=1.0,
            price_impact_critical=5.0,
        )
        super().__init__(config)
        
        # Track recent swaps for sandwich detection
        self._recent_swaps: Dict[str, list] = {}  # pool -> [swap_data]
        
        # Track pool states
        self._pool_states: Dict[str, Dict[str, Any]] = {}
    
    def get_event_signatures(self) -> Dict[str, str]:
        """Get Uniswap event signatures."""
        return {**UNISWAP_V3_EVENTS, **UNISWAP_V2_EVENTS}
    
    async def process_event(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        block_timestamp: datetime
    ) -> Optional[ProtocolAlert]:
        """Process Uniswap event."""
        self._stats["events_processed"] += 1
        
        topics = event_data.get("topics", [])
        if not topics:
            return None
        
        topic0 = topics[0]
        if isinstance(topic0, bytes):
            topic0 = "0x" + topic0.hex()
        
        # Check V3 events first
        event_name = UNISWAP_V3_EVENTS.get(topic0.lower())
        version = "v3"
        
        if not event_name:
            event_name = UNISWAP_V2_EVENTS.get(topic0.lower())
            version = "v2"
        
        if not event_name:
            return None
        
        tx_hash = event_data.get("transactionHash", "")
        if isinstance(tx_hash, bytes):
            tx_hash = "0x" + tx_hash.hex()
        
        block_number = event_data.get("blockNumber", 0)
        pool_address = event_data.get("address", "")
        
        # Route to specific handler
        if event_name == "Swap":
            return await self._handle_swap(event_data, chain_id, tx_hash, block_number, block_timestamp, version, pool_address)
        elif event_name == "Mint":
            return await self._handle_mint(event_data, chain_id, tx_hash, block_number, block_timestamp, version, pool_address)
        elif event_name == "Burn":
            return await self._handle_burn(event_data, chain_id, tx_hash, block_number, block_timestamp, version, pool_address)
        elif event_name == "Flash":
            return await self._handle_flash(event_data, chain_id, tx_hash, block_number, block_timestamp, pool_address)
        
        return None
    
    def _decode_swap_amounts(self, data: str, version: str) -> Dict[str, int]:
        """Decode swap amounts from event data bytes."""
        if isinstance(data, bytes):
            data = "0x" + data.hex()

        data = data.replace("0x", "")
        if len(data) < 128:
            return {}

        if version == "v3":
            # V3 Swap: amount0 (int256), amount1 (int256), sqrtPriceX96 (uint160),
            #          liquidity (uint128), tick (int24)
            amount0 = int.from_bytes(bytes.fromhex(data[0:64]), "big", signed=True)
            amount1 = int.from_bytes(bytes.fromhex(data[64:128]), "big", signed=True)
            sqrt_price = int(data[128:192], 16) if len(data) >= 192 else 0
            return {"amount0": amount0, "amount1": amount1, "sqrtPriceX96": sqrt_price}
        else:
            # V2 Swap: amount0In, amount1In, amount0Out, amount1Out (all uint256)
            a0_in = int(data[0:64], 16)
            a1_in = int(data[64:128], 16)
            a0_out = int(data[128:192], 16) if len(data) >= 192 else 0
            a1_out = int(data[192:256], 16) if len(data) >= 256 else 0
            return {"amount0In": a0_in, "amount1In": a1_in,
                    "amount0Out": a0_out, "amount1Out": a1_out}

    def _estimate_value_from_amounts(self, amounts: Dict[str, int]) -> float:
        """Estimate USD value from decoded amounts (uses 18-decimal ETH ~ $3000 heuristic)."""
        # Heuristic: take the larger absolute amount, assume 18 decimals and ~$3000/ETH
        ETH_PRICE_ESTIMATE = 3000.0
        vals = [abs(v) for v in amounts.values() if isinstance(v, int)]
        if not vals:
            return 0.0
        max_val = max(vals)
        # Normalize to 18-decimal tokens and multiply by ETH price
        return (max_val / 1e18) * ETH_PRICE_ESTIMATE

    def _detect_sandwich(self, pool_address: str, current_swap: Dict) -> Optional[Dict]:
        """
        Detect sandwich attack pattern in recent swaps for the same pool.

        Pattern: within the same block, 3 swaps where:
        1. Attacker swap (front-run) — same direction as victim
        2. Victim swap (large, pushed to worse price)
        3. Attacker swap (back-run) — opposite direction, extracting profit
        """
        recent = self._recent_swaps.get(pool_address, [])
        if len(recent) < 3:
            return None

        block = current_swap["block_number"]
        same_block = [s for s in recent if s["block_number"] == block]

        if len(same_block) < 3:
            return None

        # Check for A-B-A sender pattern (attacker-victim-attacker)
        for i in range(len(same_block) - 2):
            s1, s2, s3 = same_block[i], same_block[i + 1], same_block[i + 2]

            if (s1["sender"] == s3["sender"]
                    and s1["sender"] != s2["sender"]
                    and s1["tx_hash"] != s2["tx_hash"]
                    and s2["tx_hash"] != s3["tx_hash"]):
                return {
                    "attacker": s1["sender"],
                    "victim": s2["sender"],
                    "victim_tx": s2["tx_hash"],
                    "frontrun_tx": s1["tx_hash"],
                    "backrun_tx": s3["tx_hash"],
                    "victim_value_usd": s2["value_usd"],
                }

        return None

    async def _handle_swap(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        version: str,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle swap event — decode amounts, detect large swaps, price impact, and sandwiches."""
        topics = event_data.get("topics", [])
        data = event_data.get("data", "0x")

        # Parse sender/recipient
        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]

        # Decode actual swap amounts
        amounts = self._decode_swap_amounts(data, version)
        estimated_value_usd = self._estimate_value_from_amounts(amounts)

        # Compute price impact from V3 sqrtPriceX96 delta
        price_impact_percent = 0.0
        if version == "v3" and amounts.get("sqrtPriceX96"):
            pool_state = self._pool_states.get(pool_address, {})
            prev_price = pool_state.get("sqrtPriceX96", 0)
            new_price = amounts["sqrtPriceX96"]
            if prev_price and new_price:
                price_impact_percent = abs(new_price - prev_price) / max(prev_price, 1) * 100
            self._pool_states.setdefault(pool_address, {})["sqrtPriceX96"] = new_price

        # Track for sandwich detection
        swap_data = {
            "tx_hash": tx_hash,
            "block_number": block_number,
            "sender": sender,
            "value_usd": estimated_value_usd,
            "timestamp": block_timestamp,
            "amounts": amounts,
        }

        if pool_address not in self._recent_swaps:
            self._recent_swaps[pool_address] = []
        self._recent_swaps[pool_address].append(swap_data)
        self._recent_swaps[pool_address] = self._recent_swaps[pool_address][-200:]

        # --- Sandwich attack detection ---
        sandwich = self._detect_sandwich(pool_address, swap_data)
        if sandwich:
            self._stats.setdefault("sandwiches_detected", 0)
            self._stats["sandwiches_detected"] += 1
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.PRICE_IMPACT,
                severity="critical",
                title=f"Sandwich Attack on Uniswap {version.upper()} — {chain_id.title()}",
                description=(
                    f"Sandwich attack detected on pool {pool_address[:10]}... "
                    f"Attacker {sandwich['attacker'][:10]}... sandwiched victim "
                    f"{sandwich['victim'][:10]}... for ~${sandwich['victim_value_usd']:,.0f}"
                ),
                tx_hash=sandwich["victim_tx"],
                block_number=block_number,
                value_usd=sandwich["victim_value_usd"],
                affected_address=sandwich["victim"],
                affected_pool=pool_address,
                metadata={
                    "event_type": "sandwich_attack",
                    "version": version,
                    **sandwich,
                },
            )

        # --- High price impact ---
        if price_impact_percent >= self.config.price_impact_critical:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.PRICE_IMPACT,
                severity="critical",
                title=f"High Price Impact Swap on Uniswap {version.upper()}",
                description=f"Swap with {price_impact_percent:.2f}% price impact detected. "
                           f"Value: ${estimated_value_usd:,.0f}",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                affected_pool=pool_address,
                metadata={
                    "event_type": "swap",
                    "version": version,
                    "price_impact_percent": price_impact_percent,
                    "amounts": {k: str(v) for k, v in amounts.items()},
                }
            )

        # --- Large swap ---
        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            self._stats["large_txs_detected"] += 1

            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="medium",
                title=f"Large Uniswap {version.upper()} Swap on {chain_id.title()}",
                description=f"Large swap detected: ${estimated_value_usd:,.0f} by {sender[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=sender,
                affected_pool=pool_address,
                metadata={
                    "event_type": "swap",
                    "version": version,
                    "amounts": {k: str(v) for k, v in amounts.items()},
                }
            )

        return None
    
    async def _handle_mint(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        version: str,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle liquidity addition — decode amounts from event data."""
        topics = event_data.get("topics", [])
        data = event_data.get("data", "0x")

        owner = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(owner, bytes):
            owner = "0x" + owner.hex()[-40:]
        elif isinstance(owner, str) and len(owner) == 66:
            owner = "0x" + owner[-40:]

        # Decode amount from data (V3 Mint: sender, amount, amount0, amount1)
        if isinstance(data, bytes):
            data = "0x" + data.hex()
        data_hex = data.replace("0x", "")

        estimated_value_usd = 0.0
        if len(data_hex) >= 192:
            amount0 = int(data_hex[64:128], 16)
            amount1 = int(data_hex[128:192], 16)
            estimated_value_usd = max(amount0, amount1) / 1e18 * 3000.0

        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.LARGE_TRANSACTION,
                severity="low",
                title=f"Large Liquidity Addition on Uniswap {version.upper()}",
                description=f"Large LP position created: ${estimated_value_usd:,.0f} by {owner[:10]}...",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=owner,
                affected_pool=pool_address,
                metadata={
                    "event_type": "add_liquidity",
                    "version": version,
                }
            )

        return None
    
    async def _handle_burn(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        version: str,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle liquidity removal — decode amounts, detect rug-pull patterns."""
        topics = event_data.get("topics", [])
        data = event_data.get("data", "0x")

        owner = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(owner, bytes):
            owner = "0x" + owner.hex()[-40:]
        elif isinstance(owner, str) and len(owner) == 66:
            owner = "0x" + owner[-40:]

        # Decode amounts
        if isinstance(data, bytes):
            data = "0x" + data.hex()
        data_hex = data.replace("0x", "")

        estimated_value_usd = 0.0
        amount0 = amount1 = 0
        if len(data_hex) >= 128:
            amount0 = int(data_hex[0:64], 16)
            amount1 = int(data_hex[64:128], 16)
            estimated_value_usd = max(amount0, amount1) / 1e18 * 3000.0

        # Rug pull heuristic: if removal is >80% of tracked pool reserves
        severity = "medium"
        potential_rug = False
        pool_state = self._pool_states.get(pool_address, {})
        tracked_tvl = pool_state.get("tvl_estimate", 0)
        if tracked_tvl > 0 and estimated_value_usd > tracked_tvl * 0.8:
            severity = "critical"
            potential_rug = True

        if estimated_value_usd >= self.config.large_tx_threshold_usd:
            return await self.create_alert(
                chain_id=chain_id,
                alert_type=AlertType.WITHDRAWAL_SURGE,
                severity=severity,
                title=f"{'POTENTIAL RUG PULL: ' if potential_rug else ''}Large Liquidity Removal on Uniswap {version.upper()}",
                description=f"Large LP withdrawal: ${estimated_value_usd:,.0f} by {owner[:10]}... "
                           f"{'This is >80% of pool TVL — high rug-pull risk.' if potential_rug else ''}",
                tx_hash=tx_hash,
                block_number=block_number,
                value_usd=estimated_value_usd,
                affected_address=owner,
                affected_pool=pool_address,
                metadata={
                    "event_type": "remove_liquidity",
                    "version": version,
                    "potential_rug_pull": potential_rug,
                    "amount0": str(amount0),
                    "amount1": str(amount1),
                }
            )

        return None
    
    async def _handle_flash(
        self,
        event_data: Dict[str, Any],
        chain_id: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: datetime,
        pool_address: str
    ) -> Optional[ProtocolAlert]:
        """Handle flash loan from Uniswap V3 — decode actual borrowed amounts."""
        topics = event_data.get("topics", [])
        data = event_data.get("data", "0x")

        sender = topics[1] if len(topics) > 1 else "unknown"
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()[-40:]
        elif isinstance(sender, str) and len(sender) == 66:
            sender = "0x" + sender[-40:]

        # V3 Flash: sender(indexed), recipient(indexed), amount0, amount1, paid0, paid1
        if isinstance(data, bytes):
            data = "0x" + data.hex()
        data_hex = data.replace("0x", "")

        amount0 = amount1 = 0
        if len(data_hex) >= 128:
            amount0 = int(data_hex[0:64], 16)
            amount1 = int(data_hex[64:128], 16)

        estimated_value_usd = max(amount0, amount1) / 1e18 * 3000.0

        # Flash loans are always noteworthy — they precede complex atomic operations
        severity = "high" if estimated_value_usd > 500_000 else "medium"

        return await self.create_alert(
            chain_id=chain_id,
            alert_type=AlertType.LARGE_TRANSACTION,
            severity=severity,
            title=f"Uniswap V3 Flash Loan on {chain_id.title()}",
            description=f"Flash loan: ${estimated_value_usd:,.0f} by {sender[:10]}... "
                       f"(amount0={amount0/1e18:.2f}, amount1={amount1/1e18:.2f})",
            tx_hash=tx_hash,
            block_number=block_number,
            value_usd=estimated_value_usd,
            affected_address=sender,
            affected_pool=pool_address,
            metadata={
                "event_type": "flash",
                "version": "v3",
                "is_flashloan": True,
                "amount0": str(amount0),
                "amount1": str(amount1),
            }
        )
    
    async def get_metrics(self, chain_id: str) -> ProtocolMetrics:
        """Get current Uniswap metrics for a chain."""
        return ProtocolMetrics(
            protocol_id=self.config.protocol_id,
            chain_id=chain_id,
            timestamp=datetime.now(timezone.utc),
            tvl_usd=0,  # Would fetch from subgraph
            volume_24h_usd=0,
            fees_24h_usd=0,
        )


# Global instance
uniswap_monitor = UniswapMonitor()
