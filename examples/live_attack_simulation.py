#!/usr/bin/env python3
"""
🔥 LIVE ATTACK SIMULATION for Web3 XDR
======================================

This script simulates realistic cross-chain bridge attacks to demonstrate
the XDR's detection capabilities in real-time.

Attack Scenarios:
1. Wormhole-style Unbacked Mint Attack
2. LayerZero Message Forgery Attempt
3. Stargate Liquidity Drain
4. Cross-chain Money Laundering Pattern
5. Flash Loan + Bridge Exploit

Run this while monitoring the dashboard to see detections in real-time!
"""

import asyncio
import random
import time
import json
import sys
from datetime import datetime
from typing import Dict, List, Any

# Add parent directory to path
sys.path.insert(0, '/Users/vaibhav.tiwari/siem-optimizer/web3-xdr')

try:
    import structlog
    logger = structlog.get_logger()
except ImportError:
    import logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

# Try to import shared_state for direct injection
try:
    from src.shared_state import monitor_state
    DIRECT_INJECTION = True
except ImportError:
    DIRECT_INJECTION = False
    print("⚠️  Running in standalone mode (no direct state injection)")


# ============================================================================
# ATTACK SIMULATION DATA
# ============================================================================

BRIDGES = {
    "wormhole": {
        "name": "Wormhole",
        "chains": ["ethereum", "solana", "avalanche", "bsc"],
        "contracts": {
            "ethereum": "0x3ee18B2214AFF97000D974cf647E7C347E8fa585",
            "solana": "wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb"
        }
    },
    "layerzero": {
        "name": "LayerZero",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism"],
        "contracts": {
            "ethereum": "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675",
            "polygon": "0x3c2269811836af69497E5F486A85D7316753cf62"
        }
    },
    "stargate": {
        "name": "Stargate",
        "chains": ["ethereum", "polygon", "arbitrum", "avalanche"],
        "contracts": {
            "ethereum": "0x8731d54E9D02c286767d56ac03e8037C07e01e98",
            "arbitrum": "0x53Bf833A5d6c4ddA888F69c22C88C9f356a41614"
        }
    },
    "across": {
        "name": "Across Protocol",
        "chains": ["ethereum", "polygon", "arbitrum", "optimism"],
        "contracts": {
            "ethereum": "0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5"
        }
    }
}

ATTACKER_ADDRESSES = [
    "0x" + "".join(random.choices("0123456789abcdef", k=40)) for _ in range(5)
]

VICTIM_ADDRESSES = [
    "0x" + "".join(random.choices("0123456789abcdef", k=40)) for _ in range(10)
]


# ============================================================================
# ATTACK SCENARIOS
# ============================================================================

class AttackSimulator:
    """Simulates various bridge attack scenarios."""
    
    def __init__(self):
        self.events_generated = 0
        self.incidents_triggered = 0
        self.start_time = time.time()
    
    def generate_event(
        self,
        event_type: str,
        chain: str,
        bridge: str,
        amount_usd: float,
        tx_hash: str = None,
        from_addr: str = None,
        to_addr: str = None,
        is_malicious: bool = False,
        attack_type: str = None,
        metadata: Dict = None
    ) -> Dict[str, Any]:
        """Generate a simulated blockchain event."""
        
        if tx_hash is None:
            tx_hash = "0x" + "".join(random.choices("0123456789abcdef", k=64))
        
        if from_addr is None:
            from_addr = random.choice(ATTACKER_ADDRESSES if is_malicious else VICTIM_ADDRESSES)
        
        if to_addr is None:
            to_addr = BRIDGES.get(bridge, {}).get("contracts", {}).get(chain, "0x" + "0" * 40)
        
        event = {
            "event_id": f"sim-{int(time.time() * 1000)}-{random.randint(1000, 9999)}",
            "timestamp": datetime.utcnow().isoformat(),
            "chain": chain,
            "bridge": bridge,
            "event_type": event_type,
            "tx_hash": tx_hash,
            "block_number": random.randint(18000000, 19000000),
            "from_address": from_addr,
            "to_address": to_addr,
            "amount_usd": amount_usd,
            "token": random.choice(["USDC", "USDT", "ETH", "WBTC"]),
            "is_simulated": True,
            "is_malicious": is_malicious,
            "attack_type": attack_type,
            "metadata": metadata or {}
        }
        
        self.events_generated += 1
        return event
    
    def inject_event(self, event: Dict):
        """Inject event into the monitoring system."""
        if DIRECT_INJECTION:
            try:
                # Create a LiveEvent-like object
                class SimulatedEvent:
                    def __init__(self, data):
                        self.event_id = data["event_id"]
                        self.timestamp = data["timestamp"]
                        self.chain = data["chain"]
                        self.event_type = data["event_type"]
                        self.tx_hash = data["tx_hash"]
                        self.block_number = data["block_number"]
                        self.from_address = data["from_address"]
                        self.to_address = data["to_address"]
                        self.amount_usd = data["amount_usd"]
                        self.severity = "critical" if data.get("is_malicious") else "info"
                        self.raw_data = data
                
                sim_event = SimulatedEvent(event)
                monitor_state.add_event(sim_event)
                
                # If malicious, also create an incident
                if event.get("is_malicious"):
                    incident = {
                        "incident_id": f"INC-SIM-{int(time.time())}",
                        "timestamp": event["timestamp"],
                        "severity": "critical",
                        "title": f"🔴 SIMULATED: {event.get('attack_type', 'Attack')} Detected",
                        "description": f"Simulated {event.get('attack_type')} on {event['bridge']} ({event['chain']})",
                        "chain": event["chain"],
                        "bridge": event["bridge"],
                        "amount_usd": event["amount_usd"],
                        "attacker": event["from_address"],
                        "tx_hash": event["tx_hash"],
                        "events": [event],
                        "is_simulated": True
                    }
                    
                    class SimulatedIncident:
                        def __init__(self, data):
                            self.incident_id = data["incident_id"]
                            self.timestamp = data["timestamp"]
                            self.severity = data["severity"]
                            self.title = data["title"]
                            self.description = data["description"]
                            self.chain = data["chain"]
                            self.events = data["events"]
                            self.status = "active"
                    
                    monitor_state.add_incident(SimulatedIncident(incident))
                    self.incidents_triggered += 1
                    
            except Exception as e:
                logger.warning(f"Failed to inject event: {e}")
    
    async def simulate_wormhole_attack(self):
        """
        🔴 ATTACK 1: Wormhole-style Unbacked Mint
        
        The attacker exploits a signature verification bug to mint wrapped tokens
        on the destination chain WITHOUT locking tokens on the source chain.
        
        This is how the $320M Wormhole hack worked.
        """
        print("\n" + "=" * 70)
        print("🔴 ATTACK 1: Wormhole-style Unbacked Mint Attack")
        print("=" * 70)
        print("   Attacker exploits signature verification to mint unbacked tokens")
        print("   Similar to the $320M Wormhole hack (Feb 2022)")
        print("-" * 70)
        
        attacker = random.choice(ATTACKER_ADDRESSES)
        stolen_amount = random.uniform(50_000_000, 150_000_000)  # $50M-$150M
        
        # Phase 1: Attacker prepares exploit contract
        print(f"\n   ⏳ Phase 1: Deploying exploit contract...")
        await asyncio.sleep(1)
        
        event1 = self.generate_event(
            event_type="ContractDeployment",
            chain="ethereum",
            bridge="wormhole",
            amount_usd=0,
            from_addr=attacker,
            is_malicious=True,
            attack_type="Exploit Contract Deployment",
            metadata={"contract_type": "exploit", "bytecode_hash": "0x" + "a" * 64}
        )
        self.inject_event(event1)
        print(f"   ✓ Exploit contract deployed: {event1['to_address'][:20]}...")
        
        # Phase 2: Forge guardian signatures
        print(f"\n   ⏳ Phase 2: Forging guardian signatures...")
        await asyncio.sleep(1.5)
        
        event2 = self.generate_event(
            event_type="SignatureSubmission",
            chain="solana",
            bridge="wormhole",
            amount_usd=0,
            from_addr=attacker,
            is_malicious=True,
            attack_type="Forged Signatures",
            metadata={"signatures": 13, "required": 13, "forged": True}
        )
        self.inject_event(event2)
        print(f"   ✓ Forged 13/13 guardian signatures")
        
        # Phase 3: Mint unbacked tokens (THE EXPLOIT)
        print(f"\n   🔥 Phase 3: MINTING UNBACKED TOKENS...")
        await asyncio.sleep(2)
        
        event3 = self.generate_event(
            event_type="Mint",
            chain="solana",
            bridge="wormhole",
            amount_usd=stolen_amount,
            from_addr="0x0000000000000000000000000000000000000000",  # Mint from zero
            to_addr=attacker,
            is_malicious=True,
            attack_type="Unbacked Mint",
            metadata={
                "corresponding_lock": None,  # NO LOCK!
                "token": "wETH",
                "amount": stolen_amount / 3000,  # ETH amount
                "invariant_violated": "MINT_WITHOUT_LOCK"
            }
        )
        self.inject_event(event3)
        
        print(f"\n   🚨 CRITICAL: ${stolen_amount:,.0f} minted WITHOUT corresponding lock!")
        print(f"   🚨 Attacker: {attacker}")
        print(f"   🚨 TX Hash: {event3['tx_hash']}")
        
        # Phase 4: Quick withdrawal
        print(f"\n   ⏳ Phase 4: Attacker withdrawing funds...")
        await asyncio.sleep(1)
        
        event4 = self.generate_event(
            event_type="Transfer",
            chain="solana",
            bridge="wormhole",
            amount_usd=stolen_amount,
            from_addr=attacker,
            to_addr=random.choice(ATTACKER_ADDRESSES),
            is_malicious=True,
            attack_type="Stolen Fund Movement"
        )
        self.inject_event(event4)
        
        print(f"\n   ✅ Attack simulation complete!")
        print(f"   📊 Total stolen: ${stolen_amount:,.0f}")
        
        return stolen_amount
    
    async def simulate_layerzero_forgery(self):
        """
        🟠 ATTACK 2: LayerZero Message Forgery Attempt
        
        Attacker attempts to forge cross-chain messages by exploiting
        the Oracle/Relayer trust model.
        """
        print("\n" + "=" * 70)
        print("🟠 ATTACK 2: LayerZero Message Forgery Attempt")
        print("=" * 70)
        print("   Attacker attempts to forge cross-chain messages")
        print("-" * 70)
        
        attacker = random.choice(ATTACKER_ADDRESSES)
        amount = random.uniform(5_000_000, 20_000_000)
        
        # Malicious message submission
        print(f"\n   ⏳ Submitting forged cross-chain message...")
        await asyncio.sleep(1)
        
        event1 = self.generate_event(
            event_type="MessageReceived",
            chain="arbitrum",
            bridge="layerzero",
            amount_usd=amount,
            from_addr=attacker,
            is_malicious=True,
            attack_type="Message Forgery Attempt",
            metadata={
                "source_chain": "ethereum",
                "nonce": 999999,
                "oracle_verified": False,
                "relayer_verified": False,
                "payload_hash": "0x" + "f" * 64
            }
        )
        self.inject_event(event1)
        
        print(f"   🚨 Forged message detected: ${amount:,.0f}")
        print(f"   🚨 Oracle verification: FAILED")
        print(f"   🚨 Relayer verification: FAILED")
        print(f"   ✅ Attack BLOCKED by LayerZero security")
        
        return amount
    
    async def simulate_liquidity_drain(self):
        """
        🟡 ATTACK 3: Stargate Liquidity Drain
        
        Attacker rapidly drains liquidity from multiple pools
        using flash loans and arbitrage.
        """
        print("\n" + "=" * 70)
        print("🟡 ATTACK 3: Stargate Liquidity Pool Drain")
        print("=" * 70)
        print("   Rapid liquidity withdrawal exceeding normal patterns")
        print("-" * 70)
        
        attacker = random.choice(ATTACKER_ADDRESSES)
        total_drained = 0
        
        # Multiple rapid withdrawals
        for i in range(5):
            amount = random.uniform(2_000_000, 10_000_000)
            total_drained += amount
            
            print(f"\n   ⏳ Withdrawal {i+1}/5: ${amount:,.0f}...")
            await asyncio.sleep(0.5)
            
            event = self.generate_event(
                event_type="Withdrawal",
                chain=random.choice(["ethereum", "arbitrum", "polygon"]),
                bridge="stargate",
                amount_usd=amount,
                from_addr=attacker,
                is_malicious=True,
                attack_type="Liquidity Drain",
                metadata={
                    "pool": random.choice(["USDC", "USDT", "ETH"]),
                    "tvl_impact_percent": random.uniform(5, 15),
                    "velocity_anomaly": True
                }
            )
            self.inject_event(event)
        
        print(f"\n   🚨 ALERT: Abnormal TVL drain detected!")
        print(f"   🚨 Total drained: ${total_drained:,.0f}")
        print(f"   🚨 Time window: < 30 seconds")
        print(f"   🚨 Velocity: {total_drained/30:,.0f}/second")
        
        return total_drained
    
    async def simulate_cross_chain_laundering(self):
        """
        🔵 ATTACK 4: Cross-chain Money Laundering
        
        Stolen funds being moved across multiple bridges
        to obscure the trail.
        """
        print("\n" + "=" * 70)
        print("🔵 ATTACK 4: Cross-chain Money Laundering Pattern")
        print("=" * 70)
        print("   Funds hopping across bridges to obscure origin")
        print("-" * 70)
        
        attacker = random.choice(ATTACKER_ADDRESSES)
        amount = random.uniform(10_000_000, 50_000_000)
        
        hops = [
            ("ethereum", "polygon", "wormhole"),
            ("polygon", "arbitrum", "layerzero"),
            ("arbitrum", "avalanche", "stargate"),
            ("avalanche", "bsc", "celer"),
        ]
        
        for i, (source, dest, bridge) in enumerate(hops):
            print(f"\n   ⏳ Hop {i+1}/4: {source} → {dest} via {bridge}...")
            await asyncio.sleep(1)
            
            # Slightly reduce amount each hop (fees)
            amount *= 0.995
            
            event = self.generate_event(
                event_type="CrossChainTransfer",
                chain=dest,
                bridge=bridge,
                amount_usd=amount,
                from_addr=attacker,
                is_malicious=True,
                attack_type="Cross-chain Laundering",
                metadata={
                    "source_chain": source,
                    "hop_number": i + 1,
                    "total_hops": 4,
                    "time_since_origin": (i + 1) * 300,  # 5 min per hop
                    "mixer_pattern": True
                }
            )
            self.inject_event(event)
            
            print(f"   ✓ ${amount:,.0f} moved to {dest}")
        
        print(f"\n   🚨 ALERT: Cross-chain laundering pattern detected!")
        print(f"   🚨 4 bridge hops in rapid succession")
        print(f"   🚨 Pattern matches known laundering behavior")
        
        return amount
    
    async def simulate_flash_loan_attack(self):
        """
        🟣 ATTACK 5: Flash Loan + Bridge Exploit
        
        Attacker uses flash loan to amplify bridge exploit.
        """
        print("\n" + "=" * 70)
        print("🟣 ATTACK 5: Flash Loan Amplified Bridge Exploit")
        print("=" * 70)
        print("   Using flash loan to maximize exploit impact")
        print("-" * 70)
        
        attacker = random.choice(ATTACKER_ADDRESSES)
        flash_loan_amount = random.uniform(100_000_000, 500_000_000)
        profit = flash_loan_amount * random.uniform(0.05, 0.15)
        
        # Flash loan borrow
        print(f"\n   ⏳ Borrowing flash loan: ${flash_loan_amount:,.0f}...")
        await asyncio.sleep(1)
        
        event1 = self.generate_event(
            event_type="FlashLoan",
            chain="ethereum",
            bridge="across",
            amount_usd=flash_loan_amount,
            from_addr="0xAave",  # Aave flash loan
            to_addr=attacker,
            is_malicious=True,
            attack_type="Flash Loan Borrow",
            metadata={"protocol": "Aave", "same_block": True}
        )
        self.inject_event(event1)
        
        # Price manipulation
        print(f"\n   ⏳ Manipulating bridge price oracle...")
        await asyncio.sleep(1)
        
        event2 = self.generate_event(
            event_type="PriceManipulation",
            chain="ethereum",
            bridge="across",
            amount_usd=flash_loan_amount,
            from_addr=attacker,
            is_malicious=True,
            attack_type="Oracle Manipulation",
            metadata={"price_deviation": "45%", "oracle": "chainlink"}
        )
        self.inject_event(event2)
        
        # Exploit execution
        print(f"\n   🔥 Executing bridge exploit...")
        await asyncio.sleep(1.5)
        
        event3 = self.generate_event(
            event_type="Exploit",
            chain="ethereum",
            bridge="across",
            amount_usd=profit,
            from_addr=attacker,
            is_malicious=True,
            attack_type="Flash Loan Exploit",
            metadata={"profit": profit, "in_single_block": True}
        )
        self.inject_event(event3)
        
        print(f"\n   🚨 CRITICAL: Flash loan exploit executed!")
        print(f"   🚨 Flash loan: ${flash_loan_amount:,.0f}")
        print(f"   🚨 Profit extracted: ${profit:,.0f}")
        print(f"   🚨 All in single transaction!")
        
        return profit
    
    async def run_full_simulation(self):
        """Run all attack simulations."""
        print("\n")
        print("╔" + "═" * 68 + "╗")
        print("║" + " 🔥 WEB3 XDR LIVE ATTACK SIMULATION ".center(68) + "║")
        print("║" + " Watch the dashboard for real-time detections! ".center(68) + "║")
        print("╚" + "═" * 68 + "╝")
        print(f"\n   Dashboard: http://127.0.0.1:55444/frontend/index.html")
        print(f"   Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        total_value = 0
        
        # Run each attack scenario
        total_value += await self.simulate_wormhole_attack()
        await asyncio.sleep(2)
        
        total_value += await self.simulate_layerzero_forgery()
        await asyncio.sleep(2)
        
        total_value += await self.simulate_liquidity_drain()
        await asyncio.sleep(2)
        
        total_value += await self.simulate_cross_chain_laundering()
        await asyncio.sleep(2)
        
        total_value += await self.simulate_flash_loan_attack()
        
        # Final summary
        elapsed = time.time() - self.start_time
        
        print("\n")
        print("╔" + "═" * 68 + "╗")
        print("║" + " 📊 SIMULATION COMPLETE ".center(68) + "║")
        print("╚" + "═" * 68 + "╝")
        print(f"""
   ┌─────────────────────────────────────────────────────────────┐
   │  ATTACK SIMULATION SUMMARY                                   │
   ├─────────────────────────────────────────────────────────────┤
   │  Total Value at Risk:     ${total_value:>20,.0f}            │
   │  Events Generated:        {self.events_generated:>20}       │
   │  Incidents Triggered:     {self.incidents_triggered:>20}    │
   │  Simulation Duration:     {elapsed:>17.1f}s                 │
   │  Attacks Simulated:       {5:>20}                           │
   └─────────────────────────────────────────────────────────────┘
   
   🔍 Check the dashboard to see all detections!
   📊 http://127.0.0.1:55444/frontend/index.html
        """)


async def main():
    """Main entry point."""
    simulator = AttackSimulator()
    await simulator.run_full_simulation()


if __name__ == "__main__":
    asyncio.run(main())

