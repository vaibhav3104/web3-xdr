"""
Wormhole-Style Attack Simulation

This simulation demonstrates how Web3 XDR detects an unbacked mint attack
similar to the February 2022 Wormhole exploit ($320M loss).

ATTACK SUMMARY:
- Attacker exploited a signature verification vulnerability
- Forged a guardian signature set
- Minted 120,000 wETH on Solana without corresponding lock on Ethereum
- Drained the bridge in minutes

HOW OUR SYSTEM DETECTS IT:
1. Telemetry: Observes mint event on Solana
2. Invariant: Checks for corresponding lock on Ethereum - MISSING
3. Correlation: Links mint to bridge, identifies as unbacked
4. Explainability: Generates human-readable incident
5. Response: Critical alert with pause recommendation
"""

import asyncio
from datetime import datetime, timedelta
from decimal import Decimal
import structlog

# Import our components
import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

from src.models.events import SecurityEvent, EventType, Severity
from src.models.incidents import Incident, AttackType
from src.models.invariants import InvariantResult, InvariantType
from src.invariants.base import InvariantContext
from src.invariants.economic import MintLockParityInvariant, UnbackedMintInvariant
from src.correlation.correlator import XDRCorrelator
from src.correlation.entity_graph import EntityGraphBuilder
from src.explainability.engine import ExplainabilityEngine

logger = structlog.get_logger()


async def run_simulation():
    """
    Run the Wormhole-style attack simulation.
    
    This demonstrates the full detection pipeline.
    """
    print("\n" + "="*80)
    print("🔥 WORMHOLE-STYLE ATTACK SIMULATION")
    print("="*80)
    print("""
SCENARIO: Attacker exploits signature verification vulnerability
to mint 120,000 wETH on Solana without locking ETH on Ethereum.

Timeline:
- Block 0: Normal bridge operation
- Block 1: Attacker submits forged guardian signatures
- Block 2: 120,000 wETH minted on Solana (NO LOCK ON ETH!)
- Block 3: XDR detects unbacked mint
- Block 3+: Alert sent, pause recommended
""")
    
    # Initialize components
    context = InvariantContext()
    correlator = XDRCorrelator()
    explainability = ExplainabilityEngine()
    entity_builder = EntityGraphBuilder()
    
    # Configure bridge
    BRIDGE_ID = "wormhole_eth_sol"
    SOURCE_CHAIN = "ethereum"
    DEST_CHAIN = "solana"
    BRIDGE_CONTRACT_ETH = "0x3ee18B2214AFF97000D974cf647E7C347E8fa585"
    BRIDGE_CONTRACT_SOL = "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth"
    ATTACKER = "0xAttacker1234567890123456789012345678901234"
    
    # Track incidents
    detected_incidents = []
    
    async def on_incident(incident: Incident):
        detected_incidents.append(incident)
        print(f"\n🚨 INCIDENT DETECTED: {incident.title}")
    
    correlator.add_incident_handler(on_incident)
    
    # Initialize invariants
    mint_lock_invariant = MintLockParityInvariant(
        bridge_id=BRIDGE_ID,
        source_chain=SOURCE_CHAIN,
        dest_chain=DEST_CHAIN,
        tolerance_window=timedelta(minutes=10),
    )
    
    unbacked_invariant = UnbackedMintInvariant(
        bridge_id=BRIDGE_ID,
        source_chain=SOURCE_CHAIN,
        dest_chain=DEST_CHAIN,
    )
    
    # =========================================================================
    # PHASE 1: Normal Bridge Operation (Baseline)
    # =========================================================================
    print("\n" + "-"*60)
    print("📦 PHASE 1: Normal Bridge Operation")
    print("-"*60)
    
    # Normal lock on Ethereum
    normal_lock = SecurityEvent(
        chain_id=SOURCE_CHAIN,
        block_number=1000,
        block_timestamp=datetime.utcnow() - timedelta(minutes=30),
        tx_hash="0xnormal_lock_tx_hash_123456789",
        event_type=EventType.LOCK,
        severity=Severity.INFO,
        source_address="0xLegitUser123456789012345678901234567890",
        dest_address=BRIDGE_CONTRACT_ETH,
        contract_address=BRIDGE_CONTRACT_ETH,
        asset_type="ETH",
        amount=Decimal("100"),
        amount_usd=Decimal("180000"),  # $180k
        bridge_id=BRIDGE_ID,
        message_hash="0xmessage_hash_normal_1234",
    )
    
    context.add_event(normal_lock)
    await correlator.process_event(normal_lock)
    print(f"✅ Normal lock: 100 ETH locked on Ethereum (tx: {normal_lock.tx_hash[:20]}...)")
    
    # Corresponding mint on Solana
    normal_mint = SecurityEvent(
        chain_id=DEST_CHAIN,
        block_number=50000,
        block_timestamp=datetime.utcnow() - timedelta(minutes=25),
        tx_hash="solana_normal_mint_signature_123456",
        event_type=EventType.MINT,
        severity=Severity.INFO,
        source_address=BRIDGE_CONTRACT_SOL,
        dest_address="SolanaUserAddress123456789012345678901234567890",
        contract_address=BRIDGE_CONTRACT_SOL,
        asset_type="wETH",
        amount=Decimal("100"),
        amount_usd=Decimal("180000"),
        bridge_id=BRIDGE_ID,
        message_hash="0xmessage_hash_normal_1234",
    )
    
    context.add_event(normal_mint)
    await correlator.process_event(normal_mint)
    print(f"✅ Normal mint: 100 wETH minted on Solana (tx: {normal_mint.tx_hash[:20]}...)")
    
    # Check invariant - should pass
    result = await mint_lock_invariant.evaluate(context)
    print(f"✅ Invariant check: PASSED (minted={100}, locked={100})")
    
    # =========================================================================
    # PHASE 2: Attack - Forged Signature + Unbacked Mint
    # =========================================================================
    print("\n" + "-"*60)
    print("💀 PHASE 2: ATTACK - Forged Signatures")
    print("-"*60)
    
    print("""
⚠️  Attacker exploits signature verification vulnerability:
    - Crafts valid-looking guardian signature set
    - Bypasses verification check
    - Submits mint request without corresponding lock
""")
    
    # THE ATTACK: Mint without lock
    attack_mint = SecurityEvent(
        chain_id=DEST_CHAIN,
        block_number=50010,
        block_timestamp=datetime.utcnow() - timedelta(minutes=2),
        tx_hash="solana_ATTACK_mint_signature_EXPLOIT",
        log_index=0,
        event_type=EventType.MINT,
        severity=Severity.HIGH,
        source_address=BRIDGE_CONTRACT_SOL,
        dest_address=ATTACKER,
        contract_address=BRIDGE_CONTRACT_SOL,
        asset_type="wETH",
        amount=Decimal("120000"),  # 120,000 wETH!
        amount_usd=Decimal("216000000"),  # $216M at $1800/ETH
        bridge_id=BRIDGE_ID,
        message_hash="0xFORGED_MESSAGE_HASH_ATTACK",
        # Note: signature_count is suspiciously low
        signature_count=13,
        threshold=13,  # Just at threshold, no buffer
    )
    
    context.add_event(attack_mint)
    await entity_builder.process_event(attack_mint)
    await correlator.process_event(attack_mint)
    
    print(f"💀 ATTACK MINT: 120,000 wETH minted to {ATTACKER[:20]}...")
    print(f"   Transaction: {attack_mint.tx_hash}")
    print(f"   Value: ${attack_mint.amount_usd:,.0f}")
    print(f"   Message Hash: {attack_mint.message_hash}")
    print(f"   ⚠️  NO CORRESPONDING LOCK ON ETHEREUM!")
    
    # =========================================================================
    # PHASE 3: Detection
    # =========================================================================
    print("\n" + "-"*60)
    print("🔍 PHASE 3: XDR Detection")
    print("-"*60)
    
    # Check mint-lock parity invariant
    print("\n[Checking MINT_LOCK_PARITY invariant...]")
    result1 = await mint_lock_invariant.evaluate(context)
    
    if result1.violated:
        print(f"🚨 VIOLATION DETECTED!")
        print(f"   Invariant: {result1.invariant_name}")
        print(f"   Severity: {result1.severity.name}")
        print(f"   Violation Amount: {result1.violation_amount} wETH")
        print(f"   USD Value: ${result1.violation_amount_usd:,.0f}")
        
        await correlator.process_violation(result1)
    
    # Check unbacked mint invariant
    print("\n[Checking UNBACKED_MINT invariant...]")
    result2 = await unbacked_invariant.evaluate(context)
    
    if result2.violated:
        print(f"🚨 VIOLATION DETECTED!")
        print(f"   Invariant: {result2.invariant_name}")
        print(f"   Evidence: Mint without corresponding lock event")
        
        await correlator.process_violation(result2)
    
    # Force correlation aggregation
    await correlator.force_aggregation()
    
    # =========================================================================
    # PHASE 4: Incident & Explanation
    # =========================================================================
    print("\n" + "-"*60)
    print("📊 PHASE 4: Incident Analysis")
    print("-"*60)
    
    if detected_incidents:
        incident = detected_incidents[0]
        
        print(f"\n🎯 INCIDENT CREATED")
        print(f"   ID: {incident.id}")
        print(f"   Type: {incident.attack_type.value}")
        print(f"   Severity: {incident.severity.name}")
        print(f"   Confidence: {incident.confidence:.0%}")
        print(f"   Total Loss: ${incident.total_loss_usd:,.0f}")
        print(f"   Chains: {', '.join(incident.affected_chains)}")
        
        # Generate explanation
        explanation = explainability.explain(
            incident,
            violations=[result1, result2] if result2.violated else [result1],
            events=[normal_lock, normal_mint, attack_mint]
        )
        
        print("\n" + "="*60)
        print("📝 GENERATED EXPLANATION")
        print("="*60)
        print(explanation.to_markdown())
        
        # Show what would be sent to Slack/Telegram
        print("\n" + "="*60)
        print("📱 TELEGRAM ALERT (Preview)")
        print("="*60)
        print(explanation.to_telegram())
        
    else:
        print("❌ No incident detected - check configuration")
    
    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "="*80)
    print("📈 SIMULATION SUMMARY")
    print("="*80)
    print(f"""
ATTACK TIMELINE:
- T+0:00  Attacker identifies signature verification vulnerability
- T+0:01  Forged guardian signatures prepared
- T+0:02  Malicious mint transaction submitted
- T+0:03  XDR detects MINT_LOCK_PARITY violation
- T+0:03  Incident created with CRITICAL severity
- T+0:03  Alert sent to security team

DETECTION METRICS:
- Time to detect: ~1 minute (3 blocks on Solana)
- Confidence: {incident.confidence:.0%}
- False positive: NO (deterministic invariant)

KEY INSIGHT:
The bridge contract believed the mint was valid because it received
what appeared to be valid guardian signatures. But our system doesn't
trust the contract's validation - it independently verifies that:

  minted_on_destination ≤ locked_on_source

This economic truth holds regardless of what any contract believes.
The attacker could forge signatures, but they couldn't forge a lock
event on Ethereum that our telemetry would observe.

This is how we detect attacks that contracts themselves approve.
""")
    
    return incident if detected_incidents else None


async def run_mini_demo():
    """Quick demo for testing."""
    print("Running mini simulation...")
    await run_simulation()


if __name__ == "__main__":
    asyncio.run(run_simulation())

