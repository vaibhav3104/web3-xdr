#!/usr/bin/env python3
"""
Sentinel3 - Real-Time Multi-Chain Bridge Monitor
================================================
Monitors EVM, Cosmos, Aptos, Sui, Near, and Solana chains.
Uses YAML-based alert rules and supports PostgreSQL persistence.
"""

import time
import os
import sys
import yaml
import threading
import uuid
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional

# Add src to path
sys.path.insert(0, os.path.dirname(__file__))

# Suppress warnings
import warnings
warnings.filterwarnings("ignore")

from src.shared_state import monitor_state, LiveEvent, LiveIncident
from src.rules import RuleEngine, load_rules

# Cross-chain correlation
try:
    from src.correlation.cross_chain import (
        cross_chain_correlator,
        BridgeEventParser,
        CrossChainEvent,
        CrossChainEventType
    )
    CROSS_CHAIN_AVAILABLE = True
except ImportError:
    CROSS_CHAIN_AVAILABLE = False
    cross_chain_correlator = None

# Check if PostgreSQL is enabled
POSTGRES_ENABLED = os.getenv("POSTGRES_ENABLED", "true").lower() == "true"


def load_config():
    """Load configuration."""
    config_path = os.path.join(os.path.dirname(__file__), "config", "chains.yaml")
    with open(config_path) as f:
        return yaml.safe_load(f)


def start_dashboard():
    """Start the dashboard in a background thread."""
    def run():
        import uvicorn
        from src.api.server import create_app
        from fastapi.staticfiles import StaticFiles
        
        app = create_app()
        app.mount('/frontend', StaticFiles(directory='frontend', html=True), name='frontend')
        
        uvicorn.run(app, host="0.0.0.0", port=8080, log_level="error")
    
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def print_banner():
    """Print startup banner."""
    print()
    print("=" * 70)
    print("🛡️  Sentinel3 - Multi-Chain Bridge Monitor")
    print("    EVM | Cosmos | Aptos | Sui | Near | Solana")
    print("=" * 70)
    if POSTGRES_ENABLED:
        print("💾 PostgreSQL persistence: ENABLED")
    else:
        print("⚡ In-memory mode (no persistence)")
    print()


def init_database_sync():
    """Initialize PostgreSQL database synchronously using psycopg2."""
    if not POSTGRES_ENABLED:
        print("⚡ Running in-memory mode (POSTGRES_ENABLED=false)")
        return False
    
    try:
        from src.database.sync_service import ensure_tables_exist, get_sync_connection
        
        print("🔌 Connecting to PostgreSQL...")
        
        # Test connection
        conn = get_sync_connection()
        if conn:
            conn.close()
            print("   Connection successful!")
        else:
            print("   ⚠️ Connection test failed")
            return False
        
        # Create tables
        if ensure_tables_exist():
            print("✅ PostgreSQL connected and tables created")
            # Mark shared_state as DB initialized
            monitor_state._db_initialized = True
            return True
        else:
            print("   ⚠️ Table creation failed")
            return False
            
    except Exception as e:
        print(f"⚠️  PostgreSQL connection failed: {e}")
        print("   Continuing in-memory mode...")
        return False


async def init_database():
    """Initialize PostgreSQL database if enabled (async wrapper)."""
    return init_database_sync()


# Comprehensive Event signatures - bridges, DeFi, tokens
EVENT_SIGNATURES = {
    # =============================================================================
    # ERC20 / Token Events
    # =============================================================================
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": ("Transfer", "low", 0),
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": ("Approval", "low", 0),
    
    # =============================================================================
    # WORMHOLE Bridge
    # =============================================================================
    "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2": ("Wormhole:MessagePublished", "high", 50000),
    "0xcaf280c8cfeba144da67230d9b009c8f868a75bac9a528fa0474be1ba317c169": ("Wormhole:TransferRedeemed", "critical", 100000),
    
    # =============================================================================
    # LAYERZERO Bridge
    # =============================================================================
    "0xe9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82": ("LayerZero:Packet", "high", 25000),
    "0x32ed1a409ef04c7b0227189c3a103dc5ac10e775a15b785dcc510201f7c25ad3": ("LayerZero:SendToChain", "high", 50000),
    "0xd81b6f2a5a0f1c0c5e8e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c": ("LayerZero:ReceiveFromChain", "high", 50000),
    
    # =============================================================================
    # STARGATE Bridge
    # =============================================================================
    "0x34660fc8af304464529f48a778e03d03e4d34bcd5f9b6f0cfbf3cd238c642f7f": ("Stargate:Swap", "high", 25000),
    "0x44b559f101f8fbcc8a0ea43fa91a05a729a5ea6e14a7c75aa750374690137208": ("Stargate:SendCredits", "medium", 10000),
    "0xf4ad92585b1bc117fbdd644990adf0827bc4c95baeae8a23322af807b6d0020e": ("Stargate:CreditChainPath", "medium", 10000),
    
    # =============================================================================
    # ACROSS Protocol
    # =============================================================================
    "0x8ab9dc6c19fe88e69bc70221b339c84332752fdd49591b7c51e66bae3947b73c": ("Across:FilledRelay", "high", 50000),
    "0xafc4df6845a4ab948b492800d3d8a25d538a102a2bc07cd01f1cfa097fddcff6": ("Across:FundsDeposited", "high", 50000),
    "0xa123dc29aebf7d0c3322c8eeb5b999e859f39937950ed31056532713d0de396f": ("Across:V3FundsDeposited", "high", 50000),
    
    # =============================================================================
    # HOP Protocol
    # =============================================================================
    "0xe35dddd4ea75d7e9b3fe93af4f4e40e778c3da4074c9d93e7c6f3f94a7d0ec34": ("Hop:TransferSent", "high", 25000),
    "0x320958176930804eb66c2343c7343fc0367dc16249590c0f195783bee199d094": ("Hop:TransferCompleted", "high", 50000),
    
    # =============================================================================
    # SYNAPSE Bridge
    # =============================================================================
    "0xda5273705dbef4bf1b902a131c2eac086b7e1476a8ab0cb4da08af1fe1bd8e3b": ("Synapse:TokenDeposit", "high", 25000),
    "0xdc5bad4651c5fbe9977a696aadc65996c468cde1448dd468ec0d83bf61c4b57c": ("Synapse:TokenRedeem", "high", 50000),
    
    # =============================================================================
    # CELER cBridge
    # =============================================================================
    "0x89d8051e597ab4178a863a5190407b98abfeff406aa8db90c59af76612e58f01": ("Celer:Send", "high", 25000),
    "0x79fa08de5149d912dce8e5e8da7a7c17ccdf23dd5d3bfe196802f6c6d471f3f9": ("Celer:Relay", "high", 50000),
    
    # =============================================================================
    # AAVE DeFi (Flash Loans!)
    # =============================================================================
    "0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac": ("Aave:FlashLoan", "critical", 500000),
    "0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61": ("Aave:Supply", "low", 1000),
    "0x3115d1449a7b732c986cba18244e897a450f61e1bb8d589cd2e69e6c8924f9f7": ("Aave:Withdraw", "medium", 10000),
    "0xb3d084820fb1a9decffb176436bd02558d15fac9b0ddfed8c465bc7359d7dce0": ("Aave:Borrow", "medium", 10000),
    "0xa534c8dbe71f871f9f3530e97a74601fea17b426cae02e1c5aee42c96c784051": ("Aave:Repay", "medium", 5000),
    "0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be37335533e005286": ("Aave:Liquidation", "high", 100000),
    
    # =============================================================================
    # UNISWAP DEX
    # =============================================================================
    "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67": ("Uniswap:Swap", "low", 0),
    "0x7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde": ("Uniswap:Mint", "low", 0),
    "0x0c396cd989a39f4459b5fa1aed6a9a8dcdbc45908acfd67e028cd568da98982c": ("Uniswap:Burn", "medium", 5000),
    "0xbdbdb71d7860376ba52b25a5028beea23581364a40522f6bcfb86bb1f2dca633": ("Uniswap:Flash", "critical", 500000),
    "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822": ("UniswapV2:Swap", "low", 0),
    "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1": ("UniswapV2:Sync", "low", 0),
    
    # =============================================================================
    # COMPOUND DeFi
    # =============================================================================
    "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f": ("Compound:Mint", "low", 0),
    "0xe5b754fb1abb7f01b499791d0b820ae3b6af3424ac1c59768edb53f4ec31a929": ("Compound:Redeem", "medium", 10000),
    "0x13ed6866d4e1ee6da46f845c46d7e54120883d75c5ea9a2dacc1c4ca8984ab80": ("Compound:Borrow", "medium", 10000),
    "0x1a2a22cb034d26d1854bdc6666a5b91fe25efbbb5dcad3b0355478d6f5c362a1": ("Compound:RepayBorrow", "medium", 5000),
    "0x298637f684da70674f26509b10f07ec2fbc77a335ab1e7d6215a4b2484d8bb52": ("Compound:Liquidation", "high", 100000),
    
    # =============================================================================
    # CURVE Finance
    # =============================================================================
    "0x8b3e96f2b889fa771c53c981b40daf005f63f637f1869f707052d15a3dd97140": ("Curve:TokenExchange", "low", 0),
    "0x26f55a85081d24974e85c6c00045d0f0453991e95873f52bff0d21af4079a768": ("Curve:AddLiquidity", "low", 0),
    "0x7c363854ccf79623411f8995b362bce5eddff18c927edc6f5dbbb5e05819a82c": ("Curve:RemoveLiquidity", "medium", 10000),
    
    # =============================================================================
    # BALANCER (Flash Loans!)
    # =============================================================================
    "0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b": ("Balancer:Swap", "low", 0),
    "0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19f3f93ce64d5e2b7c60e9e0e2b4a3f": ("Balancer:FlashLoan", "critical", 500000),
    
    # =============================================================================
    # Generic ETH Events
    # =============================================================================
    "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c": ("Deposit", "medium", 10000),
    "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65": ("Withdrawal", "high", 50000),
    
    # =============================================================================
    # Governance Events
    # =============================================================================
    "0x7d84a6263ae0d98d3329bd7b46bb4e8d6f98cd35a7adb45c274c8b7fd5ebd5e0": ("Governance:ProposalCreated", "medium", 0),
    "0x712ae1383f79ac853f8d882153778e0260ef8f03b504e2866e0593e04d2b291f": ("Governance:ProposalExecuted", "high", 0),
}


def get_event_info(topic0_hex: str):
    """Get event name, severity, and estimated value from topic."""
    # Normalize the topic
    if not topic0_hex:
        return ("Event", "low", 0)
    
    topic = topic0_hex.lower()
    if not topic.startswith("0x"):
        topic = "0x" + topic
    
    # Try direct lookup
    info = EVENT_SIGNATURES.get(topic)
    if info:
        return info[0], info[1], info[2]
    
    # Try with original casing
    info = EVENT_SIGNATURES.get(topic0_hex)
    if info:
        return info[0], info[1], info[2]
    
    return ("Event", "low", 0)


def get_chain_type(chain_id: str) -> str:
    """Determine chain type from chain ID."""
    chain_lower = chain_id.lower()
    
    evm_chains = [
        "ethereum", "polygon", "arbitrum", "optimism",
        "bsc", "avalanche", "fantom", "base", "zksync",
        "linea", "scroll", "mantle", "blast"
    ]
    cosmos_chains = [
        "cosmos", "osmosis", "injective", "sei", "celestia",
        "dydx", "neutron", "kava", "evmos", "axelar"
    ]
    aptos_chains = ["aptos", "movement"]
    sui_chains = ["sui"]
    near_chains = ["near", "aurora"]
    solana_chains = ["solana"]
    
    if chain_lower in evm_chains or chain_lower.startswith("evm_"):
        return "evm"
    elif chain_lower in cosmos_chains or chain_lower.startswith("cosmos_"):
        return "cosmos"
    elif chain_lower in aptos_chains:
        return "aptos"
    elif chain_lower in sui_chains:
        return "sui"
    elif chain_lower in near_chains:
        return "near"
    elif chain_lower in solana_chains:
        return "solana"
    
    return "evm"  # Default to EVM


class YAMLRuleMonitor:
    """Monitor that uses YAML-based rules for alert detection."""
    
    def __init__(self, rules_dir: str = None):
        if rules_dir is None:
            rules_dir = os.path.join(os.path.dirname(__file__), "config", "rules")
        
        # Load YAML rules
        self.rule_engine = RuleEngine()
        count = self.rule_engine.load_rules_from_directory(rules_dir)
        
        print(f"📜 Loaded {count} YAML alert rules")
        stats = self.rule_engine.stats()
        print(f"   🔴 Critical: {stats['by_severity']['critical']}")
        print(f"   🟠 High: {stats['by_severity']['high']}")
        print(f"   🟡 Medium: {stats['by_severity']['medium']}")
        print(f"   🟢 Low: {stats['by_severity']['low']}")
        
        # Track created incidents to avoid duplicates
        self.recent_incidents = {}  # rule_id -> last_incident_time
        self.incident_cooldown = 60  # seconds between incidents for same rule
        
        # Velocity tracking
        self.event_counts = defaultdict(lambda: defaultdict(int))  # chain -> minute -> count
        
    def evaluate_event(self, event: LiveEvent) -> list:
        """Evaluate an event against all YAML rules."""
        incidents = []
        
        # Convert LiveEvent to dict for rule engine
        event_dict = {
            "event_id": event.id,
            "event_type": event.event_type,
            "chain": event.chain,
            "tx_hash": event.tx_hash,
            "block": event.block,
            "contract": event.contract,
            "severity": event.severity,
            "timestamp": event.timestamp.isoformat(),
            "amount_usd": event.data.get("amount_usd", 0),
            "burn_verified": event.data.get("burn_verified", True),
            "chain_type": event.data.get("chain_type", "evm"),
        }
        
        # Add velocity data
        current_minute = datetime.utcnow().strftime("%Y%m%d%H%M")
        self.event_counts[event.chain][current_minute] += 1
        event_dict["events_per_minute"] = self.event_counts[event.chain][current_minute]
        
        # Evaluate against all rules
        matches = self.rule_engine.evaluate(event_dict)
        
        for match in matches:
            rule = match.rule
            
            # Check cooldown to avoid duplicate incidents
            if self._is_on_cooldown(rule.id):
                continue
            
            # Create incident from rule match
            incident = self._create_incident_from_match(match)
            incidents.append(incident)
            
            # Record for cooldown
            self.recent_incidents[rule.id] = datetime.utcnow()
            
            # Log the match
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢"
            }.get(rule.severity, "⚪")
            
            print(f"\n{severity_emoji} YAML RULE TRIGGERED!")
            print(f"   Rule: {rule.name} ({rule.id})")
            print(f"   Severity: {rule.severity.upper()}")
            print(f"   Confidence: {rule.confidence * 100:.0f}%")
            print(f"   Event: {event.event_type} on {event.chain}")
            print()
        
        return incidents
    
    def _is_on_cooldown(self, rule_id: str) -> bool:
        """Check if rule is on cooldown."""
        last_time = self.recent_incidents.get(rule_id)
        if last_time is None:
            return False
        
        elapsed = (datetime.utcnow() - last_time).total_seconds()
        return elapsed < self.incident_cooldown
    
    def _create_incident_from_match(self, match) -> LiveIncident:
        """Create a LiveIncident from a rule match."""
        rule = match.rule
        event = match.event
        
        # Determine attack type from rule
        attack_type = rule.detection.get("type", "unknown")
        if rule.detection.get("invariant"):
            attack_type = rule.detection["invariant"].lower()
        
        # Build title
        title_prefix = {
            "critical": "🔴 CRITICAL:",
            "high": "🟠 HIGH:",
            "medium": "🟡",
            "low": "🟢"
        }.get(rule.severity, "")
        
        title = f"{title_prefix} {rule.name}"
        
        return LiveIncident(
            id=f"inc-{rule.id}-{uuid.uuid4().hex[:8]}",
            title=title,
            severity=rule.severity,
            status="open",
            attack_type=attack_type,
            confidence=rule.confidence,
            total_loss_usd=event.get("amount_usd", 0),
            affected_chains=[event.get("chain", "unknown")],
            events=[event.get("event_id", "")]
        )
    
    def cleanup_old_counts(self):
        """Remove old event counts to prevent memory leak."""
        cutoff = (datetime.utcnow() - timedelta(minutes=5)).strftime("%Y%m%d%H%M")
        for chain in list(self.event_counts.keys()):
            self.event_counts[chain] = {
                k: v for k, v in self.event_counts[chain].items()
                if k >= cutoff
            }


class EVMMonitor:
    """Monitor for EVM-compatible chains using Web3."""
    
    def __init__(self, chain_config: dict):
        from web3 import Web3
        
        self.chain_id = chain_config["chain_id"]
        self.chain_name = chain_config["chain_name"]
        self.rpc_url = chain_config["rpc_url"]
        self.bridge_contracts = chain_config.get("bridge_contracts", [])[:5]  # Limit to 5
        
        self.w3 = None
        self.last_block = 0
        self.connected = False
        
        # Contract deployment detection
        self._classifier = None
        self._init_classifier()
        
    def _init_classifier(self):
        """Initialize the ML contract classifier."""
        try:
            from src.ai.models.contract_classifier import ContractThreatClassifier
            self._classifier = ContractThreatClassifier()
            print(f"   ✅ ML Classifier initialized for {self.chain_id}")
        except Exception as e:
            print(f"   ⚠️ ML Classifier not available: {e}")
            self._classifier = None
    
    def connect(self) -> bool:
        """Connect to EVM chain."""
        from web3 import Web3
        
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={'timeout': 30}))
            if self.w3.is_connected():
                self.last_block = self.w3.eth.block_number
                self.connected = True
                return True
        except Exception as e:
            pass
        return False
    
    def scan_events(self) -> List[LiveEvent]:
        """Scan for new events and contract deployments."""
        from web3 import Web3
        
        events = []
        if not self.connected:
            return events
        
        try:
            current_block = self.w3.eth.block_number
            if current_block <= self.last_block:
                return events
            
            from_block = self.last_block + 1
            
            # Scan for bridge contract events
            for contract_addr in self.bridge_contracts:
                try:
                    logs = self.w3.eth.get_logs({
                        "fromBlock": from_block,
                        "toBlock": current_block,
                        "address": Web3.to_checksum_address(contract_addr)
                    })
                    
                    for log in logs:
                        topic0 = log["topics"][0].hex() if log["topics"] else ""
                        event_type, severity, estimated_usd = get_event_info(topic0)
                        
                        event = LiveEvent(
                            id=f"evt-{uuid.uuid4().hex[:12]}",
                            chain=self.chain_id,
                            event_type=event_type,
                            tx_hash=log["transactionHash"].hex(),
                            block=log["blockNumber"],
                            contract=contract_addr,
                            severity=severity,
                            data={
                                "topics": [t.hex() for t in log.get("topics", [])],
                                "amount_usd": estimated_usd,
                                "chain_type": "evm",
                            }
                        )
                        events.append(event)
                        
                except Exception:
                    pass
            
            # Scan for contract deployments (to=null transactions)
            contract_events = self._scan_contract_deployments(from_block, current_block)
            events.extend(contract_events)
            
            blocks_scanned = current_block - self.last_block
            self.last_block = current_block
            monitor_state.add_blocks_scanned(blocks_scanned)
            
        except Exception:
            pass
        
        return events
    
    def _scan_contract_deployments(self, from_block: int, to_block: int) -> List[LiveEvent]:
        """Scan blocks for contract deployments and analyze them."""
        import hashlib
        from src.telemetry.contract_alerts import (
            ContractThreatAlert, ThreatLevel, AlertStatus, contract_alert_store
        )
        
        events = []
        
        # Only scan last block to avoid too many RPC calls
        try:
            block = self.w3.eth.get_block(to_block, full_transactions=True)
            
            for tx in block.transactions:
                # Contract deployment = tx with to=None
                if tx.to is None:
                    try:
                        # Get receipt to find deployed contract address
                        receipt = self.w3.eth.get_transaction_receipt(tx.hash)
                        contract_address = receipt.contractAddress
                        
                        if contract_address:
                            # Get bytecode
                            bytecode = self.w3.eth.get_code(contract_address)
                            bytecode_hex = bytecode.hex() if bytecode else ""
                            
                            if len(bytecode_hex) > 10:  # Has actual code
                                # Analyze with ML classifier
                                threat_info = self._analyze_contract(
                                    bytecode_hex, 
                                    contract_address, 
                                    tx.hash.hex(),
                                    tx["from"],
                                    to_block,
                                    block.timestamp
                                )
                                
                                # Create event
                                severity = "low"
                                event_type = "ContractDeploy:Safe"
                                
                                if threat_info:
                                    if threat_info["threat_level"] in ["critical", "high"]:
                                        severity = "critical"
                                        event_type = f"ContractDeploy:{threat_info['category']}"
                                        print(f"\n🚨 MALICIOUS CONTRACT DETECTED!")
                                        print(f"   Chain: {self.chain_id}")
                                        print(f"   Contract: {contract_address}")
                                        print(f"   Threat: {threat_info['category']}")
                                        print(f"   Confidence: {threat_info['confidence']:.0%}")
                                    elif threat_info["threat_level"] == "medium":
                                        severity = "medium"
                                        event_type = f"ContractDeploy:Suspicious"
                                
                                event = LiveEvent(
                                    id=f"evt-contract-{uuid.uuid4().hex[:12]}",
                                    chain=self.chain_id,
                                    event_type=event_type,
                                    tx_hash=tx.hash.hex(),
                                    block=to_block,
                                    contract=contract_address,
                                    severity=severity,
                                    data={
                                        "type": "contract_deployment",
                                        "deployer": tx["from"],
                                        "bytecode_size": len(bytecode_hex) // 2,
                                        "threat_info": threat_info,
                                        "chain_type": "evm",
                                    }
                                )
                                events.append(event)
                                
                    except Exception as e:
                        pass
                        
        except Exception as e:
            pass
        
        return events
    
    def _analyze_contract(
        self, 
        bytecode: str, 
        address: str, 
        tx_hash: str,
        deployer: str,
        block: int,
        timestamp
    ) -> dict:
        """Analyze contract bytecode with ML classifier."""
        import hashlib
        from datetime import datetime
        from src.telemetry.contract_alerts import (
            ContractThreatAlert, ThreatLevel, AlertStatus, contract_alert_store
        )
        
        if not self._classifier:
            return None
        
        try:
            result = self._classifier.classify(bytecode, address)
            
            # Only create alert if not safe
            if result.threat_category.value != "safe":
                # Map to threat level
                threat_level = ThreatLevel.SAFE
                if result.confidence > 0.8:
                    threat_level = ThreatLevel.CRITICAL
                elif result.confidence > 0.6:
                    threat_level = ThreatLevel.HIGH
                elif result.confidence > 0.4:
                    threat_level = ThreatLevel.MEDIUM
                else:
                    threat_level = ThreatLevel.LOW
                
                # Create alert
                alert = ContractThreatAlert(
                    chain_id=self.chain_id,
                    contract_address=address,
                    deployer_address=deployer,
                    tx_hash=tx_hash,
                    block_number=block,
                    timestamp=datetime.fromtimestamp(timestamp) if isinstance(timestamp, int) else datetime.utcnow(),
                    threat_category=result.threat_category.value,
                    threat_level=threat_level,
                    confidence=result.confidence,
                    risk_score=result.risk_score,
                    risk_factors=result.risk_factors,
                    similar_exploits=result.similar_exploits,
                    recommendation=result.recommendation,
                    bytecode_size=len(bytecode) // 2,
                    bytecode_hash=hashlib.sha256(bytecode.encode()).hexdigest()[:16],
                    status=AlertStatus.ACTIVE
                )
                
                contract_alert_store.add_alert(alert)
                
                return {
                    "category": result.threat_category.value,
                    "threat_level": threat_level.value,
                    "confidence": result.confidence,
                    "risk_score": result.risk_score,
                    "risk_factors": result.risk_factors,
                    "recommendation": result.recommendation,
                    "alert_id": alert.alert_id
                }
            
            return {
                "category": "safe",
                "threat_level": "safe",
                "confidence": result.confidence,
                "risk_score": result.risk_score,
                "risk_factors": [],
                "recommendation": "Contract appears safe"
            }
            
        except Exception as e:
            return None


class CosmosMonitor:
    """Monitor for Cosmos/IBC chains."""
    
    def __init__(self, chain_config: dict):
        import aiohttp
        
        self.chain_id = chain_config["chain_id"]
        self.chain_name = chain_config["chain_name"]
        self.rpc_url = chain_config["rpc_url"]
        self.bridge_contracts = chain_config.get("bridge_contracts", [])
        self.ibc_channels = chain_config.get("ibc_channels", [])
        
        self.last_height = 0
        self.connected = False
        self.session = None
        
    async def connect(self) -> bool:
        """Connect to Cosmos chain via Tendermint RPC."""
        import aiohttp
        
        try:
            self.session = aiohttp.ClientSession()
            async with self.session.get(f"{self.rpc_url}/status", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.last_height = int(data.get("result", {}).get("sync_info", {}).get("latest_block_height", 0))
                    self.connected = True
                    return True
        except Exception as e:
            pass
        return False
    
    async def scan_events(self) -> List[LiveEvent]:
        """Scan for new Cosmos events."""
        import aiohttp
        
        events = []
        if not self.connected or not self.session:
            return events
        
        try:
            # Get latest block height
            async with self.session.get(f"{self.rpc_url}/status", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return events
                data = await resp.json()
                current_height = int(data.get("result", {}).get("sync_info", {}).get("latest_block_height", 0))
            
            if current_height <= self.last_height:
                return events
            
            # Process new blocks (limit to avoid overload)
            blocks_to_scan = min(current_height - self.last_height, 10)
            
            for height in range(self.last_height + 1, self.last_height + blocks_to_scan + 1):
                try:
                    # Get block results for events
                    async with self.session.get(
                        f"{self.rpc_url}/block_results?height={height}",
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status != 200:
                            continue
                        block_data = await resp.json()
                    
                    # Process transaction events
                    txs_results = block_data.get("result", {}).get("txs_results", []) or []
                    
                    for tx_idx, tx_result in enumerate(txs_results):
                        tx_events = tx_result.get("events", []) or []
                        
                        for evt in tx_events:
                            evt_type = evt.get("type", "")
                            
                            # Look for IBC and bridge events
                            if "ibc" in evt_type.lower() or "transfer" in evt_type.lower():
                                attrs = {
                                    attr.get("key", ""): attr.get("value", "")
                                    for attr in evt.get("attributes", [])
                                }
                                
                                # Estimate severity based on event type
                                severity = "low"
                                if "recv_packet" in evt_type:
                                    severity = "medium"
                                elif "acknowledge" in evt_type:
                                    severity = "low"
                                elif "timeout" in evt_type:
                                    severity = "high"
                                
                                event = LiveEvent(
                                    id=f"evt-cosmos-{uuid.uuid4().hex[:12]}",
                                    chain=self.chain_id,
                                    event_type=f"Cosmos:{evt_type}",
                                    tx_hash=f"block_{height}_tx_{tx_idx}",
                                    block=height,
                                    contract="IBC",
                                    severity=severity,
                                    data={
                                        "attributes": attrs,
                                        "chain_type": "cosmos",
                                        "event_type": evt_type,
                                    }
                                )
                                events.append(event)
                                
                except Exception:
                    pass
            
            monitor_state.add_blocks_scanned(blocks_to_scan)
            self.last_height = self.last_height + blocks_to_scan
            
        except Exception:
            pass
        
        return events
    
    async def close(self):
        """Close the session."""
        if self.session:
            await self.session.close()


class AptosMonitor:
    """Monitor for Aptos/Sui (Move-based) chains."""
    
    def __init__(self, chain_config: dict, chain_type: str = "aptos"):
        self.chain_id = chain_config["chain_id"]
        self.chain_name = chain_config["chain_name"]
        self.rpc_url = chain_config["rpc_url"]
        self.bridge_contracts = set(chain_config.get("bridge_contracts", []))
        self.chain_type = chain_type  # "aptos" or "sui"
        
        self.last_version = 0
        self.connected = False
        self.session = None
        
    async def connect(self) -> bool:
        """Connect to Aptos/Sui chain."""
        import aiohttp
        
        try:
            self.session = aiohttp.ClientSession()
            
            if self.chain_type == "aptos":
                async with self.session.get(self.rpc_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.last_version = int(data.get("ledger_version", 0))
                        self.connected = True
                        return True
            else:  # Sui
                async with self.session.post(
                    self.rpc_url,
                    json={"jsonrpc": "2.0", "method": "sui_getLatestCheckpointSequenceNumber", "id": 1},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.last_version = int(data.get("result", 0))
                        self.connected = True
                        return True
                        
        except Exception:
            pass
        return False
    
    async def scan_events(self) -> List[LiveEvent]:
        """Scan for new Move chain events."""
        import aiohttp
        
        events = []
        if not self.connected or not self.session:
            return events
        
        try:
            if self.chain_type == "aptos":
                events = await self._scan_aptos()
            else:
                events = await self._scan_sui()
        except Exception:
            pass
        
        return events
    
    async def _scan_aptos(self) -> List[LiveEvent]:
        """Scan Aptos transactions."""
        import aiohttp
        
        events = []
        
        try:
            async with self.session.get(
                f"{self.rpc_url}/transactions",
                params={"limit": 50, "start": self.last_version},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return events
                    
                transactions = await resp.json()
                
                for tx in transactions:
                    if tx.get("type") != "user_transaction":
                        continue
                    
                    tx_hash = tx.get("hash", "")
                    version = int(tx.get("version", 0))
                    sender = tx.get("sender", "")
                    payload = tx.get("payload", {})
                    function = payload.get("function", "")
                    
                    # Extract module address
                    module_address = function.split("::")[0] if "::" in function else ""
                    
                    # Check if bridge interaction
                    is_bridge = module_address in self.bridge_contracts
                    
                    # Check for suspicious patterns
                    suspicious_patterns = ["flash_loan", "emergency", "admin_", "upgrade"]
                    is_suspicious = any(p in function.lower() for p in suspicious_patterns)
                    
                    if is_bridge or is_suspicious:
                        severity = "high" if is_suspicious else "medium"
                        
                        event = LiveEvent(
                            id=f"evt-aptos-{uuid.uuid4().hex[:12]}",
                            chain=self.chain_id,
                            event_type=f"Aptos:{function.split('::')[-1] if '::' in function else 'call'}",
                            tx_hash=tx_hash,
                            block=version,
                            contract=module_address,
                            severity=severity,
                            data={
                                "function": function,
                                "sender": sender,
                                "chain_type": "aptos",
                                "is_bridge": is_bridge,
                            }
                        )
                        events.append(event)
                    
                    if version > self.last_version:
                        self.last_version = version
                        
        except Exception:
            pass
        
        if events:
            monitor_state.add_blocks_scanned(len(events))
        
        return events
    
    async def _scan_sui(self) -> List[LiveEvent]:
        """Scan Sui transactions."""
        import aiohttp
        
        events = []
        
        try:
            async with self.session.post(
                self.rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "suix_queryTransactionBlocks",
                    "params": [{
                        "filter": None,
                        "options": {"showInput": True, "showEffects": True}
                    }, None, 20, True],
                    "id": 1
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return events
                    
                data = await resp.json()
                transactions = data.get("result", {}).get("data", [])
                
                for tx in transactions:
                    digest = tx.get("digest", "")
                    checkpoint = tx.get("checkpoint", 0)
                    
                    tx_input = tx.get("transaction", {}).get("data", {}).get("transaction", {})
                    
                    if tx_input.get("kind") == "ProgrammableTransaction":
                        for command in tx_input.get("commands", []):
                            if command.get("MoveCall"):
                                move_call = command["MoveCall"]
                                package = move_call.get("package", "")
                                module = move_call.get("module", "")
                                function = move_call.get("function", "")
                                
                                if package in self.bridge_contracts:
                                    event = LiveEvent(
                                        id=f"evt-sui-{uuid.uuid4().hex[:12]}",
                                        chain=self.chain_id,
                                        event_type=f"Sui:{module}::{function}",
                                        tx_hash=digest,
                                        block=int(checkpoint) if checkpoint else 0,
                                        contract=package,
                                        severity="medium",
                                        data={
                                            "package": package,
                                            "module": module,
                                            "function": function,
                                            "chain_type": "sui",
                                        }
                                    )
                                    events.append(event)
                                    
        except Exception:
            pass
        
        if events:
            monitor_state.add_blocks_scanned(len(events))
        
        return events
    
    async def close(self):
        """Close the session."""
        if self.session:
            await self.session.close()


class NearMonitor:
    """Monitor for Near Protocol."""
    
    def __init__(self, chain_config: dict):
        self.chain_id = chain_config["chain_id"]
        self.chain_name = chain_config["chain_name"]
        self.rpc_url = chain_config["rpc_url"]
        self.bridge_accounts = set(chain_config.get("bridge_contracts", []))
        
        # Add known Near bridges
        self.bridge_accounts.update([
            "factory.bridge.near",
            "aurora",
            "relay.aurora",
            "client.bridge.near",
            "prover.bridge.near",
            "contract.wormhole_crypto.near",
            "allbridge.near",
        ])
        
        self.last_height = 0
        self.connected = False
        self.session = None
        
    async def connect(self) -> bool:
        """Connect to Near RPC."""
        import aiohttp
        
        try:
            self.session = aiohttp.ClientSession()
            async with self.session.post(
                self.rpc_url,
                json={"jsonrpc": "2.0", "id": "xdr", "method": "status", "params": []},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    sync_info = data.get("result", {}).get("sync_info", {})
                    self.last_height = sync_info.get("latest_block_height", 0)
                    self.connected = True
                    return True
        except Exception:
            pass
        return False
    
    async def scan_events(self) -> List[LiveEvent]:
        """Scan for new Near events."""
        import aiohttp
        
        events = []
        if not self.connected or not self.session:
            return events
        
        try:
            # Get latest status
            async with self.session.post(
                self.rpc_url,
                json={"jsonrpc": "2.0", "id": "xdr", "method": "status", "params": []},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return events
                data = await resp.json()
                current_height = data.get("result", {}).get("sync_info", {}).get("latest_block_height", 0)
            
            if current_height <= self.last_height:
                return events
            
            # Process a few blocks
            blocks_to_scan = min(current_height - self.last_height, 5)
            
            for height in range(self.last_height + 1, self.last_height + blocks_to_scan + 1):
                try:
                    # Get block
                    async with self.session.post(
                        self.rpc_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": "xdr",
                            "method": "block",
                            "params": {"block_id": height}
                        },
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status != 200:
                            continue
                        block_data = await resp.json()
                    
                    block = block_data.get("result", {})
                    
                    # Check chunks for transactions
                    for chunk in block.get("chunks", []):
                        chunk_hash = chunk.get("chunk_hash", "")
                        
                        # Get chunk details
                        try:
                            async with self.session.post(
                                self.rpc_url,
                                json={
                                    "jsonrpc": "2.0",
                                    "id": "xdr",
                                    "method": "chunk",
                                    "params": {"chunk_id": chunk_hash}
                                },
                                timeout=aiohttp.ClientTimeout(total=10)
                            ) as resp:
                                if resp.status != 200:
                                    continue
                                chunk_data = await resp.json()
                            
                            chunk_result = chunk_data.get("result", {})
                            
                            for tx in chunk_result.get("transactions", []):
                                receiver_id = tx.get("receiver_id", "")
                                signer_id = tx.get("signer_id", "")
                                
                                # Check if bridge interaction
                                if receiver_id in self.bridge_accounts:
                                    tx_hash = tx.get("hash", "")
                                    actions = tx.get("actions", [])
                                    
                                    action_type = "unknown"
                                    severity = "medium"
                                    
                                    for action in actions:
                                        if "Transfer" in action:
                                            action_type = "Transfer"
                                            severity = "medium"
                                        elif "FunctionCall" in action:
                                            fc = action["FunctionCall"]
                                            action_type = fc.get("method_name", "call")
                                            # Check for suspicious methods
                                            if any(p in action_type.lower() for p in ["admin", "emergency", "upgrade"]):
                                                severity = "critical"
                                        elif "AddKey" in action or "DeleteKey" in action:
                                            action_type = "KeyChange"
                                            severity = "critical"
                                    
                                    event = LiveEvent(
                                        id=f"evt-near-{uuid.uuid4().hex[:12]}",
                                        chain=self.chain_id,
                                        event_type=f"Near:{action_type}",
                                        tx_hash=tx_hash,
                                        block=height,
                                        contract=receiver_id,
                                        severity=severity,
                                        data={
                                            "signer": signer_id,
                                            "receiver": receiver_id,
                                            "chain_type": "near",
                                        }
                                    )
                                    events.append(event)
                                    
                        except Exception:
                            pass
                            
                except Exception:
                    pass
            
            monitor_state.add_blocks_scanned(blocks_to_scan)
            self.last_height = self.last_height + blocks_to_scan
            
        except Exception:
            pass
        
        return events
    
    async def close(self):
        """Close the session."""
        if self.session:
            await self.session.close()


async def run_async_monitors(monitors: List, rule_monitor: YAMLRuleMonitor):
    """Run async monitors (Cosmos, Aptos, Near) in parallel."""
    import aiohttp
    
    while True:
        for monitor in monitors:
            try:
                events = await monitor.scan_events()
                for event in events:
                    monitor_state.add_event(event)
                    
                    # Evaluate against YAML rules
                    incidents = rule_monitor.evaluate_event(event)
                    for incident in incidents:
                        monitor_state.add_incident(incident)
                    
                    # Log high-severity events
                    if event.severity in ["critical", "high"]:
                        severity_emoji = "🔴" if event.severity == "critical" else "🟠"
                        print(f"{severity_emoji} [{event.chain.upper():8}] {event.event_type:25} Block: {event.block:,}")
                        
            except Exception:
                pass
        
        await asyncio.sleep(3)


def monitor():
    """Main monitoring function with multi-chain support."""
    print_banner()
    
    # Initialize database if enabled (use sync version)
    if POSTGRES_ENABLED:
        db_connected = init_database_sync()
        if db_connected:
            print()
    
    config = load_config()
    
    # Separate chains by type
    evm_monitors = []
    cosmos_monitors = []
    aptos_monitors = []
    near_monitors = []
    
    print("🔗 Connecting to chains...")
    print("-" * 70)
    
    for chain_config in config.get("chains", []):
        chain_id = chain_config["chain_id"]
        chain_name = chain_config["chain_name"]
        chain_type = get_chain_type(chain_id)
        
        try:
            if chain_type == "evm":
                monitor_obj = EVMMonitor(chain_config)
                if monitor_obj.connect():
                    evm_monitors.append(monitor_obj)
                    print(f"   ✅ {chain_name} (EVM): Block {monitor_obj.last_block:,}")
                else:
                    print(f"   ❌ {chain_name} (EVM): Connection failed")
                    
            elif chain_type == "cosmos":
                monitor_obj = CosmosMonitor(chain_config)
                loop = asyncio.get_event_loop()
                if loop.run_until_complete(monitor_obj.connect()):
                    cosmos_monitors.append(monitor_obj)
                    print(f"   ✅ {chain_name} (Cosmos): Height {monitor_obj.last_height:,}")
                else:
                    print(f"   ❌ {chain_name} (Cosmos): Connection failed")
                    
            elif chain_type in ["aptos", "sui"]:
                monitor_obj = AptosMonitor(chain_config, chain_type)
                loop = asyncio.get_event_loop()
                if loop.run_until_complete(monitor_obj.connect()):
                    aptos_monitors.append(monitor_obj)
                    version_label = "Version" if chain_type == "aptos" else "Checkpoint"
                    print(f"   ✅ {chain_name} ({chain_type.upper()}): {version_label} {monitor_obj.last_version:,}")
                else:
                    print(f"   ❌ {chain_name} ({chain_type.upper()}): Connection failed")
                    
            elif chain_type == "near":
                monitor_obj = NearMonitor(chain_config)
                loop = asyncio.get_event_loop()
                if loop.run_until_complete(monitor_obj.connect()):
                    near_monitors.append(monitor_obj)
                    print(f"   ✅ {chain_name} (Near): Height {monitor_obj.last_height:,}")
                else:
                    print(f"   ❌ {chain_name} (Near): Connection failed")
                    
        except Exception as e:
            print(f"   ❌ {chain_name}: {str(e)[:40]}")
    
    total_chains = len(evm_monitors) + len(cosmos_monitors) + len(aptos_monitors) + len(near_monitors)
    
    if total_chains == 0:
        print("\n❌ No chains connected. Check your API keys.")
        return
    
    print()
    print(f"📊 Connected: {len(evm_monitors)} EVM, {len(cosmos_monitors)} Cosmos, "
          f"{len(aptos_monitors)} Move, {len(near_monitors)} Near")
    
    # Initialize YAML rule monitor
    print()
    print("-" * 70)
    rule_monitor = YAMLRuleMonitor()
    print("-" * 70)
    
    # Initialize cross-chain correlation
    if CROSS_CHAIN_AVAILABLE:
        print()
        print("🔗 Cross-Chain Correlation: ENABLED")
        print("   Monitoring for Lock/Mint parity violations")
        print("   Bridge protocols: Wormhole, LayerZero, Stargate, Across, Hop, Synapse, Celer")
    else:
        print()
        print("⚠️  Cross-Chain Correlation: Not available")
    
    # Start dashboard
    print()
    print("🖥️  Starting Dashboard...")
    start_dashboard()
    time.sleep(2)
    
    # Initialize monitor state
    monitor_state.set_start_time()
    
    print()
    print("=" * 70)
    print("🚀 MULTI-CHAIN MONITORING STARTED!")
    print("=" * 70)
    print()
    print("📊 Dashboard: http://localhost:8080/frontend/index.html")
    print("📚 API Docs:  http://localhost:8080/api/docs")
    print()
    print("Press Ctrl+C to stop")
    print()
    print("-" * 70)
    print("📡 Scanning EVM + Cosmos + Move + Near chains...")
    print("-" * 70)
    print()
    
    # Start async monitors in background thread
    async_monitors = cosmos_monitors + aptos_monitors + near_monitors
    
    if async_monitors:
        def run_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(run_async_monitors(async_monitors, rule_monitor))
        
        async_thread = threading.Thread(target=run_async, daemon=True)
        async_thread.start()
    
    scan_count = 0
    yaml_incidents = 0
    
    try:
        while True:
            # Scan EVM chains synchronously
            for evm_monitor in evm_monitors:
                try:
                    events = evm_monitor.scan_events()
                    
                    for event in events:
                        monitor_state.add_event(event)
                        
                        # Evaluate against YAML rules
                        incidents = rule_monitor.evaluate_event(event)
                        for incident in incidents:
                            monitor_state.add_incident(incident)
                        
                        # Cross-chain correlation for bridge events
                        if CROSS_CHAIN_AVAILABLE and cross_chain_correlator:
                            try:
                                cc_event = BridgeEventParser.parse_event(
                                    event_data=event.raw_data,
                                    chain_id=event.chain,
                                    block_timestamp=datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')) if isinstance(event.timestamp, str) else event.timestamp
                                )
                                if cc_event:
                                    # Run async correlation in sync context
                                    import asyncio
                                    try:
                                        loop = asyncio.get_event_loop()
                                    except RuntimeError:
                                        loop = asyncio.new_event_loop()
                                        asyncio.set_event_loop(loop)
                                    
                                    violation = loop.run_until_complete(
                                        cross_chain_correlator.process_event(cc_event)
                                    )
                                    
                                    if violation:
                                        # Create incident from violation
                                        cc_incident = LiveIncident(
                                            id=f"cc-{violation.id}",
                                            severity="critical" if violation.severity == "critical" else "high",
                                            type=f"Cross-Chain:{violation.violation_type.value}",
                                            title=f"Cross-Chain Violation: {violation.violation_type.value}",
                                            description=violation.description,
                                            timestamp=datetime.now().isoformat(),
                                            chain=f"{violation.source_chain} → {violation.dest_chain}",
                                            bridge=violation.bridge_id,
                                            status="active",
                                            events=[event.id] if hasattr(event, 'id') else [],
                                            affected_addresses=[],
                                            estimated_loss=violation.estimated_loss_usd
                                        )
                                        monitor_state.add_incident(cc_incident)
                                        print(f"🚨 CROSS-CHAIN VIOLATION: {violation.violation_type.value} on {violation.bridge_id}")
                            except Exception as cc_error:
                                pass  # Silently continue if correlation fails
                            yaml_incidents += 1
                        
                        # Log high-severity events
                        if event.severity in ["critical", "high"]:
                            severity_emoji = "🔴" if event.severity == "critical" else "🟠"
                            print(f"{severity_emoji} [{event.chain.upper():8}] {event.event_type:20} Block: {event.block:,}")
                            
                except Exception:
                    pass
            
            # Cleanup old velocity counts
            rule_monitor.cleanup_old_counts()
            
            # Status update every 10 scans
            scan_count += 1
            if scan_count % 10 == 0:
                stats = monitor_state.get_stats()
                incidents = monitor_state.get_incidents()
                uptime = int((datetime.utcnow() - stats["start_time"]).total_seconds()) if stats["start_time"] else 0
                
                # Count by chain type
                chain_events = defaultdict(int)
                for evt in monitor_state.get_events()[-1000:]:  # Last 1000 events
                    chain_type = evt.data.get("chain_type", "evm")
                    chain_events[chain_type] += 1
                
                print(f"📊 Events: {stats['total_events']} | Incidents: {yaml_incidents} | Blocks: {stats['blocks_scanned']} | Uptime: {uptime}s")
                print(f"   By type: EVM={chain_events.get('evm', 0)} Cosmos={chain_events.get('cosmos', 0)} "
                      f"Aptos={chain_events.get('aptos', 0)} Sui={chain_events.get('sui', 0)} Near={chain_events.get('near', 0)}")
                print()
            
            time.sleep(3)
            
    except KeyboardInterrupt:
        stats = monitor_state.get_stats()
        incidents = monitor_state.get_incidents()
        print("\n\n👋 Shutting down...")
        print(f"📊 Final: {stats['total_events']} events, {len(incidents)} incidents")
        print(f"   YAML rule triggers: {yaml_incidents}")
        
        # Close async monitor sessions
        loop = asyncio.new_event_loop()
        for m in cosmos_monitors + aptos_monitors + near_monitors:
            try:
                loop.run_until_complete(m.close())
            except:
                pass


if __name__ == "__main__":
    monitor()
