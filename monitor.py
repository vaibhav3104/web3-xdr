#!/usr/bin/env python3
"""
Web3 XDR - Real-Time Bridge Monitor
Now with YAML-based alert rules and PostgreSQL persistence!
"""

import time
import os
import sys
import yaml
import threading
import uuid
import asyncio
from datetime import datetime, timedelta
from web3 import Web3
from collections import defaultdict

# Add src to path
sys.path.insert(0, os.path.dirname(__file__))

# Suppress warnings
import warnings
warnings.filterwarnings("ignore")

from src.shared_state import monitor_state, LiveEvent, LiveIncident
from src.rules import RuleEngine, load_rules

# Check if PostgreSQL is enabled
POSTGRES_ENABLED = os.getenv("POSTGRES_ENABLED", "false").lower() == "true"


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
    print("🛡️  Web3 XDR - Real-Time Bridge Monitor with YAML Rules")
    print("=" * 70)
    if POSTGRES_ENABLED:
        print("💾 PostgreSQL persistence: ENABLED")
    else:
        print("⚡ In-memory mode (no persistence)")
    print()


async def init_database():
    """Initialize PostgreSQL database if enabled."""
    if not POSTGRES_ENABLED:
        print("⚡ Running in-memory mode (POSTGRES_ENABLED=false)")
        return False
    
    try:
        from src.database import DatabaseManager
        
        print("🔌 Connecting to PostgreSQL...")
        await DatabaseManager.initialize()
        await DatabaseManager.create_tables()
        
        # Also initialize in shared state
        await monitor_state.init_database()
        
        print("✅ PostgreSQL connected and tables created")
        return True
    except Exception as e:
        print(f"⚠️  PostgreSQL connection failed: {e}")
        print("   Continuing in-memory mode...")
        return False


# Event signatures - known bridge and token events
EVENT_SIGNATURES = {
    # Token events
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": ("Transfer", "low", 0),
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": ("Approval", "low", 0),
    
    # Bridge events - more suspicious
    "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2": ("LogMessagePublished", "high", 50000),
    "0x1b2a7ff080b8cb6ff436ce0372e399692bbfb6d4ae5766fd8d58a7b8cc6142e6": ("TransferRedeemed", "critical", 100000),
    "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c": ("Deposit", "medium", 10000),
    "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65": ("Withdrawal", "high", 50000),
}


def get_event_info(topic0_hex: str):
    """Get event name, severity, and estimated value from topic."""
    info = EVENT_SIGNATURES.get(topic0_hex, ("Event", "low", 0))
    return info[0], info[1], info[2]


class YAMLRuleMonitor:
    """
    Monitor that uses YAML-based rules for alert detection.
    """
    
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
        """
        Evaluate an event against all YAML rules.
        Returns list of incidents to create.
        """
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


def monitor():
    """Main monitoring function with YAML rules."""
    print_banner()
    
    # Initialize database if enabled
    if POSTGRES_ENABLED:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        db_connected = loop.run_until_complete(init_database())
        if db_connected:
            print()
    
    config = load_config()
    chains = {}
    last_blocks = {}
    
    # Connect to chains
    print("🔗 Connecting to chains...")
    print("-" * 70)
    
    for chain_config in config.get("chains", []):
        chain_id = chain_config["chain_id"]
        chain_name = chain_config["chain_name"]
        rpc_url = chain_config["rpc_url"]
        
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 30}))
            if w3.is_connected():
                block = w3.eth.block_number
                chains[chain_id] = {
                    "web3": w3,
                    "config": chain_config
                }
                last_blocks[chain_id] = block
                print(f"   ✅ {chain_name}: Block {block:,}")
            else:
                print(f"   ❌ {chain_name}: Connection failed")
        except Exception as e:
            print(f"   ❌ {chain_name}: {str(e)[:40]}")
    
    if not chains:
        print("\n❌ No chains connected. Check your API keys.")
        return
    
    # Initialize YAML rule monitor
    print()
    print("-" * 70)
    rule_monitor = YAMLRuleMonitor()
    print("-" * 70)
    
    # Start dashboard
    print()
    print("🖥️  Starting Dashboard...")
    start_dashboard()
    time.sleep(2)
    
    # Initialize monitor state (don't reset - preserves DB connection)
    monitor_state.set_start_time()
    
    print()
    print("=" * 70)
    print("🚀 MONITORING STARTED WITH YAML RULES!")
    print("=" * 70)
    print()
    print("📊 Dashboard: http://localhost:8080/frontend/index.html")
    print("📚 API Docs:  http://localhost:8080/api/docs")
    print()
    print("Press Ctrl+C to stop")
    print()
    print("-" * 70)
    print("📡 Scanning for events and evaluating against YAML rules...")
    print("-" * 70)
    print()
    
    scan_count = 0
    yaml_incidents = 0
    
    try:
        while True:
            for chain_id, chain_data in chains.items():
                w3 = chain_data["web3"]
                chain_config = chain_data["config"]
                
                try:
                    current_block = w3.eth.block_number
                    last_block = last_blocks.get(chain_id, current_block - 5)
                    
                    # Only scan new blocks
                    if current_block <= last_block:
                        continue
                    
                    from_block = last_block + 1
                    blocks_scanned = current_block - last_block
                    
                    # Scan bridge contracts
                    for contract_addr in chain_config.get("bridge_contracts", [])[:2]:
                        try:
                            logs = w3.eth.get_logs({
                                "fromBlock": from_block,
                                "toBlock": current_block,
                                "address": Web3.to_checksum_address(contract_addr)
                            })
                            
                            for log in logs:
                                # Get event type and severity
                                topic0 = log["topics"][0].hex() if log["topics"] else ""
                                event_type, severity, estimated_usd = get_event_info(topic0)
                                
                                tx_hash = log["transactionHash"].hex()
                                block_num = log["blockNumber"]
                                
                                # Create live event
                                live_event = LiveEvent(
                                    id=f"evt-{uuid.uuid4().hex[:12]}",
                                    chain=chain_id,
                                    event_type=event_type,
                                    tx_hash=tx_hash,
                                    block=block_num,
                                    contract=contract_addr,
                                    severity=severity,
                                    data={
                                        "topics": [t.hex() for t in log.get("topics", [])],
                                        "amount_usd": estimated_usd,
                                    }
                                )
                                
                                # Add to shared state
                                monitor_state.add_event(live_event)
                                
                                # ===== EVALUATE AGAINST YAML RULES =====
                                incidents = rule_monitor.evaluate_event(live_event)
                                
                                for incident in incidents:
                                    monitor_state.add_incident(incident)
                                    yaml_incidents += 1
                                
                                # Log high-severity events
                                if severity in ["critical", "high"]:
                                    severity_emoji = "🔴" if severity == "critical" else "🟠"
                                    print(f"{severity_emoji} [{chain_id.upper():8}] {event_type:20} Block: {block_num:,}")
                                    print(f"   TX: {tx_hash[:20]}...{tx_hash[-8:]}")
                                
                        except Exception:
                            pass
                    
                    monitor_state.add_blocks_scanned(blocks_scanned)
                    last_blocks[chain_id] = current_block
                    
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
                
                print(f"📊 Events: {stats['total_events']} | YAML Incidents: {yaml_incidents} | Blocks: {stats['blocks_scanned']} | Uptime: {uptime}s")
                
                # Show rules stats
                rule_stats = rule_monitor.rule_engine.stats()
                print(f"   Rules: {rule_stats['total_rules']} loaded | {len(incidents)} total incidents")
                print()
            
            time.sleep(3)
            
    except KeyboardInterrupt:
        stats = monitor_state.get_stats()
        incidents = monitor_state.get_incidents()
        print("\n\n👋 Shutting down...")
        print(f"📊 Final: {stats['total_events']} events, {len(incidents)} incidents")
        print(f"   YAML rule triggers: {yaml_incidents}")


if __name__ == "__main__":
    monitor()
