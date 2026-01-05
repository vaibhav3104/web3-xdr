#!/usr/bin/env python3
"""
Sentinel3 - Real-Time Bridge Monitor

Starts real-time monitoring of configured chains and bridges.
"""

import asyncio
import sys
import os
import yaml
from datetime import datetime
from typing import Dict, List, Any

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import structlog
from web3 import AsyncWeb3, AsyncHTTPProvider

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(colors=True)
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

log = structlog.get_logger()


class BridgeEvent:
    """Represents a detected bridge event."""
    def __init__(self, chain: str, contract: str, event_type: str, 
                 tx_hash: str, block: int, data: Dict):
        self.chain = chain
        self.contract = contract
        self.event_type = event_type
        self.tx_hash = tx_hash
        self.block = block
        self.data = data
        self.timestamp = datetime.utcnow()


class RealTimeMonitor:
    """Real-time blockchain monitor."""
    
    def __init__(self, config_path: str):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        self.chains: Dict[str, AsyncWeb3] = {}
        self.last_blocks: Dict[str, int] = {}
        self.events_detected: List[BridgeEvent] = []
        self.running = False
        
        # Stats
        self.stats = {
            "events_processed": 0,
            "blocks_scanned": 0,
            "alerts_triggered": 0,
            "start_time": None
        }
    
    async def connect_chains(self):
        """Connect to all configured chains."""
        print()
        print("=" * 60)
        print("🔗 Connecting to Chains...")
        print("=" * 60)
        
        for chain_config in self.config.get("chains", []):
            chain_id = chain_config["chain_id"]
            rpc_url = chain_config["rpc_url"]
            
            try:
                w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
                
                if await w3.is_connected():
                    block = await w3.eth.block_number
                    self.chains[chain_id] = w3
                    self.last_blocks[chain_id] = block
                    print(f"   ✅ {chain_config['chain_name']}: Block {block:,}")
                else:
                    print(f"   ❌ {chain_config['chain_name']}: Connection failed")
                    
            except Exception as e:
                print(f"   ❌ {chain_config['chain_name']}: {str(e)[:50]}")
    
    async def scan_chain(self, chain_id: str, chain_config: Dict):
        """Scan a single chain for bridge events."""
        w3 = self.chains.get(chain_id)
        if not w3:
            return []
        
        events = []
        
        try:
            current_block = await w3.eth.block_number
            last_block = self.last_blocks.get(chain_id, current_block - 10)
            
            # Don't scan more than 100 blocks at once
            from_block = max(last_block + 1, current_block - 100)
            
            if from_block > current_block:
                return []
            
            # Scan each bridge contract
            for contract_addr in chain_config.get("bridge_contracts", []):
                try:
                    logs = await w3.eth.get_logs({
                        "fromBlock": from_block,
                        "toBlock": current_block,
                        "address": contract_addr
                    })
                    
                    for log_entry in logs:
                        event = BridgeEvent(
                            chain=chain_id,
                            contract=contract_addr,
                            event_type=self._decode_event_type(log_entry),
                            tx_hash=log_entry["transactionHash"].hex(),
                            block=log_entry["blockNumber"],
                            data={
                                "topics": [t.hex() for t in log_entry.get("topics", [])],
                                "data": log_entry.get("data", "").hex() if log_entry.get("data") else ""
                            }
                        )
                        events.append(event)
                        
                except Exception as e:
                    pass  # Skip individual contract errors
            
            self.last_blocks[chain_id] = current_block
            self.stats["blocks_scanned"] += (current_block - from_block + 1)
            
        except Exception as e:
            log.error("chain_scan_error", chain=chain_id, error=str(e))
        
        return events
    
    def _decode_event_type(self, log_entry) -> str:
        """Decode event type from log entry."""
        topics = log_entry.get("topics", [])
        if not topics:
            return "Unknown"
        
        # Known event signatures
        event_signatures = {
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
            "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2": "LogMessagePublished",
            "0x1b2a7ff080b8cb6ff436ce0372e399692bbfb6d4ae5766fd8d58a7b8cc6142e6": "TransferRedeemed",
        }
        
        topic0 = topics[0].hex() if topics else ""
        return event_signatures.get(topic0, f"Event_{topic0[:10]}")
    
    def _analyze_event(self, event: BridgeEvent) -> Dict[str, Any]:
        """Analyze event for potential threats."""
        analysis = {
            "suspicious": False,
            "severity": "low",
            "reason": None
        }
        
        # Check for large transfers (simplified)
        if event.event_type == "Transfer":
            # Check data size (large values might indicate large transfers)
            data = event.data.get("data", "")
            if len(data) > 64:  # Has value data
                analysis["suspicious"] = True
                analysis["severity"] = "medium"
                analysis["reason"] = "Large transfer detected"
        
        # Check for bridge message events
        if event.event_type == "LogMessagePublished":
            analysis["suspicious"] = True
            analysis["severity"] = "info"
            analysis["reason"] = "Bridge message published"
        
        return analysis
    
    async def monitor_loop(self):
        """Main monitoring loop."""
        print()
        print("=" * 60)
        print("🚀 Real-Time Monitoring Started!")
        print("=" * 60)
        print()
        print("📊 Dashboard: http://localhost:8080/frontend/index.html")
        print("📚 API Docs:  http://localhost:8080/api/docs")
        print()
        print("Press Ctrl+C to stop")
        print()
        print("-" * 60)
        print("📡 Scanning for bridge activity...")
        print("-" * 60)
        print()
        
        self.running = True
        self.stats["start_time"] = datetime.utcnow()
        
        scan_count = 0
        
        while self.running:
            try:
                all_events = []
                
                # Scan all chains
                for chain_config in self.config.get("chains", []):
                    chain_id = chain_config["chain_id"]
                    events = await self.scan_chain(chain_id, chain_config)
                    all_events.extend(events)
                
                # Process new events
                for event in all_events:
                    self.stats["events_processed"] += 1
                    analysis = self._analyze_event(event)
                    
                    # Log significant events
                    if analysis["suspicious"] or event.event_type in ["Transfer", "LogMessagePublished", "TransferRedeemed"]:
                        severity_emoji = {
                            "critical": "🔴",
                            "high": "🟠", 
                            "medium": "🟡",
                            "low": "🟢",
                            "info": "🔵"
                        }.get(analysis["severity"], "⚪")
                        
                        print(f"{severity_emoji} [{event.chain.upper()}] {event.event_type}")
                        print(f"   Block: {event.block:,} | TX: {event.tx_hash[:16]}...")
                        if analysis["reason"]:
                            print(f"   ⚠️  {analysis['reason']}")
                        print()
                
                # Status update every 10 scans
                scan_count += 1
                if scan_count % 10 == 0:
                    uptime = (datetime.utcnow() - self.stats["start_time"]).seconds
                    print(f"📊 Status: {self.stats['events_processed']} events | {self.stats['blocks_scanned']} blocks | {uptime}s uptime")
                    print()
                
                # Wait before next scan
                await asyncio.sleep(5)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("monitor_error", error=str(e))
                await asyncio.sleep(5)
    
    async def start(self):
        """Start the monitor."""
        await self.connect_chains()
        await self.monitor_loop()
    
    def stop(self):
        """Stop the monitor."""
        self.running = False


async def start_api_server():
    """Start the API server in background."""
    import uvicorn
    from src.api.server import create_app
    from fastapi.staticfiles import StaticFiles
    
    app = create_app()
    app.mount('/frontend', StaticFiles(directory='frontend', html=True), name='frontend')
    
    config = uvicorn.Config(app, host="0.0.0.0", port=8080, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()


async def main():
    """Main entry point."""
    print()
    print("=" * 60)
    print("🛡️  Sentinel3 - Real-Time Bridge Monitor")
    print("=" * 60)
    
    config_path = os.path.join(os.path.dirname(__file__), "config", "chains.yaml")
    
    if not os.path.exists(config_path):
        print("❌ Config file not found!")
        print(f"   Expected: {config_path}")
        return
    
    # Start API server and monitor concurrently
    monitor = RealTimeMonitor(config_path)
    
    try:
        # Run both tasks
        await asyncio.gather(
            start_api_server(),
            monitor.start()
        )
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down...")
        monitor.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")

