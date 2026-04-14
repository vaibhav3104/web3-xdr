#!/usr/bin/env python3
"""
Sentinel3 Worker - Dedicated Listener Process
==============================================

A dedicated worker process that runs blockchain listeners independently
from the API server. Designed for Cloud Run and distributed deployments.

Key Features:
- Decoupled from API server (runs as separate container/process)
- Async-first design for all chain types
- Redis-backed state sharing
- Graceful shutdown handling
- Health endpoint for orchestration
- Heartbeat logging for monitoring

Usage:
    python worker.py                    # Run all configured chains
    python worker.py --chains ethereum,polygon  # Run specific chains
    python worker.py --type evm         # Run only EVM chains
    python worker.py --health-port 8081 # Custom health port

Environment Variables:
    REDIS_URL          - Redis connection URL (required for distributed mode)
    POSTGRES_ENABLED   - Enable PostgreSQL persistence
    WORKER_HEALTH_PORT - Health check endpoint port (default: 8081)
    HEARTBEAT_INTERVAL - Seconds between heartbeat logs (default: 60)
"""

import asyncio
import argparse
import os
import signal
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

# Add src to path
sys.path.insert(0, os.path.dirname(__file__))

import structlog
import yaml

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.ConsoleRenderer()
    ]
)

logger = structlog.get_logger(__name__)

# Environment configuration
REDIS_ENABLED = os.getenv("REDIS_ENABLED", "true").lower() == "true"
POSTGRES_ENABLED = os.getenv("POSTGRES_ENABLED", "false").lower() == "true"
HEALTH_PORT = int(os.getenv("WORKER_HEALTH_PORT", "8081"))
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "60"))


@dataclass
class WorkerStats:
    """Statistics for the worker process."""
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    events_processed: int = 0
    blocks_processed: int = 0
    errors: int = 0
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    active_listeners: Set[str] = field(default_factory=set)
    listener_heights: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        uptime = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return {
            "uptime_seconds": int(uptime),
            "events_processed": self.events_processed,
            "blocks_processed": self.blocks_processed,
            "errors": self.errors,
            "active_listeners": list(self.active_listeners),
            "listener_heights": self.listener_heights,
            "last_heartbeat": self.last_heartbeat.isoformat(),
        }


class Sentinel3Worker:
    """
    Dedicated worker process for running blockchain listeners.
    
    Separating listeners from the API server provides:
    - Independent scaling (more listeners != more API instances)
    - Better resource isolation
    - Cleaner shutdown/restart cycles
    - Easier debugging and monitoring
    """
    
    def __init__(
        self,
        chains: Optional[List[str]] = None,
        chain_types: Optional[List[str]] = None,
    ):
        self.chains_filter = set(chains) if chains else None
        self.chain_types_filter = set(chain_types) if chain_types else None
        
        self.stats = WorkerStats()
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Listeners
        self.evm_listeners: Dict[str, any] = {}
        self.non_evm_listeners: Dict[str, any] = {}
        
        # Shared state
        self.monitor_state = None
        self.rule_engine = None

        # Mempool alerter
        self.mempool_alerter = None
        
        logger.info(
            "worker_initialized",
            chains_filter=list(self.chains_filter) if self.chains_filter else "all",
            chain_types_filter=list(self.chain_types_filter) if self.chain_types_filter else "all",
            redis_enabled=REDIS_ENABLED,
            postgres_enabled=POSTGRES_ENABLED,
        )
    
    def load_config(self) -> dict:
        """Load chain configuration from YAML."""
        config_path = os.path.join(os.path.dirname(__file__), "config", "chains.yaml")
        with open(config_path) as f:
            return yaml.safe_load(f)
    
    def get_chain_type(self, chain_id: str) -> str:
        """Determine chain type from chain ID."""
        chain_lower = chain_id.lower()
        
        evm_chains = {
            "ethereum", "polygon", "arbitrum", "optimism",
            "bsc", "avalanche", "fantom", "base", "zksync",
            "linea", "scroll", "mantle", "blast"
        }
        cosmos_chains = {
            "cosmos", "osmosis", "injective", "sei", "celestia",
            "dydx", "neutron", "kava", "evmos", "axelar"
        }
        aptos_chains = {"aptos", "movement"}
        sui_chains = {"sui"}
        near_chains = {"near", "aurora"}
        solana_chains = {"solana"}
        
        if chain_lower in evm_chains:
            return "evm"
        elif chain_lower in cosmos_chains:
            return "cosmos"
        elif chain_lower in aptos_chains:
            return "aptos"
        elif chain_lower in sui_chains:
            return "sui"
        elif chain_lower in near_chains:
            return "near"
        elif chain_lower in solana_chains:
            return "solana"
        return "unknown"
    
    def should_include_chain(self, chain_id: str, chain_type: str) -> bool:
        """Check if chain should be included based on filters."""
        if self.chains_filter and chain_id.lower() not in {c.lower() for c in self.chains_filter}:
            return False
        if self.chain_types_filter and chain_type not in self.chain_types_filter:
            return False
        return True
    
    async def init_shared_state(self):
        """Initialize shared state and Redis connection."""
        from src.shared_state import monitor_state
        
        self.monitor_state = monitor_state
        
        # Initialize backends (Redis if enabled)
        if hasattr(monitor_state, 'init_backends'):
            await monitor_state.init_backends()
            logger.info("shared_state_backends_initialized")
        
        # Initialize rule engine
        try:
            from src.rules import RuleEngine
            self.rule_engine = RuleEngine()
            # Load rules from config directory
            rules_dir = os.path.join(os.path.dirname(__file__), "config", "rules")
            if os.path.exists(rules_dir):
                loaded = self.rule_engine.load_rules_from_directory(rules_dir)
                logger.info("rule_engine_initialized", rules_loaded=loaded)
            else:
                logger.warning("rules_directory_not_found", path=rules_dir)
        except Exception as e:
            logger.warning("rule_engine_init_failed", error=str(e))
    
    async def init_evm_listeners(self, config: dict):
        """Initialize EVM chain listeners."""
        from src.telemetry.evm_listener import EVMListener
        from src.telemetry.base import ListenerConfig
        
        for chain_config in config.get("chains", []):
            chain_id = chain_config["chain_id"]
            chain_type = self.get_chain_type(chain_id)
            
            if chain_type != "evm":
                continue
            
            if not self.should_include_chain(chain_id, chain_type):
                continue
            
            try:
                # Build RPC URLs list
                rpc_urls = []
                if chain_config.get("rpc_url"):
                    rpc_urls.append(chain_config["rpc_url"])
                rpc_urls.extend(chain_config.get("fallback_rpcs", []))
                
                listener_config = ListenerConfig(
                    chain_id=chain_id,
                    chain_name=chain_config["chain_name"],
                    rpc_url=rpc_urls[0] if rpc_urls else "",
                    fallback_rpcs=rpc_urls[1:] if len(rpc_urls) > 1 else [],
                    bridge_contracts=chain_config.get("bridge_contracts", []),
                    token_contracts=chain_config.get("tokens", []),
                )
                
                listener = EVMListener(listener_config, rpc_urls=rpc_urls)
                
                if await listener.connect():
                    self.evm_listeners[chain_id] = listener
                    self.stats.active_listeners.add(chain_id)
                    logger.info(
                        "evm_listener_started",
                        chain=chain_id,
                        rpc_count=len(rpc_urls)
                    )
                else:
                    logger.error("evm_listener_connection_failed", chain=chain_id)
                    
            except Exception as e:
                logger.error("evm_listener_init_error", chain=chain_id, error=str(e))
    
    async def init_non_evm_listeners(self, config: dict):
        """Initialize non-EVM chain listeners (Cosmos, Aptos, Near)."""
        from src.telemetry.cosmos_listener import CosmosListener, CosmosConfig
        from src.telemetry.aptos_listener import AptosListener, AptosConfig
        from src.telemetry.near_listener import NearListener, NearConfig
        
        for chain_config in config.get("chains", []):
            chain_id = chain_config["chain_id"]
            chain_type = self.get_chain_type(chain_id)
            
            if chain_type == "evm" or chain_type == "unknown":
                continue
            
            if not self.should_include_chain(chain_id, chain_type):
                continue
            
            try:
                listener = None
                
                if chain_type == "cosmos":
                    cosmos_config = CosmosConfig(
                        chain_id=chain_id,
                        chain_name=chain_config["chain_name"],
                        rpc_url=chain_config.get("rpc_url", ""),
                        tendermint_rpc=chain_config.get("rpc_url", ""),
                        fallback_rpcs=chain_config.get("fallback_rpcs", []),
                        ibc_channels=chain_config.get("ibc_channels", []),
                        bridge_contracts=chain_config.get("bridge_contracts", []),
                    )
                    listener = CosmosListener(cosmos_config)
                    
                elif chain_type in ["aptos", "sui"]:
                    aptos_config = AptosConfig(
                        chain_id=chain_id,
                        chain_name=chain_config["chain_name"],
                        rest_api=chain_config.get("rpc_url", ""),
                        fallback_rpcs=chain_config.get("fallback_rpcs", []),
                        chain_type=chain_type,
                        bridge_modules=chain_config.get("bridge_contracts", []),
                    )
                    listener = AptosListener(aptos_config)
                    
                elif chain_type == "near":
                    near_config = NearConfig(
                        chain_id=chain_id,
                        chain_name=chain_config["chain_name"],
                        rpc_url=chain_config.get("rpc_url", ""),
                        fallback_rpcs=chain_config.get("fallback_rpcs", []),
                        bridge_accounts=chain_config.get("bridge_contracts", []),
                    )
                    listener = NearListener(near_config)
                
                if listener and await listener.connect():
                    self.non_evm_listeners[chain_id] = listener
                    self.stats.active_listeners.add(chain_id)
                    logger.info(
                        "non_evm_listener_started",
                        chain=chain_id,
                        chain_type=chain_type,
                        height=listener.latest_height
                    )
                elif listener:
                    logger.error("non_evm_listener_connection_failed", chain=chain_id)
                    
            except Exception as e:
                logger.error("non_evm_listener_init_error", chain=chain_id, error=str(e))
    
    async def init_mempool_alerter(self, config: dict):
        """Initialize the MempoolAlerter with the bloXroute mempool source.

        Falls back gracefully if bloXroute credentials are not configured.
        """
        try:
            from src.runtime.mempool_alerter import MempoolAlerter, set_mempool_alerter
            from src.runtime.intent_sources.bloxroute_source import BloxrouteMempoolSource

            bloxroute_auth = os.getenv("BLOXROUTE_AUTH_HEADER", "")
            monitored_raw = os.getenv("BLOXROUTE_MONITORED_ADDRESSES", "")
            monitored_addresses = [
                a.strip() for a in monitored_raw.split(",") if a.strip()
            ]
            chain_id = os.getenv("BLOXROUTE_CHAIN_ID", "ethereum")

            if not bloxroute_auth or not monitored_addresses:
                logger.info(
                    "mempool_alerter_skipped",
                    reason="BLOXROUTE_AUTH_HEADER or BLOXROUTE_MONITORED_ADDRESSES not set",
                )
                return

            # Create the bloXroute mempool source
            source = BloxrouteMempoolSource(
                chain_id=chain_id,
                auth_header=bloxroute_auth,
                monitored_addresses=monitored_addresses,
            )
            await source.start()

            # Optionally attach the invariant engine
            invariant_engine = None
            try:
                from src.invariants.engine import create_default_engine
                invariant_engine = create_default_engine(config)
            except Exception as exc:
                logger.warning("mempool_invariant_engine_unavailable", error=str(exc))

            alerter = MempoolAlerter(
                invariant_engine=invariant_engine,
                config={
                    "mempool_alerting_enabled": os.getenv(
                        "MEMPOOL_ALERTING_ENABLED", "true"
                    ).lower()
                    == "true"
                },
            )

            # Register the global singleton so the API routes can reach it
            set_mempool_alerter(alerter)

            # Start monitoring (runs in its own asyncio task internally)
            await alerter.start(source)
            self.mempool_alerter = alerter

            logger.info(
                "mempool_alerter_initialized",
                chain_id=chain_id,
                monitored_addresses=len(monitored_addresses),
            )

        except ImportError as exc:
            logger.warning("mempool_alerter_import_failed", error=str(exc))
        except Exception as exc:
            logger.error("mempool_alerter_init_error", error=str(exc))

    async def process_event(self, event):
        """Process a security event from any listener."""
        try:
            # Convert to LiveEvent for shared state
            from src.shared_state import LiveEvent
            
            live_event = LiveEvent(
                id=getattr(event, 'event_id', str(event.transaction_hash)),
                chain=event.chain_id,
                event_type=str(event.event_type.value) if hasattr(event.event_type, 'value') else str(event.event_type),
                tx_hash=str(event.transaction_hash),
                block=event.block_number,
                contract=str(event.contract_address) if event.contract_address else "",
                severity=str(event.severity.value) if hasattr(event.severity, 'value') else str(event.severity),
                amount=float(event.value) if event.value else 0.0,
                amount_usd=float(getattr(event, 'value_usd', 0) or 0),
                data=getattr(event, 'raw_data', {}) or {},
            )
            
            self.monitor_state.add_event(live_event)
            self.stats.events_processed += 1
            
            # Update height tracking
            self.stats.listener_heights[event.chain_id] = event.block_number
            
            # Evaluate rules
            if self.rule_engine:
                incidents = self.rule_engine.evaluate(event)
                for incident in incidents:
                    self.monitor_state.add_incident(incident)
                    logger.warning(
                        "incident_detected",
                        chain=event.chain_id,
                        type=incident.attack_type,
                        severity=incident.severity
                    )
            
            # Log high-severity events
            severity_str = str(event.severity.value) if hasattr(event.severity, 'value') else str(event.severity)
            if severity_str in ["critical", "high"]:
                logger.info(
                    "high_severity_event",
                    chain=event.chain_id,
                    type=str(event.event_type),
                    tx=str(event.transaction_hash)[:16],
                    block=event.block_number
                )
                
        except Exception as e:
            self.stats.errors += 1
            logger.error("event_processing_error", error=str(e))
    
    async def run_evm_listener(self, chain_id: str, listener):
        """Run a single EVM listener."""
        try:
            while self.running and not self.shutdown_event.is_set():
                try:
                    # Get latest block
                    latest = await listener.w3.eth.block_number
                    
                    # Process new blocks
                    while listener.last_processed_block < latest and self.running:
                        listener.last_processed_block += 1
                        
                        try:
                            metadata = await listener.process_block(listener.last_processed_block)
                            self.stats.blocks_processed += 1
                            self.stats.listener_heights[chain_id] = listener.last_processed_block
                        except Exception as e:
                            logger.error(
                                "evm_block_error",
                                chain=chain_id,
                                block=listener.last_processed_block,
                                error=str(e)[:60]
                            )
                    
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    self.stats.errors += 1
                    logger.error("evm_listener_error", chain=chain_id, error=str(e)[:80])
                    await asyncio.sleep(5)
                    
        except asyncio.CancelledError:
            logger.info("evm_listener_cancelled", chain=chain_id)
    
    async def run_non_evm_listener(self, chain_id: str, listener):
        """Run a single non-EVM listener."""
        try:
            async for event in listener.listen_events():
                if not self.running or self.shutdown_event.is_set():
                    break
                await self.process_event(event)
                self.stats.listener_heights[chain_id] = listener.latest_height
                
        except asyncio.CancelledError:
            logger.info("non_evm_listener_cancelled", chain=chain_id)
        except Exception as e:
            self.stats.errors += 1
            logger.error("non_evm_listener_error", chain=chain_id, error=str(e))
    
    async def heartbeat_loop(self):
        """Periodic heartbeat logging."""
        while self.running and not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                
                self.stats.last_heartbeat = datetime.now(timezone.utc)
                
                logger.info(
                    "worker_heartbeat",
                    active_listeners=len(self.stats.active_listeners),
                    events_processed=self.stats.events_processed,
                    blocks_processed=self.stats.blocks_processed,
                    errors=self.stats.errors,
                    heights=self.stats.listener_heights
                )
                
            except asyncio.CancelledError:
                break
    
    async def health_server(self):
        """Simple HTTP health check server."""
        from aiohttp import web
        
        # Get port from environment (may have been updated by CLI)
        health_port = int(os.getenv("WORKER_HEALTH_PORT", "8081"))
        
        async def health_handler(request):
            return web.json_response({
                "status": "healthy" if self.running else "stopping",
                "stats": self.stats.to_dict()
            })
        
        async def ready_handler(request):
            if len(self.stats.active_listeners) > 0:
                return web.json_response({"ready": True})
            return web.json_response({"ready": False}, status=503)
        
        app = web.Application()
        app.router.add_get("/health", health_handler)
        app.router.add_get("/ready", ready_handler)
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", health_port)
        
        try:
            await site.start()
            logger.info("health_server_started", port=health_port)
            
            while self.running and not self.shutdown_event.is_set():
                await asyncio.sleep(1)
                
        finally:
            await runner.cleanup()
    
    async def run(self):
        """Main worker loop."""
        self.running = True
        
        logger.info("worker_starting")
        
        # Load configuration
        config = self.load_config()
        
        # Initialize shared state
        await self.init_shared_state()
        
        # Initialize listeners
        await self.init_evm_listeners(config)
        await self.init_non_evm_listeners(config)

        # Initialize mempool pre-confirmation alerter
        await self.init_mempool_alerter(config)

        if not self.stats.active_listeners:
            logger.error("no_listeners_started")
            return
        
        logger.info(
            "worker_ready",
            evm_listeners=len(self.evm_listeners),
            non_evm_listeners=len(self.non_evm_listeners),
            total=len(self.stats.active_listeners)
        )
        
        # Create tasks for all listeners
        tasks = []
        
        # EVM listeners
        for chain_id, listener in self.evm_listeners.items():
            task = asyncio.create_task(
                self.run_evm_listener(chain_id, listener),
                name=f"evm_{chain_id}"
            )
            tasks.append(task)
        
        # Non-EVM listeners
        for chain_id, listener in self.non_evm_listeners.items():
            task = asyncio.create_task(
                self.run_non_evm_listener(chain_id, listener),
                name=f"non_evm_{chain_id}"
            )
            tasks.append(task)
        
        # Heartbeat
        tasks.append(asyncio.create_task(self.heartbeat_loop(), name="heartbeat"))
        
        # Health server
        tasks.append(asyncio.create_task(self.health_server(), name="health"))
        
        try:
            # Wait for shutdown signal or task failure
            await self.shutdown_event.wait()
            
        except asyncio.CancelledError:
            logger.info("worker_cancelled")
        finally:
            self.running = False
            
            # Cancel all tasks
            for task in tasks:
                task.cancel()
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Stop mempool alerter
            if self.mempool_alerter:
                await self.mempool_alerter.stop()

            # Disconnect listeners
            for listener in self.evm_listeners.values():
                await listener.disconnect()
            for listener in self.non_evm_listeners.values():
                await listener.disconnect()

            logger.info("worker_stopped", stats=self.stats.to_dict())
    
    def signal_handler(self, sig):
        """Handle shutdown signals."""
        logger.info("shutdown_signal_received", signal=sig.name)
        self.running = False
        self.shutdown_event.set()


async def main():
    """Entry point for the worker."""
    parser = argparse.ArgumentParser(description="Sentinel3 Worker - Blockchain Listener Process")
    parser.add_argument(
        "--chains",
        type=str,
        help="Comma-separated list of chain IDs to monitor (e.g., ethereum,polygon)"
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=["evm", "cosmos", "aptos", "sui", "near", "all"],
        default="all",
        help="Chain type to monitor"
    )
    parser.add_argument(
        "--health-port",
        type=int,
        default=HEALTH_PORT,
        help=f"Health check endpoint port (default: {HEALTH_PORT})"
    )
    
    args = parser.parse_args()
    
    # Parse filters
    chains = args.chains.split(",") if args.chains else None
    chain_types = [args.type] if args.type != "all" else None
    
    # Update health port via environment (cleaner than global)
    os.environ["WORKER_HEALTH_PORT"] = str(args.health_port)
    
    # Create and run worker
    worker = Sentinel3Worker(chains=chains, chain_types=chain_types)
    
    # Setup signal handlers
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: worker.signal_handler(s))
    
    await worker.run()


if __name__ == "__main__":
    print()
    print("=" * 60)
    print("🛡️  Sentinel3 Worker - Dedicated Listener Process")
    print("=" * 60)
    print()
    
    asyncio.run(main())

