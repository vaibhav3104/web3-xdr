"""
Sentinel3 - Main Entry Point

Explainable Cross-Chain Bridge Attack Detection & Response
"""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional
import structlog
import yaml

from .telemetry.listener_pool import ListenerPool, create_listener_pool_from_config
from .invariants.engine import InvariantEngine, create_default_engine
from .correlation.correlator import XDRCorrelator
from .explainability.engine import ExplainabilityEngine
from .response.alerting import AlertRouter, AlertConfig
from .models.events import SecurityEvent
from .models.invariants import InvariantResult
from .models.incidents import Incident

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


class Web3XDR:
    """
    Main Sentinel3 Application.
    
    Orchestrates all components:
    - Telemetry collection
    - Invariant detection
    - Correlation
    - Explainability
    - Response
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.listener_pool: Optional[ListenerPool] = None
        self.invariant_engine: Optional[InvariantEngine] = None
        self.correlator: Optional[XDRCorrelator] = None
        self.explainability_engine: Optional[ExplainabilityEngine] = None
        self.alert_router: Optional[AlertRouter] = None
        
        self._is_running = False
        self._shutdown_event = asyncio.Event()
    
    def _load_config(self, config_path: Optional[str]) -> dict:
        """Load configuration from file."""
        if config_path:
            path = Path(config_path)
            if path.exists():
                with open(path) as f:
                    return yaml.safe_load(f)
        
        # Default configuration
        return self._get_default_config()
    
    def _get_default_config(self) -> dict:
        """Get default configuration."""
        return {
            "chains": [
                {
                    "chain_id": "ethereum",
                    "chain_name": "Ethereum Mainnet",
                    "rpc_url": "https://eth-mainnet.g.alchemy.com/v2/demo",
                    "bridge_contracts": [],
                    "poll_interval_seconds": 12,
                    "confirmations_required": 2,
                }
            ],
            "bridges": [
                {
                    "id": "example_bridge",
                    "source_chain": "ethereum",
                    "dest_chain": "polygon",
                    "contracts": [],
                }
            ],
            "alerting": {
                "telegram_enabled": False,
                "slack_enabled": False,
            }
        }
    
    async def initialize(self):
        """Initialize all components."""
        logger.info("initializing_web3_xdr")
        
        # Initialize telemetry
        self.listener_pool = await create_listener_pool_from_config(self.config)
        
        # Initialize invariant engine
        self.invariant_engine = create_default_engine(self.config)
        
        # Initialize correlator
        self.correlator = XDRCorrelator()
        
        # Initialize explainability
        self.explainability_engine = ExplainabilityEngine()
        
        # Initialize alerting
        alert_config = AlertConfig(
            telegram_enabled=self.config.get("alerting", {}).get("telegram_enabled", False),
            telegram_bot_token=self.config.get("alerting", {}).get("telegram_bot_token"),
            telegram_critical_channel=self.config.get("alerting", {}).get("telegram_critical_channel"),
            slack_enabled=self.config.get("alerting", {}).get("slack_enabled", False),
            slack_webhook_url=self.config.get("alerting", {}).get("slack_webhook_url"),
        )
        self.alert_router = AlertRouter(alert_config)
        await self.alert_router.initialize()
        
        # Wire up event handlers
        self._setup_event_handlers()
        
        logger.info("web3_xdr_initialized")
    
    def _setup_event_handlers(self):
        """Set up event flow between components."""
        
        # Telemetry → Invariant Engine + Correlator
        async def on_event(event: SecurityEvent):
            # Update invariant context
            await self.invariant_engine.process_event(event)
            
            # Update correlator
            await self.correlator.process_event(event)
        
        self.listener_pool.add_event_handler(on_event)
        
        # Invariant Engine → Correlator
        async def on_violation(result: InvariantResult):
            if result.violated:
                await self.correlator.process_violation(result)
        
        self.invariant_engine.add_result_handler(on_violation)
        
        # Correlator → Explainability → Alerting
        async def on_incident(incident: Incident):
            # Generate explanation
            explanation = self.explainability_engine.explain(incident)
            
            # Route alert
            await self.alert_router.route(incident, explanation)
        
        self.correlator.add_incident_handler(on_incident)
    
    async def start(self):
        """Start the XDR system."""
        logger.info("starting_web3_xdr")
        
        self._is_running = True
        
        # Start background invariant checks
        await self.invariant_engine.start_background_checks(interval_seconds=60)
        
        # Start telemetry collection
        await self.listener_pool.start()
        
        logger.info("web3_xdr_started")
        
        # Wait for shutdown
        await self._shutdown_event.wait()
    
    async def stop(self):
        """Stop the XDR system."""
        logger.info("stopping_web3_xdr")
        
        self._is_running = False
        self._shutdown_event.set()
        
        # Stop components
        if self.listener_pool:
            await self.listener_pool.stop()
        
        if self.invariant_engine:
            await self.invariant_engine.stop()
        
        logger.info("web3_xdr_stopped")
    
    def get_status(self) -> dict:
        """Get system status."""
        return {
            "is_running": self._is_running,
            "telemetry": self.listener_pool.get_status() if self.listener_pool else {},
            "invariants": self.invariant_engine.get_stats() if self.invariant_engine else {},
            "correlation": self.correlator.get_stats() if self.correlator else {},
            "alerting": self.alert_router.get_stats() if self.alert_router else {},
        }


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Sentinel3 - Cross-Chain Security")
    parser.add_argument("--config", "-c", help="Path to config file")
    parser.add_argument("--simulate", "-s", action="store_true", help="Run attack simulation")
    args = parser.parse_args()
    
    if args.simulate:
        # Run simulation
        from examples.wormhole_simulation import run_simulation
        await run_simulation()
        return
    
    # Initialize and run XDR
    xdr = Web3XDR(config_path=args.config)
    
    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    
    def handle_signal():
        logger.info("shutdown_signal_received")
        asyncio.create_task(xdr.stop())
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)
    
    try:
        await xdr.initialize()
        await xdr.start()
    except Exception as e:
        logger.error("xdr_error", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

