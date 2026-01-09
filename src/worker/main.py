#!/usr/bin/env python3
"""
Sentinel3 Worker - Chain Ingestion & Event Processing
======================================================

Phase 2: Decoupled worker process for chain monitoring.

Lifecycle:
- Loop A (Ingestion): Poll chains, track finality, publish to bus
- Loop B (Detection): Consume from bus, process events
- Health server on port 9090

HEALTH-FIRST PATTERN:
- HTTP server binds immediately (<2 seconds)
- All initialization happens in background
- Health endpoints always return 200
"""

import asyncio
import os
import signal
import sys
import yaml
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, TYPE_CHECKING
import structlog

if TYPE_CHECKING:
    # Type-only imports for IDE autocomplete (not evaluated at runtime)
    from src.runtime.runtime_engine import RuntimeEngine
    from src.models.predicted_incidents import PredictedIncident
    from src.runtime.intent_sources.pseudo_block import PseudoIntentBlockSource
    from src.runtime.risk_router import RiskRouter
    from src.runtime.simulator.anvil import AnvilSimulator
    from src.invariants.engine import InvariantEngine
    from src.database.connection import DatabaseManager
    from src.database.models import PredictedIncidentModel, SimulationRunModel

# Use aiohttp for lightweight, fast-binding health server
from aiohttp import web
from aiohttp.web import Response

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.pipeline.bus import create_event_bus, EventBus
from src.telemetry.rpc_client import MultiRpcProvider
from src.telemetry.finality_tracker import FinalityTrackerManager, ChainFinalityConfig
from src.telemetry.evm_listener import EVMListener
from src.telemetry.base import ListenerConfig
from src.models.events import SecurityEvent, EventType, EventStatus, Severity

# Runtime Security Plane imports
try:
    from src.runtime.runtime_engine import RuntimeEngine
    from src.runtime.intent_sources.pseudo_block import PseudoIntentBlockSource
    from src.runtime.risk_router import RiskRouter
    from src.runtime.simulator.anvil import AnvilSimulator
    from src.invariants.engine import InvariantEngine
    from src.models.predicted_incidents import PredictedIncident
    from src.database.connection import DatabaseManager
    from src.database.models import PredictedIncidentModel, SimulationRunModel
    from src.telemetry.metrics import (
        runtime_simulations_total,
        runtime_simulation_duration_ms,
        runtime_risk_router_decisions_total,
        runtime_budget_drops_total,
        predicted_incidents_total,
    )
    
    # bloXroute mempool source
    try:
        from src.runtime.intent_sources.bloxroute_source import BloxrouteMempoolSource
        BLOXROUTE_AVAILABLE = True
    except ImportError:
        BLOXROUTE_AVAILABLE = False
        BloxrouteMempoolSource = None
    
    RUNTIME_AVAILABLE = True
except ImportError:
    RUNTIME_AVAILABLE = False
    BLOXROUTE_AVAILABLE = False
    BloxrouteMempoolSource = None

from src.telemetry.metrics import (
    events_ingested_total,
    head_lag_blocks,
    chain_head_height,
    worker_processed_height,
    bus_queue_depth,
    bus_events_published_total,
    bus_events_consumed_total,
    finality_confirmed_blocks,
    worker_uptime_seconds,
    worker_events_processed_total,
    worker_processing_duration_seconds,
    rpc_latency_seconds,
    rpc_requests_total,
)
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

logger = structlog.get_logger(__name__)

# Log runtime availability status (after logger is defined)
if not RUNTIME_AVAILABLE:
    logger.warning("runtime_security_plane_not_available", message="Runtime security features disabled")
if not BLOXROUTE_AVAILABLE:
    logger.debug("bloxroute_source_not_available", message="bloXroute mempool source disabled")

# Configuration
# Cloud Run sets PORT automatically - use it directly for health server
# WORKER_HEALTH_PORT can override, but PORT takes precedence for Cloud Run compatibility
WORKER_HEALTH_PORT = int(os.getenv("PORT") or os.getenv("WORKER_HEALTH_PORT", "9090"))
REDIS_URL = os.getenv("REDIS_URL", "")
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "2.0"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
PROCESSING_TIMEOUT_SECONDS = float(os.getenv("PROCESSING_TIMEOUT_SECONDS", "5.0"))

# Global state for health checks
worker_instance: Optional["Sentinel3Worker"] = None
is_ready = False
init_error: Optional[str] = None
start_time = datetime.now(timezone.utc)


class Sentinel3Worker:
    """
    Sentinel3 Worker - Handles chain ingestion and event processing.
    """
    
    def __init__(self):
        self.config = self._load_config()
        self.bus: Optional[EventBus] = None
        self.finality_manager = FinalityTrackerManager()
        self.rpc_providers: Dict[str, MultiRpcProvider] = {}
        self.listeners: Dict[str, EVMListener] = {}
        self.running = False
        self.start_time = datetime.now(timezone.utc)
        
        # Track processed blocks per chain
        self.processed_blocks: Dict[str, int] = {}
        
        # Runtime Security Plane components
        self.runtime_engines: Dict[str, "RuntimeEngine"] = {}
        self.runtime_enabled = os.getenv("RUNTIME_ENABLED", "false").lower() == "true"
        
        logger.info("worker_initialized", runtime_enabled=self.runtime_enabled)
    
    def _load_config(self) -> dict:
        """Load chains configuration."""
        config_path = Path(__file__).resolve().parent.parent.parent / "config" / "chains.yaml"
        with open(config_path) as f:
            return yaml.safe_load(f)
    
    async def initialize(self):
        """Initialize worker components."""
        # Initialize database (required for runtime engine and checkpointing)
        from src.database.connection import DatabaseManager
        await DatabaseManager.initialize()
        
        # Initialize event bus
        if not REDIS_URL:
            logger.warning(
                "REDIS_URL_NOT_SET",
                message="⚠️  WARNING: REDIS_URL not set. Using in-memory bus (dev mode only).",
                hint="Data will not be shared between containers. Set REDIS_URL for production."
            )
        
        self.bus = create_event_bus()
        logger.info("event_bus_initialized", bus_type=type(self.bus).__name__)
        
        # Initialize RPC providers and listeners for EVM chains
        for chain_config in self.config.get("chains", []):
            chain_id = chain_config.get("chain_id", "")
            chain_type = chain_config.get("chain_type", "evm").lower()
            
            if chain_type != "evm":
                logger.info("skipping_non_evm_chain", chain_id=chain_id, chain_type=chain_type)
                continue
            
            # Get RPC URLs
            rpc_urls = chain_config.get("rpc_urls", [])
            if not rpc_urls and chain_config.get("rpc_url"):
                rpc_urls = [chain_config["rpc_url"]]
            
            if not rpc_urls:
                logger.warning("no_rpc_urls", chain_id=chain_id)
                continue
            
            # Create RPC provider
            rpc_provider = MultiRpcProvider(
                rpc_urls=rpc_urls,
                unhealthy_cooldown_seconds=60,
                request_timeout_seconds=30.0
            )
            self.rpc_providers[chain_id] = rpc_provider
            
            # Create finality tracker config
            finality_config = ChainFinalityConfig(
                chain_id=chain_id,
                confirmations=chain_config.get("finality", {}).get("confirmations", 12),
                max_reorg_depth=chain_config.get("finality", {}).get("max_reorg_depth", 12),
                block_time_seconds=chain_config.get("finality", {}).get("block_time_seconds", 12.0)
            )
            self.finality_manager.get_tracker(chain_id, finality_config)
            
            # Create listener
            listener_config = ListenerConfig(
                chain_id=chain_id,
                chain_name=chain_config.get("chain_name", chain_id),
                rpc_url=rpc_urls[0],
                rpc_urls=rpc_urls,
                fallback_rpcs=chain_config.get("fallback_rpcs", []),
            )
            listener = EVMListener(listener_config)
            self.listeners[chain_id] = listener
            
            logger.info("chain_initialized", chain_id=chain_id, rpc_count=len(rpc_urls))
        
        # Initialize Runtime Security Plane if enabled
        if self.runtime_enabled and RUNTIME_AVAILABLE:
            await self._initialize_runtime_engines()
    
    async def ingestion_loop(self):
        """Loop A: Ingest events from chains."""
        logger.info("ingestion_loop_started")
        
        while self.running:
            try:
                for chain_id, listener in self.listeners.items():
                    try:
                        # Get latest block (with metrics)
                        rpc_provider = self.rpc_providers[chain_id]
                        import time
                        start_time = time.time()
                        head_block = await rpc_provider.get_block_number()
                        latency = time.time() - start_time
                        rpc_latency_seconds.labels(chain=chain_id, endpoint="primary", method="eth_blockNumber").observe(latency)
                        rpc_requests_total.labels(chain=chain_id, endpoint="primary", method="eth_blockNumber", status="success").inc()
                        
                        # Update finality tracker
                        block_info = await rpc_provider.get_block(head_block, require_quorum=False)
                        if block_info:
                            block_hash = block_info.get("hash", "")
                            parent_hash = block_info.get("parentHash", "")
                            self.finality_manager.update_chain_head(
                                chain_id, head_block, block_hash, parent_hash
                            )
                        
                        # Update metrics
                        chain_head_height.labels(chain=chain_id).set(head_block)
                        tracker = self.finality_manager.get_tracker(chain_id)
                        confirmed_block = tracker.last_confirmed_block
                        finality_confirmed_blocks.labels(chain=chain_id).set(confirmed_block)
                        
                        processed = self.processed_blocks.get(chain_id, 0)
                        worker_processed_height.labels(chain=chain_id).set(processed)
                        lag = head_block - processed
                        head_lag_blocks.labels(chain=chain_id).set(lag)
                        
                        # Poll for new logs (simplified - in production, track last processed block)
                        if processed < head_block:
                            # Get logs from last processed to head
                            from_block = max(processed + 1, head_block - 100)  # Limit range
                            to_block = head_block
                            
                            try:
                                logs = await rpc_provider.get_logs(from_block, to_block)
                                
                                # Process logs into SecurityEvents
                                for log in logs:
                                    event = self._log_to_security_event(chain_id, log, head_block)
                                    if event:
                                        # Check if confirmed
                                        if self.finality_manager.is_block_confirmed(chain_id, event.block_number):
                                            event.status = EventStatus.CONFIRMED
                                            event.confirmed_at = datetime.now(timezone.utc)
                                        else:
                                            event.status = EventStatus.PENDING
                                        
                                        # Publish to bus
                                        published = await self.bus.publish(event.to_dict())
                                        if published:
                                            events_ingested_total.labels(
                                                chain=chain_id,
                                                status=event.status.value
                                            ).inc()
                                            bus_events_published_total.labels(
                                                bus_type=type(self.bus).__name__.lower().replace("bus", "")
                                            ).inc()
                                
                                # Update processed block
                                self.processed_blocks[chain_id] = head_block
                                
                            except Exception as e:
                                logger.error("log_poll_failed", chain=chain_id, error=str(e))
                        
                    except Exception as e:
                        logger.error("chain_ingestion_error", chain=chain_id, error=str(e))
                
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
                
            except Exception as e:
                logger.error("ingestion_loop_error", error=str(e))
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
    
    async def _initialize_runtime_engines(self):
        """Initialize Runtime Security Plane engines for each EVM chain."""
        if not RUNTIME_AVAILABLE:
            return
        
        logger.info("initializing_runtime_engines")
        
        # Determine mempool source type
        mempool_source_type = os.getenv("MEMPOOL_SOURCE", "pseudo").lower()
        use_bloxroute = mempool_source_type == "bloxroute" and BLOXROUTE_AVAILABLE
        bloxroute_auth_header = os.getenv("BLOXROUTE_AUTH_HEADER", "")
        
        if use_bloxroute and not bloxroute_auth_header:
            logger.warning("bloxroute_enabled_but_no_auth_header", message="Falling back to pseudo block source")
            use_bloxroute = False
        
        for chain_id, rpc_provider in self.rpc_providers.items():
            try:
                # Get chain config
                rpc_urls = self.config.get("chains", [])
                chain_config = next((c for c in rpc_urls if c.get("chain_id") == chain_id), None)
                if not chain_config:
                    continue
                
                rpc_url = chain_config.get("rpc_urls", [chain_config.get("rpc_url", "")])[0]
                if not rpc_url:
                    logger.warning("no_rpc_url_for_runtime", chain_id=chain_id)
                    continue
                
                # Determine intent source
                if use_bloxroute:
                    # Load critical contracts from chain config
                    # Priority: critical_contracts > bridge_contracts > defi_contracts
                    critical_contracts = chain_config.get("critical_contracts", [])
                    bridge_contracts = chain_config.get("bridge_contracts", [])
                    defi_contracts = chain_config.get("defi_contracts", [])
                    
                    # Combine all monitored addresses (remove duplicates)
                    monitored_addresses = []
                    seen = set()
                    for addr in critical_contracts + bridge_contracts + defi_contracts:
                        addr_lower = addr.lower() if addr else None
                        if addr_lower and addr_lower not in seen:
                            monitored_addresses.append(addr_lower)
                            seen.add(addr_lower)
                    
                    if not monitored_addresses:
                        logger.warning(
                            "bloxroute_no_monitored_addresses",
                            chain_id=chain_id,
                            message="No critical_contracts, bridge_contracts, or defi_contracts found. Falling back to pseudo source."
                        )
                        intent_source = PseudoIntentBlockSource(chain_id, rpc_provider)
                    else:
                        logger.info(
                            "bloxroute_source_selected",
                            chain_id=chain_id,
                            monitored_count=len(monitored_addresses),
                            critical=len(critical_contracts),
                            bridge=len(bridge_contracts),
                            defi=len(defi_contracts)
                        )
                        intent_source = BloxrouteMempoolSource(
                            chain_id=chain_id,
                            auth_header=bloxroute_auth_header,
                            monitored_addresses=monitored_addresses
                        )
                else:
                    # Fallback to pseudo block source
                    intent_source = PseudoIntentBlockSource(chain_id, rpc_provider)
                
                risk_router = RiskRouter()
                
                # Try to initialize Anvil simulator (may fail if Anvil not installed)
                try:
                    simulator = AnvilSimulator(chain_id, rpc_url, pool_size=2)  # Smaller pool for now
                    await simulator.initialize()
                except Exception as e:
                    logger.warning(
                        "anvil_simulator_not_available",
                        chain_id=chain_id,
                        error=str(e),
                        message="Runtime Security Plane will be disabled for this chain. Install Foundry Anvil to enable."
                    )
                    continue  # Skip this chain
                
                # Initialize invariant engine
                invariant_engine = InvariantEngine()
                
                # Create runtime engine
                runtime_engine = RuntimeEngine(
                    chain_id=chain_id,
                    intent_source=intent_source,
                    risk_router=risk_router,
                    simulator=simulator,
                    invariant_engine=invariant_engine,
                    rpc_provider=rpc_provider
                )
                
                self.runtime_engines[chain_id] = runtime_engine
                logger.info("runtime_engine_initialized", chain_id=chain_id)
            
            except Exception as e:
                logger.error("failed_to_initialize_runtime_engine", chain_id=chain_id, error=str(e))
    
    async def runtime_loop(self):
        """
        Loop C: Runtime Security Plane - Process predicted incidents.
        Runs simulation and creates predicted incidents.
        """
        if not self.runtime_enabled or not RUNTIME_AVAILABLE:
            return
        
        logger.info("runtime_loop_started")
        
        while self.running:
            try:
                # Process each runtime engine
                for chain_id, runtime_engine in self.runtime_engines.items():
                    try:
                        # Process cycle (get intents, route, simulate, evaluate)
                        predicted_incidents = await runtime_engine.process_cycle()
                        
                        # Store predicted incidents to database
                        for incident in predicted_incidents:
                            await self._store_predicted_incident(incident)
                            
                            # Store simulation run if available
                            if incident.linked_simulation_run_id:
                                await self._store_simulation_run(runtime_engine, incident.linked_simulation_run_id)
                            
                            # Publish to event bus with PREDICTED flag
                            await self._publish_predicted_incident(incident)
                            
                            # Update metrics
                            predicted_incidents_total.labels(
                                severity=incident.severity,
                                status=incident.status.value
                            ).inc()
                    
                    except Exception as e:
                        logger.error("runtime_engine_cycle_failed", chain_id=chain_id, error=str(e))
                
                # Sleep before next cycle
                await asyncio.sleep(5.0)  # Process every 5 seconds
            
            except Exception as e:
                logger.error("runtime_loop_error", error=str(e))
                await asyncio.sleep(5.0)
    
    async def _store_simulation_run(self, runtime_engine: "RuntimeEngine", simulation_run_id: str):
        """Store simulation run to database (stub - would need to get from runtime engine)."""
        # TODO: Store simulation run details
        # For now, this is a placeholder
        pass
    
    async def _store_predicted_incident(self, incident: "PredictedIncident"):
        """Store predicted incident to database."""
        if not RUNTIME_AVAILABLE:
            return
        try:
            from src.database.models import PredictedIncidentModel
            from src.database.connection import DatabaseManager
            async with DatabaseManager.get_session() as session:
                # Check if already exists (by dedupe_key)
                from sqlalchemy import select
                existing = await session.execute(
                    select(PredictedIncidentModel).where(
                        PredictedIncidentModel.dedupe_key == incident.dedupe_key
                    )
                )
                existing_incident = existing.scalar_one_or_none()
                
                if existing_incident:
                    # Update existing incident (including financial fields)
                    existing_incident.updated_at = datetime.now(timezone.utc)
                    if incident.potential_loss_usd:
                        existing_incident.potential_loss_usd = incident.potential_loss_usd
                    if incident.potential_loss_token_symbol:
                        existing_incident.potential_loss_token_symbol = incident.potential_loss_token_symbol
                    if incident.financial_impact_json:
                        existing_incident.financial_impact_json = incident.financial_impact_json
                    await session.commit()
                    logger.debug("predicted_incident_updated", dedupe_key=incident.dedupe_key[:16])
                    return
                
                # Create new incident
                db_incident = PredictedIncidentModel(
                    chain_id=incident.chain_id,
                    tx_hash=incident.tx_hash,
                    protocol_id=incident.protocol_id,
                    predicted_type=incident.predicted_type,
                    severity=incident.severity,
                    confidence=incident.confidence,
                    status=incident.status.value,
                    dedupe_key=incident.dedupe_key,
                    explanation_json=incident.explanation_json,
                    evidence_json=incident.evidence_json,
                    linked_simulation_run_id=uuid.UUID(incident.linked_simulation_run_id) if incident.linked_simulation_run_id else None,
                    # Financial impact fields (Phase 9)
                    potential_loss_usd=incident.potential_loss_usd,
                    potential_loss_token_symbol=incident.potential_loss_token_symbol,
                    financial_impact_json=incident.financial_impact_json,
                )
                
                session.add(db_incident)
                await session.commit()
                logger.info(
                    "predicted_incident_stored",
                    incident_id=str(db_incident.id),
                    potential_loss_usd=str(incident.potential_loss_usd) if incident.potential_loss_usd else None,
                    token_symbol=incident.potential_loss_token_symbol
                )
                
        except Exception as e:
            logger.error("failed_to_store_predicted_incident", error=str(e), exc_info=True)
    
    async def _publish_predicted_incident(self, incident: "PredictedIncident"):
        """Publish predicted incident to event bus with PREDICTED flag."""
        try:
            # Create a synthetic SecurityEvent for the predicted incident
            predicted_event = {
                "event_type": "PREDICTED_INCIDENT",
                "chain_id": incident.chain_id,
                "tx_hash": incident.tx_hash,
                "incident_id": incident.id,
                "predicted_type": incident.predicted_type,
                "severity": incident.severity,
                "confidence": incident.confidence,
                "status": "PREDICTED",  # Special flag
                "explanation": incident.explanation_json,
                "evidence": incident.evidence_json,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            
            await self.bus.publish(predicted_event)
            logger.debug("predicted_incident_published", incident_id=incident.id)
        
        except Exception as e:
            logger.error("failed_to_publish_predicted_incident", error=str(e))
    
    def _log_to_security_event(self, chain_id: str, log: dict, block_number: int) -> Optional[SecurityEvent]:
        """Convert log to SecurityEvent (simplified)."""
        try:
            event = SecurityEvent(
                chain_id=chain_id,
                tx_hash=log.get("transactionHash", ""),
                block_number=block_number,
                log_index=log.get("logIndex", 0),
                contract_address=log.get("address", ""),
                event_type=EventType.UNKNOWN,
                severity=Severity.INFO,
                raw_event=log
            )
            return event
        except Exception as e:
            logger.error("log_conversion_failed", error=str(e))
            return None
    
    async def detection_loop(self):
        """Loop B: Consume events from bus and process."""
        logger.info("detection_loop_started")
        
        while self.running:
            try:
                # Consume batch of events
                messages = await self.bus.consume(
                    batch_size=BATCH_SIZE,
                    timeout_seconds=PROCESSING_TIMEOUT_SECONDS
                )
                
                if not messages:
                    continue
                
                # Update queue depth metric
                queue_depth = await self.bus.get_queue_depth()
                bus_type = type(self.bus).__name__.lower().replace("bus", "")
                bus_queue_depth.labels(bus_type=bus_type).set(queue_depth)
                
                # Process each event
                for message in messages:
                    try:
                        event_data = message.event_data
                        chain_id = event_data.get("chain_id", "unknown")
                        
                        # Stub for Phase 3: Just log for now
                        logger.info(
                            "processing_event",
                            event_id=event_data.get("event_id", "unknown"),
                            chain=chain_id,
                            status=event_data.get("status", "unknown")
                        )
                        
                        worker_events_processed_total.labels(
                            chain=chain_id,
                            status=event_data.get("status", "unknown")
                        ).inc()
                        
                        bus_events_consumed_total.labels(bus_type=bus_type).inc()
                        
                    except Exception as e:
                        logger.error("event_processing_error", error=str(e))
                
            except Exception as e:
                logger.error("detection_loop_error", error=str(e))
                await asyncio.sleep(1.0)
    
    async def start(self):
        """Start the worker."""
        self.running = True
        
        await self.initialize()
        
        # Start ingestion and detection loops
        ingestion_task = asyncio.create_task(self.ingestion_loop())
        detection_task = asyncio.create_task(self.detection_loop())
        
        # Start runtime loop if enabled
        runtime_task = None
        if self.runtime_enabled and RUNTIME_AVAILABLE:
            # Start runtime engines
            for runtime_engine in self.runtime_engines.values():
                await runtime_engine.start()
            runtime_task = asyncio.create_task(self.runtime_loop())
            logger.info("runtime_loop_started")
        
        # Update uptime metric periodically
        async def update_uptime():
            while self.running:
                uptime = (datetime.now(timezone.utc) - self.start_time).total_seconds()
                worker_uptime_seconds.set(uptime)
                await asyncio.sleep(10.0)
        
        uptime_task = asyncio.create_task(update_uptime())
        
        logger.info("worker_started", health_port=WORKER_HEALTH_PORT, runtime_enabled=self.runtime_enabled)
        
        # Wait for tasks
        tasks = [ingestion_task, detection_task, uptime_task]
        if runtime_task:
            tasks.append(runtime_task)
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def stop(self):
        """Stop the worker gracefully."""
        logger.info("worker_stopping")
        self.running = False
        
        # Shutdown runtime engines
        if self.runtime_enabled and RUNTIME_AVAILABLE:
            for chain_id, runtime_engine in self.runtime_engines.items():
                try:
                    await runtime_engine.stop()
                    logger.info("runtime_engine_stopped", chain_id=chain_id)
                except Exception as e:
                    logger.error("failed_to_stop_runtime_engine", chain_id=chain_id, error=str(e))
        
        # Close RPC providers
        for provider in self.rpc_providers.values():
            await provider.close()
        
        # Close bus
        if self.bus:
            await self.bus.close()
        
        logger.info("worker_stopped")


# ============================================================================
# Health-First HTTP Server (aiohttp)
# ============================================================================

async def health_handler(request):
    """Health check endpoint - always returns 200."""
    global worker_instance, is_ready, init_error, start_time
    
    uptime = (datetime.now(timezone.utc) - start_time).total_seconds()
    
    if is_ready and worker_instance and worker_instance.running:
        return web.json_response({
            "status": "healthy",
            "ready": True,
            "uptime_seconds": uptime,
            "chains_monitored": len(worker_instance.listeners) if worker_instance.listeners else 0,
            "bus_type": type(worker_instance.bus).__name__ if worker_instance.bus else "none"
        })
    elif init_error:
        return web.json_response({
            "status": "alive",
            "ready": False,
            "uptime_seconds": uptime,
            "error": init_error
        }, status=200)  # Still return 200 - container is alive
    else:
        return web.json_response({
            "status": "starting",
            "ready": False,
            "uptime_seconds": uptime,
            "message": "Worker initialization in progress"
        })


async def root_handler(request):
    """Root endpoint - same as health."""
    return await health_handler(request)


async def metrics_handler(request):
    """Prometheus metrics endpoint."""
    return Response(
        body=generate_latest(),
        content_type=CONTENT_TYPE_LATEST
    )


async def index_handler(request):
    """
    SPA catch-all handler - serves index.html for any unknown route.
    This allows React Router to handle client-side routing.
    """
    static_dir = Path("/app/static")
    index_file = static_dir / "index.html"
    
    if not index_file.exists():
        return web.Response(
            text="War Room UI not found. Build the frontend first.",
            status=404
        )
    
    return web.FileResponse(index_file)


async def background_init():
    """
    Background initialization - all heavy startup logic goes here.
    This runs AFTER the HTTP server is already listening.
    """
    global worker_instance, is_ready, init_error
    
    try:
        logger.info("background_init_started")
        
        # Create worker instance
        worker_instance = Sentinel3Worker()
        logger.info("worker_instance_created")
        
        # Start worker (this does all initialization: DB, Redis, RPC, Runtime, etc.)
        await worker_instance.start()
        
        # Mark as ready
        is_ready = True
        init_error = None
        logger.info("background_init_completed", ready=True)
        
    except Exception as e:
        # Log error but DO NOT crash - keep health server running
        init_error = str(e)
        logger.error(
            "background_init_failed",
            error=str(e),
            exc_info=True,
            message="Worker initialization failed, but health server remains running for debugging"
        )
        # Don't raise - container stays alive


async def main():
    """
    Main entry point - HEALTH-FIRST PATTERN.
    
    1. Bind HTTP server immediately (<2 seconds)
    2. Start background initialization
    3. Keep server running forever
    """
    global start_time
    
    # CRITICAL: Print immediately to stdout (Cloud Run needs to see this)
    print(f"[WORKER] Starting Sentinel3 Worker on port {WORKER_HEALTH_PORT}", flush=True)
    sys.stdout.flush()
    sys.stderr.flush()
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        print(f"[WORKER] Signal received: {sig}", flush=True)
        logger.info("signal_received", signal=sig)
        if worker_instance:
            asyncio.create_task(worker_instance.stop())
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # STEP 1: Create and bind HTTP server IMMEDIATELY (no blocking operations before this)
        print(f"[WORKER] Creating aiohttp application...", flush=True)
        logger.info("binding_health_server", port=WORKER_HEALTH_PORT, port_env=os.getenv("PORT"))
        
        app = web.Application()
        
        # API routes (defined BEFORE catch-all)
        app.router.add_get("/health", health_handler)
        app.router.add_get("/metrics", metrics_handler)
        
        # Static files for React app (JS/CSS/images)
        static_dir = Path("/app/static")
        if static_dir.exists():
            app.router.add_static('/assets', static_dir / 'assets', name='assets')
            logger.info("static_assets_configured", path="/assets")
        
        # SPA catch-all route (MUST be last)
        # This serves index.html for any route not matched above
        # Allows React Router to handle client-side routing
        app.router.add_get('/{tail:.*}', index_handler)
        
        print(f"[WORKER] Setting up AppRunner...", flush=True)
        # Create site and bind to port immediately
        runner = web.AppRunner(app)
        await runner.setup()
        
        print(f"[WORKER] Starting TCPSite on 0.0.0.0:{WORKER_HEALTH_PORT}...", flush=True)
        # Bind to 0.0.0.0 (not 127.0.0.1) - critical for Cloud Run
        site = web.TCPSite(runner, host="0.0.0.0", port=WORKER_HEALTH_PORT)
        await site.start()
        
        print(f"[WORKER] ✓ Health server bound successfully on port {WORKER_HEALTH_PORT}", flush=True)
        logger.info("health_server_bound", port=WORKER_HEALTH_PORT, host="0.0.0.0")
        
        # Keep references to prevent garbage collection
        app['_runner'] = runner
        app['_site'] = site
        
        # Verify server is actually listening (with retry)
        import socket
        for i in range(5):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', WORKER_HEALTH_PORT))
                sock.close()
                if result == 0:
                    print(f"[WORKER] ✓ Port {WORKER_HEALTH_PORT} is listening and accepting connections", flush=True)
                    break
                else:
                    print(f"[WORKER] Port check attempt {i+1}/5 failed (result={result}), retrying...", flush=True)
                    await asyncio.sleep(0.5)
            except Exception as e:
                print(f"[WORKER] Port check error: {e}", flush=True)
                await asyncio.sleep(0.5)
        
        # STEP 2: Start background initialization (non-blocking)
        print(f"[WORKER] Starting background initialization...", flush=True)
        init_task = asyncio.create_task(background_init())
        
        # STEP 3: Keep server running forever
        print(f"[WORKER] Health server is running. Waiting for initialization...", flush=True)
        try:
            # Wait for initialization to complete (or fail) - but don't block server
            await asyncio.wait_for(init_task, timeout=None)
        except asyncio.TimeoutError:
            print(f"[WORKER] Initialization timeout (this shouldn't happen)", flush=True)
        except Exception as e:
            print(f"[WORKER] Initialization error: {e}", flush=True)
            logger.error("unexpected_error_in_main", error=str(e), exc_info=True)
        
        # Keep server running even if init fails
        print(f"[WORKER] Server will continue running for health checks", flush=True)
        logger.info("health_server_running", message="Server will continue running for health checks")
        
        # Wait indefinitely (until SIGTERM)
        while True:
            await asyncio.sleep(60.0)
            
    except Exception as e:
        # Critical error - log and re-raise so Cloud Run sees the failure
        print(f"[WORKER] CRITICAL ERROR: {e}", flush=True)
        import traceback
        traceback.print_exc()
        logger.error("critical_startup_error", error=str(e), exc_info=True)
        raise
    finally:
        print(f"[WORKER] Shutting down...", flush=True)
        try:
            await runner.cleanup()
        except:
            pass
        logger.info("health_server_shutdown")


if __name__ == "__main__":
    # CRITICAL: Print immediately to ensure Cloud Run sees the process started
    print("[WORKER] Python script starting...", flush=True)
    sys.stdout.flush()
    sys.stderr.flush()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[WORKER] Interrupted by user", flush=True)
    except Exception as e:
        print(f"[WORKER] Fatal error: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)
