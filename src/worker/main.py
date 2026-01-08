#!/usr/bin/env python3
"""
Sentinel3 Worker - Chain Ingestion & Event Processing
======================================================

Phase 2: Decoupled worker process for chain monitoring.

Lifecycle:
- Loop A (Ingestion): Poll chains, track finality, publish to bus
- Loop B (Detection): Consume from bus, process events
- Health server on port 9090
"""

import asyncio
import os
import signal
import sys
import yaml
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional
import structlog

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.pipeline.bus import create_event_bus, EventBus
from src.telemetry.rpc_client import MultiRpcProvider
from src.telemetry.finality_tracker import FinalityTrackerManager, ChainFinalityConfig
from src.telemetry.evm_listener import EVMListener
from src.telemetry.base import ListenerConfig
from src.models.events import SecurityEvent, EventType, EventStatus, Severity
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
from fastapi.responses import Response

logger = structlog.get_logger(__name__)

# Configuration
WORKER_HEALTH_PORT = int(os.getenv("WORKER_HEALTH_PORT", "9090"))
REDIS_URL = os.getenv("REDIS_URL", "")
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "2.0"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
PROCESSING_TIMEOUT_SECONDS = float(os.getenv("PROCESSING_TIMEOUT_SECONDS", "5.0"))


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
        
        logger.info("worker_initialized")
    
    def _load_config(self) -> dict:
        """Load chains configuration."""
        config_path = Path(__file__).resolve().parent.parent.parent / "config" / "chains.yaml"
        with open(config_path) as f:
            return yaml.safe_load(f)
    
    async def initialize(self):
        """Initialize worker components."""
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
        
        # Update uptime metric periodically
        async def update_uptime():
            while self.running:
                uptime = (datetime.now(timezone.utc) - self.start_time).total_seconds()
                worker_uptime_seconds.set(uptime)
                await asyncio.sleep(10.0)
        
        uptime_task = asyncio.create_task(update_uptime())
        
        logger.info("worker_started", health_port=WORKER_HEALTH_PORT)
        
        # Wait for tasks
        await asyncio.gather(ingestion_task, detection_task, uptime_task, return_exceptions=True)
    
    async def stop(self):
        """Stop the worker gracefully."""
        logger.info("worker_stopping")
        self.running = False
        
        # Close RPC providers
        for provider in self.rpc_providers.values():
            await provider.close()
        
        # Close bus
        if self.bus:
            await self.bus.close()
        
        logger.info("worker_stopped")


# Health server
health_app = FastAPI()

worker_instance: Optional[Sentinel3Worker] = None


@health_app.get("/health")
async def health():
    """Health check endpoint."""
    if worker_instance and worker_instance.running:
        return JSONResponse(content={
            "status": "healthy",
            "uptime_seconds": (datetime.now(timezone.utc) - worker_instance.start_time).total_seconds(),
            "chains_monitored": len(worker_instance.listeners),
            "bus_type": type(worker_instance.bus).__name__ if worker_instance.bus else "none"
        })
    return JSONResponse(content={"status": "starting"}, status_code=503)


@health_app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


async def main():
    """Main entry point."""
    global worker_instance
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        logger.info("signal_received", signal=sig)
        if worker_instance:
            asyncio.create_task(worker_instance.stop())
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create worker
    worker_instance = Sentinel3Worker()
    
    # Start health server
    config = uvicorn.Config(
        health_app,
        host="0.0.0.0",
        port=WORKER_HEALTH_PORT,
        log_level="error"
    )
    server = uvicorn.Server(config)
    health_server_task = asyncio.create_task(server.serve())
    
    # Start worker
    try:
        await worker_instance.start()
    finally:
        await worker_instance.stop()
        health_server_task.cancel()
        try:
            await health_server_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())

