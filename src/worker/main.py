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
import json
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
    except ImportError as blox_import_error:
        BLOXROUTE_AVAILABLE = False
        BloxrouteMempoolSource = None
        # Use print for early logging before logger is guaranteed to be initialized
        import sys
        print(f"[DEBUG] bloXroute source not available: {blox_import_error}", file=sys.stderr)
    
    RUNTIME_AVAILABLE = True
    # Use print for early logging
    import sys
    print("[INFO] Runtime Security Plane imports successful", file=sys.stderr)
except ImportError as import_error:
    # CRITICAL: Log the full import error with stack trace
    # Use print() directly since logger may not be initialized yet
    import traceback
    import sys
    error_trace = traceback.format_exc()
    
    # Print to stderr (Cloud Run captures this)
    print("=" * 80, file=sys.stderr)
    print("CRITICAL RUNTIME IMPORT FAILURE", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print(f"Error Type: {type(import_error).__name__}", file=sys.stderr)
    print(f"Error Message: {str(import_error)}", file=sys.stderr)
    print("\nFull Traceback:", file=sys.stderr)
    print(error_trace, file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    
    # Try to log with structlog if available (may fail if structlog import also failed)
    try:
        import structlog
        temp_logger = structlog.get_logger(__name__)
        temp_logger.error(
            "CRITICAL_RUNTIME_IMPORT_FAILURE",
            error_type=type(import_error).__name__,
            error_message=str(import_error),
            error_traceback=error_trace,
            message="Runtime Security Plane imports failed - this will disable all runtime threat detection"
        )
    except:
        pass  # If logging fails, we already printed to stderr
    
    RUNTIME_AVAILABLE = False
    BLOXROUTE_AVAILABLE = False
    BloxrouteMempoolSource = None
except Exception as unexpected_error:
    # Catch any other unexpected errors (circular imports, syntax errors, etc.)
    import traceback
    import sys
    error_trace = traceback.format_exc()
    
    # Print to stderr (Cloud Run captures this)
    print("=" * 80, file=sys.stderr)
    print("CRITICAL RUNTIME IMPORT UNEXPECTED ERROR", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print(f"Error Type: {type(unexpected_error).__name__}", file=sys.stderr)
    print(f"Error Message: {str(unexpected_error)}", file=sys.stderr)
    print("\nFull Traceback:", file=sys.stderr)
    print(error_trace, file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    
    # Try to log with structlog if available
    try:
        import structlog
        temp_logger = structlog.get_logger(__name__)
        temp_logger.error(
            "CRITICAL_RUNTIME_IMPORT_UNEXPECTED_ERROR",
            error_type=type(unexpected_error).__name__,
            error_message=str(unexpected_error),
            error_traceback=error_trace,
            message="Unexpected error during runtime imports (not ImportError - could be circular import, syntax error, etc.)"
        )
    except:
        pass  # If logging fails, we already printed to stderr
    
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


class RateLimitHandler:
    """
    Handles RPC rate limiting with exponential backoff.
    
    Tracks rate limit errors per chain and applies exponential backoff
    to avoid overwhelming rate-limited endpoints.
    """
    
    def __init__(self):
        self._backoff_until: Dict[str, float] = {}  # chain_id -> timestamp
        self._consecutive_errors: Dict[str, int] = {}  # chain_id -> error count
        self._base_backoff = 5.0  # Base backoff in seconds
        self._max_backoff = 300.0  # Max backoff (5 minutes)
        self._rate_limit_codes = {-32005, -32000, 429}  # Common rate limit error codes
    
    def is_rate_limited(self, chain_id: str) -> bool:
        """Check if chain is currently in backoff period."""
        import time
        backoff_until = self._backoff_until.get(chain_id, 0)
        return time.time() < backoff_until
    
    def get_remaining_backoff(self, chain_id: str) -> float:
        """Get remaining backoff time in seconds."""
        import time
        backoff_until = self._backoff_until.get(chain_id, 0)
        remaining = backoff_until - time.time()
        return max(0, remaining)
    
    def record_success(self, chain_id: str):
        """Record successful request - reset error count."""
        self._consecutive_errors[chain_id] = 0
    
    def record_rate_limit(self, chain_id: str, error: Exception) -> float:
        """
        Record rate limit error and calculate backoff.
        
        Returns: backoff duration in seconds
        """
        import time
        import random
        
        # Increment error count
        errors = self._consecutive_errors.get(chain_id, 0) + 1
        self._consecutive_errors[chain_id] = errors
        
        # Calculate exponential backoff with jitter
        backoff = min(
            self._base_backoff * (2 ** (errors - 1)),
            self._max_backoff
        )
        # Add 10-30% jitter
        jitter = backoff * (0.1 + random.random() * 0.2)
        backoff_with_jitter = backoff + jitter
        
        # Set backoff deadline
        self._backoff_until[chain_id] = time.time() + backoff_with_jitter
        
        logger.warning(
            "rate_limit_backoff",
            chain=chain_id,
            consecutive_errors=errors,
            backoff_seconds=round(backoff_with_jitter, 1),
            error=str(error)[:100]
        )
        
        return backoff_with_jitter
    
    def is_rate_limit_error(self, error: Exception) -> bool:
        """Check if error is a rate limit error."""
        error_str = str(error).lower()
        
        # Check for common rate limit indicators
        if any(indicator in error_str for indicator in [
            "rate limit", "limit exceeded", "too many requests",
            "429", "-32005", "throttl", "quota"
        ]):
            return True
        
        # Check for error codes in exception
        if hasattr(error, 'code') and error.code in self._rate_limit_codes:
            return True
        
        # Check for nested error codes
        if hasattr(error, 'args') and error.args:
            for arg in error.args:
                if isinstance(arg, dict) and arg.get('code') in self._rate_limit_codes:
                    return True
        
        return False


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
        
        # Rate limit handler for RPC endpoints
        self.rate_limiter = RateLimitHandler()
        
        # Runtime Security Plane components
        self.runtime_engines: Dict[str, "RuntimeEngine"] = {}
        self.runtime_enabled = os.getenv("RUNTIME_ENABLED", "false").lower() == "true"
        
        # YAML Rule Engine (initialized in initialize())
        self.rule_engine = None
        
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
        
        # Run database migrations to ensure schema is up to date
        from src.database.migrations import run_migrations
        try:
            await run_migrations()
            logger.info("database_migrations_completed")
        except Exception as e:
            logger.error("database_migrations_failed", error=str(e))
        
        # Initialize event bus
        if not REDIS_URL:
            logger.warning(
                "REDIS_URL_NOT_SET",
                message="⚠️  WARNING: REDIS_URL not set. Using in-memory bus (dev mode only).",
                hint="Data will not be shared between containers. Set REDIS_URL for production."
            )
        
        self.bus = create_event_bus()
        logger.info("event_bus_initialized", bus_type=type(self.bus).__name__)
        
        # Initialize YAML Rule Engine for ingestion-time rule evaluation
        from src.rules.engine import RuleEngine
        self.rule_engine = RuleEngine()
        rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "rules")
        rules_loaded = self.rule_engine.load_rules_from_directory(rules_dir)
        logger.info("yaml_rules_loaded_for_ingestion", count=rules_loaded, stats=self.rule_engine.stats())
        
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
            
            # Connect listener and register event handler for contract deployments
            try:
                connected = await listener.connect()
                if connected:
                    # Register handler to save contract deployment events to database
                    listener.add_event_handler(self._save_event_to_db)
                    logger.info("listener_connected", chain_id=chain_id)
                else:
                    logger.warning("listener_connect_failed", chain_id=chain_id)
            except Exception as conn_err:
                logger.warning("listener_connect_error", chain_id=chain_id, error=str(conn_err))
            
            logger.info("chain_initialized", chain_id=chain_id, rpc_count=len(rpc_urls))
        
        # Initialize Runtime Security Plane if enabled
        if self.runtime_enabled and RUNTIME_AVAILABLE:
            await self._initialize_runtime_engines()
        
        # Auto-start contract scanner if enabled
        if os.getenv("AUTO_START_SCANNER", "false").lower() == "true":
            try:
                from src.ai.collectors import start_auto_collection
                scanner_chains = os.getenv("SCANNER_CHAINS", "ethereum,polygon,arbitrum").split(",")
                scanner_chains = [c.strip() for c in scanner_chains if c.strip()]
                await start_auto_collection(chains=scanner_chains)
                logger.info("contract_scanner_auto_started", chains=scanner_chains)
            except ImportError as e:
                logger.warning("scanner_module_not_available", error=str(e))
            except Exception as e:
                logger.warning("scanner_auto_start_failed", error=str(e), exc_info=True)
    
    async def ingestion_loop(self):
        """Loop A: Ingest events from chains."""
        logger.info("ingestion_loop_started")
        
        # Track chains that successfully process
        successful_chains = set()
        
        while self.running:
            try:
                # Log periodic status
                if not successful_chains:
                    logger.info("ingestion_loop_iteration", listener_count=len(self.listeners))
                
                for chain_id, listener in self.listeners.items():
                    try:
                        # Skip chains where listener didn't connect (w3 is None)
                        if listener is None or listener.w3 is None:
                            continue
                        
                        # Check if chain is rate limited
                        if self.rate_limiter.is_rate_limited(chain_id):
                            remaining = self.rate_limiter.get_remaining_backoff(chain_id)
                            logger.debug("chain_rate_limited_skipping", chain=chain_id, remaining_seconds=round(remaining, 1))
                            continue
                        
                        # Get latest block (with metrics and timeout)
                        rpc_provider = self.rpc_providers[chain_id]
                        import time
                        start_time = time.time()
                        
                        # Add timeout to prevent blocking
                        try:
                            head_block = await asyncio.wait_for(
                                rpc_provider.get_block_number(),
                                timeout=30.0  # 30 second timeout
                            )
                        except asyncio.TimeoutError:
                            logger.warning("rpc_timeout", chain=chain_id, method="get_block_number")
                            self.rate_limiter.record_rate_limit(chain_id, Exception("RPC timeout"))
                            continue
                        
                        latency = time.time() - start_time
                        rpc_latency_seconds.labels(chain=chain_id, endpoint="primary", method="eth_blockNumber").observe(latency)
                        rpc_requests_total.labels(chain=chain_id, endpoint="primary", method="eth_blockNumber", status="success").inc()
                        
                        # Record success - reset rate limit counter
                        self.rate_limiter.record_success(chain_id)
                        
                        # Track successful chain
                        if chain_id not in successful_chains:
                            successful_chains.add(chain_id)
                            logger.info("chain_processing_started", chain=chain_id, head_block=head_block)
                        
                        # Update finality tracker (with timeout)
                        try:
                            block_info = await asyncio.wait_for(
                                rpc_provider.get_block(head_block, require_quorum=False),
                                timeout=30.0
                            )
                        except asyncio.TimeoutError:
                            logger.warning("rpc_timeout", chain=chain_id, method="get_block")
                            block_info = None
                        
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
                        
                        # On first run, start from current head (don't try to catch up from 0)
                        if processed == 0:
                            processed = head_block - 1
                            self.processed_blocks[chain_id] = processed
                            logger.info("first_run_starting_from_head", chain=chain_id, head_block=head_block)
                        
                        worker_processed_height.labels(chain=chain_id).set(processed)
                        lag = head_block - processed
                        head_lag_blocks.labels(chain=chain_id).set(lag)
                        
                        # Poll for new logs (limit to 3 blocks to avoid RPC rate limits)
                        if processed < head_block:
                            # Get logs from last processed to head (max 3 blocks to avoid rate limits)
                            from_block = max(processed + 1, head_block - 3)
                            to_block = head_block
                            
                            # Process blocks via listener for contract deployment detection
                            # This calls emit_event() which triggers _save_event_to_db handler
                            if listener is not None and listener.w3 is not None:
                                try:
                                    logger.debug("listener_processing_blocks", chain=chain_id, from_block=from_block, to_block=to_block)
                                    for block_num in range(from_block, to_block + 1):
                                        # Check rate limit before each block
                                        if self.rate_limiter.is_rate_limited(chain_id):
                                            logger.debug("block_processing_rate_limited", chain=chain_id, block=block_num)
                                            break
                                        await listener.process_block(block_num)
                                        # Small delay between blocks to avoid rate limits
                                        await asyncio.sleep(0.1)
                                except Exception as listener_err:
                                    if self.rate_limiter.is_rate_limit_error(listener_err):
                                        self.rate_limiter.record_rate_limit(chain_id, listener_err)
                                        logger.warning("listener_rate_limited", chain=chain_id, error=str(listener_err)[:100])
                                    else:
                                        logger.warning("listener_process_block_error", chain=chain_id, from_block=from_block, to_block=to_block, error=str(listener_err), exc_info=True)
                            else:
                                logger.debug("listener_not_available", chain=chain_id, listener_exists=listener is not None, w3_exists=listener.w3 is not None if listener else False)
                            
                            try:
                                # Get logs with timeout
                                try:
                                    logs = await asyncio.wait_for(
                                        rpc_provider.get_logs(from_block, to_block),
                                        timeout=60.0  # 60 second timeout for logs
                                    )
                                except asyncio.TimeoutError:
                                    logger.warning("rpc_timeout", chain=chain_id, method="get_logs", from_block=from_block, to_block=to_block)
                                    self.rate_limiter.record_rate_limit(chain_id, Exception("get_logs timeout"))
                                    continue
                                
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
                                        
                                        # ALWAYS save directly to database (bypass broken Redis consumer)
                                        from src.database.service import DatabaseService
                                        import hashlib
                                        try:
                                            # Generate stable event_id based on chain, tx_hash, and log_index
                                            log_index = getattr(event, 'log_index', 0)
                                            stable_key = f"{chain_id}:{event.tx_hash}:{log_index}"
                                            event_id = hashlib.sha256(stable_key.encode()).hexdigest()[:32]
                                            
                                            # Convert severity to string name (INFO, LOW, MEDIUM, HIGH, CRITICAL)
                                            # Severity enum has .name for string and .value for int
                                            severity_str = event.severity.name if hasattr(event.severity, 'name') else str(event.severity).upper()
                                            
                                            # Serialize raw_data to handle HexBytes
                                            raw_data = self._serialize_raw_data(event.raw_event if hasattr(event, 'raw_event') else {})
                                            
                                            # Use actual block timestamp from event, fallback to now
                                            block_ts = event.block_timestamp if hasattr(event, 'block_timestamp') and event.block_timestamp else datetime.now(timezone.utc)
                                            if hasattr(block_ts, 'isoformat'):
                                                block_ts_str = block_ts.isoformat()
                                            else:
                                                block_ts_str = str(block_ts)
                                            
                                            # Extract amount and amount_usd from event
                                            amount = getattr(event, 'amount', None)
                                            amount_usd = getattr(event, 'amount_usd', None)
                                            
                                            # Convert Decimal to float for JSON serialization
                                            if amount is not None:
                                                amount = float(amount) if hasattr(amount, '__float__') else amount
                                            if amount_usd is not None:
                                                amount_usd = float(amount_usd) if hasattr(amount_usd, '__float__') else amount_usd
                                            
                                            db_event = {
                                                "event_id": event_id,
                                                "chain_id": chain_id,
                                                "event_type": event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type),
                                                "tx_hash": event.tx_hash,
                                                "block_number": event.block_number,
                                                "block_timestamp": block_ts_str,
                                                "contract_address": event.contract_address,
                                                "from_address": getattr(event, 'from_address', None) or getattr(event, 'source_address', None),
                                                "to_address": getattr(event, 'to_address', None) or getattr(event, 'dest_address', None),
                                                "amount": amount,
                                                "amount_usd": amount_usd,
                                                "severity": severity_str,
                                                "raw_data": raw_data,
                                            }
                                            await DatabaseService.save_events_batch([db_event])
                                            events_ingested_total.labels(
                                                chain=chain_id,
                                                status=event.status.value
                                            ).inc()
                                            logger.info("event_saved_directly", chain=chain_id, tx_hash=event.tx_hash)
                                            
                                            # ========================================
                                            # YAML RULE EVALUATION (in ingestion loop)
                                            # ========================================
                                            # Evaluate rules directly here instead of relying on event bus
                                            if self.rule_engine:
                                                try:
                                                    rule_matches = self.rule_engine.evaluate(db_event)
                                                    if rule_matches:
                                                        for match in rule_matches:
                                                            logger.warning(
                                                                "yaml_rule_triggered",
                                                                rule_id=match.rule.id,
                                                                rule_name=match.rule.name,
                                                                severity=match.rule.severity,
                                                                chain=chain_id,
                                                                event_type=db_event.get("event_type"),
                                                                tx_hash=event.tx_hash[:20] if event.tx_hash else ""
                                                            )
                                                            
                                                            # Create incident for HIGH and CRITICAL severity rules
                                                            if match.rule.severity.upper() in ["HIGH", "CRITICAL"]:
                                                                await self._create_incident_from_rule(
                                                                    rule=match.rule,
                                                                    event_data=db_event,
                                                                    db_event=db_event,
                                                                    match_details=match.match_details
                                                                )
                                                            # Also create incidents for MEDIUM rules (optional, but useful)
                                                            elif match.rule.severity.upper() == "MEDIUM":
                                                                await self._create_incident_from_rule(
                                                                    rule=match.rule,
                                                                    event_data=db_event,
                                                                    db_event=db_event,
                                                                    match_details=match.match_details
                                                                )
                                                except Exception as rule_err:
                                                    logger.debug("ingestion_rule_evaluation_error", error=str(rule_err))
                                            
                                        except Exception as db_error:
                                            logger.error("direct_db_save_failed", chain=chain_id, tx_hash=event.tx_hash, error=str(db_error), exc_info=True)
                                        
                                        # Also publish to bus for runtime engine (best effort, ignore errors)
                                        try:
                                            await self.bus.publish(event.to_dict())
                                            bus_events_published_total.labels(
                                                bus_type=type(self.bus).__name__.lower().replace("bus", "")
                                            ).inc()
                                        except:
                                            pass  # Ignore bus errors
                                
                                # Update processed block
                                self.processed_blocks[chain_id] = head_block
                                
                                # Update blocks scanned in shared state
                                from src.shared_state import monitor_state
                                blocks_processed = to_block - from_block + 1
                                monitor_state.add_blocks_scanned(blocks_processed)
                                
                            except Exception as e:
                                # Check if this is a rate limit error
                                if self.rate_limiter.is_rate_limit_error(e):
                                    backoff = self.rate_limiter.record_rate_limit(chain_id, e)
                                    logger.warning("log_poll_rate_limited", chain=chain_id, backoff_seconds=round(backoff, 1))
                                else:
                                    logger.error("log_poll_failed", chain=chain_id, error=str(e))
                        
                    except Exception as e:
                        # Check if this is a rate limit error
                        if self.rate_limiter.is_rate_limit_error(e):
                            backoff = self.rate_limiter.record_rate_limit(chain_id, e)
                            logger.warning("chain_ingestion_rate_limited", chain=chain_id, backoff_seconds=round(backoff, 1))
                        else:
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
                
                # Initialize invariant engine with default invariants
                invariant_engine = InvariantEngine()
                
                # Register default invariants for threat detection
                try:
                    from src.invariants import (
                        MintLockParityInvariant,
                        UnbackedMintInvariant,
                        TVLVelocityInvariant,
                        TransactionVelocityInvariant,
                    )
                    
                    # Add economic invariants (detect unbacked mints, parity violations)
                    # MintLockParityInvariant(bridge_id, source_chain, dest_chain)
                    invariant_engine.add_invariant(MintLockParityInvariant(
                        bridge_id=chain_id,
                        source_chain=chain_id,
                        dest_chain="ethereum"  # Cross-chain to ethereum
                    ))
                    
                    # UnbackedMintInvariant(bridge_id, source_chain, dest_chain)
                    invariant_engine.add_invariant(UnbackedMintInvariant(
                        bridge_id=chain_id,
                        source_chain=chain_id,
                        dest_chain="ethereum"  # Cross-chain to ethereum
                    ))
                    
                    # Add velocity invariants (detect rapid drains)
                    # TVLVelocityInvariant(bridge_id, max_drain_percent_per_hour, min_drain_usd)
                    invariant_engine.add_invariant(TVLVelocityInvariant(
                        bridge_id=chain_id,
                        max_drain_percent_per_hour=10.0,  # 10% per hour max
                        min_drain_usd=100_000  # Alert on >$100k drain
                    ))
                    
                    # TransactionVelocityInvariant(bridge_id, max_tx_per_hour, spike_multiplier)
                    invariant_engine.add_invariant(TransactionVelocityInvariant(
                        bridge_id=chain_id,
                        max_tx_per_hour=1000,  # Max 1000 tx per hour
                        spike_multiplier=5.0  # 5x normal = alert
                    ))
                    
                    logger.info("invariants_registered", chain_id=chain_id, count=4)
                except Exception as inv_err:
                    logger.warning("failed_to_register_invariants", chain_id=chain_id, error=str(inv_err), exc_info=True)
                
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
    
    def _serialize_raw_data(self, data: dict) -> dict:
        """Convert HexBytes and other non-JSON-serializable types to strings."""
        if not data:
            return {}
        
        result = {}
        for key, value in data.items():
            if hasattr(value, 'hex'):
                # HexBytes or similar
                result[key] = value.hex() if callable(value.hex) else str(value)
            elif isinstance(value, bytes):
                result[key] = value.hex()
            elif isinstance(value, dict):
                result[key] = self._serialize_raw_data(value)
            elif isinstance(value, list):
                result[key] = [
                    v.hex() if hasattr(v, 'hex') else str(v) if isinstance(v, bytes) else v
                    for v in value
                ]
            else:
                result[key] = value
        return result
    
    async def _save_event_to_db(self, event: SecurityEvent):
        """
        Event handler to save SecurityEvent to database.
        Called by listener's emit_event() for contract deployments and other events.
        """
        from src.database.service import DatabaseService
        import hashlib
        
        try:
            chain_id = event.chain_id
            log_index = getattr(event, 'log_index', 0)
            stable_key = f"{chain_id}:{event.tx_hash}:{log_index}"
            event_id = hashlib.sha256(stable_key.encode()).hexdigest()[:32]
            
            # Convert severity to string name
            severity_str = event.severity.name if hasattr(event.severity, 'name') else str(event.severity).upper()
            
            # Convert event_type to string
            event_type_str = event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type)
            
            # Serialize raw_data to handle HexBytes
            raw_data = self._serialize_raw_data(event.raw_event if hasattr(event, 'raw_event') else {})
            
            db_event = {
                "event_id": event_id,
                "chain_id": chain_id,
                "event_type": event_type_str,
                "tx_hash": event.tx_hash,
                "block_number": event.block_number,
                "block_timestamp": event.block_timestamp.isoformat() if hasattr(event.block_timestamp, 'isoformat') else str(event.block_timestamp),
                "contract_address": event.contract_address,
                "from_address": getattr(event, 'from_address', None) or getattr(event, 'source_address', None),
                "to_address": getattr(event, 'to_address', None) or getattr(event, 'dest_address', None),
                "severity": severity_str,
                "raw_data": raw_data,
            }
            
            await DatabaseService.save_events_batch([db_event])
            logger.info(
                "event_handler_saved",
                chain=chain_id,
                event_type=event_type_str,
                tx_hash=event.tx_hash[:20] + "..."
            )
        except Exception as e:
            logger.error("event_handler_save_failed", error=str(e), exc_info=True)
    
    def _log_to_security_event(self, chain_id: str, log: dict, block_number: int) -> Optional[SecurityEvent]:
        """Convert log to SecurityEvent with event classification."""
        from src.telemetry.event_signatures import get_event_info
        
        try:
            # Get topic0 for event classification
            topics = log.get("topics", [])
            topic0 = topics[0] if topics else ""
            if hasattr(topic0, 'hex'):
                topic0 = topic0.hex()
            if topic0 and not topic0.startswith("0x"):
                topic0 = "0x" + topic0
            
            # Look up event info from signature database
            event_info = get_event_info(topic0) if topic0 else {}
            event_type = event_info.get("type", EventType.UNKNOWN)
            event_severity = event_info.get("severity", "low")
            
            # Map severity string to Severity enum
            severity_map = {
                "info": Severity.INFO,
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL
            }
            severity = severity_map.get(event_severity, Severity.LOW)
            
            event = SecurityEvent(
                chain_id=chain_id,
                tx_hash=log.get("transactionHash", ""),
                block_number=block_number,
                log_index=log.get("logIndex", 0),
                contract_address=log.get("address", ""),
                event_type=event_type,
                severity=severity,
                raw_event=log
            )
            return event
        except Exception as e:
            logger.error("log_conversion_failed", error=str(e))
            return None
    
    async def _create_incident_from_rule(
        self,
        rule,
        event_data: Dict,
        db_event: Dict,
        match_details: Dict
    ):
        """Create an incident when a HIGH/CRITICAL rule is triggered."""
        from src.database.service import DatabaseService
        
        try:
            # Generate unique incident ID based on rule and event
            chain_id = event_data.get("chain_id", "unknown")
            tx_hash = event_data.get("tx_hash", "")[:16]
            incident_id = f"inc_{rule.id}_{chain_id}_{tx_hash}_{int(datetime.now(timezone.utc).timestamp())}"
            
            # Build incident data
            incident_data = {
                "incident_id": incident_id,
                "title": f"[{rule.severity.upper()}] {rule.name}",
                "summary": rule.description or f"Rule {rule.name} triggered on {chain_id}",
                "severity": rule.severity.upper(),
                "status": "OPEN_PENDING",
                "attack_type": rule.category or "RULE_TRIGGERED",
                "confidence": rule.confidence or 0.8,
                "total_loss_usd": 0,  # Will be updated if amount is available
                "affected_chains": [chain_id],
                "event_ids": [db_event.get("event_id", "")],
                "rule_ids": [rule.id],
                "recommended_actions": rule.recommended_actions or [
                    "Review the transaction details",
                    "Check related transactions",
                    "Investigate the involved addresses"
                ],
                "cluster_key": f"{rule.id}_{chain_id}_{datetime.now(timezone.utc).strftime('%Y%m%d%H')}",
            }
            
            # Save to database
            saved_id = await DatabaseService.save_incident(incident_data)
            if saved_id:
                logger.info(
                    "incident_created_from_rule",
                    incident_id=saved_id,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    chain=chain_id
                )
        except Exception as e:
            logger.error("incident_creation_failed", error=str(e), rule_id=rule.id)
    
    async def detection_loop(self):
        """Loop B: Consume events from bus and process."""
        logger.info("detection_loop_started")
        
        # Import database service for event persistence
        from src.database.service import DatabaseService
        
        # Load YAML detection rules
        from src.rules.engine import RuleEngine
        rule_engine = RuleEngine()
        rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "rules")
        rules_loaded = rule_engine.load_rules_from_directory(rules_dir)
        logger.info("yaml_rules_loaded", count=rules_loaded, stats=rule_engine.stats())
        
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
                
                # Batch events for efficient database saving
                events_to_save = []
                
                # Process each event
                for message in messages:
                    try:
                        event_data = message.event_data
                        chain_id = event_data.get("chain_id", "unknown")
                        
                        # Prepare event for database persistence
                        db_event = {
                            "event_id": event_data.get("event_id") or str(uuid.uuid4()),
                            "chain_id": chain_id,
                            "event_type": event_data.get("event_type", "Unknown"),
                            "tx_hash": event_data.get("tx_hash"),
                            "block_number": event_data.get("block_number"),
                            "block_timestamp": event_data.get("block_timestamp") or event_data.get("timestamp"),
                            "contract_address": event_data.get("contract_address") or event_data.get("contract"),
                            "from_address": event_data.get("from_address") or event_data.get("from"),
                            "to_address": event_data.get("to_address") or event_data.get("to"),
                            "amount": event_data.get("amount") or event_data.get("value"),
                            "amount_usd": event_data.get("amount_usd"),
                            "severity": (event_data.get("severity") or "LOW").upper(),
                            "raw_data": event_data.get("raw_data") or event_data,
                        }
                        events_to_save.append(db_event)
                        
                        logger.info(
                            "processing_event",
                            event_id=event_data.get("event_id", "unknown"),
                            chain=chain_id,
                            status=event_data.get("status", "unknown")
                        )
                        
                        # Evaluate YAML rules against this event
                        try:
                            rule_matches = rule_engine.evaluate(event_data)
                            if rule_matches:
                                for match in rule_matches:
                                    logger.warning(
                                        "yaml_rule_triggered",
                                        rule_id=match.rule.id,
                                        rule_name=match.rule.name,
                                        severity=match.rule.severity,
                                        confidence=match.rule.confidence,
                                        chain=chain_id,
                                        event_type=event_data.get("event_type"),
                                        tx_hash=event_data.get("tx_hash", "")[:20]
                                    )
                                    # Update event severity based on rule
                                    if match.rule.is_critical:
                                        db_event["severity"] = "CRITICAL"
                                    elif match.rule.is_high and db_event["severity"] not in ["CRITICAL"]:
                                        db_event["severity"] = "HIGH"
                                    
                                    # Create incident for HIGH and CRITICAL severity rules
                                    if match.rule.severity.upper() in ["HIGH", "CRITICAL"]:
                                        await self._create_incident_from_rule(
                                            rule=match.rule,
                                            event_data=event_data,
                                            db_event=db_event,
                                            match_details=match.match_details
                                        )
                        except Exception as rule_err:
                            logger.debug("rule_evaluation_error", error=str(rule_err))
                        
                        worker_events_processed_total.labels(
                            chain=chain_id,
                            status=event_data.get("status", "unknown")
                        ).inc()
                        
                        bus_events_consumed_total.labels(bus_type=bus_type).inc()
                        
                    except Exception as e:
                        logger.error("event_processing_error", error=str(e))
                
                # Save batch to database
                if events_to_save:
                    try:
                        saved_count = await DatabaseService.save_events_batch(events_to_save)
                        logger.info("events_saved_to_database", count=saved_count, batch_size=len(events_to_save))
                    except Exception as e:
                        logger.error("database_save_failed", error=str(e), exc_info=True)
                
            except Exception as e:
                logger.error("detection_loop_error", error=str(e))
                await asyncio.sleep(1.0)
    
    async def start(self):
        """Start the worker."""
        self.running = True
        
        # Set start time in shared state for uptime tracking
        from src.shared_state import monitor_state
        monitor_state.set_start_time()
        logger.info("worker_start_time_set")
        
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
        
        # Start continuous learning if enabled
        continuous_learning_task = None
        continuous_learning_enabled = os.getenv("CONTINUOUS_LEARNING_ENABLED", "true").lower() == "true"
        if continuous_learning_enabled:
            try:
                from src.ai.continuous_learning import start_continuous_learning, get_learning_system, LearningConfig
                
                # Configure continuous learning with chains from config
                chain_ids = [c.get("chain_id") for c in self.config.get("chains", []) if c.get("chain_type", "evm").lower() == "evm"]
                learning_config = LearningConfig(
                    chains=chain_ids[:6],  # Limit to first 6 EVM chains
                    retrain_interval_hours=6,  # Retrain every 6 hours
                    min_new_samples=50,  # Minimum samples before retraining
                )
                
                continuous_learning_task = asyncio.create_task(start_continuous_learning(learning_config))
                
                # Add callback to save contract deployments to database AND create incidents for threats
                async def save_contract_to_db(analysis):
                    """
                    Save contract analysis from continuous learning to database.
                    ENHANCED: Auto-creates incidents for detected threats.
                    """
                    try:
                        from src.database.service import DatabaseService
                        from src.models.events import EventType, Severity
                        from src.models.incidents import IncidentStatus
                        import uuid
                        import json
                        
                        contract = analysis.contract
                        event_id = str(uuid.uuid4())
                        
                        # Map threat category to severity
                        severity = Severity.INFO
                        if analysis.is_threat:
                            if analysis.risk_score > 0.7:
                                severity = Severity.CRITICAL
                            elif analysis.risk_score > 0.5:
                                severity = Severity.HIGH
                            elif analysis.risk_score > 0.3:
                                severity = Severity.MEDIUM
                            else:
                                severity = Severity.LOW
                        
                        event_data = {
                            "event_id": event_id,
                            "chain_id": contract.chain,
                            "block_number": contract.block_number,
                            "block_timestamp": contract.timestamp.isoformat() if contract.timestamp else datetime.now(timezone.utc).isoformat(),
                            "tx_hash": contract.tx_hash or "",
                            "event_type": "contract_deploy",
                            "severity": severity.name,
                            "from_address": contract.deployer or "",
                            "to_address": "",
                            "contract_address": contract.address,
                            "amount": "",
                            "amount_usd": "",
                            "token_symbol": "",
                            "raw_data": json.dumps({
                                "threat_category": analysis.threat_category,
                                "risk_score": analysis.risk_score,
                                "confidence": analysis.confidence,
                                "is_threat": analysis.is_threat,
                                "alerts": analysis.alerts,
                                "bytecode_size": contract.bytecode_length,
                                "source": "continuous_learning"
                            })
                        }
                        
                        await DatabaseService.save_events_batch([event_data])
                        logger.info("continuous_learning_contract_saved", chain=contract.chain, address=contract.address[:20], is_threat=analysis.is_threat)
                        
                        # AUTO-CREATE INCIDENT FOR THREATS
                        if analysis.is_threat and severity.value >= Severity.MEDIUM.value:
                            try:
                                # Generate unique incident ID
                                incident_id = f"inc_ml_{contract.chain}_{contract.address[:10]}_{int(datetime.now(timezone.utc).timestamp())}"
                                
                                # Map threat category to attack type
                                threat_to_attack = {
                                    "reentrancy_exploit": "Reentrancy Attack",
                                    "flash_loan_exploit": "Flash Loan Attack",
                                    "rug_pull": "Rug Pull",
                                    "honeypot": "Honeypot Contract",
                                    "phishing": "Phishing Contract",
                                    "price_manipulation": "Price Manipulation",
                                    "access_control": "Access Control Vulnerability",
                                    "integer_overflow": "Integer Overflow",
                                }
                                attack_type = threat_to_attack.get(analysis.threat_category, f"Malicious Contract ({analysis.threat_category})")
                                
                                # Build incident data
                                incident_data = {
                                    "incident_id": incident_id,
                                    "title": f"[{severity.name}] {attack_type} Detected on {contract.chain.title()}",
                                    "summary": f"ML Contract Scanner detected a potentially malicious contract deployment. "
                                               f"Contract {contract.address} deployed by {contract.deployer or 'unknown'} "
                                               f"has been classified as '{analysis.threat_category}' with {analysis.confidence:.1%} confidence "
                                               f"and risk score of {analysis.risk_score:.0f}/100.",
                                    "severity": severity.name,
                                    "status": "OPEN_PENDING",  # Matches database model expectation
                                    "attack_type": attack_type,
                                    "confidence": analysis.confidence,
                                    "total_loss_usd": 0.0,  # Unknown at detection time
                                    "affected_chains": [contract.chain],
                                    "event_ids": [event_id],
                                    "rule_ids": ["ml_contract_scanner"],
                                    "created_at": datetime.now(timezone.utc),
                                    "recommended_actions": [
                                        f"Review contract code at {contract.address}",
                                        "Check deployer wallet history for suspicious patterns",
                                        "Monitor for interactions with known DeFi protocols",
                                        "Consider adding contract to blocklist if confirmed malicious",
                                    ],
                                    "affected_contracts": [contract.address],
                                    "affected_addresses": [contract.deployer] if contract.deployer else [],
                                }
                                
                                saved_incident_id = await DatabaseService.save_incident(incident_data)
                                if saved_incident_id:
                                    logger.info(
                                        "threat_incident_created",
                                        incident_id=saved_incident_id,
                                        severity=severity.name,
                                        threat_category=analysis.threat_category,
                                        chain=contract.chain,
                                        contract=contract.address[:20],
                                        confidence=f"{analysis.confidence:.1%}"
                                    )
                            except Exception as inc_error:
                                logger.error("threat_incident_creation_failed", error=str(inc_error), exc_info=True)
                        
                    except Exception as e:
                        logger.error("continuous_learning_save_error", error=str(e), exc_info=True)
                
                # Wait a bit for the learning system to initialize, then add callback
                await asyncio.sleep(2)
                learning_system = get_learning_system()
                if learning_system:
                    # Register callback for ALL analyzed contracts (threats and safe)
                    # This uses the new add_analysis_callback method
                    learning_system.add_analysis_callback(save_contract_to_db)
                    logger.info("continuous_learning_db_callback_registered", callback_type="analysis")
                
                logger.info("continuous_learning_started", chains=chain_ids[:6], retrain_interval_hours=6)
            except Exception as e:
                logger.warning("continuous_learning_start_failed", error=str(e))
        
        # Update uptime metric periodically
        async def update_uptime():
            while self.running:
                uptime = (datetime.now(timezone.utc) - self.start_time).total_seconds()
                worker_uptime_seconds.set(uptime)
                await asyncio.sleep(10.0)
        
        uptime_task = asyncio.create_task(update_uptime())
        
        logger.info("worker_started", health_port=WORKER_HEALTH_PORT, runtime_enabled=self.runtime_enabled, continuous_learning=continuous_learning_enabled)
        
        # Wait for tasks
        tasks = [ingestion_task, detection_task, uptime_task]
        if runtime_task:
            tasks.append(runtime_task)
        if continuous_learning_task:
            tasks.append(continuous_learning_task)
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def stop(self):
        """Stop the worker gracefully."""
        logger.info("worker_stopping")
        self.running = False
        
        # Stop continuous learning
        try:
            from src.ai.continuous_learning import stop_continuous_learning
            await stop_continuous_learning()
            logger.info("continuous_learning_stopped")
        except Exception as e:
            logger.warning("continuous_learning_stop_failed", error=str(e))
        
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
        
        # API routes
        app.router.add_get("/health", health_handler)
        app.router.add_get("/metrics", metrics_handler)
        
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
