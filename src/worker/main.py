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
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, TYPE_CHECKING
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
    rpc_latency_seconds,
    rpc_requests_total,
    incidents_created_total,
    invariant_violations_total,
    circuit_breaker_state,
    alerts_sent_total,
    alerts_failed_total,
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


class CircuitBreaker:
    """
    Per-chain circuit breaker.

    States:
    - CLOSED:    Normal operation. Failures increment a counter.
    - OPEN:      Too many failures. Skip this chain entirely until cooldown expires.
    - HALF_OPEN: Cooldown expired. Allow one probe request. Success → CLOSED, failure → OPEN.

    Separate from RateLimitHandler (which handles HTTP 429). This catches
    persistent connection failures, dead RPCs, or chains that consistently error.
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        failure_threshold: int = 10,
        cooldown_seconds: float = 120.0,
        max_cooldown_seconds: float = 600.0,
    ):
        self._failure_threshold = failure_threshold
        self._base_cooldown = cooldown_seconds
        self._max_cooldown = max_cooldown_seconds
        self._states: Dict[str, str] = {}          # chain_id → state
        self._failures: Dict[str, int] = {}         # chain_id → consecutive failures
        self._open_until: Dict[str, float] = {}     # chain_id → timestamp
        self._trip_count: Dict[str, int] = {}       # chain_id → times tripped (for escalating cooldown)

    def state(self, chain_id: str) -> str:
        import time
        st = self._states.get(chain_id, self.CLOSED)
        if st == self.OPEN and time.time() >= self._open_until.get(chain_id, 0):
            self._states[chain_id] = self.HALF_OPEN
            return self.HALF_OPEN
        return st

    def allow_request(self, chain_id: str) -> bool:
        st = self.state(chain_id)
        return st in (self.CLOSED, self.HALF_OPEN)

    def record_success(self, chain_id: str):
        self._failures[chain_id] = 0
        self._states[chain_id] = self.CLOSED

    def record_failure(self, chain_id: str):
        failures = self._failures.get(chain_id, 0) + 1
        self._failures[chain_id] = failures

        if self.state(chain_id) == self.HALF_OPEN:
            # Probe failed → reopen with escalating cooldown
            self._trip(chain_id)
        elif failures >= self._failure_threshold:
            self._trip(chain_id)

    def _trip(self, chain_id: str):
        import time
        trips = self._trip_count.get(chain_id, 0) + 1
        self._trip_count[chain_id] = trips
        cooldown = min(self._base_cooldown * (2 ** (trips - 1)), self._max_cooldown)
        self._open_until[chain_id] = time.time() + cooldown
        self._states[chain_id] = self.OPEN
        logger.warning(
            "circuit_breaker_open",
            chain=chain_id,
            consecutive_failures=self._failures.get(chain_id, 0),
            cooldown_seconds=round(cooldown, 1),
            trip_count=trips,
        )

    def get_stats(self) -> Dict[str, dict]:
        return {
            cid: {
                "state": self.state(cid),
                "failures": self._failures.get(cid, 0),
                "trips": self._trip_count.get(cid, 0),
            }
            for cid in self._states
        }


def max_severity(sev1: str, sev2: str) -> str:
    """Return the higher severity level."""
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    s1 = severity_order.get(sev1.upper(), 0)
    s2 = severity_order.get(sev2.upper(), 0)
    return sev1.upper() if s1 >= s2 else sev2.upper()


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

        # Circuit breaker for persistent chain failures
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=10,
            cooldown_seconds=120.0,
            max_cooldown_seconds=600.0,
        )

        # Track last reconnect attempt per chain (avoid tight reconnect loops)
        self._last_reconnect_attempt: Dict[str, datetime] = {}
        self._reconnect_interval = timedelta(minutes=2)
        
        # Runtime Security Plane components
        self.runtime_engines: Dict[str, "RuntimeEngine"] = {}
        self.runtime_enabled = os.getenv("RUNTIME_ENABLED", "false").lower() == "true"
        
        # YAML Rule Engine (initialized in initialize())
        self.rule_engine = None

        # Economic Invariant Engine (bridge exploit detection)
        self.invariant_engine = None
        self._bridge_contract_map: Dict[str, dict] = {}  # contract_address → {bridge_id, source_chain, dest_chain}
        
        # Security Graph components (Wiz-for-Web3)
        self.graph_builder = None
        self.graph_enabled = os.getenv("GRAPH_ENABLED", "true").lower() == "true"
        
        # ML Threat Detector (initialized in initialize())
        self.ml_threat_detector = None
        self.ml_enabled = os.getenv("ML_DETECTION_ENABLED", "true").lower() == "true"
        
        logger.info("worker_initialized", runtime_enabled=self.runtime_enabled, graph_enabled=self.graph_enabled, ml_enabled=self.ml_enabled)
    
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
        await DatabaseManager.create_tables()

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

        # Bootstrap TP/FP feedback loop from historical incident data
        try:
            from src.rules.feedback_loop import get_feedback_loop
            import psycopg2
            fl = get_feedback_loop()
            pg_password = os.getenv("POSTGRES_PASSWORD")
            if not pg_password:
                raise ValueError("POSTGRES_PASSWORD not set")
            pg_conn = psycopg2.connect(
                host=os.getenv("POSTGRES_HOST", "postgres"),
                port=os.getenv("POSTGRES_PORT", "5432"),
                dbname=os.getenv("POSTGRES_DB", "sentinel"),
                user=os.getenv("POSTGRES_USER", "sentinel"),
                password=pg_password,
            )
            loaded = fl.load_from_db(pg_conn.cursor())
            pg_conn.close()
            logger.info("feedback_loop_bootstrapped", feedbacks_loaded=loaded)
        except Exception as e:
            logger.warning("feedback_loop_bootstrap_failed", error=str(e))

        # Initialize Security Graph (Wiz-for-Web3)
        if self.graph_enabled:
            try:
                from src.graph.connection import get_neo4j_connection
                from src.graph.builder import GraphBuilder
                
                neo4j_uri = os.getenv("NEO4J_URI")
                if neo4j_uri:
                    conn = get_neo4j_connection(use_mock=False)
                    await conn.connect()
                    self.graph_builder = GraphBuilder(conn)
                    await self.graph_builder.initialize()
                    logger.info("security_graph_initialized", uri=neo4j_uri.split("@")[-1] if "@" in neo4j_uri else "configured")
                else:
                    # Use mock connection for development
                    conn = get_neo4j_connection(use_mock=True)
                    await conn.connect()
                    self.graph_builder = GraphBuilder(conn)
                    logger.info("security_graph_initialized_mock", message="Using mock graph (set NEO4J_URI for production)")
            except Exception as e:
                logger.warning("security_graph_init_failed", error=str(e), message="Continuing without graph")
                self.graph_enabled = False
        
        # Initialize ML Threat Detector
        if self.ml_enabled:
            try:
                from src.ml.threat_detector import ThreatDetector
                from src.ml.feature_extractor import FeatureExtractor
                
                model_path = os.getenv("ML_MODEL_PATH", "data/models/threat_detector.pt")
                vertex_endpoint = os.getenv("VERTEX_AI_ENDPOINT")
                
                self.ml_feature_extractor = FeatureExtractor()
                self.ml_threat_detector = ThreatDetector(
                    model_path=model_path if os.path.exists(model_path) else None,
                    vertex_endpoint=vertex_endpoint
                )
                logger.info("ml_threat_detector_initialized", 
                           has_local_model=os.path.exists(model_path),
                           has_vertex=bool(vertex_endpoint))
            except Exception as e:
                logger.warning("ml_threat_detector_init_failed", error=str(e), message="Continuing without ML")
                self.ml_enabled = False
        
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

        # Register reorg handler to invalidate events/incidents from reorged blocks
        from src.telemetry.finality_tracker import invalidate_reorged_events
        self.finality_manager.register_reorg_handler(invalidate_reorged_events)
        logger.info("reorg_handler_registered", trackers=len(self.finality_manager.trackers))

        # Initialize non-EVM chain listeners (Solana, Cosmos, Aptos, Sui, Near)
        self.non_evm_listeners = {}
        for chain_config in self.config.get("chains", []):
            chain_id = chain_config.get("chain_id", "")
            chain_type = chain_config.get("chain_type", "evm").lower()
            if chain_type == "evm":
                continue

            rpc_url = chain_config.get("rpc_url", "")
            if not rpc_url:
                continue

            # Build base config fields from YAML dict
            base_kwargs = dict(
                chain_id=chain_id,
                chain_name=chain_config.get("chain_name", chain_id),
                rpc_url=rpc_url,
                ws_url=chain_config.get("ws_url"),
                bridge_contracts=chain_config.get("bridge_contracts", []),
                token_contracts=chain_config.get("token_contracts", []),
                poll_interval_seconds=chain_config.get("poll_interval_seconds", 1.0),
                confirmations_required=chain_config.get("confirmations_required", 1),
                fallback_rpcs=chain_config.get("fallback_rpcs", []),
            )

            try:
                listener = None
                if chain_type == "solana":
                    from src.telemetry.solana_listener import SolanaListener
                    cfg = ListenerConfig(**base_kwargs)
                    listener = SolanaListener(cfg)
                elif chain_type in ("cosmos", "ibc"):
                    from src.telemetry.cosmos_listener import CosmosListener, CosmosConfig
                    cfg = CosmosConfig(
                        **base_kwargs,
                        tendermint_rpc=rpc_url,
                        ibc_channels=chain_config.get("ibc_channels", []),
                    )
                    listener = CosmosListener(cfg)
                elif chain_type in ("aptos", "sui", "move"):
                    from src.telemetry.aptos_listener import AptosListener, AptosConfig
                    cfg = AptosConfig(
                        **base_kwargs,
                        rest_api=rpc_url,
                        chain_type=chain_type,
                        bridge_modules=chain_config.get("bridge_modules", []),
                    )
                    listener = AptosListener(cfg)
                elif chain_type == "near":
                    from src.telemetry.near_listener import NearListener, NearConfig
                    cfg = NearConfig(
                        **base_kwargs,
                        bridge_accounts=chain_config.get("bridge_contracts", []),
                    )
                    listener = NearListener(cfg)

                if listener:
                    connected = await listener.connect()
                    if connected:
                        self.non_evm_listeners[chain_id] = listener
                        logger.info("non_evm_listener_connected", chain_id=chain_id, chain_type=chain_type)
                    else:
                        logger.warning("non_evm_listener_connect_failed", chain_id=chain_id)
            except Exception as e:
                logger.warning("non_evm_listener_init_failed", chain_id=chain_id, error=str(e))

        if self.non_evm_listeners:
            logger.info("non_evm_listeners_initialized", count=len(self.non_evm_listeners),
                        chains=list(self.non_evm_listeners.keys()))

        # Initialize Economic Invariant Engine for bridge exploit detection
        try:
            from src.invariants.engine import InvariantEngine
            from src.invariants.economic import MintLockParityInvariant, UnbackedMintInvariant
            from src.telemetry.price_feed import get_price_feed

            price_feed = get_price_feed()
            self.invariant_engine = InvariantEngine(price_feed=price_feed)

            # Build bridge contract → bridge_id lookup and create invariants
            bridges = self.config.get("bridges", [])
            for bridge in bridges:
                bridge_id = bridge.get("id", "")
                source_chain = bridge.get("source_chain", "")
                dest_chain = bridge.get("dest_chain", "")
                contracts = bridge.get("contracts", [])

                for addr in contracts:
                    self._bridge_contract_map[addr.lower()] = {
                        "bridge_id": bridge_id,
                        "source_chain": source_chain,
                        "dest_chain": dest_chain,
                    }

                # Create invariants for bridges that have both source and dest chains
                if source_chain and dest_chain:
                    self.invariant_engine.add_invariant(
                        MintLockParityInvariant(
                            bridge_id=bridge_id,
                            source_chain=source_chain,
                            dest_chain=dest_chain,
                            tolerance_window=timedelta(minutes=30),
                        )
                    )
                    self.invariant_engine.add_invariant(
                        UnbackedMintInvariant(
                            bridge_id=bridge_id,
                            source_chain=source_chain,
                            dest_chain=dest_chain,
                        )
                    )

            # Register violation handler → create incident
            self.invariant_engine.add_result_handler(self._handle_invariant_violation)

            logger.info(
                "invariant_engine_initialized",
                bridge_contracts=len(self._bridge_contract_map),
                invariants=len(self.invariant_engine.invariants),
            )
        except Exception as e:
            logger.warning("invariant_engine_init_failed", error=str(e))
            self.invariant_engine = None

        # Initialize Runtime Security Plane if enabled
        if self.runtime_enabled and RUNTIME_AVAILABLE:
            await self._initialize_runtime_engines()
        
        # Auto-start contract scanner if enabled
        if os.getenv("AUTO_START_SCANNER", "false").lower() == "true":
            try:
                from src.ai.collectors import start_auto_collection
                raw = os.getenv("SCANNER_CHAINS", "ethereum,polygon,arbitrum")
                scanner_chains = [c.strip() for c in raw.replace(":", ",").split(",") if c.strip()]
                await start_auto_collection(chains=scanner_chains)
                logger.info("contract_scanner_auto_started", chains=scanner_chains)
            except ImportError as e:
                logger.warning("scanner_module_not_available", error=str(e))
            except Exception as e:
                logger.warning("scanner_auto_start_failed", error=str(e), exc_info=True)
    
    async def _run_non_evm_listener(self, chain_id: str, listener):
        """Run a non-EVM chain listener, saving events and analyzing contracts."""
        logger.info("non_evm_listener_started", chain_id=chain_id)
        try:
            async for event in listener.listen_events():
                try:
                    await self._save_event_to_db(event)

                    # Analyze WASM contracts from non-EVM deployments
                    if event.event_type == EventType.CONTRACT_DEPLOYED:
                        await self._analyze_non_evm_contract(chain_id, event)
                except Exception as e:
                    logger.warning("non_evm_event_save_failed", chain_id=chain_id, error=str(e))
        except Exception as e:
            logger.error("non_evm_listener_crashed", chain_id=chain_id, error=str(e))

    async def _analyze_non_evm_contract(self, chain_id: str, event: SecurityEvent):
        """Analyze a non-EVM contract deployment using WASM feature extraction."""
        try:
            raw = event.raw_event or {}
            chain_type = raw.get("chain_type", "unknown")
            wasm_analysis = raw.get("wasm_analysis", {})

            # Near contracts include inline WASM analysis from the listener
            if chain_type == "near" and wasm_analysis:
                risk_score = wasm_analysis.get("risk_score", 0)
                risk_factors = wasm_analysis.get("risk_factors", [])
                contract_type = wasm_analysis.get("likely_contract_type", "unknown")

                if risk_score >= 0.25:
                    logger.warning(
                        "non_evm_contract_threat",
                        chain=chain_id,
                        chain_type=chain_type,
                        contract=event.contract_address,
                        risk_score=f"{risk_score:.2f}",
                        contract_type=contract_type,
                        risk_factors=risk_factors,
                    )
                else:
                    logger.info(
                        "non_evm_contract_safe",
                        chain=chain_id,
                        contract=event.contract_address,
                        risk_score=f"{risk_score:.2f}",
                        contract_type=contract_type,
                    )

            # Cosmos/Injective contracts - log the deployment for tracking
            elif chain_type == "cosmos":
                logger.info(
                    "cosmos_contract_deployed",
                    chain=chain_id,
                    contract=event.contract_address,
                    code_id=raw.get("code_id", ""),
                    action=raw.get("action", ""),
                )

        except Exception as e:
            logger.warning("non_evm_contract_analysis_failed", chain_id=chain_id, error=str(e))

    async def ingestion_loop(self):
        """Loop A: Ingest events from chains."""
        logger.info("ingestion_loop_started")

        # Track chains that successfully process
        successful_chains = set()
        iteration_count = 0
        
        while self.running:
            try:
                iteration_count += 1
                
                # Log periodic status every 10 iterations
                if iteration_count % 10 == 1:
                    connected_chains = [cid for cid, l in self.listeners.items() if l and l.w3]
                    logger.info(
                        "ingestion_loop_iteration",
                        iteration=iteration_count,
                        listener_count=len(self.listeners),
                        connected_chains=len(connected_chains),
                        successful_chains=len(successful_chains)
                    )
                
                # --- Auto-reconnect disconnected listeners (every 2 min) ---
                now_utc = datetime.now(timezone.utc)
                for chain_id, listener in list(self.listeners.items()):
                    if listener is not None and listener.w3 is None:
                        last_try = self._last_reconnect_attempt.get(chain_id)
                        if last_try and (now_utc - last_try) < self._reconnect_interval:
                            continue
                        self._last_reconnect_attempt[chain_id] = now_utc
                        try:
                            connected = await listener.connect()
                            if connected:
                                listener.add_event_handler(self._save_event_to_db)
                                self.circuit_breaker.record_success(chain_id)
                                logger.info("listener_reconnected", chain_id=chain_id)
                            else:
                                self.circuit_breaker.record_failure(chain_id)
                                logger.debug("listener_reconnect_failed", chain_id=chain_id)
                        except Exception as reconn_err:
                            self.circuit_breaker.record_failure(chain_id)
                            logger.debug("listener_reconnect_error", chain_id=chain_id, error=str(reconn_err)[:100])

                for chain_id, listener in self.listeners.items():
                    try:
                        # Skip chains where listener didn't connect (w3 is None)
                        if listener is None or listener.w3 is None:
                            continue

                        # Check circuit breaker (persistent failures)
                        if not self.circuit_breaker.allow_request(chain_id):
                            logger.debug("chain_circuit_open", chain=chain_id)
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
                            self.circuit_breaker.record_failure(chain_id)
                            continue

                        latency = time.time() - start_time
                        rpc_latency_seconds.labels(chain=chain_id, endpoint="primary", method="eth_blockNumber").observe(latency)
                        rpc_requests_total.labels(chain=chain_id, endpoint="primary", method="eth_blockNumber", status="success").inc()

                        # Record success - reset rate limit counter and circuit breaker
                        self.rate_limiter.record_success(chain_id)
                        self.circuit_breaker.record_success(chain_id)
                        chain_head_height.labels(chain=chain_id).set(head_block)
                        circuit_breaker_state.labels(chain=chain_id).set(0)  # CLOSED

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
                                
                                # Process logs into SecurityEvents with full parsing
                                for log in logs:
                                    # Get block timestamp for the event
                                    block_ts = datetime.now(timezone.utc)  # Default to now
                                    try:
                                        log_block = log.get("blockNumber", head_block)
                                        if hasattr(log_block, 'hex'):
                                            log_block = int(log_block.hex(), 16) if log_block else head_block
                                        elif isinstance(log_block, str) and log_block.startswith("0x"):
                                            log_block = int(log_block, 16)
                                    except:
                                        log_block = head_block
                                    
                                    # Full parsing with amount, addresses, and USD calculation
                                    event = await self._log_to_security_event(chain_id, log, log_block, block_ts)
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
                                            
                                            # Get event type string
                                            event_type_str = event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type) if event.event_type else 'unknown'

                                            # ========================================
                                            # FILTER: Skip unknown events to reduce noise
                                            # Only store events we can classify
                                            # ========================================
                                            if event_type_str.lower() == 'unknown':
                                                logger.debug("skipping_unknown_event", 
                                                            chain=chain_id, 
                                                            tx_hash=event.tx_hash[:16] if event.tx_hash else "N/A")
                                                continue  # Skip to next event
                                            
                                            db_event = {
                                                "event_id": event_id,
                                                "chain_id": chain_id,
                                                "event_type": event_type_str,
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
                                            
                                            # Track event types for debugging
                                            if not hasattr(self, '_event_type_stats'):
                                                self._event_type_stats = {}
                                                self._event_type_stats_last_log = datetime.now(timezone.utc)
                                            
                                            self._event_type_stats[event_type_str] = self._event_type_stats.get(event_type_str, 0) + 1
                                            
                                            # Log event type stats every 60 seconds
                                            if (datetime.now(timezone.utc) - self._event_type_stats_last_log).total_seconds() > 60:
                                                logger.info(
                                                    "event_type_stats",
                                                    stats=dict(sorted(self._event_type_stats.items(), key=lambda x: -x[1])[:10]),
                                                    total=sum(self._event_type_stats.values())
                                                )
                                                self._event_type_stats_last_log = datetime.now(timezone.utc)
                                            
                                            logger.debug("event_saved_directly", chain=chain_id, tx_hash=event.tx_hash, event_type=event_type_str)

                                            # ========================================
                                            # ECONOMIC INVARIANT EVALUATION
                                            # Feed bridge events to the invariant engine
                                            # ========================================
                                            if self.invariant_engine and event.event_type in (
                                                EventType.LOCK, EventType.UNLOCK,
                                                EventType.MINT, EventType.BURN,
                                                EventType.BRIDGE_DEPOSIT, EventType.BRIDGE_WITHDRAW,
                                            ):
                                                # Enrich event with bridge_id from contract lookup
                                                bridge_info = self._bridge_contract_map.get(
                                                    (event.contract_address or "").lower()
                                                )
                                                if bridge_info:
                                                    event.bridge_id = bridge_info["bridge_id"]
                                                try:
                                                    await self.invariant_engine.process_event(event)
                                                except Exception as inv_err:
                                                    logger.debug("invariant_eval_error", error=str(inv_err)[:100])

                                            # Rule evaluation happens in _save_event_to_db handler only
                                            # (removed duplicate evaluation here to prevent velocity counter inflation)

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
                                    self.circuit_breaker.record_failure(chain_id)
                                    logger.error("log_poll_failed", chain=chain_id, error=str(e))

                    except Exception as e:
                        # Check if this is a rate limit error
                        if self.rate_limiter.is_rate_limit_error(e):
                            backoff = self.rate_limiter.record_rate_limit(chain_id, e)
                            logger.warning("chain_ingestion_rate_limited", chain=chain_id, backoff_seconds=round(backoff, 1))
                        else:
                            self.circuit_breaker.record_failure(chain_id)
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
        """Store simulation run to database if not already persisted."""
        if not RUNTIME_AVAILABLE:
            return
        try:
            from src.database.models import SimulationRunModel
            from src.database.connection import DatabaseManager
            from sqlalchemy import select
            async with DatabaseManager.get_session() as session:
                existing = await session.execute(
                    select(SimulationRunModel).where(
                        SimulationRunModel.id == uuid.UUID(simulation_run_id)
                    )
                )
                if existing.scalar_one_or_none():
                    return  # Already stored

                # Retrieve from engine's predicted incidents cache
                sim_data = None
                for inc in runtime_engine._predicted_incidents.values():
                    if inc.linked_simulation_run_id == simulation_run_id:
                        sim_data = inc.evidence_json.get("simulation", {})
                        break

                if not sim_data:
                    logger.debug("simulation_run_data_not_found", simulation_run_id=simulation_run_id[:16])
                    return

                db_sim = SimulationRunModel(
                    id=uuid.UUID(simulation_run_id),
                    chain_id=sim_data.get("chain_id", "unknown"),
                    block_number=sim_data.get("block", {}).get("number", 0),
                    block_hash=sim_data.get("block", {}).get("hash", ""),
                    tx_hash=sim_data.get("tx_hash", ""),
                    tx_from=sim_data.get("tx_from"),
                    tx_to=sim_data.get("tx_to"),
                    tx_selector=sim_data.get("tx_selector"),
                    mode=sim_data.get("mode", "FAST"),
                    status=sim_data.get("status", "SUCCESS"),
                    duration_ms=sim_data.get("duration_ms", 0),
                    rpc_calls=sim_data.get("rpc_calls", 0),
                    state_diff_fingerprint=sim_data.get("state_diff_fingerprint"),
                    invariant_results=sim_data.get("invariant_results", []),
                    confidence=sim_data.get("confidence", 0.0),
                    confidence_reasons=sim_data.get("confidence_reasons"),
                    assumptions=sim_data.get("assumptions"),
                )
                session.add(db_sim)
                await session.commit()
                logger.info("simulation_run_stored", simulation_run_id=simulation_run_id[:16])
        except (ConnectionError, OSError, ImportError, RuntimeError, ValueError) as e:
            logger.warning("simulation_run_store_failed", error=str(e))
    
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

    async def _publish_to_ws(self, channel: str, data: dict):
        """Publish a message to Redis for WebSocket streaming to dashboards."""
        try:
            redis_url = os.getenv("REDIS_URL")
            if not redis_url:
                return
            import redis.asyncio as aioredis
            r = aioredis.from_url(redis_url, decode_responses=True)
            await r.publish(channel, json.dumps(data))
            await r.close()
        except Exception:
            pass  # Non-critical - don't block event processing

    async def _save_event_to_db(self, event: SecurityEvent):
        """
        Event handler to save SecurityEvent to database.
        Called by listener's emit_event() for contract deployments and other events.
        Single canonical path for YAML rule evaluation.
        """
        from src.database.service import DatabaseService
        import hashlib

        try:
            chain_id = event.chain_id
            log_index = getattr(event, 'log_index', 0)
            stable_key = f"{chain_id}:{event.tx_hash}:{log_index}"
            event_id = hashlib.sha256(stable_key.encode()).hexdigest()[:32]

            # Dedup: skip if we already processed this event in this handler
            if not hasattr(self, '_handler_seen_events'):
                self._handler_seen_events = set()
            if event_id in self._handler_seen_events:
                return
            self._handler_seen_events.add(event_id)
            # Cap dedup cache at 20K entries
            if len(self._handler_seen_events) > 20000:
                self._handler_seen_events = set(list(self._handler_seen_events)[-10000:])
            
            # Convert severity to string name
            severity_str = event.severity.name if hasattr(event.severity, 'name') else str(event.severity).upper()
            
            # Convert event_type to string
            event_type_str = event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type)
            
            # Serialize raw_data to handle HexBytes
            raw_data = self._serialize_raw_data(event.raw_event if hasattr(event, 'raw_event') else {})
            
            # Extract amount and amount_usd from event
            amount_val = getattr(event, 'amount', None)
            amount_usd_val = getattr(event, 'amount_usd', None)

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
                "amount": str(amount_val) if amount_val is not None else None,
                "amount_usd": str(amount_usd_val) if amount_usd_val is not None else None,
                "raw_data": raw_data,
            }
            
            await DatabaseService.save_events_batch([db_event])
            logger.info(
                "event_handler_saved",
                chain=chain_id,
                event_type=event_type_str,
                tx_hash=event.tx_hash[:20] + "..."
            )

            # Publish high-severity events to Redis for WebSocket streaming
            if severity_str in ("CRITICAL", "HIGH"):
                await self._publish_to_ws(
                    channel="security_events",
                    data={
                        "type": "security_event",
                        "chain_id": chain_id,
                        "event_type": event_type_str,
                        "tx_hash": event.tx_hash,
                        "contract_address": event.contract_address,
                        "severity": severity_str,
                        "status": "open",
                        "timestamp": int(datetime.now(timezone.utc).timestamp()),
                    },
                )

            # ========================================
            # YAML RULE EVALUATION (in event handler)
            # ========================================
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
                                event_type=event_type_str,
                                tx_hash=event.tx_hash[:20] if event.tx_hash else ""
                            )
                            
                            # Create incident for HIGH, CRITICAL, and MEDIUM severity rules
                            if match.rule.severity.upper() in ["HIGH", "CRITICAL", "MEDIUM"]:
                                await self._create_incident_from_rule(
                                    rule=match.rule,
                                    event_data=db_event,
                                    db_event=db_event,
                                    match_details=match.match_details
                                )
                except Exception as rule_err:
                    logger.debug("event_handler_rule_evaluation_error", error=str(rule_err))
            
            # ========================================
            # SECURITY GRAPH UPDATE (Wiz-for-Web3)
            # ========================================
            if self.graph_enabled and self.graph_builder:
                try:
                    # Convert to graph-compatible format
                    graph_event = {
                        "chain_id": chain_id,
                        "tx_hash": event.tx_hash,
                        "block_number": event.block_number,
                        "block_timestamp": event.block_timestamp,
                        "event_type": event_type_str,
                        "contract_address": event.contract_address,
                        "source_address": getattr(event, 'source_address', None) or getattr(event, 'from_address', None),
                        "dest_address": getattr(event, 'dest_address', None) or getattr(event, 'to_address', None),
                        "amount_usd": float(getattr(event, 'amount_usd', 0) or 0),
                        "raw_event": raw_data
                    }
                    
                    # Process event into graph (non-blocking)
                    asyncio.create_task(self.graph_builder.process_event(graph_event))
                    
                except Exception as graph_err:
                    logger.debug("graph_update_error", error=str(graph_err))
            
            # ========================================
            # ML THREAT DETECTION
            # ========================================
            if self.ml_enabled and self.ml_threat_detector:
                try:
                    # Extract features
                    ml_event = {
                        "chain_id": chain_id,
                        "event_type": event_type_str,
                        "amount_usd": float(getattr(event, 'amount_usd', 0) or 0),
                        "source_address": getattr(event, 'source_address', None),
                        "dest_address": getattr(event, 'dest_address', None),
                        "contract_address": event.contract_address,
                        "block_timestamp": event.block_timestamp,
                        "severity": severity_str
                    }
                    
                    features = self.ml_feature_extractor.extract_features(ml_event)
                    prediction = await self.ml_threat_detector.predict(features.to_dict())
                    
                    # Create incident if ML detects threat
                    # FINE-TUNED: Increased threshold and filter out low-confidence unknown threats
                    should_create_incident = (
                        prediction.is_threat and 
                        prediction.risk_score >= 75 and  # Increased from 60 to 75
                        prediction.confidence >= 0.70 and  # Require 70% confidence
                        # Filter out low-confidence unknown_threat and governance_attack
                        not (prediction.threat_type in ["unknown_threat", "governance_attack"] and prediction.confidence < 0.85)
                    )
                    
                    if should_create_incident:
                        logger.warning(
                            "ml_threat_detected",
                            threat_type=prediction.threat_type,
                            risk_score=prediction.risk_score,
                            confidence=prediction.confidence,
                            chain=chain_id,
                            tx_hash=event.tx_hash[:20] if event.tx_hash else ""
                        )
                        
                        # Create ML-based incident
                        await self._create_ml_incident(
                            event=event,
                            db_event=db_event,
                            prediction=prediction
                        )
                        
                except Exception as ml_err:
                    logger.debug("ml_detection_error", error=str(ml_err))
                    
        except Exception as e:
            logger.error("event_handler_save_failed", error=str(e), exc_info=True)
    
    async def _log_to_security_event(self, chain_id: str, log: dict, block_number: int, block_timestamp: Optional[datetime] = None) -> Optional[SecurityEvent]:
        """
        Convert log to SecurityEvent with FULL parsing.
        
        This method now does complete parsing including:
        - Event type classification from signature database
        - from_address and to_address extraction from topics
        - Amount parsing from data field
        - USD value calculation via price feed
        """
        from src.telemetry.event_signatures import get_event_info
        from src.telemetry.price_feed import get_price_feed
        from decimal import Decimal
        
        # Standard ERC20 Transfer topic
        
        try:
            # Get topics
            topics = log.get("topics", [])
            if not topics:
                return None
            
            # Extract topic0 for event classification
            topic0 = topics[0] if topics else ""
            if hasattr(topic0, 'hex'):
                topic0 = topic0.hex()
            if topic0 and not topic0.startswith("0x"):
                topic0 = "0x" + topic0
            
            # Get contract address
            contract_address = log.get("address", "")
            if hasattr(contract_address, 'lower'):
                contract_address = contract_address.lower()
            
            # Get tx_hash
            tx_hash = log.get("transactionHash", "")
            if hasattr(tx_hash, 'hex'):
                tx_hash = tx_hash.hex()
            
            # Get log_index
            log_index = log.get("logIndex", 0)
            if hasattr(log_index, 'hex'):
                log_index = int(log_index.hex(), 16) if log_index else 0
            elif isinstance(log_index, str) and log_index.startswith("0x"):
                log_index = int(log_index, 16)
            
            # Look up event info from signature database
            event_info = get_event_info(topic0) if topic0 else {}
            event_type = event_info.get("type", EventType.UNKNOWN)
            event_severity = event_info.get("severity", "low")
            event_name = event_info.get("name", "Unknown")
            protocol = event_info.get("protocol", "unknown")
            
            # Map severity string to Severity enum
            severity_map = {
                "info": Severity.INFO,
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL
            }
            severity = severity_map.get(event_severity, Severity.LOW)
            
            # ========================================
            # EXTRACT ADDRESSES FROM TOPICS
            # ========================================
            from_address = None
            to_address = None
            
            # For Transfer events: Transfer(from, to, value)
            # Topics: [topic0, from (indexed), to (indexed)]
            # Data: value (not indexed)
            if len(topics) >= 2:
                topic1 = topics[1]
                if hasattr(topic1, 'hex'):
                    topic1 = topic1.hex()
                if topic1:
                    # Extract last 40 chars (20 bytes = address)
                    from_address = "0x" + topic1[-40:].lower()
            
            if len(topics) >= 3:
                topic2 = topics[2]
                if hasattr(topic2, 'hex'):
                    topic2 = topic2.hex()
                if topic2:
                    to_address = "0x" + topic2[-40:].lower()
            
            # ========================================
            # PARSE AMOUNT FROM DATA FIELD
            # ========================================
            amount = Decimal("0")
            raw_amount = 0
            data = log.get("data", "0x")
            if hasattr(data, 'hex'):
                data = data.hex()
            
            # Remove 0x prefix if present
            if data and data.startswith("0x"):
                data = data[2:]
            
            # Parse raw amount from data
            # For simple events (Transfer): first 32 bytes is the value
            # For Swap events: data has multiple amount fields, pick the largest
            if data and len(data) >= 64:
                try:
                    is_swap = event_type in (EventType.SWAP,) or event_name in ("Swap",)
                    if is_swap and len(data) >= 256:
                        # Uniswap V2 Swap: (amount0In, amount1In, amount0Out, amount1Out)
                        # Uniswap V3 Swap: (amount0, amount1, sqrtPriceX96, liquidity, tick)
                        # Take the largest non-zero field from the first 4 words
                        candidates = []
                        for i in range(4):
                            try:
                                val = int(data[i*64:(i+1)*64], 16)
                                # Handle int256 (V3): if top bit set, it's negative
                                if val >= 2**255:
                                    val = val - 2**256
                                candidates.append(abs(val))
                            except (ValueError, TypeError):
                                pass
                        raw_amount = max(candidates) if candidates else 0
                    else:
                        raw_amount = int(data[:64], 16)
                except (ValueError, TypeError):
                    pass
            
            # ========================================
            # GET TOKEN DECIMALS & CALCULATE USD VALUE
            # ========================================
            amount_usd = Decimal("0")
            price = 0.0
            decimals = 18  # Default
            
            # Only process if we have a raw amount and contract address
            if raw_amount > 0 and contract_address:
                try:
                    price_feed = get_price_feed()
                    
                    # Get correct decimals for this token (critical for stablecoins!)
                    decimals = price_feed.get_token_decimals(chain_id, contract_address)
                    
                    # Convert raw amount to human-readable using correct decimals
                    amount = Decimal(raw_amount) / Decimal(10 ** decimals)
                    
                    # Cap amount to prevent database overflow (max 10^19)
                    MAX_AMOUNT = Decimal("9999999999999999999")  # ~10^19
                    if amount > MAX_AMOUNT:
                        logger.debug("amount_capped", original=str(amount)[:20], capped=str(MAX_AMOUNT))
                        amount = MAX_AMOUNT
                    
                    # Get price and calculate USD value
                    price = await price_feed.get_price(chain_id, contract_address)
                    if price > 0:
                        amount_usd = price_feed.calculate_usd_value(amount, price, decimals)
                        
                        # Sanity check: Values over $10B are likely calculation errors
                        # Set to 0 (unknown) rather than showing misleading $10B cap
                        MAX_USD = Decimal("10000000000")  # $10B
                        if amount_usd > MAX_USD:
                            logger.warning("usd_value_unrealistic_zeroed", 
                                          original=str(amount_usd)[:20], 
                                          token=contract_address[:10],
                                          decimals=decimals,
                                          reason="likely_decimal_error")
                            amount_usd = Decimal("0")  # Show as unknown, not misleading cap
                        
                        # Update severity based on USD value
                        if amount_usd >= Decimal("10000000"):  # $10M+
                            severity = Severity.CRITICAL
                        elif amount_usd >= Decimal("1000000"):  # $1M+
                            severity = Severity.HIGH
                        elif amount_usd >= Decimal("100000"):  # $100K+
                            severity = Severity.MEDIUM
                            
                except Exception as price_err:
                    logger.debug("price_fetch_error_in_log_parse", 
                                token=contract_address[:10] if contract_address else "N/A", 
                                error=str(price_err))
                    # Fallback: use 18 decimals if we couldn't get proper decimals
                    if raw_amount > 0:
                        amount = Decimal(raw_amount) / Decimal(10 ** 18)
            
            # ========================================
            # GET TOKEN SYMBOL
            # ========================================
            token_symbol = "UNKNOWN"
            if contract_address:
                try:
                    price_feed = get_price_feed()
                    token_symbol = price_feed.get_token_symbol(chain_id, contract_address) or "UNKNOWN"
                except:
                    pass
            
            # ========================================
            # BUILD ENRICHED RAW_EVENT
            # ========================================
            # Serialize the original log data
            raw_event = {}
            for key, value in log.items():
                if hasattr(value, 'hex'):
                    raw_event[key] = value.hex()
                elif isinstance(value, list):
                    raw_event[key] = [v.hex() if hasattr(v, 'hex') else v for v in value]
                else:
                    raw_event[key] = value
            
            # Add enriched fields
            raw_event["event_name"] = event_name
            raw_event["protocol"] = protocol
            raw_event["token_symbol"] = token_symbol
            raw_event["amount_human"] = str(amount)
            raw_event["amount_usd"] = str(amount_usd)
            raw_event["token_price_usd"] = price
            raw_event["from_address"] = from_address
            raw_event["to_address"] = to_address
            
            # ========================================
            # CREATE SECURITY EVENT
            # ========================================
            event = SecurityEvent(
                chain_id=chain_id,
                tx_hash=tx_hash,
                block_number=block_number,
                block_timestamp=block_timestamp or datetime.now(timezone.utc),
                log_index=log_index,
                contract_address=contract_address,
                event_type=event_type,
                severity=severity,
                source_address=from_address or "",
                dest_address=to_address or "",
                amount=amount,
                amount_usd=amount_usd,
                asset_type=token_symbol,
                asset_address=contract_address,
                raw_event=raw_event
            )
            
            return event
            
        except Exception as e:
            logger.error("log_conversion_failed", error=str(e), exc_info=True)
            return None
    
    async def _handle_invariant_violation(self, result):
        """Handle an invariant violation — create a CRITICAL/HIGH incident."""
        from src.database.service import DatabaseService

        if not result.violated:
            return

        invariant_violations_total.labels(
            invariant_type=result.invariant_name,
            bridge_id=(result.details or {}).get("bridge_id", "unknown")
        ).inc()

        try:
            inv_name = result.invariant_name
            severity = result.severity.name if hasattr(result.severity, 'name') else str(result.severity).upper()
            details = result.details or {}
            bridge_id = details.get("bridge_id", "unknown")
            violation_amount = getattr(result, 'violation_amount', 0)
            confidence = getattr(result, 'confidence', 0.9)

            # Dedup: one incident per invariant+bridge per hour
            dedupe_key = f"inv_{inv_name}_{bridge_id}"
            if not hasattr(self, '_invariant_incident_cache'):
                self._invariant_incident_cache = {}
            now = datetime.now(timezone.utc)
            if dedupe_key in self._invariant_incident_cache:
                if (now - self._invariant_incident_cache[dedupe_key]).total_seconds() < 3600:
                    return
            self._invariant_incident_cache[dedupe_key] = now

            incident_id = f"inc_inv_{inv_name}_{bridge_id}_{int(now.timestamp())}"
            usd_value = float(details.get("violation_usd", 0) or 0)

            incident_data = {
                "incident_id": incident_id,
                "title": f"[{severity}] Bridge Invariant Violation: {inv_name.replace('_', ' ').title()}",
                "summary": f"Economic invariant '{inv_name}' violated on bridge '{bridge_id}'. "
                           f"Violation amount: {violation_amount} tokens. "
                           f"This indicates potential unbacked minting or lock/mint imbalance — "
                           f"a pattern seen in Ronin ($625M) and Nomad ($190M) bridge exploits.",
                "severity": severity,
                "status": "OPEN_PENDING",
                "attack_type": "BRIDGE_EXPLOIT",
                "confidence": confidence,
                "total_loss_usd": usd_value,
                "affected_chains": list(set(filter(None, [
                    details.get("source_chain"),
                    details.get("dest_chain"),
                ]))),
                "event_ids": [],
                "rule_ids": [f"invariant:{inv_name}"],
                "recommended_actions": [
                    "IMMEDIATE: Verify bridge lock/mint parity on-chain",
                    "Check if validator signatures are valid",
                    "Monitor for additional unbacked withdrawals",
                    "Consider emergency bridge pause if confirmed",
                ],
                "cluster_key": f"inv_{inv_name}_{bridge_id}_{now.strftime('%Y%m%d%H')}",
                "raw_data": {
                    "invariant": inv_name,
                    "bridge_id": bridge_id,
                    "violation_amount": str(violation_amount),
                    "details": {k: str(v) for k, v in details.items()},
                },
            }

            saved_id = await DatabaseService.save_incident(incident_data)
            if saved_id:
                incidents_created_total.labels(severity=severity, source="invariant").inc()
                logger.warning(
                    "invariant_violation_incident_created",
                    incident_id=saved_id,
                    invariant=inv_name,
                    bridge=bridge_id,
                    severity=severity,
                    violation_amount=violation_amount,
                )
                asyncio.create_task(self._send_alert_notification(incident_data))
                asyncio.create_task(self._trigger_guardian_response(incident_data))
        except Exception as e:
            logger.error("invariant_violation_handler_failed", error=str(e), exc_info=True)

    async def _create_incident_from_rule(
        self,
        rule,
        event_data: Dict,
        db_event: Dict,
        match_details: Dict
    ):
        """
        Create an incident when a YAML rule is triggered.
        
        Uses ML Alert Analyzer to filter false positives before creating incidents.
        Only creates incidents if ML analysis confirms it's likely a true positive.
        """
        from src.database.service import DatabaseService
        
        try:
            # Generate unique incident ID based on rule and event
            chain_id = event_data.get("chain_id", "unknown")
            contract_addr = (event_data.get("contract_address") or "")[:10]
            
            # ========================================
            # DEDUPLICATION: Use EVENT (chain+contract+block) as key
            # This prevents multiple rules from creating duplicate incidents for the same event
            # ========================================
            event_block = db_event.get("block_number", "")
            tx_hash = db_event.get("tx_hash", "")[:16] if db_event.get("tx_hash") else ""
            
            # Event-level dedup key (same event = same incident, regardless of which rule triggered)
            event_dedupe_key = f"{chain_id}_{contract_addr}_{event_block}_{tx_hash}" if contract_addr else f"{chain_id}_{event_block}_{tx_hash}"
            
            # Rule-level dedup key (same rule+contract = don't re-alert within window)
            rule_dedupe_key = f"{rule.id[:15]}_{chain_id}_{contract_addr}" if contract_addr else f"{rule.id[:15]}_{chain_id}"
            
            # Check if we've already created an incident for this EVENT
            if not hasattr(self, '_event_incident_cache'):
                self._event_incident_cache = {}
            if not hasattr(self, '_rule_incident_cache'):
                self._rule_incident_cache = {}
            
            now = datetime.now(timezone.utc)
            
            # First check: Has ANY rule already created an incident for this event?
            if event_dedupe_key in self._event_incident_cache:
                last_created = self._event_incident_cache[event_dedupe_key]
                if (now - last_created).total_seconds() < 300:  # 5 min window for same event
                    logger.debug("incident_deduplicated_same_event", 
                                event_key=event_dedupe_key[:30], 
                                rule=rule.id,
                                reason="Another rule already created incident for this event")
                    return
            
            # Second check: Has THIS rule already alerted on this contract recently?
            if rule_dedupe_key in self._rule_incident_cache:
                last_created = self._rule_incident_cache[rule_dedupe_key]
                if (now - last_created).total_seconds() < 1800:  # 30 min window for same rule+contract
                    logger.debug("incident_deduplicated_same_rule", 
                                rule_key=rule_dedupe_key[:30],
                                reason="Same rule already alerted on this contract")
                    return
            
            # ========================================
            # ML ALERT ANALYZER - Filter False Positives
            # ========================================
            try:
                from src.ml.alert_analyzer import analyze_yaml_alert, AlertVerdict
                
                # Analyze the alert with ML
                analysis_result = await analyze_yaml_alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    chain_id=chain_id,
                    event=event_data
                )
                
                # Log the analysis
                logger.info(
                    "yaml_alert_analyzed",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    verdict=analysis_result.verdict.value,
                    tp_probability=round(analysis_result.tp_probability, 2),
                    should_create=analysis_result.should_create_incident
                )
                
                # Skip incident creation if ML says it's a false positive
                if not analysis_result.should_create_incident:
                    logger.info(
                        "yaml_alert_filtered_as_fp",
                        rule_id=rule.id,
                        rule_name=rule.name,
                        tp_probability=round(analysis_result.tp_probability, 2),
                        reasoning=analysis_result.reasoning[:2]  # First 2 reasons
                    )
                    return
                
                # Use ML-adjusted severity
                adjusted_severity = analysis_result.adjusted_severity.upper()
                ml_confidence = analysis_result.tp_probability
                ml_reasoning = analysis_result.reasoning
                
            except ImportError:
                # ML analyzer not available, proceed without filtering
                adjusted_severity = rule.severity.upper()
                ml_confidence = None
                ml_reasoning = None
            except Exception as ml_err:
                logger.warning("ml_alert_analysis_failed", error=str(ml_err))
                adjusted_severity = rule.severity.upper()
                ml_confidence = None
                ml_reasoning = None
            
            incident_id = f"inc_rule_{rule_dedupe_key}_{int(now.timestamp())}"
            
            # ========================================
            # Map rule ID to specific attack type
            # ========================================
            rule_id_lower = rule.id.lower()
            
            # Map rule patterns to attack types (expanded for better coverage)
            attack_type_mapping = {
                # Attack types
                "flash": "FLASH_LOAN_ATTACK",
                "reentrancy": "REENTRANCY_ATTACK",
                "mint": "UNBACKED_MINT",
                "bridge": "BRIDGE_EXPLOIT",
                "oracle": "ORACLE_MANIPULATION",
                "price": "PRICE_MANIPULATION",
                "governance": "GOVERNANCE_ATTACK",
                "rug": "RUG_PULL",
                "honeypot": "HONEYPOT",
                "drain": "FUND_DRAIN",
                "liquidation": "LIQUIDATION_RISK",
                "sandwich": "SANDWICH_ATTACK",
                "frontrun": "FRONT_RUNNING",
                "mev": "MEV_ATTACK",
                "mempool": "MEV_ATTACK",
                "exploit": "EXPLOIT",
                # Activity types
                "swap": "LARGE_SWAP",
                "transfer": "LARGE_TRANSFER",
                "velocity": "VELOCITY_ANOMALY",
                "spike": "VELOCITY_ANOMALY",
                "whale": "WHALE_ACTIVITY",
                "large": "LARGE_TRANSACTION",
                # L2/Chain specific
                "arbitrum": "L2_ANOMALY",
                "optimism": "L2_ANOMALY",
                "base": "L2_ANOMALY",
                "sequencer": "SEQUENCER_ISSUE",
                "delayed-inbox": "L2_ANOMALY",
                # Protocol specific
                "uniswap": "DEX_ANOMALY",
                "pancakeswap": "DEX_ANOMALY",
                "sushiswap": "DEX_ANOMALY",
                "curve": "DEX_ANOMALY",
                "stargate": "BRIDGE_ACTIVITY",
                "aave": "LENDING_ANOMALY",
                "compound": "LENDING_ANOMALY",
                "maker": "LENDING_ANOMALY",
                # NFT
                "nft": "NFT_ANOMALY",
                "wash": "NFT_WASH_TRADING",
                # Other
                "hft": "HFT_PATTERN",
                "failed": "FAILED_TX_SPIKE",
                "liquidity": "LIQUIDITY_CHANGE",
                "removal": "LIQUIDITY_REMOVAL",
            }
            
            # Find matching attack type (check multiple patterns)
            category = "RULE_TRIGGERED"
            for pattern, attack_type in attack_type_mapping.items():
                if pattern in rule_id_lower or pattern in rule.name.lower():
                    category = attack_type
                    break
            
            # Fallback: Try to infer from rule name if still generic
            if category == "RULE_TRIGGERED":
                rule_name_lower = rule.name.lower()
                if "swap" in rule_name_lower:
                    category = "LARGE_SWAP"
                elif "transfer" in rule_name_lower:
                    category = "LARGE_TRANSFER"
                elif "bridge" in rule_name_lower:
                    category = "BRIDGE_ACTIVITY"
                elif "trading" in rule_name_lower:
                    category = "TRADING_ANOMALY"
                elif "pattern" in rule_name_lower:
                    category = "PATTERN_DETECTED"
            
            # Get recommended_actions safely (may not exist on AlertRule)
            recommended_actions = getattr(rule, 'recommended_actions', None) or [
                "Review the transaction details",
                "Check related transactions",
                "Investigate the involved addresses"
            ]
            
            # Get confidence - use ML confidence if available
            base_confidence = getattr(rule, 'confidence', 0.8) or 0.8
            confidence = ml_confidence if ml_confidence is not None else base_confidence
            
            # ========================================
            # SEVERITY ADJUSTMENT: Based on confidence and loss amount
            # This reduces false positives by downgrading low-confidence alerts
            # ========================================
            amount_usd = float(event_data.get("amount_usd", 0) or 0)
            
            # Cap unrealistic values
            if amount_usd > 10_000_000_000:  # > $10B is unrealistic
                amount_usd = 0  # Treat as unknown rather than misleading
            
            # Downgrade severity for low confidence
            if confidence < 0.5:
                if adjusted_severity == "CRITICAL":
                    adjusted_severity = "HIGH"
                    logger.debug("severity_downgraded", reason="low_confidence", original="CRITICAL", new="HIGH", confidence=confidence)
                elif adjusted_severity == "HIGH":
                    adjusted_severity = "MEDIUM"
                    logger.debug("severity_downgraded", reason="low_confidence", original="HIGH", new="MEDIUM", confidence=confidence)
            
            # Downgrade severity for $0 loss (unless it's a detection-only rule)
            if amount_usd == 0 and adjusted_severity == "CRITICAL":
                # Activity rules without monetary loss shouldn't be CRITICAL
                if category not in {"REENTRANCY_ATTACK", "FLASH_LOAN_ATTACK", "BRIDGE_EXPLOIT", "RUG_PULL"}:
                    adjusted_severity = "HIGH"
                    logger.debug("severity_downgraded", reason="zero_loss", original="CRITICAL", new="HIGH", category=category)
            
            # Upgrade severity for very high confirmed losses
            if amount_usd >= 1_000_000 and confidence >= 0.8 and adjusted_severity in {"MEDIUM", "HIGH"}:
                adjusted_severity = "CRITICAL"
                logger.debug("severity_upgraded", reason="high_loss", amount_usd=amount_usd, confidence=confidence)
            
            # ========================================
            # Extract contract and address information
            # ========================================
            contract_address = event_data.get("contract_address") or ""
            from_address = event_data.get("from_address") or event_data.get("source_address") or ""
            to_address = event_data.get("to_address") or event_data.get("dest_address") or ""
            
            # Build affected_contracts list
            affected_contracts = []
            if contract_address:
                affected_contracts.append(contract_address)
            
            # Build affected_addresses list (unique addresses involved)
            affected_addresses = []
            if from_address and from_address not in affected_addresses:
                affected_addresses.append(from_address)
            if to_address and to_address not in affected_addresses:
                affected_addresses.append(to_address)
            
            # Build incident data
            incident_data = {
                "incident_id": incident_id,
                "title": f"[{adjusted_severity}] {rule.name}",
                "summary": rule.description or f"Rule {rule.name} triggered on {chain_id}",
                "severity": adjusted_severity,
                "status": "OPEN_PENDING",
                "attack_type": category,
                "confidence": confidence,
                # Use the already-capped amount_usd value
                "total_loss_usd": amount_usd,
                "affected_chains": [chain_id],
                "affected_contracts": affected_contracts,
                "affected_addresses": affected_addresses,
                "event_ids": [db_event.get("event_id", "")],
                "rule_ids": [rule.id],
                "recommended_actions": recommended_actions,
                "cluster_key": f"{rule.id}_{chain_id}_{(contract_address or 'no_contract')[:10]}_{datetime.now(timezone.utc).strftime('%Y%m%d%H')}",
            }
            
            # Add ML analysis to raw_data if available
            if ml_reasoning:
                incident_data["raw_data"] = {
                    "ml_analysis": {
                        "tp_probability": ml_confidence,
                        "reasoning": ml_reasoning,
                        "original_severity": rule.severity.upper(),
                        "adjusted_severity": adjusted_severity
                    }
                }
            
            # Save to database
            saved_id = await DatabaseService.save_incident(incident_data)
            if saved_id:
                # Record in BOTH caches to prevent duplicates
                self._event_incident_cache[event_dedupe_key] = now
                self._rule_incident_cache[rule_dedupe_key] = now
                
                # Clean old cache entries (older than 1 hour)
                cutoff = now - timedelta(hours=1)
                self._event_incident_cache = {
                    k: v for k, v in self._event_incident_cache.items() 
                    if v > cutoff
                }
                self._rule_incident_cache = {
                    k: v for k, v in self._rule_incident_cache.items() 
                    if v > cutoff
                }
                
                incidents_created_total.labels(severity=adjusted_severity, source="rule").inc()
                logger.info(
                    "incident_created_from_rule",
                    incident_id=saved_id,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=adjusted_severity,
                    chain=chain_id,
                    ml_filtered=ml_confidence is not None,
                    tp_probability=round(ml_confidence, 2) if ml_confidence else None
                )

                # Send alert notification (fire-and-forget for HIGH/CRITICAL)
                asyncio.create_task(self._send_alert_notification(incident_data))

                # Guardian auto-response (fire-and-forget)
                asyncio.create_task(self._trigger_guardian_response(incident_data))
        except Exception as e:
            logger.error("incident_creation_failed", error=str(e), rule_id=rule.id, exc_info=True)

    async def _create_ml_incident(
        self,
        event: SecurityEvent,
        db_event: Dict,
        prediction
    ):
        """Create an incident from ML threat detection."""
        from src.database.service import DatabaseService
        
        try:
            chain_id = event.chain_id
            event.tx_hash[:16] if event.tx_hash else ""
            contract_addr = event.contract_address[:10] if event.contract_address else "unknown"
            
            # ========================================
            # DEDUPLICATION: Use contract+threat_type as key (not timestamp)
            # ========================================
            dedupe_key = f"ml_{prediction.threat_type}_{chain_id}_{contract_addr}"
            
            # Check if we've already created an incident for this contract+threat in the last hour
            if not hasattr(self, '_ml_incident_cache'):
                self._ml_incident_cache = {}
            
            cache_key = dedupe_key
            now = datetime.now(timezone.utc)
            if cache_key in self._ml_incident_cache:
                last_created = self._ml_incident_cache[cache_key]
                if (now - last_created).total_seconds() < 3600:  # 1 hour dedup window
                    logger.debug("ml_incident_deduplicated", dedupe_key=cache_key)
                    return
            
            # Use dedupe_key as incident_id for consistency
            incident_id = f"inc_{dedupe_key}_{int(now.timestamp())}"
            
            # ========================================
            # SEVERITY GRADATION: Based on risk score + confidence
            # Risk score is the PRIMARY factor, threat type is a secondary modifier
            # ========================================
            # Known dangerous threat types (can bump severity UP if risk is high)
            critical_threats = {"flash_loan_exploit", "reentrancy_exploit", "bridge_exploit"}
            high_threats = {"oracle_manipulation", "rug_pull"}
            
            # PRIMARY: Severity based on RISK SCORE (most important factor)
            # This ensures low risk scores NEVER get CRITICAL severity
            if prediction.risk_score >= 80 and prediction.confidence >= 0.85:
                severity = "CRITICAL"
            elif prediction.risk_score >= 60 and prediction.confidence >= 0.70:
                severity = "HIGH"
            elif prediction.risk_score >= 40 and prediction.confidence >= 0.50:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            # SECONDARY: Bump severity for known dangerous threat types (only if confidence is high)
            # But ONLY bump - never let threat type alone make something CRITICAL
            if prediction.confidence >= 0.85 and prediction.risk_score >= 50:
                if prediction.threat_type in critical_threats and severity == "HIGH":
                    severity = "CRITICAL"  # Bump HIGH → CRITICAL for dangerous threats
                elif prediction.threat_type in high_threats and severity == "MEDIUM":
                    severity = "HIGH"  # Bump MEDIUM → HIGH for dangerous threats
            
            # IMPORTANT: Risk score 35 with confidence 78% should be MEDIUM at most
            # The above logic already handles this correctly:
            # - risk_score=35 < 40 → severity = "LOW" (or MEDIUM if confidence >= 0.50)
            logger.debug("ml_severity_calculated",
                        risk_score=prediction.risk_score,
                        confidence=prediction.confidence,
                        threat_type=prediction.threat_type,
                        final_severity=severity)
            
            # Build incident data
            incident_data = {
                "incident_id": incident_id,
                "title": f"[ML-{severity}] {prediction.threat_type.replace('_', ' ').title()} Detected",
                "summary": f"ML model detected potential {prediction.threat_type} with {prediction.confidence:.0%} confidence. Risk score: {prediction.risk_score}/100",
                "severity": severity,
                "status": "OPEN_PENDING",
                "attack_type": prediction.threat_type,
                "confidence": prediction.confidence,
                # Set unrealistic values (>$10B) to 0 (unknown) rather than misleading cap
                "total_loss_usd": 0.0 if float(getattr(event, 'amount_usd', 0) or 0) > 10_000_000_000 else float(getattr(event, 'amount_usd', 0) or 0),
                "affected_chains": [chain_id],
                "event_ids": [db_event.get("event_id", "")],
                "rule_ids": ["ml_threat_detector"],
                "recommended_actions": [
                    f"Investigate {prediction.threat_type} indicators",
                    "Review transaction details and involved addresses",
                    "Check for related transactions in the same block",
                    "Verify if this is a known pattern"
                ],
                "cluster_key": f"ml_{prediction.threat_type}_{chain_id}_{contract_addr}_{datetime.now(timezone.utc).strftime('%Y%m%d%H')}",
                "raw_data": {
                    "ml_prediction": {
                        "threat_type": prediction.threat_type,
                        "risk_score": prediction.risk_score,
                        "confidence": prediction.confidence,
                        "top_factors": prediction.top_factors,
                        "model_version": prediction.model_version
                    }
                }
            }
            
            # Save to database
            saved_id = await DatabaseService.save_incident(incident_data)
            if saved_id:
                # Record in cache to prevent duplicates
                self._ml_incident_cache[cache_key] = now
                
                # Clean old cache entries (older than 2 hours)
                cutoff = now - timedelta(hours=2)
                self._ml_incident_cache = {
                    k: v for k, v in self._ml_incident_cache.items() 
                    if v > cutoff
                }
                
                incidents_created_total.labels(severity=severity, source="ml").inc()
                logger.info(
                    "ml_incident_created",
                    incident_id=saved_id,
                    threat_type=prediction.threat_type,
                    risk_score=prediction.risk_score,
                    severity=severity,
                    chain=chain_id
                )

                # Send alert notification (fire-and-forget for HIGH/CRITICAL)
                asyncio.create_task(self._send_alert_notification(incident_data))

                # Guardian auto-response (fire-and-forget)
                asyncio.create_task(self._trigger_guardian_response(incident_data))
        except Exception as e:
            logger.error("ml_incident_creation_failed", error=str(e), exc_info=True)

    async def _trigger_guardian_response(self, incident_data: Dict):
        """Trigger Guardian auto-response for critical incidents. Fire-and-forget."""
        severity = incident_data.get("severity", "LOW")
        if severity not in ("CRITICAL", "HIGH"):
            return
        try:
            from src.response.guardian import auto_respond_to_incident

            chains = incident_data.get("affected_chains", [])
            contracts = incident_data.get("affected_contracts", [])
            record = await auto_respond_to_incident(
                incident_id=incident_data.get("incident_id", "unknown"),
                severity=severity.lower(),
                attack_type=incident_data.get("attack_type", "unknown"),
                protocol=incident_data.get("explanation_json", {}).get("protocol", "unknown") if incident_data.get("explanation_json") else "unknown",
                estimated_loss_usd=float(incident_data.get("total_loss_usd", 0) or 0),
                chain=chains[0] if chains else "unknown",
                contract=contracts[0] if contracts else "unknown",
            )
            if record:
                logger.info(
                    "guardian_response_triggered",
                    incident_id=incident_data.get("incident_id"),
                    action=record.action.value,
                    status=record.status.value,
                )
        except Exception as e:
            logger.debug("guardian_response_skipped", error=str(e))

    async def _send_alert_notification(self, incident_data: Dict):
        """
        Send alert notification for HIGH/CRITICAL incidents via Slack and Telegram.

        Direct HTTP calls — no dependency on the full AlertRouter/Incident model chain.
        Fire-and-forget: failures are logged but never block incident creation.
        """
        severity = incident_data.get("severity", "LOW")
        if severity not in ("CRITICAL", "HIGH"):
            return

        title = incident_data.get("title", "Security Incident")
        summary = incident_data.get("summary", "")
        chains = ", ".join(incident_data.get("affected_chains", []))
        loss_usd = incident_data.get("total_loss_usd", 0)
        incident_id = incident_data.get("incident_id", "unknown")

        # Format loss string
        if loss_usd and loss_usd > 0:
            if loss_usd >= 1_000_000:
                loss_str = f"${loss_usd/1_000_000:,.1f}M"
            elif loss_usd >= 1_000:
                loss_str = f"${loss_usd/1_000:,.1f}K"
            else:
                loss_str = f"${loss_usd:,.0f}"
        else:
            loss_str = "Unknown"

        emoji = "\U0001f6a8\U0001f6a8\U0001f6a8" if severity == "CRITICAL" else "\U0001f6a8"

        # ---- Slack Webhook ----
        slack_url = os.getenv("SLACK_WEBHOOK_URL", "")
        if slack_url:
            try:
                import httpx
                payload = {
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} {severity}: {title}",
                                "emoji": True
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Severity:* {severity}"},
                                {"type": "mrkdwn", "text": f"*Chains:* {chains}"},
                                {"type": "mrkdwn", "text": f"*Est. Exposure:* {loss_str}"},
                                {"type": "mrkdwn", "text": f"*Incident:* `{incident_id[:24]}`"},
                            ]
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*Summary:* {summary[:500]}"}
                        }
                    ]
                }
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(slack_url, json=payload)
                    if resp.status_code == 200:
                        alerts_sent_total.labels(channel="slack", severity=severity).inc()
                        logger.info("slack_alert_sent", incident_id=incident_id, severity=severity)
                    else:
                        alerts_failed_total.labels(channel="slack", error_type=f"http_{resp.status_code}").inc()
                        logger.warning("slack_alert_failed", status=resp.status_code, body=resp.text[:200])
            except Exception as e:
                alerts_failed_total.labels(channel="slack", error_type="exception").inc()
                logger.error("slack_alert_error", error=str(e))

        # ---- Telegram Bot API ----
        tg_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        tg_channel = os.getenv("TELEGRAM_CHANNEL_ID", "")
        if tg_token and tg_channel:
            try:
                import httpx
                message = (
                    f"{emoji} <b>{severity} ALERT</b>\n\n"
                    f"<b>{title}</b>\n\n"
                    f"<b>Chains:</b> {chains}\n"
                    f"<b>Exposure:</b> {loss_str}\n"
                    f"<b>ID:</b> <code>{incident_id[:24]}</code>\n\n"
                    f"{summary[:400]}"
                )
                url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
                payload = {
                    "chat_id": tg_channel,
                    "text": message,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                }
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 200:
                        alerts_sent_total.labels(channel="telegram", severity=severity).inc()
                        logger.info("telegram_alert_sent", incident_id=incident_id, severity=severity)
                    else:
                        alerts_failed_total.labels(channel="telegram", error_type=f"http_{resp.status_code}").inc()
                        logger.warning("telegram_alert_failed", status=resp.status_code, body=resp.text[:200])
            except Exception as e:
                alerts_failed_total.labels(channel="telegram", error_type="exception").inc()
                logger.error("telegram_alert_error", error=str(e))

    async def detection_loop(self):
        """Loop B: Consume events from bus and process."""
        logger.info("detection_loop_started")
        
        # Import database service for event persistence
        from src.database.service import DatabaseService
        
        while self.running:
            try:
                # Consume batch of events
                messages = await self.bus.consume(
                    batch_size=BATCH_SIZE,
                    timeout_seconds=PROCESSING_TIMEOUT_SECONDS
                )
                
                if not messages:
                    # Sleep briefly to avoid tight loop when queue is empty
                    await asyncio.sleep(0.5)
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
                        
                        # Rule evaluation happens in _save_event_to_db handler only
                        # (removed duplicate evaluation here to prevent velocity counter inflation)

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

        # Signal readiness as soon as core init completes — before optional subsystems
        global is_ready
        is_ready = True
        logger.info("worker_ready", ready=True)

        # Start ingestion and detection loops
        ingestion_task = asyncio.create_task(self.ingestion_loop())
        detection_task = asyncio.create_task(self.detection_loop())

        # Start non-EVM listener tasks
        non_evm_tasks = []
        for chain_id, listener in getattr(self, 'non_evm_listeners', {}).items():
            task = asyncio.create_task(self._run_non_evm_listener(chain_id, listener))
            non_evm_tasks.append(task)
        if non_evm_tasks:
            logger.info("non_evm_ingestion_started", count=len(non_evm_tasks))

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
                        from src.models.events import Severity
                        import uuid
                        import json
                        
                        contract = analysis.contract
                        event_id = str(uuid.uuid4())
                        
                        # Map threat category to severity using BOTH risk_score AND confidence
                        # risk_score is 0-1 (combined ML + scanner)
                        # Must match incident-creation thresholds to avoid inflated DB counts
                        severity = Severity.INFO
                        if analysis.is_threat:
                            rs = analysis.risk_score
                            conf = analysis.confidence
                            if rs >= 0.80 and conf >= 0.85:
                                severity = Severity.CRITICAL
                            elif rs >= 0.65 and conf >= 0.70:
                                severity = Severity.HIGH
                            elif rs >= 0.50 and conf >= 0.55:
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
                                "risk_score": round(analysis.risk_score, 4),
                                "confidence": round(analysis.confidence, 4),
                                "is_threat": analysis.is_threat,
                                "alerts": analysis.alerts,
                                "bytecode_size": contract.bytecode_length,
                                "source": "continuous_learning",
                                "severity": severity.name,
                            })
                        }
                        
                        await DatabaseService.save_events_batch([event_data])
                        logger.info("continuous_learning_contract_saved", chain=contract.chain, address=contract.address[:20], is_threat=analysis.is_threat)
                        
                        # AUTO-CREATE INCIDENT FOR THREATS
                        # Apply ML-based TP filtering to reduce false positives
                        
                        # Confidence thresholds for incident creation
                        MIN_CONFIDENCE_FOR_INCIDENT = 0.50  # 50% minimum (raised from 25%)

                        # Only process threats
                        if not analysis.is_threat:
                            return  # Not a threat, skip incident creation

                        # Filter out low-confidence detections
                        if analysis.confidence < MIN_CONFIDENCE_FOR_INCIDENT:
                            logger.info(
                                "ml_threat_filtered_low_confidence",
                                chain=contract.chain,
                                contract=contract.address[:20],
                                confidence=f"{analysis.confidence:.1%}",
                                threat_category=analysis.threat_category,
                                reason="Below minimum confidence threshold"
                            )
                            return  # Skip incident creation

                        # Filter out 'unknown_threat' with low confidence (likely FP)
                        if analysis.threat_category == "unknown_threat" and analysis.confidence < 0.70:
                            logger.info(
                                "ml_threat_filtered_unknown",
                                chain=contract.chain,
                                contract=contract.address[:20],
                                confidence=f"{analysis.confidence:.1%}",
                                reason="Unknown threat with low confidence"
                            )
                            return  # Skip incident creation

                        # Adjust severity based on confidence AND risk score
                        # risk_score is 0-1 (combined ML + scanner from auto_collector)
                        rs = analysis.risk_score
                        conf = analysis.confidence
                        if rs >= 0.80 and conf >= 0.85:
                            severity = Severity.CRITICAL
                        elif rs >= 0.65 and conf >= 0.70:
                            severity = Severity.HIGH
                        elif rs >= 0.50 and conf >= 0.55:
                            severity = Severity.MEDIUM
                        else:
                            severity = Severity.LOW
                        
                        # Only create incidents for MEDIUM+ severity
                        if severity not in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                            logger.info(
                                "ml_threat_filtered_low_severity",
                                chain=contract.chain,
                                contract=contract.address[:20],
                                severity=severity.name,
                                confidence=f"{analysis.confidence:.1%}"
                            )
                            return  # Skip incident creation
                        
                        # Passed all filters - create incident
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
                                "governance_attack": "Governance Attack",
                                "bridge_exploit": "Bridge Exploit",
                            }
                            attack_type = threat_to_attack.get(analysis.threat_category, f"Malicious Contract ({analysis.threat_category})")
                            
                            # Build incident data
                            incident_data = {
                                "incident_id": incident_id,
                                "title": f"[{severity.name}] {attack_type} Detected on {contract.chain.title()}",
                                "summary": f"ML Contract Scanner detected a potentially malicious contract deployment. "
                                           f"Contract {contract.address} deployed by {contract.deployer or 'unknown'} "
                                           f"has been classified as '{analysis.threat_category}' with {analysis.confidence:.1%} confidence "
                                           f"and risk score of {analysis.risk_score * 100:.0f}/100.",
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
        
        # Start periodic feedback loop evaluation (every 5 min)
        async def feedback_loop_evaluation():
            """Periodically evaluate rules and auto-suppress/unsuppress based on FP rates."""
            try:
                from src.rules.feedback_loop import get_feedback_loop
                fl = get_feedback_loop()
            except Exception as e:
                logger.warning("feedback_loop_task_disabled", error=str(e))
                return

            while self.running:
                await asyncio.sleep(300)  # 5 minutes
                try:
                    actions = fl.evaluate_rules()
                    non_healthy = [a for a in actions if a[1] != "healthy"]
                    if non_healthy:
                        logger.info(
                            "feedback_loop_evaluation",
                            actions=[f"{a[0]}:{a[1]}({a[2]:.0%})" for a in non_healthy],
                        )
                except Exception as e:
                    logger.warning("feedback_loop_evaluation_error", error=str(e))

        feedback_task = asyncio.create_task(feedback_loop_evaluation())

        # Start periodic data retention/cleanup (runs every 6 hours)
        async def data_retention_job():
            """Delete events older than retention period to prevent unbounded DB growth."""
            retention_days = int(os.getenv("EVENT_RETENTION_DAYS", "90"))
            incident_retention_days = int(os.getenv("INCIDENT_RETENTION_DAYS", "365"))
            interval_hours = int(os.getenv("RETENTION_INTERVAL_HOURS", "6"))

            # Wait 5 minutes after startup before first run
            await asyncio.sleep(300)

            while self.running:
                try:
                    from src.database.service import DatabaseService

                    # Clean old events
                    events_deleted = await DatabaseService.cleanup_old_events(days=retention_days)
                    if events_deleted > 0:
                        logger.info(
                            "retention_events_cleaned",
                            deleted=events_deleted,
                            retention_days=retention_days,
                        )

                    # Clean old resolved incidents
                    try:
                        from src.database.models import IncidentModel
                        from sqlalchemy import delete as sa_delete
                        from src.database.connection import DatabaseManager

                        cutoff = datetime.now(timezone.utc) - timedelta(days=incident_retention_days)
                        async with DatabaseManager.get_session() as session:
                            stmt = sa_delete(IncidentModel).where(
                                IncidentModel.created_at < cutoff,
                                IncidentModel.status.in_(["RESOLVED", "FALSE_POSITIVE", "CLOSED"]),
                            )
                            result = await session.execute(stmt)
                            incidents_deleted = result.rowcount
                            if incidents_deleted > 0:
                                logger.info(
                                    "retention_incidents_cleaned",
                                    deleted=incidents_deleted,
                                    retention_days=incident_retention_days,
                                )
                    except Exception as e:
                        logger.warning("incident_retention_error", error=str(e))

                except Exception as e:
                    logger.warning("data_retention_error", error=str(e))

                await asyncio.sleep(interval_hours * 3600)

        retention_task = asyncio.create_task(data_retention_job())

        logger.info("worker_started", health_port=WORKER_HEALTH_PORT, runtime_enabled=self.runtime_enabled, continuous_learning=continuous_learning_enabled)

        # Wait for tasks
        tasks = [ingestion_task, detection_task, uptime_task, feedback_task, retention_task] + non_evm_tasks
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
        cb_stats = worker_instance.circuit_breaker.get_stats() if hasattr(worker_instance, 'circuit_breaker') else {}
        connected = [cid for cid, l in worker_instance.listeners.items() if l and l.w3] if worker_instance.listeners else []
        return web.json_response({
            "status": "healthy",
            "ready": True,
            "uptime_seconds": uptime,
            "chains_monitored": len(worker_instance.listeners) if worker_instance.listeners else 0,
            "chains_connected": len(connected),
            "bus_type": type(worker_instance.bus).__name__ if worker_instance.bus else "none",
            "circuit_breakers": cb_stats,
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
    # aiohttp rejects charset in content_type — strip it
    ct = CONTENT_TYPE_LATEST.split(";")[0]
    return Response(
        body=generate_latest(),
        content_type=ct
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
    
    # Handle graceful shutdown via event loop signal handlers
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def signal_handler():
        print("[WORKER] Shutdown signal received", flush=True)
        logger.info("signal_received")
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)
    
    try:
        # STEP 1: Create and bind HTTP server IMMEDIATELY (no blocking operations before this)
        print("[WORKER] Creating aiohttp application...", flush=True)
        logger.info("binding_health_server", port=WORKER_HEALTH_PORT, port_env=os.getenv("PORT"))
        
        app = web.Application()
        
        # API routes
        app.router.add_get("/", root_handler)
        app.router.add_get("/health", health_handler)
        app.router.add_get("/metrics", metrics_handler)
        
        print("[WORKER] Setting up AppRunner...", flush=True)
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
        print("[WORKER] Starting background initialization...", flush=True)
        init_task = asyncio.create_task(background_init())
        
        # STEP 3: Keep server running forever
        print("[WORKER] Health server is running. Waiting for initialization...", flush=True)
        try:
            # Wait for initialization to complete (or fail) - but don't block server
            await asyncio.wait_for(init_task, timeout=None)
        except asyncio.TimeoutError:
            print("[WORKER] Initialization timeout (this shouldn't happen)", flush=True)
        except Exception as e:
            print(f"[WORKER] Initialization error: {e}", flush=True)
            logger.error("unexpected_error_in_main", error=str(e), exc_info=True)
        
        # Keep server running even if init fails
        print("[WORKER] Server will continue running for health checks", flush=True)
        logger.info("health_server_running")

        # Wait until shutdown signal
        await shutdown_event.wait()

        # Graceful drain: let in-flight work finish
        print("[WORKER] Draining in-flight work (30s timeout)...", flush=True)
        if worker_instance:
            try:
                await asyncio.wait_for(worker_instance.stop(), timeout=25.0)
                print("[WORKER] Worker drained successfully", flush=True)
            except asyncio.TimeoutError:
                print("[WORKER] Drain timeout — forcing shutdown", flush=True)
                logger.warning("drain_timeout")
            
    except Exception as e:
        # Critical error - log and re-raise so Cloud Run sees the failure
        print(f"[WORKER] CRITICAL ERROR: {e}", flush=True)
        import traceback
        traceback.print_exc()
        logger.error("critical_startup_error", error=str(e), exc_info=True)
        raise
    finally:
        print("[WORKER] Shutting down...", flush=True)
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
