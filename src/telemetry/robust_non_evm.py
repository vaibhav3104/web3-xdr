"""
Robust Non-EVM Provider Base
============================

Provides a robust base class for non-EVM chain listeners (Cosmos, Aptos, Sui, Near)
with the same resilience features as the EVM RobustHTTPProvider:

1. Multi-RPC URL failover
2. Health tracking per endpoint
3. Exponential backoff
4. Heartbeat logging
5. Auto-reconnection
6. Graceful session management

Usage:
    class MyChainListener(RobustNonEVMListener):
        async def _make_request(self, method, params):
            # Implement chain-specific request logic
            pass
            
        async def _process_block(self, height):
            # Implement chain-specific block processing
            pass
"""

import asyncio
import os
import random
import time
from abc import abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, AsyncGenerator
from enum import Enum

import structlog
import aiohttp

from .base import ChainListener, ListenerConfig
from ..models.events import SecurityEvent

logger = structlog.get_logger(__name__)

# Configuration
UNHEALTHY_COOLDOWN_SECONDS = int(os.getenv("RPC_UNHEALTHY_COOLDOWN", "60"))
MAX_BACKOFF_SECONDS = int(os.getenv("RPC_MAX_BACKOFF", "120"))
REQUEST_TIMEOUT_SECONDS = float(os.getenv("RPC_TIMEOUT", "30.0"))
MAX_RETRIES_PER_REQUEST = int(os.getenv("RPC_MAX_RETRIES", "3"))
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("HEARTBEAT_INTERVAL", "60"))


class EndpointHealth(Enum):
    """Health status of an RPC endpoint."""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class EndpointStats:
    """Statistics for a single RPC endpoint."""
    url: str
    status: EndpointHealth = EndpointHealth.UNKNOWN
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    failure_count: int = 0
    success_count: int = 0
    total_requests: int = 0
    total_latency_ms: float = 0.0
    unhealthy_until: Optional[datetime] = None
    last_error: Optional[str] = None
    
    @property
    def avg_latency_ms(self) -> float:
        if self.success_count == 0:
            return 0.0
        return self.total_latency_ms / self.success_count
    
    @property
    def is_healthy(self) -> bool:
        if self.status == EndpointHealth.UNHEALTHY:
            if self.unhealthy_until and datetime.now(timezone.utc) < self.unhealthy_until:
                return False
            self.status = EndpointHealth.UNKNOWN
        return self.status != EndpointHealth.UNHEALTHY


@dataclass
class NonEVMConfig(ListenerConfig):
    """Extended config for non-EVM chains with failover support."""
    # Override rpc_url with default to make it optional
    rpc_url: str = ""
    rpc_urls: List[str] = field(default_factory=list)
    fallback_rpcs: List[str] = field(default_factory=list)
    ws_urls: List[str] = field(default_factory=list)
    heartbeat_interval: int = HEARTBEAT_INTERVAL_SECONDS
    
    def get_all_rpc_urls(self) -> List[str]:
        """Get all RPC URLs including fallbacks."""
        urls = []
        if self.rpc_url:
            urls.append(self.rpc_url)
        urls.extend(self.rpc_urls)
        urls.extend(self.fallback_rpcs)
        seen = set()
        return [x for x in urls if not (x in seen or seen.add(x))]


class RobustNonEVMListener(ChainListener):
    """
    Abstract base class for robust non-EVM chain listeners.
    
    Provides:
    - Multi-RPC failover with health tracking
    - Automatic reconnection
    - Heartbeat logging for monitoring
    - Graceful session management
    - Exponential backoff on failures
    
    Subclasses must implement:
    - _make_chain_request(url, method, params) - Chain-specific RPC call
    - _get_latest_block_height() - Get current block/version
    - _process_block(height) - Process a single block
    """
    
    def __init__(self, config: NonEVMConfig):
        super().__init__(config)
        self.config: NonEVMConfig = config
        
        # RPC endpoints with health tracking
        self._rpc_urls: List[str] = config.get_all_rpc_urls()
        self._endpoints: Dict[str, EndpointStats] = {
            url: EndpointStats(url=url) for url in self._rpc_urls
        }
        self._current_url_index = 0
        
        # HTTP session
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()
        
        # State
        self._connected = False
        self._running = False
        self.latest_height = 0
        
        # Heartbeat
        self._last_heartbeat = datetime.now(timezone.utc)
        self._events_since_heartbeat = 0
        self._blocks_since_heartbeat = 0
        
        # Backoff state
        self._consecutive_failures = 0
        self._last_backoff_time: Optional[datetime] = None
        
        logger.info(
            "robust_non_evm_listener_initialized",
            chain_id=self.chain_id,
            rpc_count=len(self._rpc_urls),
            primary_rpc=self._rpc_urls[0][:50] + "..." if self._rpc_urls else "none"
        )
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with proper lifecycle management."""
        async with self._session_lock:
            if self._session is None or self._session.closed:
                timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
                self._session = aiohttp.ClientSession(timeout=timeout)
            return self._session
    
    async def _close_session(self):
        """Close HTTP session gracefully."""
        async with self._session_lock:
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None
    
    def _get_next_healthy_url(self) -> Tuple[str, int]:
        """Get next healthy RPC URL using round-robin."""
        healthy_urls = [
            url for url, stats in self._endpoints.items()
            if stats.is_healthy
        ]
        
        if not healthy_urls:
            # All unhealthy - reset oldest
            oldest = min(
                self._endpoints.values(),
                key=lambda s: s.unhealthy_until or datetime.max.replace(tzinfo=timezone.utc)
            )
            oldest.status = EndpointHealth.UNKNOWN
            healthy_urls = [oldest.url]
            logger.warning(
                "all_endpoints_unhealthy_resetting",
                chain=self.chain_id,
                reset_url=oldest.url[:40]
            )
        
        self._current_url_index = (self._current_url_index + 1) % len(healthy_urls)
        selected = healthy_urls[self._current_url_index]
        return selected, self._endpoints[selected].total_requests + 1
    
    def _record_success(self, url: str, latency_ms: float):
        """Record successful request."""
        if url in self._endpoints:
            stats = self._endpoints[url]
            stats.status = EndpointHealth.HEALTHY
            stats.last_success = datetime.now(timezone.utc)
            stats.success_count += 1
            stats.total_requests += 1
            stats.total_latency_ms += latency_ms
            stats.failure_count = 0
            
            self._consecutive_failures = 0
            self._last_backoff_time = None
    
    def _record_failure(self, url: str, error: str, is_5xx: bool = False, is_timeout: bool = False):
        """Record failed request."""
        if url in self._endpoints:
            stats = self._endpoints[url]
            stats.total_requests += 1
            stats.failure_count += 1
            stats.last_failure = datetime.now(timezone.utc)
            stats.last_error = error[:100]
            
            if is_5xx or is_timeout or stats.failure_count >= 3:
                stats.status = EndpointHealth.UNHEALTHY
                stats.unhealthy_until = datetime.now(timezone.utc) + timedelta(
                    seconds=UNHEALTHY_COOLDOWN_SECONDS
                )
                logger.warning(
                    "rpc_endpoint_marked_unhealthy",
                    chain=self.chain_id,
                    url=url[:40],
                    error=error[:50],
                    cooldown=UNHEALTHY_COOLDOWN_SECONDS
                )
            
            self._consecutive_failures += 1
            if self._consecutive_failures >= len(self._endpoints):
                self._last_backoff_time = datetime.now(timezone.utc)
    
    def _calculate_backoff(self) -> float:
        """Calculate exponential backoff time."""
        backoff = min(
            2 ** (self._consecutive_failures - len(self._endpoints)),
            MAX_BACKOFF_SECONDS
        )
        jitter = backoff * 0.2 * (random.random() * 2 - 1)
        return backoff + jitter
    
    async def _make_request(
        self,
        method: str,
        params: Any = None,
        is_json_rpc: bool = False
    ) -> Optional[Dict]:
        """
        Make an RPC request with automatic failover.
        
        Args:
            method: RPC method or endpoint path
            params: Request parameters
            is_json_rpc: If True, use JSON-RPC format
            
        Returns:
            Response data or None on failure
        """
        last_error = None
        
        for attempt in range(MAX_RETRIES_PER_REQUEST):
            url, _ = self._get_next_healthy_url()
            start_time = time.time()
            
            try:
                session = await self._get_session()
                result = await self._make_chain_request(session, url, method, params, is_json_rpc)
                
                latency_ms = (time.time() - start_time) * 1000
                self._record_success(url, latency_ms)
                
                return result
                
            except asyncio.TimeoutError:
                latency_ms = (time.time() - start_time) * 1000
                self._record_failure(url, "Request timeout", is_timeout=True)
                last_error = "timeout"
                
            except aiohttp.ClientError as e:
                latency_ms = (time.time() - start_time) * 1000
                error_str = str(e)
                is_5xx = any(code in error_str for code in ["500", "502", "503", "504"])
                self._record_failure(url, error_str, is_5xx=is_5xx)
                last_error = error_str
                
            except Exception as e:
                latency_ms = (time.time() - start_time) * 1000
                self._record_failure(url, str(e))
                last_error = str(e)
            
            logger.warning(
                "non_evm_request_failed",
                chain=self.chain_id,
                url=url[:40],
                method=method,
                attempt=attempt + 1,
                error=str(last_error)[:60]
            )
            
            if attempt < MAX_RETRIES_PER_REQUEST - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
        
        return None
    
    @abstractmethod
    async def _make_chain_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        params: Any,
        is_json_rpc: bool
    ) -> Optional[Dict]:
        """
        Make chain-specific RPC request.
        
        Must be implemented by subclasses.
        """
        pass
    
    @abstractmethod
    async def _get_latest_block_height(self) -> int:
        """
        Get the latest block height/version for this chain.
        
        Must be implemented by subclasses.
        """
        pass
    
    @abstractmethod
    async def _process_block_impl(self, height: int) -> List[SecurityEvent]:
        """
        Process a single block and return security events.
        
        Must be implemented by subclasses.
        """
        pass
    
    # Implement ChainListener abstract methods
    async def get_latest_block(self) -> int:
        """Get the latest block number (implements ChainListener)."""
        return await self._get_latest_block_height()
    
    async def process_block(self, block_number: int):
        """Process a single block (implements ChainListener)."""
        events = await self._process_block_impl(block_number)
        for event in events:
            await self.emit_event(event)
        return {"events_processed": len(events)}
    
    async def subscribe_to_events(self):
        """Subscribe to events - uses polling by default (implements ChainListener)."""
        async for event in self.listen_events():
            yield event
    
    async def connect(self) -> bool:
        """
        Connect to the chain with automatic failover.
        
        Returns:
            True if connected successfully
        """
        try:
            # Test connection by getting latest block
            height = await self._get_latest_block_height()
            
            if height > 0:
                self.latest_height = height
                self._connected = True
                
                logger.info(
                    "non_evm_connected",
                    chain=self.chain_id,
                    height=height,
                    healthy_endpoints=sum(1 for s in self._endpoints.values() if s.is_healthy),
                    total_endpoints=len(self._endpoints)
                )
                return True
            
        except Exception as e:
            logger.error(
                "non_evm_connection_failed",
                chain=self.chain_id,
                error=str(e)
            )
        
        return False
    
    async def disconnect(self):
        """Disconnect from the chain."""
        self._connected = False
        self._running = False
        await self._close_session()
        logger.info("non_evm_disconnected", chain=self.chain_id)
    
    async def _emit_heartbeat(self):
        """Emit heartbeat log for monitoring."""
        now = datetime.now(timezone.utc)
        elapsed = (now - self._last_heartbeat).total_seconds()
        
        if elapsed >= self.config.heartbeat_interval:
            healthy_count = sum(1 for s in self._endpoints.values() if s.is_healthy)
            
            logger.info(
                "listener_heartbeat",
                chain=self.chain_id,
                height=self.latest_height,
                events_processed=self._events_since_heartbeat,
                blocks_processed=self._blocks_since_heartbeat,
                healthy_endpoints=f"{healthy_count}/{len(self._endpoints)}",
                uptime_seconds=elapsed
            )
            
            self._last_heartbeat = now
            self._events_since_heartbeat = 0
            self._blocks_since_heartbeat = 0
    
    async def listen_events(self) -> AsyncGenerator[SecurityEvent, None]:
        """
        Poll for new blocks and yield security events.
        
        Includes:
        - Automatic reconnection on failure
        - Heartbeat logging
        - Block catch-up on restart
        """
        self._running = True
        poll_interval = getattr(self.config, 'poll_interval_seconds', 2.0)
        
        while self._running and self._connected:
            try:
                # Get latest block
                current_height = await self._get_latest_block_height()
                
                if current_height == 0:
                    # Connection issue - wait and retry
                    logger.warning(
                        "non_evm_poll_no_height",
                        chain=self.chain_id
                    )
                    await asyncio.sleep(5)
                    continue
                
                # Process new blocks
                while self.latest_height < current_height and self._running:
                    self.latest_height += 1
                    
                    try:
                        events = await self._process_block_impl(self.latest_height)
                        self._blocks_since_heartbeat += 1
                        
                        for event in events:
                            self._events_since_heartbeat += 1
                            yield event
                            
                    except Exception as e:
                        logger.error(
                            "non_evm_block_processing_error",
                            chain=self.chain_id,
                            height=self.latest_height,
                            error=str(e)[:80]
                        )
                
                # Emit heartbeat
                await self._emit_heartbeat()
                
                # Wait before next poll
                await asyncio.sleep(poll_interval)
                
            except asyncio.CancelledError:
                logger.info("non_evm_listener_cancelled", chain=self.chain_id)
                break
                
            except Exception as e:
                logger.error(
                    "non_evm_poll_error",
                    chain=self.chain_id,
                    error=str(e)
                )
                await asyncio.sleep(5)
                
                # Try to reconnect
                if not await self.connect():
                    logger.error(
                        "non_evm_reconnection_failed",
                        chain=self.chain_id
                    )
    
    def get_endpoint_stats(self) -> Dict[str, Any]:
        """Get statistics for all endpoints."""
        healthy = sum(1 for s in self._endpoints.values() if s.is_healthy)
        return {
            "chain_id": self.chain_id,
            "total_endpoints": len(self._endpoints),
            "healthy_endpoints": healthy,
            "unhealthy_endpoints": len(self._endpoints) - healthy,
            "latest_height": self.latest_height,
            "connected": self._connected,
            "endpoints": [
                {
                    "url": s.url[:50] + "..." if len(s.url) > 50 else s.url,
                    "status": s.status.value,
                    "success_count": s.success_count,
                    "failure_count": s.failure_count,
                    "avg_latency_ms": f"{s.avg_latency_ms:.1f}",
                    "last_error": s.last_error,
                }
                for s in self._endpoints.values()
            ]
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current listener status."""
        base_status = super().get_status()
        base_status.update({
            "latest_height": self.latest_height,
            "connected": self._connected,
            "running": self._running,
            "healthy_endpoints": sum(1 for s in self._endpoints.values() if s.is_healthy),
            "total_endpoints": len(self._endpoints),
        })
        return base_status

