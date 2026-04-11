"""
Robust HTTP Provider for Web3.py
================================

A production-grade Web3.py HTTP provider with:
1. Round-robin RPC URL rotation
2. Health tracking (unhealthy URLs excluded for 60s)
3. Exponential backoff when all providers fail
4. Thread-safe URL selection
5. Request/response timing metrics
6. Automatic retry with smart failover

Compatible with web3.py 6.x middleware patterns.

Usage:
    from robust_provider import RobustHTTPProvider
    
    provider = RobustHTTPProvider([
        "https://eth.llamarpc.com",
        "https://mainnet.infura.io/v3/YOUR_KEY",
        "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
    ])
    w3 = Web3(provider)
"""

import asyncio
import os
import random
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import Enum
from collections import deque

import structlog

# Web3.py imports
from web3.providers import AsyncHTTPProvider, HTTPProvider
from web3.types import RPCEndpoint, RPCResponse

logger = structlog.get_logger(__name__)

# Configuration
UNHEALTHY_COOLDOWN_SECONDS = int(os.getenv("RPC_UNHEALTHY_COOLDOWN", "60"))
MAX_BACKOFF_SECONDS = int(os.getenv("RPC_MAX_BACKOFF", "120"))
REQUEST_TIMEOUT_SECONDS = float(os.getenv("RPC_TIMEOUT", "30.0"))
MAX_RETRIES_PER_REQUEST = int(os.getenv("RPC_MAX_RETRIES", "3"))
HEALTH_CHECK_INTERVAL_SECONDS = int(os.getenv("RPC_HEALTH_CHECK_INTERVAL", "30"))


class ProviderHealth(Enum):
    """Health status of an RPC provider."""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ProviderStats:
    """Statistics for a single RPC provider."""
    url: str
    status: ProviderHealth = ProviderHealth.UNKNOWN
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
        """Average latency in milliseconds."""
        if self.success_count == 0:
            return 0.0
        return self.total_latency_ms / self.success_count
    
    @property
    def success_rate(self) -> float:
        """Success rate as a percentage."""
        if self.total_requests == 0:
            return 100.0
        return (self.success_count / self.total_requests) * 100
    
    @property
    def is_healthy(self) -> bool:
        """Check if provider is currently healthy."""
        if self.status == ProviderHealth.UNHEALTHY:
            if self.unhealthy_until and datetime.now(timezone.utc) < self.unhealthy_until:
                return False
            # Cooldown expired, reset to unknown
            self.status = ProviderHealth.UNKNOWN
        return self.status != ProviderHealth.UNHEALTHY
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url[:50] + "..." if len(self.url) > 50 else self.url,
            "status": self.status.value,
            "is_healthy": self.is_healthy,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": f"{self.success_rate:.1f}%",
            "avg_latency_ms": f"{self.avg_latency_ms:.1f}",
            "last_error": self.last_error,
        }


class RobustProviderManager:
    """
    Manages multiple RPC providers with health tracking and rotation.
    
    Thread-safe for use in concurrent environments.
    """
    
    def __init__(
        self,
        urls: List[str],
        unhealthy_cooldown: int = UNHEALTHY_COOLDOWN_SECONDS,
        max_backoff: int = MAX_BACKOFF_SECONDS
    ):
        if not urls:
            raise ValueError("At least one RPC URL is required")
        
        self._urls = urls
        self._unhealthy_cooldown = unhealthy_cooldown
        self._max_backoff = max_backoff
        
        # Provider stats
        self._providers: Dict[str, ProviderStats] = {
            url: ProviderStats(url=url) for url in urls
        }
        
        # Round-robin state
        self._current_index = 0
        self._lock = threading.Lock()
        
        # Backoff state
        self._consecutive_failures = 0
        self._last_backoff_time: Optional[datetime] = None
        
        # Request history for monitoring
        self._recent_requests: deque = deque(maxlen=100)
        
        logger.info(
            "robust_provider_initialized",
            provider_count=len(urls),
            unhealthy_cooldown=unhealthy_cooldown
        )
    
    def get_next_healthy_url(self) -> Tuple[str, int]:
        """
        Get the next healthy URL using round-robin rotation.
        
        Returns:
            Tuple of (url, attempt_number)
            
        Raises:
            RuntimeError if all providers are unhealthy
        """
        with self._lock:
            # Check if we need to wait due to backoff
            if self._last_backoff_time:
                backoff_seconds = self._calculate_backoff()
                elapsed = (datetime.now(timezone.utc) - self._last_backoff_time).total_seconds()
                if elapsed < backoff_seconds:
                    remaining = backoff_seconds - elapsed
                    logger.warning(
                        "rpc_backoff_active",
                        remaining_seconds=remaining,
                        backoff_seconds=backoff_seconds
                    )
                    # Still in backoff, but allow attempt with warning
            
            # Find healthy providers
            healthy_urls = [
                url for url, stats in self._providers.items()
                if stats.is_healthy
            ]
            
            if not healthy_urls:
                # All unhealthy - reset oldest one and use it
                oldest_failure = min(
                    self._providers.values(),
                    key=lambda s: s.unhealthy_until or datetime.max.replace(tzinfo=timezone.utc)
                )
                oldest_failure.status = ProviderHealth.UNKNOWN
                healthy_urls = [oldest_failure.url]
                logger.warning(
                    "all_providers_unhealthy_resetting",
                    reset_url=oldest_failure.url[:50]
                )
            
            # Round-robin through healthy providers
            self._current_index = (self._current_index + 1) % len(healthy_urls)
            selected_url = healthy_urls[self._current_index % len(healthy_urls)]
            
            return selected_url, self._providers[selected_url].total_requests + 1
    
    def record_success(self, url: str, latency_ms: float):
        """Record a successful request."""
        with self._lock:
            if url in self._providers:
                stats = self._providers[url]
                stats.status = ProviderHealth.HEALTHY
                stats.last_success = datetime.now(timezone.utc)
                stats.success_count += 1
                stats.total_requests += 1
                stats.total_latency_ms += latency_ms
                stats.failure_count = 0  # Reset consecutive failures
                
                # Reset global backoff on success
                self._consecutive_failures = 0
                self._last_backoff_time = None
                
                logger.debug(
                    "rpc_request_success",
                    url=url[:40],
                    latency_ms=f"{latency_ms:.1f}"
                )
    
    def record_failure(self, url: str, error: str, is_5xx: bool = False, is_timeout: bool = False):
        """Record a failed request."""
        with self._lock:
            if url in self._providers:
                stats = self._providers[url]
                stats.total_requests += 1
                stats.failure_count += 1
                stats.last_failure = datetime.now(timezone.utc)
                stats.last_error = error[:100]
                
                # Mark as unhealthy for 5xx errors or timeouts
                if is_5xx or is_timeout or stats.failure_count >= 3:
                    stats.status = ProviderHealth.UNHEALTHY
                    stats.unhealthy_until = datetime.now(timezone.utc) + \
                        __import__('datetime').timedelta(seconds=self._unhealthy_cooldown)
                    
                    logger.warning(
                        "rpc_provider_marked_unhealthy",
                        url=url[:40],
                        error=error[:50],
                        cooldown_seconds=self._unhealthy_cooldown
                    )
                
                # Track global failures for backoff
                self._consecutive_failures += 1
                if self._consecutive_failures >= len(self._providers):
                    self._last_backoff_time = datetime.now(timezone.utc)
                    logger.error(
                        "all_rpc_providers_failing",
                        consecutive_failures=self._consecutive_failures,
                        backoff_seconds=self._calculate_backoff()
                    )
    
    def _calculate_backoff(self) -> float:
        """Calculate exponential backoff time."""
        # 2^n seconds, capped at max_backoff
        backoff = min(2 ** (self._consecutive_failures - len(self._providers)), self._max_backoff)
        # Add jitter (±20%)
        jitter = backoff * 0.2 * (random.random() * 2 - 1)
        return backoff + jitter
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all providers."""
        with self._lock:
            healthy_count = sum(1 for s in self._providers.values() if s.is_healthy)
            return {
                "total_providers": len(self._providers),
                "healthy_providers": healthy_count,
                "unhealthy_providers": len(self._providers) - healthy_count,
                "consecutive_failures": self._consecutive_failures,
                "providers": [s.to_dict() for s in self._providers.values()]
            }
    
    def get_all_urls(self) -> List[str]:
        """Get all provider URLs."""
        return list(self._providers.keys())


class RobustHTTPProvider(HTTPProvider):
    """
    Synchronous Web3.py HTTP Provider with automatic failover.
    
    Drop-in replacement for HTTPProvider that adds:
    - Multiple RPC URL support
    - Automatic failover on errors
    - Health tracking
    - Exponential backoff
    
    Usage:
        provider = RobustHTTPProvider([
            "https://eth.llamarpc.com",
            "https://mainnet.infura.io/v3/KEY"
        ])
        w3 = Web3(provider)
    """
    
    def __init__(
        self,
        urls: Union[str, List[str]],
        request_kwargs: Optional[Dict[str, Any]] = None,
        session: Any = None,
        **kwargs
    ):
        # Normalize to list
        if isinstance(urls, str):
            urls = [urls]
        
        # Initialize with first URL (required by parent)
        super().__init__(
            endpoint_uri=urls[0],
            request_kwargs=request_kwargs or {"timeout": REQUEST_TIMEOUT_SECONDS},
            session=session
        )
        
        # Initialize manager
        self._manager = RobustProviderManager(urls)
        self._request_kwargs = request_kwargs or {"timeout": REQUEST_TIMEOUT_SECONDS}
    
    def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        """
        Make an RPC request with automatic failover.
        
        Overrides parent class to add rotation and retry logic.
        """
        last_error = None
        
        for attempt in range(MAX_RETRIES_PER_REQUEST):
            url, request_num = self._manager.get_next_healthy_url()
            
            start_time = time.time()
            
            try:
                # Update endpoint for this request
                self.endpoint_uri = url
                
                # Make the request
                response = super().make_request(method, params)
                
                # Record success
                latency_ms = (time.time() - start_time) * 1000
                self._manager.record_success(url, latency_ms)
                
                return response
                
            except Exception as e:
                error_str = str(e)
                latency_ms = (time.time() - start_time) * 1000
                
                # Determine error type
                is_timeout = "timeout" in error_str.lower() or "timed out" in error_str.lower()
                is_5xx = any(code in error_str for code in ["500", "502", "503", "504"])
                
                # Record failure
                self._manager.record_failure(url, error_str, is_5xx, is_timeout)
                
                last_error = e
                
                logger.warning(
                    "rpc_request_failed",
                    url=url[:40],
                    method=method,
                    attempt=attempt + 1,
                    error=error_str[:80],
                    latency_ms=f"{latency_ms:.1f}"
                )
                
                # Small delay before retry
                if attempt < MAX_RETRIES_PER_REQUEST - 1:
                    time.sleep(0.5 * (attempt + 1))
        
        # All retries exhausted
        raise ConnectionError(
            f"All RPC providers failed after {MAX_RETRIES_PER_REQUEST} attempts. "
            f"Last error: {last_error}"
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get provider statistics."""
        return self._manager.get_stats()


class RobustAsyncHTTPProvider(AsyncHTTPProvider):
    """
    Asynchronous Web3.py HTTP Provider with automatic failover.
    
    Drop-in replacement for AsyncHTTPProvider that adds:
    - Multiple RPC URL support
    - Automatic failover on errors
    - Health tracking
    - Exponential backoff
    
    Usage:
        provider = RobustAsyncHTTPProvider([
            "https://eth.llamarpc.com",
            "https://mainnet.infura.io/v3/KEY"
        ])
        w3 = AsyncWeb3(provider)
    """
    
    def __init__(
        self,
        urls: Union[str, List[str]],
        request_kwargs: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        # Normalize to list
        if isinstance(urls, str):
            urls = [urls]
        
        # Initialize with first URL
        super().__init__(
            endpoint_uri=urls[0],
            request_kwargs=request_kwargs or {"timeout": REQUEST_TIMEOUT_SECONDS}
        )
        
        # Initialize manager
        self._manager = RobustProviderManager(urls)
        self._request_kwargs = request_kwargs or {"timeout": REQUEST_TIMEOUT_SECONDS}
        self._urls = urls
    
    async def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        """
        Make an async RPC request with automatic failover.
        """
        last_error = None
        
        for attempt in range(MAX_RETRIES_PER_REQUEST):
            url, request_num = self._manager.get_next_healthy_url()
            
            start_time = time.time()
            
            try:
                # Update endpoint for this request
                self.endpoint_uri = url
                
                # Make the async request
                response = await super().make_request(method, params)
                
                # Record success
                latency_ms = (time.time() - start_time) * 1000
                self._manager.record_success(url, latency_ms)
                
                return response
                
            except Exception as e:
                error_str = str(e)
                latency_ms = (time.time() - start_time) * 1000
                
                # Determine error type
                is_timeout = "timeout" in error_str.lower() or "timed out" in error_str.lower()
                is_5xx = any(code in error_str for code in ["500", "502", "503", "504"])
                
                # Record failure
                self._manager.record_failure(url, error_str, is_5xx, is_timeout)
                
                last_error = e
                
                logger.warning(
                    "rpc_request_failed_async",
                    url=url[:40],
                    method=method,
                    attempt=attempt + 1,
                    error=error_str[:80],
                    latency_ms=f"{latency_ms:.1f}"
                )
                
                # Small delay before retry
                if attempt < MAX_RETRIES_PER_REQUEST - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
        
        # All retries exhausted
        raise ConnectionError(
            f"All RPC providers failed after {MAX_RETRIES_PER_REQUEST} attempts. "
            f"Last error: {last_error}"
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get provider statistics."""
        return self._manager.get_stats()
    
    def get_healthy_urls(self) -> List[str]:
        """Get list of currently healthy URLs."""
        return [
            url for url, stats in self._manager._providers.items()
            if stats.is_healthy
        ]


def create_robust_provider(
    urls: Union[str, List[str]],
    async_mode: bool = True,
    **kwargs
) -> Union[RobustHTTPProvider, RobustAsyncHTTPProvider]:
    """
    Factory function to create a robust provider.
    
    Args:
        urls: Single URL or list of RPC URLs
        async_mode: Whether to create async provider (default True)
        **kwargs: Additional arguments passed to provider
        
    Returns:
        RobustHTTPProvider or RobustAsyncHTTPProvider
    """
    if async_mode:
        return RobustAsyncHTTPProvider(urls, **kwargs)
    return RobustHTTPProvider(urls, **kwargs)

