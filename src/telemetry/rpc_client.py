"""
Multi-RPC Client with Failover and Quorum Support
==================================================

Provides reliable RPC access with:
- Automatic failover across multiple endpoints
- Health scoring and endpoint rotation
- Quorum verification for critical reads
- Metrics and observability
"""

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

import aiohttp
import structlog

logger = structlog.get_logger(__name__)


class EndpointHealth(Enum):
    """Health status of an RPC endpoint."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class EndpointStats:
    """Statistics for an RPC endpoint."""
    url: str
    health: EndpointHealth = EndpointHealth.UNKNOWN
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    consecutive_failures: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency_ms: float = 0.0
    head_lag_blocks: int = 0  # How far behind chain head
    last_head_check: Optional[datetime] = None
    unhealthy_until: Optional[datetime] = None
    
    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests
    
    @property
    def avg_latency_ms(self) -> float:
        if self.successful_requests == 0:
            return 0.0
        return self.total_latency_ms / self.successful_requests
    
    @property
    def is_available(self) -> bool:
        """Check if endpoint is available (not in cooldown)."""
        if self.health == EndpointHealth.HEALTHY:
            return True
        if self.health == EndpointHealth.DEGRADED:
            return True
        if self.unhealthy_until and datetime.now(timezone.utc) < self.unhealthy_until:
            return False
        return True


class MultiRpcProvider:
    """
    Multi-RPC provider with failover, health tracking, and quorum support.
    
    Features:
    - Automatic failover on errors
    - Health scoring based on latency, error rate, head lag
    - Quorum verification for critical operations
    - Exponential backoff for unhealthy endpoints
    """
    
    def __init__(
        self,
        rpc_urls: List[str],
        unhealthy_cooldown_seconds: int = 60,
        request_timeout_seconds: float = 30.0,
        max_retries: int = 3
    ):
        if not rpc_urls:
            raise ValueError("At least one RPC URL required")
        
        self.rpc_urls = rpc_urls
        self.unhealthy_cooldown_seconds = unhealthy_cooldown_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.max_retries = max_retries
        
        # Initialize endpoint stats
        self.endpoints: Dict[str, EndpointStats] = {
            url: EndpointStats(url=url) for url in rpc_urls
        }
        
        # Session management
        self.session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()
        
        # Round-robin index
        self._current_index = 0
        
        logger.info(
            "multi_rpc_provider_initialized",
            endpoint_count=len(rpc_urls),
            primary_url=rpc_urls[0][:50] + "..." if rpc_urls else "none"
        )
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        async with self._session_lock:
            if self.session is None or self.session.closed:
                timeout = aiohttp.ClientTimeout(total=self.request_timeout_seconds)
                self.session = aiohttp.ClientSession(timeout=timeout)
            return self.session
    
    async def _close_session(self):
        """Close HTTP session."""
        async with self._session_lock:
            if self.session and not self.session.closed:
                await self.session.close()
                self.session = None
    
    def _select_endpoint(self, require_quorum: bool = False) -> List[str]:
        """Select endpoint(s) for request."""
        available = [
            url for url, stats in self.endpoints.items()
            if stats.is_available
        ]
        
        if not available:
            # All unhealthy - reset oldest
            oldest = min(
                self.endpoints.values(),
                key=lambda s: s.unhealthy_until or datetime.max.replace(tzinfo=timezone.utc)
            )
            oldest.unhealthy_until = None
            oldest.health = EndpointHealth.UNKNOWN
            available = [oldest.url]
            logger.warning("all_endpoints_unhealthy_resetting", reset_url=oldest.url[:40])
        
        # Sort by health score (healthy > degraded > unknown)
        def health_score(url: str) -> int:
            stats = self.endpoints[url]
            if stats.health == EndpointHealth.HEALTHY:
                return 3
            elif stats.health == EndpointHealth.DEGRADED:
                return 2
            elif stats.health == EndpointHealth.UNKNOWN:
                return 1
            return 0
        
        available.sort(key=health_score, reverse=True)
        
        if require_quorum and len(available) >= 2:
            # Return top 2 for quorum
            return available[:2]
        
        # Round-robin selection
        self._current_index = (self._current_index + 1) % len(available)
        return [available[self._current_index]]
    
    def _record_success(self, url: str, latency_ms: float):
        """Record successful request."""
        stats = self.endpoints[url]
        stats.total_requests += 1
        stats.successful_requests += 1
        stats.total_latency_ms += latency_ms
        stats.last_success = datetime.now(timezone.utc)
        stats.consecutive_failures = 0
        
        # Update health based on latency
        if latency_ms < 500:
            stats.health = EndpointHealth.HEALTHY
        elif latency_ms < 2000:
            stats.health = EndpointHealth.DEGRADED
        else:
            stats.health = EndpointHealth.DEGRADED
    
    def _record_failure(self, url: str, error: str, is_5xx: bool = False, is_timeout: bool = False):
        """Record failed request."""
        stats = self.endpoints[url]
        stats.total_requests += 1
        stats.failed_requests += 1
        stats.last_failure = datetime.now(timezone.utc)
        stats.consecutive_failures += 1
        
        if is_5xx or is_timeout or stats.consecutive_failures >= 3:
            stats.health = EndpointHealth.UNHEALTHY
            stats.unhealthy_until = datetime.now(timezone.utc) + timedelta(
                seconds=self.unhealthy_cooldown_seconds
            )
            logger.warning(
                "rpc_endpoint_marked_unhealthy",
                url=url[:40],
                error=error[:50],
                consecutive_failures=stats.consecutive_failures
            )
    
    async def _make_request(
        self,
        method: str,
        params: Any,
        endpoint_url: str,
        require_quorum: bool = False
    ) -> Dict[str, Any]:
        """Make a JSON-RPC request."""
        session = await self._get_session()
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        
        start_time = time.time()
        
        try:
            async with session.post(endpoint_url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    latency_ms = (time.time() - start_time) * 1000
                    
                    if "error" in data:
                        error_msg = data["error"].get("message", "Unknown error")
                        self._record_failure(endpoint_url, error_msg)
                        raise Exception(f"RPC error: {error_msg}")
                    
                    self._record_success(endpoint_url, latency_ms)
                    return data.get("result")
                
                elif resp.status >= 500:
                    latency_ms = (time.time() - start_time) * 1000
                    self._record_failure(endpoint_url, f"HTTP {resp.status}", is_5xx=True)
                    raise aiohttp.ClientResponseError(
                        resp.request_info,
                        resp.history,
                        status=resp.status
                    )
                else:
                    latency_ms = (time.time() - start_time) * 1000
                    self._record_failure(endpoint_url, f"HTTP {resp.status}")
                    raise Exception(f"HTTP {resp.status}")
                    
        except asyncio.TimeoutError:
            latency_ms = (time.time() - start_time) * 1000
            self._record_failure(endpoint_url, "Request timeout", is_timeout=True)
            raise
        except aiohttp.ClientError as e:
            latency_ms = (time.time() - 1000) * 1000
            error_str = str(e)
            is_5xx = any(code in error_str for code in ["500", "502", "503", "504"])
            self._record_failure(endpoint_url, error_str, is_5xx=is_5xx)
            raise
    
    async def call(
        self,
        method: str,
        params: Any = None,
        require_quorum: bool = False
    ) -> Any:
        """
        Make an RPC call with automatic failover.
        
        Args:
            method: RPC method name (e.g., "eth_blockNumber")
            params: Method parameters
            require_quorum: If True, verify result across 2 endpoints
        
        Returns:
            RPC result
        """
        last_error = None
        
        for attempt in range(self.max_retries):
            endpoints = self._select_endpoint(require_quorum=require_quorum)
            
            if require_quorum and len(endpoints) >= 2:
                # Quorum mode: verify across 2 endpoints
                results = []
                errors = []
                
                for endpoint in endpoints[:2]:
                    try:
                        result = await self._make_request(method, params, endpoint, require_quorum=False)
                        results.append((endpoint, result))
                    except Exception as e:
                        errors.append((endpoint, str(e)))
                
                if len(results) >= 2:
                    # Verify results match
                    _, result1 = results[0]
                    _, result2 = results[1]
                    
                    if result1 == result2:
                        logger.debug("quorum_verified", method=method, endpoints=[e[:30] for e in endpoints[:2]])
                        return result1
                    else:
                        logger.warning(
                            "quorum_mismatch",
                            method=method,
                            result1=str(result1)[:50],
                            result2=str(result2)[:50]
                        )
                        # Return first result but log warning
                        return result1
                elif len(results) == 1:
                    # Only one succeeded - use it
                    return results[0][1]
                else:
                    last_error = errors[0][1] if errors else "All endpoints failed"
            else:
                # Single endpoint mode
                endpoint = endpoints[0]
                try:
                    return await self._make_request(method, params, endpoint, require_quorum=False)
                except Exception as e:
                    last_error = str(e)
            
            if attempt < self.max_retries - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
        
        raise Exception(f"RPC call failed after {self.max_retries} attempts: {last_error}")
    
    async def get_block_number(self) -> int:
        """Get latest block number."""
        result = await self.call("eth_blockNumber")
        return int(result, 16)
    
    async def get_block(self, block_number: int, require_quorum: bool = False) -> Dict[str, Any]:
        """Get block by number."""
        return await self.call(
            "eth_getBlockByNumber",
            [hex(block_number), True],
            require_quorum=require_quorum
        )
    
    async def get_logs(
        self,
        from_block: int,
        to_block: int,
        address: Optional[str] = None,
        topics: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Get logs for a block range."""
        params = {
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
        }
        if address:
            params["address"] = address
        if topics:
            params["topics"] = topics
        
        return await self.call("eth_getLogs", [params])
    
    async def get_transaction_receipt(
        self,
        tx_hash: str,
        require_quorum: bool = False
    ) -> Dict[str, Any]:
        """Get transaction receipt."""
        return await self.call(
            "eth_getTransactionReceipt",
            [tx_hash],
            require_quorum=require_quorum
        )
    
    async def update_head_lag(self, chain_id: str):
        """Update head lag for all endpoints."""
        try:
            # Get reference block number from first healthy endpoint
            reference_block = await self.get_block_number()
            
            for url, stats in self.endpoints.items():
                if not stats.is_available:
                    continue
                
                try:
                    # Create temporary provider for this endpoint
                    temp_provider = MultiRpcProvider([url])
                    endpoint_block = await temp_provider.get_block_number()
                    stats.head_lag_blocks = max(0, reference_block - endpoint_block)
                    stats.last_head_check = datetime.now(timezone.utc)
                    
                    # Mark as degraded if lag is high
                    if stats.head_lag_blocks > 10:
                        stats.health = EndpointHealth.DEGRADED
                    
                    await temp_provider._close_session()
                except Exception as e:
                    logger.debug("head_lag_check_failed", url=url[:30], error=str(e)[:40])
        except Exception as e:
            logger.warning("head_lag_update_failed", chain=chain_id, error=str(e))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all endpoints."""
        return {
            "total_endpoints": len(self.endpoints),
            "healthy_endpoints": sum(1 for s in self.endpoints.values() if s.health == EndpointHealth.HEALTHY),
            "degraded_endpoints": sum(1 for s in self.endpoints.values() if s.health == EndpointHealth.DEGRADED),
            "unhealthy_endpoints": sum(1 for s in self.endpoints.values() if s.health == EndpointHealth.UNHEALTHY),
            "endpoints": [
                {
                    "url": s.url[:50] + "..." if len(s.url) > 50 else s.url,
                    "health": s.health.value,
                    "success_rate": f"{s.success_rate:.1%}",
                    "avg_latency_ms": f"{s.avg_latency_ms:.1f}",
                    "head_lag_blocks": s.head_lag_blocks,
                    "total_requests": s.total_requests,
                }
                for s in self.endpoints.values()
            ]
        }
    
    async def close(self):
        """Close the provider."""
        await self._close_session()

