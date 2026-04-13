"""
LLM Rate Limiter & Spend Cap
=============================

Prevents runaway costs when noisy alert rules trigger many LLM calls.
Enforces per-minute request limits, daily request caps, and estimated
daily spend caps based on Claude Sonnet token pricing.

Usage:
    from .rate_limiter import make_llm_call

    response = make_llm_call(
        messages=[{"role": "user", "content": "Analyze this alert..."}],
        system="You are a Web3 security analyst.",
    )
    if response is None:
        # Rate-limited or client unavailable
        ...
"""

import os
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

from .client import MODEL, get_client

logger = structlog.get_logger(__name__)

# Claude Sonnet pricing (USD per million tokens)
_INPUT_COST_PER_MTOK = 3.0
_OUTPUT_COST_PER_MTOK = 15.0


@dataclass
class LLMRateLimiter:
    """
    Thread-safe rate limiter with RPM throttling and daily spend/request caps.

    Config is read from environment variables at init time:
        LLM_RPM_LIMIT          — max requests per minute (default: 30)
        LLM_DAILY_SPEND_CAP    — max estimated daily spend in USD (default: 50.0)
        LLM_DAILY_REQUEST_CAP  — max requests per day (default: 1000)
    """

    rpm_limit: int = field(init=False)
    daily_spend_cap: float = field(init=False)
    daily_request_cap: int = field(init=False)

    # Internal state
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _request_timestamps: deque = field(default_factory=deque, repr=False)
    _daily_request_count: int = field(default=0, repr=False)
    _daily_spend_usd: float = field(default=0.0, repr=False)
    _current_day: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        self.rpm_limit = int(os.getenv("LLM_RPM_LIMIT", "30"))
        self.daily_spend_cap = float(os.getenv("LLM_DAILY_SPEND_CAP", "50.0"))
        self.daily_request_cap = int(os.getenv("LLM_DAILY_REQUEST_CAP", "1000"))
        self._current_day = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        logger.info(
            "rate_limiter_initialized",
            rpm_limit=self.rpm_limit,
            daily_spend_cap=self.daily_spend_cap,
            daily_request_cap=self.daily_request_cap,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def can_make_request(self) -> bool:
        """Check whether a new request is allowed under all limits."""
        with self._lock:
            self._reset_if_new_day()
            self._evict_old_timestamps()

            if len(self._request_timestamps) >= self.rpm_limit:
                logger.warning(
                    "rate_limit_rpm_exceeded",
                    current_rpm=len(self._request_timestamps),
                    limit=self.rpm_limit,
                )
                return False

            if self._daily_request_count >= self.daily_request_cap:
                logger.warning(
                    "rate_limit_daily_requests_exceeded",
                    daily_count=self._daily_request_count,
                    cap=self.daily_request_cap,
                )
                return False

            if self._daily_spend_usd >= self.daily_spend_cap:
                logger.warning(
                    "rate_limit_daily_spend_exceeded",
                    daily_spend=round(self._daily_spend_usd, 4),
                    cap=self.daily_spend_cap,
                )
                return False

            return True

    def record_request(self, input_tokens: int, output_tokens: int) -> None:
        """Record a completed request's token usage."""
        cost = self._estimate_cost(input_tokens, output_tokens)

        with self._lock:
            self._reset_if_new_day()
            now = datetime.now(timezone.utc)
            self._request_timestamps.append(now)
            self._daily_request_count += 1
            self._daily_spend_usd += cost

        logger.debug(
            "llm_request_recorded",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=round(cost, 6),
            daily_spend=round(self._daily_spend_usd, 4),
            daily_count=self._daily_request_count,
        )

    def get_usage_stats(self) -> Dict[str, Any]:
        """Return a snapshot of current usage vs. limits."""
        with self._lock:
            self._reset_if_new_day()
            self._evict_old_timestamps()

            return {
                "current_rpm": len(self._request_timestamps),
                "rpm_limit": self.rpm_limit,
                "daily_request_count": self._daily_request_count,
                "daily_request_cap": self.daily_request_cap,
                "daily_spend_usd": round(self._daily_spend_usd, 4),
                "daily_spend_cap": self.daily_spend_cap,
                "utc_day": self._current_day,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _reset_if_new_day(self) -> None:
        """Reset daily counters if the UTC date has changed. Must hold lock."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if today != self._current_day:
            logger.info(
                "daily_counters_reset",
                previous_day=self._current_day,
                previous_spend=round(self._daily_spend_usd, 4),
                previous_count=self._daily_request_count,
            )
            self._current_day = today
            self._daily_request_count = 0
            self._daily_spend_usd = 0.0

    def _evict_old_timestamps(self) -> None:
        """Remove timestamps older than 60 seconds. Must hold lock."""
        now = datetime.now(timezone.utc)
        while self._request_timestamps:
            age = (now - self._request_timestamps[0]).total_seconds()
            if age > 60.0:
                self._request_timestamps.popleft()
            else:
                break

    @staticmethod
    def _estimate_cost(input_tokens: int, output_tokens: int) -> float:
        """Estimate cost in USD based on Claude Sonnet pricing."""
        input_cost = (input_tokens / 1_000_000) * _INPUT_COST_PER_MTOK
        output_cost = (output_tokens / 1_000_000) * _OUTPUT_COST_PER_MTOK
        return input_cost + output_cost


# ------------------------------------------------------------------
# Singleton accessor
# ------------------------------------------------------------------

_rate_limiter: Optional[LLMRateLimiter] = None
_singleton_lock = threading.Lock()


def get_rate_limiter() -> LLMRateLimiter:
    """Get or create the shared LLMRateLimiter singleton."""
    global _rate_limiter
    if _rate_limiter is not None:
        return _rate_limiter

    with _singleton_lock:
        # Double-check after acquiring the lock
        if _rate_limiter is None:
            _rate_limiter = LLMRateLimiter()
    return _rate_limiter


# ------------------------------------------------------------------
# Convenience helper
# ------------------------------------------------------------------


def make_llm_call(
    messages: List[Dict[str, str]],
    system: str = "",
    max_tokens: int = 1024,
    model: Optional[str] = None,
) -> Any:
    """
    Make a rate-limited LLM call through the shared Anthropic client.

    Returns the API response on success, or None if rate-limited or
    the client is unavailable.
    """
    limiter = get_rate_limiter()

    if not limiter.can_make_request():
        logger.warning("llm_call_skipped_rate_limited", model=model or MODEL)
        return None

    client = get_client()
    if client is None:
        logger.warning("llm_call_skipped_no_client")
        return None

    resolved_model = model or MODEL

    try:
        response = client.messages.create(
            model=resolved_model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )

        limiter.record_request(
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )

        logger.debug(
            "llm_call_completed",
            model=resolved_model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )

        return response

    except Exception as e:
        logger.error("llm_call_failed", model=resolved_model, error=str(e))
        return None
