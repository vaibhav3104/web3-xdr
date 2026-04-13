"""
Shared Anthropic client for all LLM modules.

Reads ANTHROPIC_API_KEY from environment. All modules use this
singleton to avoid creating multiple HTTP connections.

Provides both sync and async clients.
"""

import os
import structlog

logger = structlog.get_logger(__name__)

_client = None
_async_client = None


def get_client():
    """Get or create the shared sync Anthropic client."""
    global _client
    if _client is not None:
        return _client

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning(
            "anthropic_api_key_not_set",
            hint="Set ANTHROPIC_API_KEY to enable LLM-powered analysis",
        )
        return None

    import anthropic

    _client = anthropic.Anthropic(api_key=api_key)
    logger.info("anthropic_client_initialized")
    return _client


def get_async_client():
    """Get or create the shared async Anthropic client."""
    global _async_client
    if _async_client is not None:
        return _async_client

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning(
            "anthropic_api_key_not_set",
            hint="Set ANTHROPIC_API_KEY to enable LLM-powered analysis",
        )
        return None

    import anthropic

    _async_client = anthropic.AsyncAnthropic(api_key=api_key)
    logger.info("anthropic_async_client_initialized")
    return _async_client


MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-20250514")
MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1024"))
