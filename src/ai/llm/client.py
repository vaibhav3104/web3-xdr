"""
Shared Anthropic client for all LLM modules.

Reads ANTHROPIC_API_KEY from environment. All modules use this
singleton to avoid creating multiple HTTP connections.
"""

import os
import structlog

logger = structlog.get_logger(__name__)

_client = None


def get_client():
    """Get or create the shared Anthropic client."""
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


MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-20250514")
MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1024"))
