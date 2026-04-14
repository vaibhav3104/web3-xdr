"""
Shared LLM client for all AI modules.

Uses Google Gemini (free tier) as the primary provider.
Falls back to Anthropic if ANTHROPIC_API_KEY is set and Gemini is unavailable.

All modules call get_client() / get_async_client() which return a wrapper
that exposes the same .messages.create() interface regardless of backend.
"""

import os
import structlog
from dataclasses import dataclass
from typing import List, Any

logger = structlog.get_logger(__name__)

_client = None
_async_client = None

# ── Model configuration ──────────────────────────────────────────────
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
ANTHROPIC_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-20250514")
MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1024"))

# Expose MODEL for backward compat — set after client init
MODEL = GEMINI_MODEL


# ── Response wrappers (match Anthropic SDK shape) ────────────────────
@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class MessageResponse:
    content: List[TextBlock]
    model: str = ""
    role: str = "assistant"


class MessagesAPI:
    """Wraps either Gemini or Anthropic behind Anthropic's messages.create() interface."""

    def __init__(self, provider: str, raw_client: Any):
        self._provider = provider
        self._raw = raw_client

    def create(self, model: str, max_tokens: int, messages: list,
               system: str = "", **kwargs) -> MessageResponse:
        """Sync call — matches anthropic.Anthropic().messages.create()."""
        if self._provider == "gemini":
            return self._gemini_call(model, max_tokens, messages, system)
        else:
            return self._anthropic_call(model, max_tokens, messages, system)

    async def acreate(self, model: str, max_tokens: int, messages: list,
                      system: str = "", **kwargs) -> MessageResponse:
        """Async call — used by async client wrapper."""
        if self._provider == "gemini":
            return await self._gemini_async_call(model, max_tokens, messages, system)
        else:
            return await self._anthropic_async_call(model, max_tokens, messages, system)

    # ── Gemini ────────────────────────────────────────────────────────
    def _gemini_call(self, model, max_tokens, messages, system):
        from google import genai

        prompt = self._build_gemini_prompt(messages, system)
        response = self._raw.models.generate_content(
            model=model,
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                temperature=0.2,
            ),
        )
        return MessageResponse(
            content=[TextBlock(text=response.text)],
            model=model,
        )

    async def _gemini_async_call(self, model, max_tokens, messages, system):
        from google import genai

        prompt = self._build_gemini_prompt(messages, system)
        response = await self._raw.aio.models.generate_content(
            model=model,
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                temperature=0.2,
            ),
        )
        return MessageResponse(
            content=[TextBlock(text=response.text)],
            model=model,
        )

    def _build_gemini_prompt(self, messages, system):
        """Convert Anthropic-style messages to a single Gemini prompt."""
        parts = []
        if system:
            parts.append(f"System instructions:\n{system}\n")
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "user":
                parts.append(content)
            else:
                parts.append(f"Assistant: {content}")
        return "\n".join(parts)

    # ── Anthropic ─────────────────────────────────────────────────────
    def _anthropic_call(self, model, max_tokens, messages, system):
        resp = self._raw.messages.create(
            model=model, max_tokens=max_tokens,
            system=system, messages=messages,
        )
        return MessageResponse(
            content=[TextBlock(text=resp.content[0].text)],
            model=model,
        )

    async def _anthropic_async_call(self, model, max_tokens, messages, system):
        resp = await self._raw.messages.create(
            model=model, max_tokens=max_tokens,
            system=system, messages=messages,
        )
        return MessageResponse(
            content=[TextBlock(text=resp.content[0].text)],
            model=model,
        )


class LLMClient:
    """Unified client exposing .messages.create() for any backend."""

    def __init__(self, provider: str, raw_client: Any):
        self.provider = provider
        self.messages = MessagesAPI(provider, raw_client)


class AsyncLLMClient:
    """Unified async client exposing .messages.create() for any backend."""

    def __init__(self, provider: str, raw_client: Any):
        self.provider = provider
        self.messages = _AsyncMessagesProxy(provider, raw_client)


class _AsyncMessagesProxy:
    """Translates .messages.create() to the async acreate() path."""

    def __init__(self, provider: str, raw_client: Any):
        self._api = MessagesAPI(provider, raw_client)

    async def create(self, model: str, max_tokens: int, messages: list,
                     system: str = "", **kwargs) -> MessageResponse:
        return await self._api.acreate(model, max_tokens, messages, system)


# ── Client factories ─────────────────────────────────────────────────

def _try_gemini():
    """Try to initialize the Google Gemini client."""
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return None
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        # Quick validation — list models doesn't cost anything
        logger.info("gemini_client_initialized", model=GEMINI_MODEL)
        return client
    except Exception as e:
        logger.warning("gemini_init_failed", error=str(e))
        return None


def _try_anthropic():
    """Try to initialize the Anthropic client."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        logger.info("anthropic_client_initialized", model=ANTHROPIC_MODEL)
        return client
    except Exception as e:
        logger.warning("anthropic_init_failed", error=str(e))
        return None


def _try_anthropic_async():
    """Try to initialize the async Anthropic client."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
        return anthropic.AsyncAnthropic(api_key=api_key)
    except Exception:
        return None


def get_client():
    """Get or create the shared sync LLM client (Gemini first, Anthropic fallback)."""
    global _client, MODEL
    if _client is not None:
        return _client

    # Try Gemini first (free)
    gemini = _try_gemini()
    if gemini:
        MODEL = GEMINI_MODEL
        _client = LLMClient("gemini", gemini)
        return _client

    # Fall back to Anthropic
    anthropic = _try_anthropic()
    if anthropic:
        MODEL = ANTHROPIC_MODEL
        _client = LLMClient("anthropic", anthropic)
        return _client

    logger.warning(
        "no_llm_client_available",
        hint="Set GEMINI_API_KEY for free Gemini or ANTHROPIC_API_KEY for Claude",
    )
    return None


def get_async_client():
    """Get or create the shared async LLM client."""
    global _async_client, MODEL
    if _async_client is not None:
        return _async_client

    # Try Gemini first (free) — same client works for sync+async
    gemini = _try_gemini()
    if gemini:
        MODEL = GEMINI_MODEL
        _async_client = AsyncLLMClient("gemini", gemini)
        return _async_client

    # Fall back to Anthropic async
    anthropic_async = _try_anthropic_async()
    if anthropic_async:
        MODEL = ANTHROPIC_MODEL
        _async_client = AsyncLLMClient("anthropic", anthropic_async)
        return _async_client

    logger.warning(
        "no_async_llm_client_available",
        hint="Set GEMINI_API_KEY for free Gemini or ANTHROPIC_API_KEY for Claude",
    )
    return None
