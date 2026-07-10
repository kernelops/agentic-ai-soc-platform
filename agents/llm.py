"""
LLM factory and resilience helpers for the agentic layer.

Every LLM-calling agent goes through here so retry/backoff and structured-output
handling live in exactly one place. We use LangChain's ChatGroq (Llama 3.3 70B)
and drive retries ourselves (`max_retries=0` on the client) so we can honor
`Retry-After` and apply jittered backoff tuned to Groq's free-tier limits.

Structured output: agents call `structured_invoke(Model, messages)`, which forces
the model to emit their existing Pydantic schema via Groq's function-calling
channel. On a schema/parse failure it retries once with an explicit "valid JSON"
nudge, then raises — the calling agent applies its own safe default (e.g.
investigation falls back to an UNVERIFIED verdict, which routes to reporting
rather than remediation).
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Awaitable, Callable, Sequence, TypeVar

from langchain_groq import ChatGroq
from pydantic import BaseModel

from common.config import settings

logger = logging.getLogger("soc.agents.llm")

T = TypeVar("T")
Message = tuple[str, str]  # (role, content), e.g. ("system", "..."), ("human", "...")

# Cache ChatGroq clients by (temperature, max_tokens) so we don't rebuild per call.
_llm_cache: dict[tuple[float, int], ChatGroq] = {}


def get_llm(temperature: float | None = None, max_tokens: int | None = None) -> ChatGroq:
    """Return a shared ChatGroq client for the given generation settings."""
    temp = settings.agent_llm_temperature if temperature is None else temperature
    tokens = settings.agent_llm_max_tokens if max_tokens is None else max_tokens
    key = (temp, tokens)
    if key not in _llm_cache:
        _llm_cache[key] = ChatGroq(
            model=settings.groq_model,
            api_key=settings.groq_api_key,
            temperature=temp,
            max_tokens=tokens,
            max_retries=0,  # we own the retry loop (see with_retry)
        )
    return _llm_cache[key]


# ---------------------------------------------------------------------------
# Retry / backoff
# ---------------------------------------------------------------------------

def _status_of(exc: Exception) -> int | None:
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(getattr(exc, "response", None), "status_code", None)
    return status if isinstance(status, int) else None


def _retry_after_seconds(exc: Exception) -> float | None:
    """Extract a Retry-After header value from a Groq error, if present."""
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None)
    if not headers:
        return None
    raw = headers.get("retry-after") or headers.get("Retry-After")
    try:
        return float(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _is_retryable(exc: Exception) -> bool:
    name = type(exc).__name__
    if any(k in name for k in ("RateLimit", "APIConnection", "InternalServer", "Timeout")):
        return True
    status = _status_of(exc)
    return status in (408, 409, 429, 500, 502, 503, 504)


async def with_retry(factory: Callable[[], Awaitable[T]], *, what: str = "llm call") -> T:
    """
    Await `factory()` with exponential backoff on rate-limit / transient errors.

    `factory` is a zero-arg callable returning a fresh awaitable each attempt
    (e.g. `lambda: chain.ainvoke(messages)`). Non-retryable errors propagate
    immediately; retryable ones back off (honoring Retry-After) up to
    `settings.agent_max_retries` attempts.
    """
    attempts = max(1, settings.agent_max_retries)
    last_exc: Exception | None = None

    for attempt in range(1, attempts + 1):
        try:
            return await factory()
        except Exception as exc:  # noqa: BLE001 - classified below
            last_exc = exc
            if not _is_retryable(exc) or attempt >= attempts:
                logger.error("%s failed (attempt %d/%d): %r", what, attempt, attempts, exc)
                raise
            delay = _retry_after_seconds(exc)
            if delay is None:
                delay = min(2 ** (attempt - 1), 30) + random.uniform(0.0, 0.5)
            logger.warning(
                "%s transient error (attempt %d/%d) — retrying in %.1fs: %s",
                what, attempt, attempts, delay, type(exc).__name__,
            )
            await asyncio.sleep(delay)

    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Structured output
# ---------------------------------------------------------------------------

async def structured_invoke(
    model_cls: type[T],
    messages: Sequence[Message],
    *,
    what: str,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> T:
    """
    Invoke the LLM and return a validated instance of `model_cls`.

    Uses Groq function-calling to force the schema. On a parse/validation failure
    it retries once with an explicit JSON nudge, then raises (caller applies its
    own safe default). Nothing here binds tools — structured output and tool
    calling must never share a single model turn (Groq channel conflict).
    """
    assert issubclass(model_cls, BaseModel), "structured_invoke requires a Pydantic model"
    llm = get_llm(temperature=temperature, max_tokens=max_tokens)
    structured = llm.with_structured_output(model_cls, method="function_calling")

    try:
        return await with_retry(lambda: structured.ainvoke(list(messages)), what=what)
    except Exception as first_exc:  # noqa: BLE001
        logger.warning("%s structured parse failed, nudging once: %r", what, first_exc)
        nudged = list(messages) + [
            ("human", "Return ONLY a valid JSON object that exactly matches the required schema.")
        ]
        return await with_retry(lambda: structured.ainvoke(nudged), what=f"{what} (nudge)")
