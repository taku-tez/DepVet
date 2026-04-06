"""Shared HTTP retry utilities with exponential backoff."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

_DEFAULT_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})


async def retry_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    max_retries: int = 3,
    base_delay: float = 1.0,
    retryable_statuses: frozenset[int] = _DEFAULT_RETRYABLE_STATUSES,
    timeout: aiohttp.ClientTimeout | None = None,
    **kwargs: Any,
) -> aiohttp.ClientResponse:
    """
    Execute an HTTP request with retry and exponential backoff.

    On retryable status codes (429, 5xx) or transient connection errors,
    retries up to *max_retries* times with exponential backoff + jitter.

    For 429 responses, honours the ``Retry-After`` header when present.

    Returns the final :class:`aiohttp.ClientResponse` so the caller's
    existing status-code handling continues to work unchanged.
    Raises the last exception if all retries fail on connection errors.
    """
    last_exc: BaseException | None = None

    for attempt in range(max_retries + 1):
        try:
            resp = await session.request(
                method,
                url,
                timeout=timeout,
                **kwargs,
            )

            if resp.status not in retryable_statuses or attempt == max_retries:
                return resp

            # Retryable status — compute delay
            delay = _backoff_delay(attempt, base_delay)
            if resp.status == 429:
                retry_after = _parse_retry_after(resp)
                if retry_after is not None:
                    delay = max(delay, retry_after)

            logger.warning(
                "Retryable %s %s (status=%d), attempt %d/%d, retry in %.1fs",
                method,
                url,
                resp.status,
                attempt + 1,
                max_retries,
                delay,
            )
            resp.release()
            await asyncio.sleep(delay)

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            last_exc = exc
            if attempt == max_retries:
                raise

            delay = _backoff_delay(attempt, base_delay)
            logger.warning(
                "Transient error %s %s (%s), attempt %d/%d, retry in %.1fs",
                method,
                url,
                exc,
                attempt + 1,
                max_retries,
                delay,
            )
            await asyncio.sleep(delay)

    # Unreachable, but keeps mypy happy
    assert last_exc is not None
    raise last_exc  # pragma: no cover


def _backoff_delay(attempt: int, base: float) -> float:
    """Exponential backoff with jitter: base * 2^attempt * (0.5–1.0)."""
    return base * (2**attempt) * (0.5 + random.random() * 0.5)


def _parse_retry_after(resp: aiohttp.ClientResponse) -> float | None:
    """Parse ``Retry-After`` header (seconds only, not HTTP-date)."""
    value = resp.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def retry_sync(func, *args, max_retries: int = 3, base_delay: float = 1.0):
    """
    Synchronous retry wrapper for blocking calls (e.g. XML-RPC).

    Catches :class:`Exception` and retries with exponential backoff.
    Returns the result on success; re-raises the last exception on failure.
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return func(*args)
        except Exception as exc:
            last_exc = exc
            if attempt == max_retries:
                raise
            delay = _backoff_delay(attempt, base_delay)
            logger.warning(
                "Retry sync %s (%s), attempt %d/%d, retry in %.1fs",
                getattr(func, "__name__", str(func)),
                exc,
                attempt + 1,
                max_retries,
                delay,
            )
            time.sleep(delay)

    assert last_exc is not None
    raise last_exc  # pragma: no cover
