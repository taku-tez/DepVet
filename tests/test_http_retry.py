"""Tests for depvet.http retry utilities."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from depvet.http import _backoff_delay, retry_request, retry_sync


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status: int, headers: dict | None = None) -> AsyncMock:
    """Create a mock aiohttp.ClientResponse."""
    resp = AsyncMock(spec=aiohttp.ClientResponse)
    resp.status = status
    resp.headers = headers or {}
    resp.release = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# retry_request tests
# ---------------------------------------------------------------------------


class TestRetryRequest:
    """Tests for the async retry_request helper."""

    @pytest.mark.asyncio
    async def test_success_on_first_try(self):
        """200 response should be returned immediately without retry."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        ok_resp = _make_response(200)
        session.request = AsyncMock(return_value=ok_resp)

        resp = await retry_request(session, "GET", "https://example.com")
        assert resp.status == 200
        assert session.request.call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_503_then_success(self):
        """503 followed by 200 should retry and succeed."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        fail_resp = _make_response(503)
        ok_resp = _make_response(200)
        session.request = AsyncMock(side_effect=[fail_resp, ok_resp])

        with patch("depvet.http.asyncio.sleep", new_callable=AsyncMock):
            resp = await retry_request(
                session,
                "GET",
                "https://example.com",
                max_retries=2,
                base_delay=0.01,
            )
        assert resp.status == 200
        assert session.request.call_count == 2

    @pytest.mark.asyncio
    async def test_max_retries_returns_last_response(self):
        """After exhausting retries, the last retryable response is returned."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        fail_resp = _make_response(502)
        session.request = AsyncMock(return_value=fail_resp)

        with patch("depvet.http.asyncio.sleep", new_callable=AsyncMock):
            resp = await retry_request(
                session,
                "GET",
                "https://example.com",
                max_retries=2,
                base_delay=0.01,
            )
        assert resp.status == 502
        # initial + 2 retries = 3
        assert session.request.call_count == 3

    @pytest.mark.asyncio
    async def test_429_with_retry_after_header(self):
        """429 with Retry-After header should use at least that delay."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        rate_resp = _make_response(429, headers={"Retry-After": "5"})
        ok_resp = _make_response(200)
        session.request = AsyncMock(side_effect=[rate_resp, ok_resp])

        sleep_calls = []

        async def mock_sleep(delay):
            sleep_calls.append(delay)

        with patch("depvet.http.asyncio.sleep", side_effect=mock_sleep):
            resp = await retry_request(
                session,
                "GET",
                "https://example.com",
                max_retries=2,
                base_delay=0.01,
            )
        assert resp.status == 200
        assert len(sleep_calls) == 1
        # Should respect Retry-After: 5
        assert sleep_calls[0] >= 5.0

    @pytest.mark.asyncio
    async def test_connection_error_retry_then_success(self):
        """Transient connection error should be retried."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        ok_resp = _make_response(200)
        session.request = AsyncMock(
            side_effect=[aiohttp.ClientConnectionError("conn reset"), ok_resp],
        )

        with patch("depvet.http.asyncio.sleep", new_callable=AsyncMock):
            resp = await retry_request(
                session,
                "GET",
                "https://example.com",
                max_retries=2,
                base_delay=0.01,
            )
        assert resp.status == 200
        assert session.request.call_count == 2

    @pytest.mark.asyncio
    async def test_connection_error_exhausted_raises(self):
        """All retries failing with connection error should re-raise."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        session.request = AsyncMock(
            side_effect=aiohttp.ClientConnectionError("refused"),
        )

        with patch("depvet.http.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(aiohttp.ClientConnectionError):
                await retry_request(
                    session,
                    "GET",
                    "https://example.com",
                    max_retries=1,
                    base_delay=0.01,
                )
        # initial + 1 retry = 2
        assert session.request.call_count == 2

    @pytest.mark.asyncio
    async def test_timeout_error_retried(self):
        """asyncio.TimeoutError should be retried."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        ok_resp = _make_response(200)
        session.request = AsyncMock(
            side_effect=[asyncio.TimeoutError(), ok_resp],
        )

        with patch("depvet.http.asyncio.sleep", new_callable=AsyncMock):
            resp = await retry_request(
                session,
                "GET",
                "https://example.com",
                max_retries=2,
                base_delay=0.01,
            )
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_non_retryable_status_returned_immediately(self):
        """404 (non-retryable) should be returned without retry."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        resp_404 = _make_response(404)
        session.request = AsyncMock(return_value=resp_404)

        resp = await retry_request(session, "GET", "https://example.com")
        assert resp.status == 404
        assert session.request.call_count == 1

    @pytest.mark.asyncio
    async def test_post_method(self):
        """POST requests should work the same way."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        ok_resp = _make_response(200)
        session.request = AsyncMock(return_value=ok_resp)

        resp = await retry_request(
            session,
            "POST",
            "https://example.com",
            json={"key": "value"},
        )
        assert resp.status == 200
        session.request.assert_called_once_with(
            "POST",
            "https://example.com",
            timeout=None,
            json={"key": "value"},
        )


# ---------------------------------------------------------------------------
# retry_sync tests
# ---------------------------------------------------------------------------


class TestRetrySync:
    """Tests for the synchronous retry_sync helper."""

    def test_success_on_first_try(self):
        func = MagicMock(return_value=42)
        result = retry_sync(func, max_retries=2, base_delay=0.01)
        assert result == 42
        assert func.call_count == 1

    def test_retry_then_success(self):
        func = MagicMock(side_effect=[ConnectionError("fail"), 42])
        with patch("depvet.http.time.sleep"):
            result = retry_sync(func, max_retries=2, base_delay=0.01)
        assert result == 42
        assert func.call_count == 2

    def test_all_retries_exhausted_raises(self):
        func = MagicMock(side_effect=ConnectionError("always fails"))
        with patch("depvet.http.time.sleep"):
            with pytest.raises(ConnectionError, match="always fails"):
                retry_sync(func, max_retries=1, base_delay=0.01)
        # initial + 1 retry = 2
        assert func.call_count == 2

    def test_with_arguments(self):
        func = MagicMock(return_value="ok")
        result = retry_sync(func, "arg1", "arg2", max_retries=1, base_delay=0.01)
        assert result == "ok"
        func.assert_called_once_with("arg1", "arg2")


# ---------------------------------------------------------------------------
# _backoff_delay tests
# ---------------------------------------------------------------------------


class TestBackoffDelay:
    """Tests for exponential backoff calculation."""

    def test_exponential_growth(self):
        """Delay should roughly double each attempt."""
        d0 = _backoff_delay(0, 1.0)
        d1 = _backoff_delay(1, 1.0)
        d2 = _backoff_delay(2, 1.0)
        # With jitter (0.5–1.0), ranges are:
        # attempt 0: 0.5–1.0, attempt 1: 1.0–2.0, attempt 2: 2.0–4.0
        assert 0.5 <= d0 <= 1.0
        assert 1.0 <= d1 <= 2.0
        assert 2.0 <= d2 <= 4.0

    def test_base_delay_scaling(self):
        """Custom base_delay should scale the result."""
        d = _backoff_delay(0, 5.0)
        assert 2.5 <= d <= 5.0
