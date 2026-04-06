"""Tests for Go and Cargo version transition signal analysis."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from contextlib import asynccontextmanager

from depvet.analyzer.version_signal import (
    analyze_go_transition,
    analyze_cargo_transition,
    get_transition_context,
)


def make_mock_session(responses: dict):
    """Create a mock aiohttp.ClientSession for given URL→response mapping."""
    session = MagicMock()

    @asynccontextmanager
    async def mock_get(url, **kwargs):
        resp = MagicMock()
        for key, data in responses.items():
            if key in url:
                resp.status = 200
                resp.json = AsyncMock(return_value=data)
                break
        else:
            resp.status = 404
            resp.json = AsyncMock(return_value={})
        yield resp

    session.get = mock_get
    return session


# ─── Go transition analysis ───────────────────────────────────────────────────


class TestGoTransition:
    @pytest.mark.asyncio
    async def test_basic_ok_no_signals(self):
        """Normal update with short gap → no signals."""
        session = make_mock_session(
            {
                "v1.9.0.info": {"Version": "v1.9.0", "Time": "2023-01-01T00:00:00Z"},
                "v1.9.1.info": {"Version": "v1.9.1", "Time": "2023-02-01T00:00:00Z"},
            }
        )
        ctx = await analyze_go_transition("github.com/gin-gonic/gin", "v1.9.0", "v1.9.1", session)
        assert ctx.ecosystem == "go"
        dormancy = [s for s in ctx.signals if "DORMANCY" in s.signal_id]
        assert not dormancy

    @pytest.mark.asyncio
    async def test_long_dormancy_detected(self):
        """Gap > 365 days should trigger LONG_DORMANCY."""
        session = make_mock_session(
            {
                "v1.0.0.info": {"Version": "v1.0.0", "Time": "2021-01-01T00:00:00Z"},
                "v1.0.1.info": {"Version": "v1.0.1", "Time": "2023-06-01T00:00:00Z"},  # ~880 days
            }
        )
        ctx = await analyze_go_transition("github.com/some/lib", "v1.0.0", "v1.0.1", session)
        assert any(s.signal_id == "LONG_DORMANCY" for s in ctx.signals)

    @pytest.mark.asyncio
    async def test_medium_dormancy_detected(self):
        """Gap 180-365 days → MEDIUM_DORMANCY."""
        session = make_mock_session(
            {
                "v1.0.0.info": {"Version": "v1.0.0", "Time": "2023-01-01T00:00:00Z"},
                "v1.0.1.info": {"Version": "v1.0.1", "Time": "2023-09-01T00:00:00Z"},  # ~243 days
            }
        )
        ctx = await analyze_go_transition("github.com/some/lib", "v1.0.0", "v1.0.1", session)
        assert any(s.signal_id == "MEDIUM_DORMANCY" for s in ctx.signals)

    @pytest.mark.asyncio
    async def test_vcs_origin_changed(self):
        """VCS URL change should trigger CRITICAL VCS_ORIGIN_CHANGED."""
        session = make_mock_session(
            {
                "v1.0.0.info": {
                    "Version": "v1.0.0",
                    "Time": "2023-01-01T00:00:00Z",
                    "Origin": {"URL": "https://github.com/legit/repo"},
                },
                "v1.0.1.info": {
                    "Version": "v1.0.1",
                    "Time": "2023-02-01T00:00:00Z",
                    "Origin": {"URL": "https://github.com/hijacker/repo"},
                },
            }
        )
        ctx = await analyze_go_transition("github.com/some/lib", "v1.0.0", "v1.0.1", session)
        assert any(s.signal_id == "VCS_ORIGIN_CHANGED" for s in ctx.signals)
        vcs_signal = next(s for s in ctx.signals if s.signal_id == "VCS_ORIGIN_CHANGED")
        assert vcs_signal.severity == "CRITICAL"
        assert vcs_signal.confidence_boost >= 0.3

    @pytest.mark.asyncio
    async def test_same_vcs_origin_no_signal(self):
        """Same VCS URL → no VCS_ORIGIN_CHANGED."""
        session = make_mock_session(
            {
                "v1.0.0.info": {
                    "Version": "v1.0.0",
                    "Time": "2023-01-01T00:00:00Z",
                    "Origin": {"URL": "https://github.com/legit/repo"},
                },
                "v1.0.1.info": {
                    "Version": "v1.0.1",
                    "Time": "2023-02-01T00:00:00Z",
                    "Origin": {"URL": "https://github.com/legit/repo"},
                },
            }
        )
        ctx = await analyze_go_transition("github.com/legit/repo", "v1.0.0", "v1.0.1", session)
        assert not any(s.signal_id == "VCS_ORIGIN_CHANGED" for s in ctx.signals)

    @pytest.mark.asyncio
    async def test_api_error_returns_empty_context(self):
        """Network failure should return context without signals (no crash)."""
        session = make_mock_session({})  # all 404
        ctx = await analyze_go_transition("github.com/foo/bar", "v1.0.0", "v1.0.1", session)
        assert ctx.ecosystem == "go"
        assert ctx.signals == []

    @pytest.mark.asyncio
    async def test_security_package_skips_dormancy(self):
        """golang.org/x/crypto should not get LONG_DORMANCY."""
        session = make_mock_session(
            {
                "v0.9.0.info": {"Version": "v0.9.0", "Time": "2021-01-01T00:00:00Z"},
                "v0.14.0.info": {"Version": "v0.14.0", "Time": "2023-06-01T00:00:00Z"},
            }
        )
        ctx = await analyze_go_transition("golang.org/x/crypto", "v0.9.0", "v0.14.0", session)
        assert not any("DORMANCY" in s.signal_id for s in ctx.signals)


# ─── Cargo transition analysis ────────────────────────────────────────────────


class TestCargoTransition:
    def _make_crate_response(self, versions_data: list[dict]) -> dict:
        return {"crate": {"name": "test-crate"}, "versions": versions_data}

    @pytest.mark.asyncio
    async def test_basic_ok_no_signals(self):
        """Normal update → no signals."""
        data = self._make_crate_response(
            [
                {"num": "1.0.1", "created_at": "2023-02-01T00:00:00Z", "yanked": False},
                {"num": "1.0.0", "created_at": "2023-01-01T00:00:00Z", "yanked": False},
            ]
        )
        session = make_mock_session({"crates/test-crate": data})
        ctx = await analyze_cargo_transition("test-crate", "1.0.0", "1.0.1", session)
        assert ctx.ecosystem == "cargo"
        assert ctx.signals == []

    @pytest.mark.asyncio
    async def test_long_dormancy_detected(self):
        """Gap > 365 days → LONG_DORMANCY."""
        data = self._make_crate_response(
            [
                {"num": "2.0.0", "created_at": "2024-06-01T00:00:00.000000Z", "yanked": False},
                {"num": "1.0.0", "created_at": "2021-01-01T00:00:00.000000Z", "yanked": False},
            ]
        )
        session = make_mock_session({"crates/my-crate": data})
        ctx = await analyze_cargo_transition("my-crate", "1.0.0", "2.0.0", session)
        assert any(s.signal_id == "LONG_DORMANCY" for s in ctx.signals)

    @pytest.mark.asyncio
    async def test_yanked_predecessor_detected(self):
        """If old version is yanked, YANKED_PREDECESSOR signal emitted."""
        data = self._make_crate_response(
            [
                {"num": "1.0.1", "created_at": "2023-02-01T00:00:00.000000Z", "yanked": False},
                {"num": "1.0.0", "created_at": "2023-01-01T00:00:00.000000Z", "yanked": True},
            ]
        )
        session = make_mock_session({"crates/test-crate": data})
        ctx = await analyze_cargo_transition("test-crate", "1.0.0", "1.0.1", session)
        assert any(s.signal_id == "YANKED_PREDECESSOR" for s in ctx.signals)

    @pytest.mark.asyncio
    async def test_not_yanked_no_signal(self):
        """Non-yanked predecessor → no YANKED_PREDECESSOR."""
        data = self._make_crate_response(
            [
                {"num": "1.0.1", "created_at": "2023-02-01T00:00:00.000000Z", "yanked": False},
                {"num": "1.0.0", "created_at": "2023-01-01T00:00:00.000000Z", "yanked": False},
            ]
        )
        session = make_mock_session({"crates/test-crate": data})
        ctx = await analyze_cargo_transition("test-crate", "1.0.0", "1.0.1", session)
        assert not any(s.signal_id == "YANKED_PREDECESSOR" for s in ctx.signals)

    @pytest.mark.asyncio
    async def test_api_404_returns_empty_context(self):
        """API error → empty context, no crash."""
        session = make_mock_session({})
        ctx = await analyze_cargo_transition("unknown-crate", "1.0.0", "1.0.1", session)
        assert ctx.ecosystem == "cargo"
        assert ctx.signals == []


# ─── get_transition_context routing ──────────────────────────────────────────


class TestGetTransitionContextRouting:
    @pytest.mark.asyncio
    async def test_routes_go(self):
        with patch("depvet.analyzer.version_signal.analyze_go_transition") as mock_go:
            mock_go.return_value = MagicMock(ecosystem="go", signals=[])
            _ = await get_transition_context("github.com/foo/bar", "v1.0.0", "v1.0.1", "go")
            mock_go.assert_called_once()

    @pytest.mark.asyncio
    async def test_routes_cargo(self):
        with patch("depvet.analyzer.version_signal.analyze_cargo_transition") as mock_cargo:
            mock_cargo.return_value = MagicMock(ecosystem="cargo", signals=[])
            _ = await get_transition_context("serde", "1.0.0", "1.0.1", "cargo")
            mock_cargo.assert_called_once()

    @pytest.mark.asyncio
    async def test_routes_pypi(self):
        with patch("depvet.analyzer.version_signal.analyze_pypi_transition") as mock_pypi:
            mock_pypi.return_value = MagicMock(ecosystem="pypi", signals=[])
            _ = await get_transition_context("requests", "2.31.0", "2.32.0", "pypi")
            mock_pypi.assert_called_once()

    @pytest.mark.asyncio
    async def test_unknown_ecosystem_returns_none(self):
        ctx = await get_transition_context("foo", "1.0", "2.0", "maven")
        assert ctx is None
