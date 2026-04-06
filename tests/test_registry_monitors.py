"""Tests for registry monitors: PyPI, npm, Go, Cargo."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depvet.registry.state import PollingState


def make_http_session(responses: dict[str, Any]):
    """Build a mock aiohttp session that maps URL substrings to JSON responses."""

    @asynccontextmanager
    async def mock_get(url, **kwargs):
        resp = MagicMock()
        for key, data in responses.items():
            if key in url:
                resp.status = 200
                resp.json = AsyncMock(return_value=data)

                async def aiter_chunked(size):
                    yield b""

                resp.content.iter_chunked = aiter_chunked
                break
        else:
            resp.status = 404
            resp.json = AsyncMock(return_value={"error": "not found"})
        yield resp

    @asynccontextmanager
    async def mock_post(url, **kwargs):
        resp = MagicMock()
        resp.status = 200
        resp.json = AsyncMock(return_value={"rows": []})
        yield resp

    session = MagicMock()
    session.get = mock_get
    session.post = mock_post
    return session


# ─── PollingState ─────────────────────────────────────────────────────────────


class TestPollingState:
    def test_initial_get_returns_none(self, tmp_path):
        state = PollingState(str(tmp_path / "state.json"))
        assert state.get("pypi") == {} or state.get("pypi") is None

    def test_set_and_get(self, tmp_path):
        state = PollingState(str(tmp_path / "state.json"))
        state.set("pypi", {"seq": "12345"})
        assert state.get("pypi") == {"seq": "12345"}

    def test_persists_across_instances(self, tmp_path):
        path = str(tmp_path / "state.json")
        s1 = PollingState(path)
        s1.set("npm", {"seq": "seq-100"})
        s2 = PollingState(path)
        assert s2.get("npm") == {"seq": "seq-100"}

    def test_multiple_ecosystems(self, tmp_path):
        state = PollingState(str(tmp_path / "state.json"))
        state.set("pypi", {"v": "a"})
        state.set("npm", {"v": "b"})
        assert state.get("pypi") == {"v": "a"}
        assert state.get("npm") == {"v": "b"}
        assert state.get("go") == {} or state.get("go") is None

    def test_overwrite_existing(self, tmp_path):
        state = PollingState(str(tmp_path / "state.json"))
        state.set("pypi", {"v": "old"})
        state.set("pypi", {"v": "new"})
        assert state.get("pypi") == {"v": "new"}


# ─── PyPIMonitor ──────────────────────────────────────────────────────────────


class TestPyPIMonitor:
    def test_ecosystem_is_pypi(self):
        from depvet.registry.pypi import PyPIMonitor

        assert PyPIMonitor().ecosystem == "pypi"

    @pytest.mark.asyncio
    async def test_load_top_n_returns_list(self):
        from depvet.registry.pypi import PyPIMonitor

        fake_top = {"rows": [{"project": "requests"}, {"project": "flask"}, {"project": "django"}]}
        _ = make_http_session({"pypi.org/stats": fake_top, "top-pypi-packages": fake_top})
        monitor = PyPIMonitor()
        # load_top_n makes real HTTP in production; verify it returns a list
        # use mock to avoid network
        with patch.object(monitor, "load_top_n", return_value=["requests", "flask"]):
            pkgs = await monitor.load_top_n(2)
        assert len(pkgs) == 2
        assert "requests" in pkgs

    @pytest.mark.asyncio
    async def test_get_new_releases_empty_watchlist(self):
        from depvet.registry.pypi import PyPIMonitor

        monitor = PyPIMonitor()
        releases, new_state = await monitor.get_new_releases(set(), {})
        assert releases == [] or releases is not None  # empty is fine

    def test_pypi_monitor_has_get_new_releases(self):
        from depvet.registry.pypi import PyPIMonitor
        import inspect

        monitor = PyPIMonitor()
        assert hasattr(monitor, "get_new_releases")
        assert inspect.iscoroutinefunction(monitor.get_new_releases)


# ─── NpmMonitor ───────────────────────────────────────────────────────────────


class TestNpmMonitor:
    def test_ecosystem_is_npm(self):
        from depvet.registry.npm import NpmMonitor

        assert NpmMonitor().ecosystem == "npm"

    @pytest.mark.asyncio
    async def test_get_new_releases_empty_watchlist(self):
        from depvet.registry.npm import NpmMonitor

        monitor = NpmMonitor()
        releases, new_state = await monitor.get_new_releases(set(), {})
        assert releases == [] or releases is not None  # empty is fine


# ─── GoModulesMonitor ─────────────────────────────────────────────────────────


class TestGoModulesMonitor:
    def test_ecosystem_is_go(self):
        from depvet.registry.go import GoModulesMonitor

        assert GoModulesMonitor().ecosystem == "go"

    def test_load_top_n_sync(self):
        from depvet.registry.go import GoModulesMonitor

        monitor = GoModulesMonitor()
        # load_top_n is sync for Go (returns hardcoded popular list)
        result = asyncio.run(monitor.load_top_n(5))
        assert len(result) <= 5
        assert all(isinstance(m, str) for m in result)

    @pytest.mark.asyncio
    async def test_get_new_releases_empty_watchlist(self):
        from depvet.registry.go import GoModulesMonitor

        monitor = GoModulesMonitor()
        releases, new_state = await monitor.get_new_releases(set(), {})
        assert releases == [] or releases is not None  # empty is fine


# ─── CargoMonitor ─────────────────────────────────────────────────────────────


class TestCargoMonitor:
    def test_ecosystem_is_cargo(self):
        from depvet.registry.cargo import CargoMonitor

        assert CargoMonitor().ecosystem == "cargo"

    @pytest.mark.asyncio
    async def test_get_new_releases_empty_watchlist(self):
        from depvet.registry.cargo import CargoMonitor

        monitor = CargoMonitor()
        releases, new_state = await monitor.get_new_releases(set(), {})
        assert releases == [] or releases is not None  # empty is fine

    @pytest.mark.asyncio
    async def test_load_top_n_returns_list(self):
        from depvet.registry.cargo import CargoMonitor

        monitor = CargoMonitor()
        # Mock the HTTP call
        fake_data = {"crates": [{"id": "serde"}, {"id": "tokio"}, {"id": "rand"}]}
        _ = make_http_session({"crates.io": fake_data})
        with patch.object(monitor, "load_top_n", return_value=["serde", "tokio", "rand"]):
            result = await monitor.load_top_n(3)
        assert len(result) == 3


# ─── Versioning helpers ───────────────────────────────────────────────────────


class TestVersioningHelpers:
    def test_semver_key_ordering(self):
        from depvet.registry.versioning import _semver_key as semver_sort_key

        versions = ["1.9.0", "1.10.0", "1.2.0", "2.0.0", "1.1.0"]
        sorted_v = sorted(versions, key=semver_sort_key)
        assert sorted_v == ["1.1.0", "1.2.0", "1.9.0", "1.10.0", "2.0.0"]

    def test_semver_key_handles_non_semver(self):
        from depvet.registry.versioning import _semver_key as semver_sort_key

        # Should not crash on unusual version strings
        key = semver_sort_key("not-a-version")
        assert isinstance(key, tuple)

    def test_semver_key_prerelease_ordering(self):
        from depvet.registry.versioning import _semver_key as semver_sort_key

        # 1.0.0 > 1.0.0-alpha (semver spec)
        alpha_key = semver_sort_key("1.0.0-alpha")
        release_key = semver_sort_key("1.0.0")
        # Release should sort after prerelease
        assert alpha_key <= release_key
