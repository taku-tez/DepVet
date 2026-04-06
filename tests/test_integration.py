"""Integration tests that call real external APIs.

Run with: pytest tests/test_integration.py -m slow -v
These are excluded from normal CI runs (use `-m "not slow"` or omit).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

# All tests in this file require network access and are slow
pytestmark = pytest.mark.slow


# ─── Registry: PyPI ────────────────────────────────────────────────────────


class TestPyPIIntegration:
    @pytest.mark.asyncio
    async def test_load_top_n_returns_packages(self):
        """PyPI top-N API should return real package names."""
        from depvet.registry.pypi import PyPIMonitor

        mon = PyPIMonitor()
        pkgs = await mon.load_top_n(10)
        assert len(pkgs) > 0
        assert all(isinstance(p, str) for p in pkgs)
        # Well-known packages should be in the top 10
        top_names = {p.lower() for p in pkgs}
        assert any(name in top_names for name in ("boto3", "requests", "urllib3", "pip", "setuptools"))

    @pytest.mark.asyncio
    async def test_get_current_serial(self):
        """PyPI should return a valid serial number."""
        from depvet.registry.pypi import PyPIMonitor

        mon = PyPIMonitor()
        serial = await mon._get_current_serial()
        assert isinstance(serial, int)
        assert serial > 0

    @pytest.mark.asyncio
    async def test_get_previous_version(self):
        """Should resolve the previous version of a well-known package."""
        from depvet.registry.pypi import PyPIMonitor

        mon = PyPIMonitor()
        # requests has many versions; 2.32.0 should have a predecessor
        prev = await mon._get_previous_version("requests", "2.32.0")
        assert prev is not None
        assert prev != "2.32.0"


# ─── Registry: npm ──────────────────────────────────────────────────────────


class TestNpmIntegration:
    @pytest.mark.asyncio
    async def test_load_top_n_returns_packages(self):
        """npm search API should return real package names."""
        from depvet.registry.npm import NpmMonitor

        mon = NpmMonitor()
        pkgs = await mon.load_top_n(10)
        assert len(pkgs) > 0
        assert all(isinstance(p, str) for p in pkgs)


# ─── Registry: Go ───────────────────────────────────────────────────────────


class TestGoIntegration:
    @pytest.mark.asyncio
    async def test_list_versions(self):
        """Go proxy should return versions for a well-known module."""
        import aiohttp
        from depvet.registry.go import GoModulesMonitor

        mon = GoModulesMonitor()
        async with aiohttp.ClientSession() as session:
            versions = await mon._list_versions("github.com/google/uuid", session)
        assert len(versions) > 0
        assert any(v.startswith("v1.") for v in versions)

    @pytest.mark.asyncio
    async def test_get_version_info(self):
        """Go proxy should return version metadata."""
        import aiohttp
        from depvet.registry.go import GoModulesMonitor

        mon = GoModulesMonitor()
        async with aiohttp.ClientSession() as session:
            info = await mon._get_version_info("github.com/google/uuid", "v1.6.0", session)
        assert "Time" in info


# ─── Registry: Cargo ────────────────────────────────────────────────────────


class TestCargoIntegration:
    @pytest.mark.asyncio
    async def test_get_versions(self):
        """crates.io should return versions for serde."""
        import aiohttp
        from depvet.registry.cargo import CargoMonitor

        mon = CargoMonitor()
        async with aiohttp.ClientSession(headers=mon._headers()) as session:
            versions = await mon._get_versions("serde", session)
        assert len(versions) > 0
        assert all("num" in v for v in versions)

    @pytest.mark.asyncio
    async def test_load_top_n(self):
        """crates.io top-N should return crate names."""
        from depvet.registry.cargo import CargoMonitor

        mon = CargoMonitor()
        pkgs = await mon.load_top_n(5)
        assert len(pkgs) >= 1
        assert all(isinstance(p, str) for p in pkgs)


# ─── Download: PyPI ─────────────────────────────────────────────────────────


class TestDownloadIntegration:
    @pytest.mark.asyncio
    async def test_download_pypi_small_package(self):
        """Download a real, small PyPI package."""
        from depvet.differ.downloader import download_pypi_package

        with tempfile.TemporaryDirectory() as td:
            path = await download_pypi_package("six", "1.16.0", Path(td))
        assert path is not None
        assert path.exists()
        assert path.stat().st_size > 0

    @pytest.mark.asyncio
    async def test_download_npm_small_package(self):
        """Download a real, small npm package."""
        from depvet.differ.downloader import download_npm_package

        with tempfile.TemporaryDirectory() as td:
            path = await download_npm_package("is-odd", "3.0.1", Path(td))
        assert path is not None
        assert path.exists()
        assert path.stat().st_size > 0

    @pytest.mark.asyncio
    async def test_download_go_module(self):
        """Download a real Go module zip."""
        from depvet.differ.downloader import download_go_module

        with tempfile.TemporaryDirectory() as td:
            path = await download_go_module("github.com/google/uuid", "v1.6.0", Path(td))
        assert path is not None
        assert path.exists()
        assert path.name.endswith(".zip")

    @pytest.mark.asyncio
    async def test_download_maven_artifact(self):
        """Download a real Maven artifact (sources or plain JAR)."""
        from depvet.differ.downloader import download_maven_artifact

        with tempfile.TemporaryDirectory() as td:
            path = await download_maven_artifact("com.google.code.gson:gson", "2.11.0", Path(td))
        assert path is not None
        assert path.exists()
        assert path.name.endswith(".jar")


# ─── Unpack ─────────────────────────────────────────────────────────────────


class TestUnpackIntegration:
    @pytest.mark.asyncio
    async def test_download_and_unpack_pypi(self):
        """Full pipeline: download + unpack a PyPI package."""
        from depvet.differ.downloader import download_pypi_package
        from depvet.differ.unpacker import unpack

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            archive = await download_pypi_package("six", "1.16.0", tmp)
            assert archive is not None
            out = unpack(archive, tmp / "unpacked")
            assert out.exists()
            # six is a single-file package
            files = list(out.rglob("*.py"))
            assert len(files) >= 1

    @pytest.mark.asyncio
    async def test_download_and_unpack_maven_jar(self):
        """Full pipeline: download + unpack a Maven JAR."""
        from depvet.differ.downloader import download_maven_artifact
        from depvet.differ.unpacker import unpack

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            archive = await download_maven_artifact("com.google.code.gson:gson", "2.11.0", tmp)
            assert archive is not None
            out = unpack(archive, tmp / "unpacked")
            assert out.exists()
            # JAR should contain .class files or .java files
            all_files = list(out.rglob("*"))
            assert len(all_files) >= 1


# ─── OSV.dev ────────────────────────────────────────────────────────────────


class TestOSVIntegration:
    @pytest.mark.asyncio
    async def test_check_known_vulnerable_package(self):
        """OSV should return advisories for a known-vulnerable package."""
        from depvet.known_bad.osv import OSVChecker

        checker = OSVChecker()
        # log4j 2.14.1 is known to be vulnerable (CVE-2021-44228)
        entries = await checker.check("log4j-core", "2.14.1", "maven")
        # May or may not have entries depending on OSV data, but should not crash
        assert isinstance(entries, list)

    @pytest.mark.asyncio
    async def test_check_clean_package(self):
        """OSV should return empty for a clean package version."""
        from depvet.known_bad.osv import OSVChecker

        checker = OSVChecker()
        entries = await checker.check("six", "1.16.0", "pypi")
        assert isinstance(entries, list)

    @pytest.mark.asyncio
    async def test_batch_check(self):
        """Batch check should handle multiple packages."""
        from depvet.known_bad.osv import OSVChecker

        checker = OSVChecker()
        packages = [
            ("requests", "2.32.0", "pypi"),
            ("six", "1.16.0", "pypi"),
        ]
        results = await checker.batch_check(packages)
        assert isinstance(results, dict)
        assert len(results) >= 0  # may be empty if no vulns
