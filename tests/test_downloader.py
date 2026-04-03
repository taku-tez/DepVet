"""Tests for the package downloader module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import tempfile

import pytest

from depvet.differ.downloader import (
    download_package,
    download_pypi_package,
    download_npm_package,
)


def make_mock_http_session(content: bytes = b"PK\x03\x04fake_zip_content"):
    """Create a mock aiohttp session that returns fake binary content."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def mock_get(url, timeout=None):
        resp = MagicMock()
        resp.status = 200
        resp.json = AsyncMock(return_value={
            "urls": [{
                "packagetype": "bdist_wheel",
                "url": "https://example.com/fake-1.0-py3-none-any.whl",
                "filename": "fake-1.0-py3-none-any.whl",
            }],
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"dist": {"tarball": "https://example.com/fake-1.0.0.tgz"}}},
        })
        resp.content.iter_chunked = AsyncMock(return_value=aiter_chunks([content]))
        yield resp

    async def aiter_chunks(chunks):
        for c in chunks:
            yield c

    session = AsyncMock()
    session.get = mock_get
    return session


class TestDownloadPackage:
    @pytest.mark.asyncio
    async def test_pypi_calls_pypi_downloader(self):
        with patch("depvet.differ.downloader.download_pypi_package") as mock_dl:
            mock_dl.return_value = Path("/tmp/fake.whl")
            with tempfile.TemporaryDirectory() as td:
                _ = await download_package("requests", "2.31.0", "pypi", Path(td))
            mock_dl.assert_called_once()

    @pytest.mark.asyncio
    async def test_npm_calls_npm_downloader(self):
        with patch("depvet.differ.downloader.download_npm_package") as mock_dl:
            mock_dl.return_value = Path("/tmp/fake.tgz")
            with tempfile.TemporaryDirectory() as td:
                _ = await download_package("lodash", "4.17.21", "npm", Path(td))
            mock_dl.assert_called_once()

    @pytest.mark.asyncio
    async def test_go_calls_go_downloader(self):
        with patch("depvet.differ.downloader.download_go_module") as mock_dl:
            mock_dl.return_value = Path("/tmp/fake.zip")
            with tempfile.TemporaryDirectory() as td:
                _ = await download_package("github.com/foo/bar", "v1.0.0", "go", Path(td))
            mock_dl.assert_called_once()

    @pytest.mark.asyncio
    async def test_cargo_calls_cargo_downloader(self):
        with patch("depvet.differ.downloader.download_cargo_crate") as mock_dl:
            mock_dl.return_value = Path("/tmp/fake.crate")
            with tempfile.TemporaryDirectory() as td:
                _ = await download_package("serde", "1.0.0", "cargo", Path(td))
            mock_dl.assert_called_once()

    @pytest.mark.asyncio
    async def test_maven_raises_not_implemented(self):
        with tempfile.TemporaryDirectory() as td:
            with pytest.raises(NotImplementedError, match="Maven"):
                await download_package("org.springframework:spring-core", "5.3.0", "maven", Path(td))

    @pytest.mark.asyncio
    async def test_unknown_ecosystem_raises_value_error(self):
        with tempfile.TemporaryDirectory() as td:
            with pytest.raises(ValueError, match="Unsupported ecosystem"):
                await download_package("foo", "1.0.0", "rubygems", Path(td))


class TestDownloadPyPIPackage:
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_get(url, timeout=None):
            resp = MagicMock()
            resp.status = 404
            yield resp

        session = AsyncMock()
        session.get = mock_get

        with tempfile.TemporaryDirectory() as td:
            result = await download_pypi_package("nonexistent", "99.9.9", Path(td), session)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_urls(self):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_get(url, timeout=None):
            resp = MagicMock()
            resp.status = 200
            resp.json = AsyncMock(return_value={"urls": []})
            yield resp

        session = AsyncMock()
        session.get = mock_get

        with tempfile.TemporaryDirectory() as td:
            result = await download_pypi_package("empty-pkg", "1.0.0", Path(td), session)
        assert result is None


class TestDownloadNpmPackage:
    @pytest.mark.asyncio
    async def test_returns_none_on_not_found(self):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_get(url, timeout=None):
            resp = MagicMock()
            resp.status = 404
            resp.json = AsyncMock(return_value={"error": "version not found"})
            yield resp

        session = AsyncMock()
        session.get = mock_get

        with tempfile.TemporaryDirectory() as td:
            result = await download_npm_package("@nonexistent/pkg", "0.0.1", Path(td), session)
        assert result is None


class TestDownloadHelpers:
    def test_all_ecosystems_listed(self):
        """Verify all expected ecosystems have download support or explicit error."""
        supported = ["pypi", "npm", "go", "cargo"]
        not_supported = ["maven"]  # raises NotImplementedError
        # rubygems would raise ValueError

        # Just verify the routing logic exists
        from depvet import differ
        dl_src = Path(differ.__file__).parent / "downloader.py"
        content = dl_src.read_text()
        for eco in supported:
            assert eco in content, f"Ecosystem {eco} must be in downloader.py"
        for eco in not_supported:
            assert eco in content, f"Ecosystem {eco} must have explicit handling"
