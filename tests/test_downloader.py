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
        resp.json = AsyncMock(
            return_value={
                "urls": [
                    {
                        "packagetype": "bdist_wheel",
                        "url": "https://example.com/fake-1.0-py3-none-any.whl",
                        "filename": "fake-1.0-py3-none-any.whl",
                    }
                ],
                "dist-tags": {"latest": "1.0.0"},
                "versions": {"1.0.0": {"dist": {"tarball": "https://example.com/fake-1.0.0.tgz"}}},
            }
        )
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
    async def test_maven_calls_maven_downloader(self):
        with patch("depvet.differ.downloader.download_maven_artifact") as mock_dl:
            mock_dl.return_value = Path("/tmp/fake.jar")
            with tempfile.TemporaryDirectory() as td:
                _ = await download_package("org.springframework:spring-core", "5.3.0", "maven", Path(td))
            mock_dl.assert_called_once()

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


class TestDownloadMavenArtifact:
    @pytest.mark.asyncio
    async def test_returns_none_on_invalid_name(self):
        from depvet.differ.downloader import download_maven_artifact

        with tempfile.TemporaryDirectory() as td:
            result = await download_maven_artifact("invalid-no-colon", "1.0", Path(td))
        assert result is None

    @pytest.mark.asyncio
    async def test_prefers_sources_jar(self):
        """When sources JAR is available, it should be downloaded instead of plain JAR."""
        from depvet.differ.downloader import download_maven_artifact

        async def aiter_chunks(chunks):
            for c in chunks:
                yield c

        call_urls = []

        async def fake_request(method, url, timeout=None, **kwargs):
            call_urls.append(url)
            resp = MagicMock()
            resp.headers = {}
            resp.release = MagicMock()
            if "-sources.jar" in url:
                resp.status = 200
                resp.content.iter_chunked = MagicMock(return_value=aiter_chunks([b"PK\x03\x04fake"]))
            else:
                resp.status = 404
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        session = AsyncMock()
        session.request = fake_request

        with tempfile.TemporaryDirectory() as td:
            result = await download_maven_artifact("com.google.guava:guava", "33.0.0-jre", Path(td), session)

        assert result is not None
        assert "sources" in result.name
        assert any("-sources.jar" in u for u in call_urls)

    @pytest.mark.asyncio
    async def test_falls_back_to_plain_jar(self):
        """When sources JAR is 404, should fall back to plain JAR."""
        from depvet.differ.downloader import download_maven_artifact

        async def aiter_chunks(chunks):
            for c in chunks:
                yield c

        async def fake_request(method, url, timeout=None, **kwargs):
            resp = MagicMock()
            resp.headers = {}
            resp.release = MagicMock()
            if "-sources.jar" in url:
                resp.status = 404
            else:
                resp.status = 200
                resp.content.iter_chunked = MagicMock(return_value=aiter_chunks([b"PK\x03\x04fake"]))
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        session = AsyncMock()
        session.request = fake_request

        with tempfile.TemporaryDirectory() as td:
            result = await download_maven_artifact("com.google.guava:guava", "33.0.0-jre", Path(td), session)

        assert result is not None
        assert "sources" not in result.name
        assert result.name.endswith(".jar")

    @pytest.mark.asyncio
    async def test_returns_none_on_both_404(self):
        """When both sources and plain JAR are 404, should return None."""
        from depvet.differ.downloader import download_maven_artifact

        async def fake_request(method, url, timeout=None, **kwargs):
            resp = MagicMock()
            resp.headers = {}
            resp.release = MagicMock()
            resp.status = 404
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        session = AsyncMock()
        session.request = fake_request

        with tempfile.TemporaryDirectory() as td:
            result = await download_maven_artifact("com.google.guava:guava", "33.0.0-jre", Path(td), session)
        assert result is None


class TestMavenArtifactUrl:
    def test_simple_artifact(self):
        from depvet.differ.downloader import _maven_artifact_url

        url = _maven_artifact_url("com.google.guava", "guava", "33.0.0-jre")
        assert url == "https://repo1.maven.org/maven2/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.jar"

    def test_sources_classifier(self):
        from depvet.differ.downloader import _maven_artifact_url

        url = _maven_artifact_url("com.google.guava", "guava", "33.0.0-jre", classifier="sources")
        assert url == "https://repo1.maven.org/maven2/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre-sources.jar"

    def test_nested_group_id(self):
        from depvet.differ.downloader import _maven_artifact_url

        url = _maven_artifact_url("org.apache.commons", "commons-lang3", "3.14.0")
        assert "/org/apache/commons/commons-lang3/3.14.0/" in url

    def test_pom_extension(self):
        from depvet.differ.downloader import _maven_artifact_url

        url = _maven_artifact_url("com.google.guava", "guava", "33.0.0-jre", ext="pom")
        assert url.endswith(".pom")


class TestDownloadHelpers:
    def test_all_ecosystems_listed(self):
        """Verify all expected ecosystems have download support."""
        supported = ["pypi", "npm", "go", "cargo", "maven"]

        from depvet import differ

        dl_src = Path(differ.__file__).parent / "downloader.py"
        content = dl_src.read_text()
        for eco in supported:
            assert eco in content, f"Ecosystem {eco} must be in downloader.py"
