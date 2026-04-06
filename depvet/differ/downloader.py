"""Package downloader for PyPI, npm, Go, Cargo, and Maven."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import aiohttp

from depvet.http import retry_request

logger = logging.getLogger(__name__)

PYPI_JSON_API = "https://pypi.org/pypi/{name}/{version}/json"
NPM_REGISTRY_URL = "https://registry.npmjs.org/{name}/{version}"

_METADATA_TIMEOUT = aiohttp.ClientTimeout(total=30)
_DOWNLOAD_TIMEOUT = aiohttp.ClientTimeout(total=120)


async def download_pypi_package(
    name: str,
    version: str,
    dest_dir: Path,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[Path]:
    """Download a PyPI package (wheel or sdist) to dest_dir."""
    close_session = session is None
    if session is None:
        session = aiohttp.ClientSession()

    try:
        url = PYPI_JSON_API.format(name=name, version=version)
        resp = await retry_request(session, "GET", url, timeout=_METADATA_TIMEOUT)
        async with resp:
            if resp.status != 200:
                logger.warning(f"PyPI JSON API returned {resp.status} for {name}=={version}")
                return None
            data = await resp.json()

        urls = data.get("urls", [])
        # Prefer wheel, fall back to sdist
        wheel = next((u for u in urls if u["packagetype"] == "bdist_wheel"), None)
        sdist = next((u for u in urls if u["packagetype"] == "sdist"), None)
        chosen = wheel or sdist
        if not chosen:
            logger.warning(f"No downloadable release found for {name}=={version}")
            return None

        file_url = chosen["url"]
        filename = chosen["filename"]
        dest_path = dest_dir / filename

        resp = await retry_request(session, "GET", file_url, timeout=_DOWNLOAD_TIMEOUT)
        async with resp:
            if resp.status != 200:
                logger.warning(f"Failed to download {file_url}")
                return None
            with open(dest_path, "wb") as f:
                async for chunk in resp.content.iter_chunked(65536):
                    f.write(chunk)

        logger.info(f"Downloaded {name}=={version} -> {dest_path}")
        return dest_path

    finally:
        if close_session:
            await session.close()


async def download_npm_package(
    name: str,
    version: str,
    dest_dir: Path,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[Path]:
    """Download an npm package tarball to dest_dir."""
    close_session = session is None
    if session is None:
        session = aiohttp.ClientSession()

    try:
        # Scoped packages: @scope/name -> @scope%2Fname
        encoded_name = name.replace("/", "%2F")
        url = NPM_REGISTRY_URL.format(name=encoded_name, version=version)

        resp = await retry_request(session, "GET", url, timeout=_METADATA_TIMEOUT)
        async with resp:
            if resp.status != 200:
                logger.warning(f"npm registry returned {resp.status} for {name}@{version}")
                return None
            data = await resp.json()

        tarball_url = data.get("dist", {}).get("tarball")
        if not tarball_url:
            logger.warning(f"No tarball URL found for {name}@{version}")
            return None

        filename = f"{name.replace('/', '_')}_{version}.tgz"
        dest_path = dest_dir / filename

        resp = await retry_request(session, "GET", tarball_url, timeout=_DOWNLOAD_TIMEOUT)
        async with resp:
            if resp.status != 200:
                logger.warning(f"Failed to download {tarball_url}")
                return None
            with open(dest_path, "wb") as f:
                async for chunk in resp.content.iter_chunked(65536):
                    f.write(chunk)

        logger.info(f"Downloaded {name}@{version} -> {dest_path}")
        return dest_path

    finally:
        if close_session:
            await session.close()


async def download_package(
    name: str,
    version: str,
    ecosystem: str,
    dest_dir: Path,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[Path]:
    """Download a package from the specified ecosystem."""
    if ecosystem == "pypi":
        return await download_pypi_package(name, version, dest_dir, session)
    elif ecosystem == "npm":
        return await download_npm_package(name, version, dest_dir, session)
    elif ecosystem == "go":
        return await download_go_module(name, version, dest_dir, session)
    elif ecosystem == "cargo":
        return await download_cargo_crate(name, version, dest_dir, session)
    elif ecosystem == "maven":
        return await download_maven_artifact(name, version, dest_dir, session)
    else:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")


async def download_go_module(
    name: str,
    version: str,
    dest_dir: Path,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[Path]:
    """Download a Go module source zip from the module proxy."""
    close_session = session is None
    if session is None:
        session = aiohttp.ClientSession()

    try:
        encoded = name.replace("/", "%2F")
        url = f"https://proxy.golang.org/{encoded}/@v/{version}.zip"
        filename = f"{name.replace('/', '_')}_{version}.zip"
        dest_path = dest_dir / filename

        resp = await retry_request(session, "GET", url, timeout=_DOWNLOAD_TIMEOUT)
        async with resp:
            if resp.status != 200:
                logger.warning(f"Go proxy returned {resp.status} for {name}@{version}")
                return None
            with open(dest_path, "wb") as f:
                async for chunk in resp.content.iter_chunked(65536):
                    f.write(chunk)

        logger.info(f"Downloaded Go module {name}@{version} -> {dest_path}")
        return dest_path

    finally:
        if close_session:
            await session.close()


async def download_cargo_crate(
    name: str,
    version: str,
    dest_dir: Path,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[Path]:
    """Download a Cargo crate from crates.io."""
    close_session = session is None
    if session is None:
        session = aiohttp.ClientSession(headers={"User-Agent": "depvet/0.1.0 (github.com/taku-tez/DepVet)"})

    try:
        url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
        filename = f"{name}-{version}.crate"
        dest_path = dest_dir / filename

        resp = await retry_request(session, "GET", url, timeout=_DOWNLOAD_TIMEOUT)
        async with resp:
            if resp.status != 200:
                logger.warning(f"crates.io returned {resp.status} for {name}-{version}")
                return None
            with open(dest_path, "wb") as f:
                async for chunk in resp.content.iter_chunked(65536):
                    f.write(chunk)

        logger.info(f"Downloaded Cargo crate {name}@{version} -> {dest_path}")
        return dest_path

    finally:
        if close_session:
            await session.close()


MAVEN_REPO_URL = "https://repo1.maven.org/maven2"


def _maven_artifact_url(group_id: str, artifact_id: str, version: str, classifier: str = "", ext: str = "jar") -> str:
    """Build a Maven Central download URL.

    Example: com.google.guava:guava:33.0.0-jre
    → https://repo1.maven.org/maven2/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.jar
    """
    group_path = group_id.replace(".", "/")
    suffix = f"-{classifier}" if classifier else ""
    return f"{MAVEN_REPO_URL}/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}{suffix}.{ext}"


async def download_maven_artifact(
    name: str,
    version: str,
    dest_dir: Path,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[Path]:
    """Download a Maven artifact (sources JAR preferred, plain JAR fallback).

    ``name`` must be ``groupId:artifactId`` format.
    """
    if ":" not in name:
        logger.warning(f"Maven artifact must be 'groupId:artifactId': {name}")
        return None

    group_id, artifact_id = name.split(":", 1)
    close_session = session is None
    if session is None:
        session = aiohttp.ClientSession()

    try:
        # Try sources JAR first (contains actual .java source files for diff)
        sources_url = _maven_artifact_url(group_id, artifact_id, version, classifier="sources")
        resp = await retry_request(session, "GET", sources_url, timeout=_METADATA_TIMEOUT)
        async with resp:
            if resp.status == 200:
                filename = f"{artifact_id}-{version}-sources.jar"
                dest_path = dest_dir / filename
                with open(dest_path, "wb") as f:
                    async for chunk in resp.content.iter_chunked(65536):
                        f.write(chunk)
                logger.info(f"Downloaded Maven sources {name}@{version} -> {dest_path}")
                return dest_path

        # Fallback to plain JAR (contains .class files, less useful for diff
        # but still contains resources, META-INF, and potentially .java/.kt/.scala)
        jar_url = _maven_artifact_url(group_id, artifact_id, version)
        resp = await retry_request(session, "GET", jar_url, timeout=_DOWNLOAD_TIMEOUT)
        async with resp:
            if resp.status != 200:
                logger.warning(f"Maven Central returned {resp.status} for {name}@{version}")
                return None
            filename = f"{artifact_id}-{version}.jar"
            dest_path = dest_dir / filename
            with open(dest_path, "wb") as f:
                async for chunk in resp.content.iter_chunked(65536):
                    f.write(chunk)

        logger.info(f"Downloaded Maven JAR {name}@{version} -> {dest_path}")
        return dest_path

    finally:
        if close_session:
            await session.close()
