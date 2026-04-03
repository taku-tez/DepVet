"""Package downloader for PyPI and npm."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

PYPI_JSON_API = "https://pypi.org/pypi/{name}/{version}/json"
NPM_REGISTRY_URL = "https://registry.npmjs.org/{name}/{version}"


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
        async with session.get(url) as resp:
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

        async with session.get(file_url) as resp:
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

        async with session.get(url) as resp:
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

        async with session.get(tarball_url) as resp:
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
        raise NotImplementedError(
            f"Maven package download is not yet implemented. "
            f"Cannot download {name}=={version} from Maven Central. "
            "Maven support is limited to SBOM import and watchlist tracking."
        )
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

        async with session.get(url) as resp:
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
        session = aiohttp.ClientSession(
            headers={"User-Agent": "depvet/0.1.0 (github.com/taku-tez/DepVet)"}
        )

    try:
        url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
        filename = f"{name}-{version}.crate"
        dest_path = dest_dir / filename

        async with session.get(url) as resp:
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
