"""PyPI registry watcher using XML-RPC changelog_since_serial."""
from __future__ import annotations

import asyncio
import logging
import xmlrpc.client
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from depvet.models.package import Release
from depvet.registry.base import BaseRegistry
from depvet.registry.state import RegistryState

logger = logging.getLogger(__name__)

XMLRPC_ENDPOINT = "https://pypi.org/pypi"
JSON_API = "https://pypi.org/pypi/{name}/{version}/json"
TOP_PACKAGES_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
)


class PyPIRegistry(BaseRegistry):
    """
    Watches PyPI for new package releases using the XML-RPC changelog API.

    State keys:
        pypi_serial (int): The last-seen changelog serial number.
    """

    def __init__(self, state: RegistryState, session: Optional[aiohttp.ClientSession] = None):
        self._state = state
        self._session = session
        self._owns_session = session is None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
            self._owns_session = True
        return self._session

    async def poll(self) -> list[Release]:
        """Poll PyPI for new releases since the last known serial."""
        serial: int = self._state.get("pypi_serial", 0)

        if serial == 0:
            serial = await self._get_current_serial()
            self._state.set("pypi_serial", serial)
            return []

        events = await self._changelog_since_serial(serial)
        if not events:
            return []

        new_serial = max(int(e[3]) for e in events)

        releases: list[Release] = []
        seen: set[tuple[str, str]] = set()

        for name, version, ts, event_serial, action in events:
            if action != "new release":
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)

            prev = await self._get_previous_version(name, version)
            published_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

            releases.append(Release(
                name=name,
                version=version,
                ecosystem="pypi",
                previous_version=prev,
                published_at=published_at,
                url=f"https://pypi.org/project/{name}/{version}/",
            ))

        self._state.set("pypi_serial", new_serial)
        return releases

    async def get_versions(self, package_name: str) -> list[str]:
        """Get all versions of a package from PyPI JSON API."""
        session = await self._ensure_session()
        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
            return sorted(data.get("releases", {}).keys())
        except Exception as e:
            logger.error(f"Failed to get versions for {package_name}: {e}")
            return []

    async def close(self) -> None:
        """Clean up the aiohttp session if we own it."""
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_current_serial(self) -> int:
        """Fetch the current changelog serial from PyPI XML-RPC."""
        loop = asyncio.get_event_loop()
        client = xmlrpc.client.ServerProxy(XMLRPC_ENDPOINT)
        try:
            serial = await loop.run_in_executor(None, client.changelog_last_serial)
            return int(serial)
        except Exception as e:
            logger.warning(f"Failed to get current serial: {e}")
            return 0
        finally:
            try:
                client("close")()  # type: ignore[operator]
            except Exception:
                pass

    async def _changelog_since_serial(self, serial: int) -> list:
        """Fetch changelog events since the given serial via XML-RPC."""
        loop = asyncio.get_event_loop()
        client = xmlrpc.client.ServerProxy(XMLRPC_ENDPOINT)
        try:
            events = await loop.run_in_executor(
                None,
                lambda: client.changelog_since_serial(serial),
            )
            return events or []
        except Exception as e:
            logger.error(f"PyPI changelog_since_serial failed: {e}")
            return []
        finally:
            try:
                client("close")()  # type: ignore[operator]
            except Exception:
                pass

    async def _get_previous_version(self, name: str, version: str) -> Optional[str]:
        """Fetch the version just before the given version from PyPI."""
        try:
            versions = await self.get_versions(name)
            if version in versions:
                idx = versions.index(version)
                if idx > 0:
                    return versions[idx - 1]
        except Exception as e:
            logger.debug(f"Could not get previous version for {name}=={version}: {e}")
        return None

    async def load_top_packages(self, n: int = 100) -> list[str]:
        """Load the top N PyPI packages by download count."""
        session = await self._ensure_session()
        try:
            async with session.get(TOP_PACKAGES_URL) as resp:
                data = await resp.json(content_type=None)
            rows = data.get("rows", [])
            return [r["project"] for r in rows[:n]]
        except Exception as e:
            logger.error(f"Failed to load top PyPI packages: {e}")
            return []
