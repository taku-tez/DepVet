"""PyPI registry monitor using XML-RPC changelog_since_serial."""

from __future__ import annotations

import asyncio
import logging
import xmlrpc.client  # nosec B411 — PyPI official endpoint, no untrusted XML
from datetime import datetime, timezone

import aiohttp

from depvet.http import retry_request, retry_sync
from depvet.models.package import Release
from depvet.registry.base import BaseRegistryMonitor
from depvet.registry.versioning import sort_versions

logger = logging.getLogger(__name__)

XMLRPC_ENDPOINT = "https://pypi.org/pypi"
JSON_API = "https://pypi.org/pypi/{name}/{version}/json"
TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

_TIMEOUT = aiohttp.ClientTimeout(total=15)


class PyPIMonitor(BaseRegistryMonitor):
    """Monitors PyPI for new package releases via XML-RPC changelog API."""

    @property
    def ecosystem(self) -> str:
        return "pypi"

    async def get_new_releases(self, watchlist, since_state):
        serial = since_state.get("serial", 0)
        if serial == 0:
            serial = await self._get_current_serial()
        events = await self._changelog_since_serial(serial)
        if not events:
            return [], {"serial": serial}
        new_serial = max(int(e[3]) for e in events)
        releases = []
        seen = set()
        for name, version, ts, event_serial, action in events:
            if action != "new release" or name not in watchlist:
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            prev = await self._get_previous_version(name, version)
            published_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            releases.append(
                Release(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    previous_version=prev,
                    published_at=published_at,
                    url=f"https://pypi.org/project/{name}/{version}/",
                )
            )
        return releases, {"serial": new_serial}

    async def load_top_n(self, n):
        try:
            async with aiohttp.ClientSession() as session:
                resp = await retry_request(
                    session,
                    "GET",
                    TOP_PACKAGES_URL,
                    timeout=_TIMEOUT,
                )
                async with resp:
                    data = await resp.json(content_type=None)
            rows = data.get("rows", [])
            return [r["project"] for r in rows[:n]]
        except Exception as e:
            logger.error(f"Failed to load top PyPI packages: {e}")
            return []

    async def _get_current_serial(self):
        loop = asyncio.get_event_loop()
        client = xmlrpc.client.ServerProxy(XMLRPC_ENDPOINT)
        try:
            serial = await loop.run_in_executor(
                None,
                lambda: retry_sync(client.changelog_last_serial),
            )
            return int(serial)
        except Exception as e:
            logger.warning(f"Failed to get current serial: {e}")
            return 0

    async def _changelog_since_serial(self, serial):
        loop = asyncio.get_event_loop()
        client = xmlrpc.client.ServerProxy(XMLRPC_ENDPOINT)
        try:
            events = await loop.run_in_executor(
                None,
                lambda: retry_sync(client.changelog_since_serial, serial),
            )
            return events or []
        except Exception as e:
            logger.error(f"PyPI changelog_since_serial failed: {e}")
            return []

    async def _get_previous_version(self, name, version):
        try:
            url = f"https://pypi.org/pypi/{name}/json"
            async with aiohttp.ClientSession() as session:
                resp = await retry_request(session, "GET", url, timeout=_TIMEOUT)
                async with resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
            releases = sort_versions(list(data.get("releases", {}).keys()), "pypi")
            if version in releases:
                idx = releases.index(version)
                if idx > 0:
                    return releases[idx - 1]
        except Exception as e:
            logger.debug(f"Could not get previous version for {name}=={version}: {e}")
        return None
