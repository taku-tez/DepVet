"""Top-N packages watchlist source."""

from __future__ import annotations

import asyncio
import logging
import time

import aiohttp

logger = logging.getLogger(__name__)


class TopNSource:
    """Fetches and caches top-N packages from registries."""

    def __init__(self, refresh_interval: int = 86400):
        self._refresh_interval = refresh_interval
        self._cache: dict[str, list[str]] = {}
        self._last_refresh: dict[str, float] = {}

    async def get(self, ecosystem: str, n: int, monitor=None) -> set[str]:
        now = time.time()
        last = self._last_refresh.get(ecosystem, 0)
        if ecosystem not in self._cache or (now - last) > self._refresh_interval:
            if monitor is not None:
                try:
                    pkgs = await monitor.load_top_n(n)
                    self._cache[ecosystem] = pkgs
                    self._last_refresh[ecosystem] = now
                    logger.info(f"Refreshed top-{n} {ecosystem} packages")
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.error(f"Failed to refresh top-{n} {ecosystem}: {e}")
                    if ecosystem not in self._cache:
                        return set()
            else:
                return set()
        return set(self._cache.get(ecosystem, [])[:n])

    def is_stale(self, ecosystem: str) -> bool:
        last = self._last_refresh.get(ecosystem, 0)
        return (time.time() - last) > self._refresh_interval
