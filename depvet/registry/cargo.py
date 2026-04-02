"""Cargo (Rust) registry monitor using crates.io API."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from depvet.models.package import Release
from depvet.registry.base import BaseRegistryMonitor

logger = logging.getLogger(__name__)

CRATES_IO_API = "https://crates.io/api/v1"
CRATES_IO_ACTIVITY = "https://crates.io/api/v1/summary"

# User-Agent required by crates.io policy
DEFAULT_UA = "depvet/0.1.0 (github.com/taku-tez/DepVet)"


class CargoMonitor(BaseRegistryMonitor):
    """
    Monitors crates.io for new Cargo package releases.

    Uses the crates.io REST API to check for new versions.
    State format: {"crates": {"<name>": "<last_version>"}}

    Note: crates.io requires a User-Agent header.
    """

    def __init__(self, user_agent: str = DEFAULT_UA):
        self._user_agent = user_agent

    @property
    def ecosystem(self) -> str:
        return "cargo"

    def _headers(self) -> dict:
        return {"User-Agent": self._user_agent}

    async def get_new_releases(
        self,
        watchlist: set[str],
        since_state: dict,
    ) -> tuple[list[Release], dict]:
        if not watchlist:
            return [], since_state

        known_versions: dict[str, str] = since_state.get("crates", {})
        releases: list[Release] = []
        new_known: dict[str, str] = dict(known_versions)

        async with aiohttp.ClientSession(headers=self._headers()) as session:
            for crate in watchlist:
                try:
                    versions = await self._get_versions(crate, session)
                    if not versions:
                        continue

                    # Versions are sorted newest first from crates.io
                    latest = versions[0]
                    prev_known = known_versions.get(crate)

                    if prev_known is None:
                        new_known[crate] = latest["num"]
                        continue

                    if latest["num"] != prev_known:
                        # Find previous version (second in list, or prev_known)
                        prev_version = versions[1]["num"] if len(versions) > 1 else prev_known

                        releases.append(Release(
                            name=crate,
                            version=latest["num"],
                            ecosystem="cargo",
                            previous_version=prev_version,
                            published_at=latest.get("created_at", datetime.now(timezone.utc).isoformat()),
                            url=f"https://crates.io/crates/{crate}/{latest['num']}",
                        ))
                        new_known[crate] = latest["num"]

                except Exception as e:
                    logger.warning(f"Failed to check Cargo crate {crate}: {e}")

        return releases, {"crates": new_known}

    async def load_top_n(self, n: int) -> list[str]:
        """Load top N crates by recent downloads from crates.io."""
        url = f"{CRATES_IO_API}/crates?sort=downloads&per_page={min(n, 100)}"
        try:
            async with aiohttp.ClientSession(headers=self._headers()) as session:
                page = 1
                results = []
                while len(results) < n:
                    params = {"sort": "downloads", "per_page": 100, "page": page}
                    async with session.get(
                        f"{CRATES_IO_API}/crates",
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status != 200:
                            break
                        data = await resp.json()
                    crates = data.get("crates", [])
                    if not crates:
                        break
                    results.extend(c["name"] for c in crates)
                    page += 1
                    if len(crates) < 100:
                        break
                return results[:n]
        except Exception as e:
            logger.error(f"Failed to load top Cargo crates: {e}")
            return []

    async def _get_versions(
        self, crate: str, session: aiohttp.ClientSession
    ) -> list[dict]:
        """Get version list for a crate (newest first, non-yanked)."""
        url = f"{CRATES_IO_API}/crates/{crate}/versions"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 404:
                logger.debug(f"Crate not found: {crate}")
                return []
            if resp.status != 200:
                logger.warning(f"crates.io returned {resp.status} for {crate}")
                return []
            data = await resp.json()

        versions = [v for v in data.get("versions", []) if not v.get("yanked", False)]
        return versions  # Already sorted newest first by crates.io
