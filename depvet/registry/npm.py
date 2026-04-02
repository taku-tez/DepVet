"""npm registry watcher using CouchDB _changes feed."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from depvet.models.package import Release
from depvet.registry.base import BaseRegistry
from depvet.registry.state import RegistryState

logger = logging.getLogger(__name__)

CHANGES_URL = "https://replicate.npmjs.com/_changes"
REGISTRY_URL = "https://registry.npmjs.org"

MAX_SEQ_GAP = 10_000


class NpmRegistry(BaseRegistry):
    """
    Watches npm for new package releases using the CouchDB _changes feed.

    State keys:
        npm_seq (str):   The last-seen CouchDB sequence identifier.
        npm_epoch (int): Epoch counter; bumped when the sequence is reset.
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
        """Poll the npm _changes feed for new releases."""
        seq: str = self._state.get("npm_seq", "now")
        epoch: int = self._state.get("npm_epoch", 0)

        session = await self._ensure_session()
        params = {
            "since": seq,
            "limit": 500,
            "include_docs": "true",
        }

        try:
            async with session.get(
                CHANGES_URL,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    logger.warning(f"npm _changes returned {resp.status}")
                    return []
                data = await resp.json(content_type=None)
        except Exception as e:
            logger.error(f"npm _changes feed failed: {e}")
            return []

        results = data.get("results", [])
        if not results:
            return []

        new_seq = str(results[-1].get("seq", seq))

        # Detect sequence reset: if the numeric portion of the seq jumps
        # backwards by more than MAX_SEQ_GAP, bump the epoch and start fresh.
        try:
            old_num = int(str(seq).split("-")[0]) if seq != "now" else 0
            new_num = int(str(new_seq).split("-")[0])
            if new_num < old_num - MAX_SEQ_GAP:
                epoch += 1
                logger.warning(
                    f"npm sequence reset detected ({old_num} -> {new_num}), "
                    f"bumping epoch to {epoch}"
                )
        except (ValueError, IndexError):
            pass

        releases: list[Release] = []

        for row in results:
            doc = row.get("doc", {})
            name = doc.get("name", "")
            if not name:
                continue

            dist_tags = doc.get("dist-tags", {})
            latest = dist_tags.get("latest")
            if not latest:
                continue

            versions = doc.get("versions", {})
            version_list = sorted(versions.keys())
            if latest not in version_list:
                continue

            idx = version_list.index(latest)
            prev = version_list[idx - 1] if idx > 0 else None

            time_data = doc.get("time", {})
            published_at_raw = time_data.get(latest, "")
            try:
                published_at = datetime.fromisoformat(
                    published_at_raw.replace("Z", "+00:00")
                ).isoformat()
            except Exception:
                published_at = datetime.now(timezone.utc).isoformat()

            releases.append(Release(
                name=name,
                version=latest,
                ecosystem="npm",
                previous_version=prev,
                published_at=published_at,
                url=f"https://www.npmjs.com/package/{name}/v/{latest}",
            ))

        self._state.set("npm_seq", new_seq)
        self._state.set("npm_epoch", epoch)
        return releases

    async def get_versions(self, package_name: str) -> list[str]:
        """Get all versions of a package from the npm registry."""
        session = await self._ensure_session()
        url = f"{REGISTRY_URL}/{package_name}"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
            return sorted(data.get("versions", {}).keys())
        except Exception as e:
            logger.error(f"Failed to get versions for {package_name}: {e}")
            return []

    async def close(self) -> None:
        """Clean up the aiohttp session if we own it."""
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()

    async def load_top_packages(self, n: int = 100) -> list[str]:
        """Load top N npm packages by searching the registry."""
        session = await self._ensure_session()
        url = f"{REGISTRY_URL}/-/v1/search"
        params = {"text": "", "size": min(n, 250), "from": 0}
        try:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
            objects = data.get("objects", [])
            return [obj["package"]["name"] for obj in objects]
        except Exception as e:
            logger.error(f"Failed to load top npm packages: {e}")
            return []
