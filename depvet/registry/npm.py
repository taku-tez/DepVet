"""npm registry monitor using CouchDB _changes feed."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import aiohttp

from depvet.http import retry_request
from depvet.models.package import Release
from depvet.registry.base import BaseRegistryMonitor
from depvet.registry.versioning import sort_versions

logger = logging.getLogger(__name__)

CHANGES_URL = "https://replicate.npmjs.com/_changes"
REGISTRY_URL = "https://registry.npmjs.org/{name}"
TOP_PACKAGES_URL = "https://registry.npmjs.org/-/v1/search?text=&size={n}&from=0"
MAX_SEQ_GAP = 10_000

_CHANGES_TIMEOUT = aiohttp.ClientTimeout(total=30)
_TIMEOUT = aiohttp.ClientTimeout(total=15)


class NpmMonitor(BaseRegistryMonitor):
    """Monitors npm for new package releases via CouchDB _changes feed."""

    @property
    def ecosystem(self) -> str:
        return "npm"

    async def get_new_releases(self, watchlist, since_state):
        seq = since_state.get("seq", "now")
        params = {"since": seq, "limit": 500, "include_docs": "true"}
        releases = []
        new_seq = seq
        try:
            async with aiohttp.ClientSession() as session:
                resp = await retry_request(
                    session,
                    "GET",
                    CHANGES_URL,
                    params=params,
                    timeout=_CHANGES_TIMEOUT,
                )
                async with resp:
                    if resp.status != 200:
                        logger.warning(f"npm _changes returned {resp.status}")
                        return [], since_state
                    data = await resp.json(content_type=None)
        except Exception as e:
            logger.error(f"npm _changes feed failed: {e}")
            return [], since_state
        results = data.get("results", [])
        if results:
            new_seq = str(results[-1].get("seq", seq))
        for row in results:
            doc = row.get("doc", {})
            name = doc.get("name", "")
            if not name or name not in watchlist:
                continue
            dist_tags = doc.get("dist-tags", {})
            latest = dist_tags.get("latest")
            if not latest:
                continue
            versions = sort_versions(list(doc.get("versions", {}).keys()), "npm")
            if latest not in versions:
                continue
            idx = versions.index(latest)
            prev = versions[idx - 1] if idx > 0 else None
            time_data = doc.get("time", {})
            published_raw = time_data.get(latest, "")
            try:
                published_at = datetime.fromisoformat(published_raw.replace("Z", "+00:00")).isoformat()
            except Exception:
                published_at = datetime.now(timezone.utc).isoformat()
            releases.append(
                Release(
                    name=name,
                    version=latest,
                    ecosystem="npm",
                    previous_version=prev,
                    published_at=published_at,
                    url=f"https://www.npmjs.com/package/{name}/v/{latest}",
                )
            )
        return releases, {"seq": new_seq, "epoch": 0}

    async def load_top_n(self, n):
        url = TOP_PACKAGES_URL.format(n=min(n, 250))
        try:
            async with aiohttp.ClientSession() as session:
                resp = await retry_request(session, "GET", url, timeout=_TIMEOUT)
                async with resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json(content_type=None)
            return [obj["package"]["name"] for obj in data.get("objects", [])]
        except Exception as e:
            logger.error(f"Failed to load top npm packages: {e}")
            return []
