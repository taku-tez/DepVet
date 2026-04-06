"""Maven Central registry monitor."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from depvet.http import retry_request
from depvet.models.package import Release
from depvet.registry.base import BaseRegistryMonitor

logger = logging.getLogger(__name__)

# Maven Central REST API
SEARCH_API = "https://search.maven.org/solrsearch/select"
ARTIFACT_API = "https://repo1.maven.org/maven2"
RECENT_API = "https://search.maven.org/solrsearch/select?q=*&rows=20&wt=json&sort=timestamp+desc"

_TIMEOUT = aiohttp.ClientTimeout(total=15)
# Max concurrent version fetches per poll cycle
_MAX_CONCURRENT_CHECKS = 20


class MavenMonitor(BaseRegistryMonitor):
    """
    Monitors Maven Central for new artifact releases.

    Watchlist format: "groupId:artifactId" (e.g., "com.fasterxml.jackson.core:jackson-databind")
    Artifacts are checked in parallel (up to _MAX_CONCURRENT_CHECKS).
    State format: {"artifacts": {"<groupId:artifactId>": "<last_version>"}}
    """

    @property
    def ecosystem(self) -> str:
        return "maven"

    async def get_new_releases(
        self,
        watchlist: set[str],
        since_state: dict,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> tuple[list[Release], dict]:
        if not watchlist:
            return [], since_state

        known_versions: dict[str, str] = since_state.get("artifacts", {})
        releases: list[Release] = []
        new_known: dict[str, str] = dict(known_versions)

        close_session = session is None
        if session is None:
            session = aiohttp.ClientSession()

        sem = asyncio.Semaphore(_MAX_CONCURRENT_CHECKS)

        async def _check_one(artifact: str) -> None:
            async with sem:
                if ":" not in artifact:
                    logger.warning(f"Maven artifact should be 'groupId:artifactId': {artifact}")
                    return
                group_id, artifact_id = artifact.split(":", 1)
                try:
                    versions = await self._get_versions(group_id, artifact_id, session)
                    if not versions:
                        return

                    latest = versions[0]
                    prev_known = known_versions.get(artifact)

                    if prev_known is None:
                        new_known[artifact] = latest["version"]
                        return

                    if latest["version"] != prev_known:
                        prev_version = versions[1]["version"] if len(versions) > 1 else prev_known
                        ts = latest.get("timestamp", 0)
                        published_at = (
                            datetime.fromtimestamp(ts / 1000, tz=timezone.utc).isoformat()
                            if ts
                            else datetime.now(timezone.utc).isoformat()
                        )
                        releases.append(
                            Release(
                                name=artifact,
                                version=latest["version"],
                                ecosystem="maven",
                                previous_version=prev_version,
                                published_at=published_at,
                                url=f"https://search.maven.org/artifact/{group_id}/{artifact_id}/{latest['version']}/jar",
                            )
                        )
                        new_known[artifact] = latest["version"]

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.warning(f"Failed to check Maven artifact {artifact}: {e}")

        try:
            await asyncio.gather(*[_check_one(a) for a in watchlist])
        finally:
            if close_session:
                await session.close()

        return releases, {"artifacts": new_known}

    async def load_top_n(self, n: int, session: Optional[aiohttp.ClientSession] = None) -> list[str]:
        """Return popular Maven artifacts."""
        popular = [
            "com.fasterxml.jackson.core:jackson-databind",
            "org.springframework:spring-core",
            "org.springframework.boot:spring-boot",
            "com.google.guava:guava",
            "org.apache.commons:commons-lang3",
            "org.slf4j:slf4j-api",
            "junit:junit",
            "org.mockito:mockito-core",
            "org.apache.logging.log4j:log4j-core",
            "io.netty:netty-all",
            "org.apache.httpcomponents:httpclient",
            "commons-io:commons-io",
            "com.google.code.gson:gson",
            "org.bouncycastle:bcprov-jdk15on",
            "org.yaml:snakeyaml",
        ]
        return popular[:n]

    async def _get_versions(self, group_id: str, artifact_id: str, session: aiohttp.ClientSession) -> list[dict]:
        """Get version list from Maven Central search API."""
        params = {
            "q": f"g:{group_id}+AND+a:{artifact_id}",
            "core": "gav",
            "rows": "20",
            "wt": "json",
        }
        resp = await retry_request(session, "GET", SEARCH_API, params=params, timeout=_TIMEOUT)
        async with resp:
            if resp.status != 200:
                logger.warning(f"Maven search API returned {resp.status}")
                return []
            data = await resp.json(content_type=None)

        docs = data.get("response", {}).get("docs", [])
        return sorted(docs, key=lambda d: d.get("timestamp", 0), reverse=True)
