"""Maven Central registry monitor."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import aiohttp

from depvet.models.package import Release
from depvet.registry.base import BaseRegistryMonitor

logger = logging.getLogger(__name__)

# Maven Central REST API
SEARCH_API = "https://search.maven.org/solrsearch/select"
ARTIFACT_API = "https://repo1.maven.org/maven2"
# Maven recent activity feed
RECENT_API = "https://search.maven.org/solrsearch/select?q=*&rows=20&wt=json&sort=timestamp+desc"


class MavenMonitor(BaseRegistryMonitor):
    """
    Monitors Maven Central for new artifact releases.

    Watchlist format: "groupId:artifactId" (e.g., "com.fasterxml.jackson.core:jackson-databind")
    State format: {"artifacts": {"<groupId:artifactId>": "<last_version>"}}
    """

    @property
    def ecosystem(self) -> str:
        return "maven"

    async def get_new_releases(
        self,
        watchlist: set[str],
        since_state: dict,
    ) -> tuple[list[Release], dict]:
        if not watchlist:
            return [], since_state

        known_versions: dict[str, str] = since_state.get("artifacts", {})
        releases: list[Release] = []
        new_known: dict[str, str] = dict(known_versions)

        async with aiohttp.ClientSession() as session:
            for artifact in watchlist:
                if ":" not in artifact:
                    logger.warning(f"Maven artifact should be 'groupId:artifactId': {artifact}")
                    continue
                group_id, artifact_id = artifact.split(":", 1)
                try:
                    versions = await self._get_versions(group_id, artifact_id, session)
                    if not versions:
                        continue

                    latest = versions[0]  # newest first
                    prev_known = known_versions.get(artifact)

                    if prev_known is None:
                        new_known[artifact] = latest["version"]
                        continue

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

        return releases, {"artifacts": new_known}

    async def load_top_n(self, n: int) -> list[str]:
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
        async with session.get(SEARCH_API, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                logger.warning(f"Maven search API returned {resp.status}")
                return []
            data = await resp.json(content_type=None)

        docs = data.get("response", {}).get("docs", [])
        return sorted(docs, key=lambda d: d.get("timestamp", 0), reverse=True)
