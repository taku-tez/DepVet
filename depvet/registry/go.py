"""Go Modules registry monitor using proxy.golang.org."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from depvet.http import retry_request
from depvet.models.package import Release
from depvet.registry.base import BaseRegistryMonitor
from depvet.registry.versioning import sort_versions

logger = logging.getLogger(__name__)

# Go module proxy endpoints
GOPROXY_URL = "https://proxy.golang.org"
SUMDB_URL = "https://sum.golang.org"

_TIMEOUT = aiohttp.ClientTimeout(total=10)
# Max concurrent version-list fetches per poll cycle
_MAX_CONCURRENT_CHECKS = 20


class GoModulesMonitor(BaseRegistryMonitor):
    """
    Monitors Go module proxy for new releases.

    Since Go doesn't have a registry-level feed, we poll each module
    in the watchlist individually via proxy.golang.org/@v/list.
    Modules are checked in parallel (up to _MAX_CONCURRENT_CHECKS).

    State format: {"modules": {"<module_path>": "<last_version>"}}
    """

    @property
    def ecosystem(self) -> str:
        return "go"

    async def get_new_releases(
        self,
        watchlist: set[str],
        since_state: dict,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> tuple[list[Release], dict]:
        if not watchlist:
            return [], since_state

        known_versions: dict[str, str] = since_state.get("modules", {})
        releases: list[Release] = []
        new_known: dict[str, str] = dict(known_versions)

        close_session = session is None
        if session is None:
            session = aiohttp.ClientSession()

        sem = asyncio.Semaphore(_MAX_CONCURRENT_CHECKS)

        async def _check_one(module: str) -> None:
            async with sem:
                try:
                    versions = await self._list_versions(module, session)
                    if not versions:
                        return

                    latest = versions[-1]
                    prev = known_versions.get(module)

                    if prev is None:
                        new_known[module] = latest
                        return

                    if latest != prev:
                        info = await self._get_version_info(module, latest, session)
                        published_at = info.get("Time", datetime.now(timezone.utc).isoformat())
                        releases.append(
                            Release(
                                name=module,
                                version=latest,
                                ecosystem="go",
                                previous_version=prev,
                                published_at=published_at,
                                url=f"https://pkg.go.dev/{module}@{latest}",
                            )
                        )
                        new_known[module] = latest

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.warning(f"Failed to check Go module {module}: {e}")

        try:
            await asyncio.gather(*[_check_one(m) for m in watchlist])
        finally:
            if close_session:
                await session.close()

        return releases, {"modules": new_known}

    # Fallback list when the search API is unavailable
    _POPULAR_FALLBACK = [
        "github.com/gin-gonic/gin",
        "github.com/gorilla/mux",
        "github.com/stretchr/testify",
        "github.com/spf13/cobra",
        "github.com/spf13/viper",
        "github.com/uber-go/zap",
        "github.com/sirupsen/logrus",
        "github.com/pkg/errors",
        "github.com/go-redis/redis",
        "gorm.io/gorm",
        "github.com/golang/protobuf",
        "google.golang.org/grpc",
        "github.com/aws/aws-sdk-go",
        "github.com/docker/docker",
        "k8s.io/client-go",
        "github.com/hashicorp/vault",
        "github.com/prometheus/client_golang",
        "go.opentelemetry.io/otel",
        "github.com/google/uuid",
        "github.com/go-chi/chi",
    ]

    async def load_top_n(self, n: int, session: Optional[aiohttp.ClientSession] = None) -> list[str]:
        """Load top Go modules by import count from pkg.go.dev search API.

        Falls back to a curated list if the API is unavailable.
        """
        close_session = session is None
        if session is None:
            session = aiohttp.ClientSession()
        try:
            results: list[str] = []
            for query in ("", "github.com", "google.golang.org", "go.uber.org"):
                if len(results) >= n:
                    break
                url = "https://pkg.go.dev/search"
                params = {"q": query, "m": "package", "limit": min(n, 100)}
                resp = await retry_request(session, "GET", url, params=params, timeout=_TIMEOUT)
                async with resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text()
                import re

                for m in re.finditer(r'data-href="/(?:mod/)?([^"@?]+)"', text):
                    mod = m.group(1).strip("/")
                    if mod and mod not in results and "." in mod:
                        results.append(mod)
                        if len(results) >= n:
                            break
            if results:
                return results[:n]
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning("Failed to fetch Go top-N from pkg.go.dev: %s", e)
        finally:
            if close_session:
                await session.close()

        return self._POPULAR_FALLBACK[:n]

    async def _list_versions(self, module: str, session: aiohttp.ClientSession) -> list[str]:
        """List available versions for a Go module."""
        encoded = module.replace("/", "%2F")
        url = f"{GOPROXY_URL}/{encoded}/@v/list"
        resp = await retry_request(session, "GET", url, timeout=_TIMEOUT)
        async with resp:
            if resp.status == 410:
                return []
            if resp.status != 200:
                logger.debug(f"Go proxy returned {resp.status} for {module}")
                return []
            text = await resp.text()
        versions = [v.strip() for v in text.strip().splitlines() if v.strip()]
        return sort_versions(versions, "go")

    async def _get_version_info(self, module: str, version: str, session: aiohttp.ClientSession) -> dict:
        """Get version info (timestamp etc.) from Go proxy."""
        encoded_mod = module.replace("/", "%2F")
        url = f"{GOPROXY_URL}/{encoded_mod}/@v/{version}.info"
        try:
            resp = await retry_request(session, "GET", url, timeout=_TIMEOUT)
            async with resp:
                if resp.status == 200:
                    return await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return {}
