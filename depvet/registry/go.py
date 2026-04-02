"""Go Modules registry monitor using proxy.golang.org."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from depvet.models.package import Release
from depvet.registry.base import BaseRegistryMonitor

logger = logging.getLogger(__name__)

# Go module proxy endpoints
GOPROXY_URL = "https://proxy.golang.org"
SUMDB_URL = "https://sum.golang.org"

# Note: Go doesn't have a simple "changelog" API like PyPI/npm.
# We poll the module proxy for specific modules in the watchlist.
# State: {"checked_at": ISO8601 per module}


class GoModulesMonitor(BaseRegistryMonitor):
    """
    Monitors Go module proxy for new releases.

    Since Go doesn't have a registry-level feed, we poll each module
    in the watchlist individually via proxy.golang.org/@v/list.

    State format: {"modules": {"<module_path>": "<last_version>"}}
    """

    @property
    def ecosystem(self) -> str:
        return "go"

    async def get_new_releases(
        self,
        watchlist: set[str],
        since_state: dict,
    ) -> tuple[list[Release], dict]:
        if not watchlist:
            return [], since_state

        known_versions: dict[str, str] = since_state.get("modules", {})
        releases: list[Release] = []
        new_known: dict[str, str] = dict(known_versions)

        async with aiohttp.ClientSession() as session:
            for module in watchlist:
                try:
                    versions = await self._list_versions(module, session)
                    if not versions:
                        continue

                    latest = versions[-1]
                    prev = known_versions.get(module)

                    if prev is None:
                        # First time seeing this module; record latest but don't alert
                        new_known[module] = latest
                        continue

                    if latest != prev:
                        # New version appeared
                        prev_ver = prev
                        info = await self._get_version_info(module, latest, session)
                        published_at = info.get("Time", datetime.now(timezone.utc).isoformat())

                        releases.append(Release(
                            name=module,
                            version=latest,
                            ecosystem="go",
                            previous_version=prev_ver,
                            published_at=published_at,
                            url=f"https://pkg.go.dev/{module}@{latest}",
                        ))
                        new_known[module] = latest

                except Exception as e:
                    logger.warning(f"Failed to check Go module {module}: {e}")

        return releases, {"modules": new_known}

    async def load_top_n(self, n: int) -> list[str]:
        """
        Go doesn't have a direct "top N" API.
        Return a curated list of popular modules.
        """
        popular = [
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
        return popular[:n]

    async def _list_versions(
        self, module: str, session: aiohttp.ClientSession
    ) -> list[str]:
        """List available versions for a Go module."""
        encoded = module.replace("/", "%2F")
        url = f"{GOPROXY_URL}/{encoded}/@v/list"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 410:
                return []  # Module not found or retracted
            if resp.status != 200:
                logger.debug(f"Go proxy returned {resp.status} for {module}")
                return []
            text = await resp.text()
        versions = [v.strip() for v in text.strip().splitlines() if v.strip()]
        return sorted(versions)

    async def _get_version_info(
        self, module: str, version: str, session: aiohttp.ClientSession
    ) -> dict:
        """Get version info (timestamp etc.) from Go proxy."""
        encoded_mod = module.replace("/", "%2F")
        url = f"{GOPROXY_URL}/{encoded_mod}/@v/{version}.info"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.json(content_type=None)
        except Exception:
            pass
        return {}
