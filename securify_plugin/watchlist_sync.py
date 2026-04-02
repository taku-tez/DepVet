"""SBOM-to-watchlist synchronization job for Securify integration."""

from __future__ import annotations

import logging
from typing import Optional

from depvet.watchlist.manager import WatchlistManager
from depvet.watchlist.sbom import SBOMParser

logger = logging.getLogger(__name__)


class WatchlistSyncJob:
    """
    Securify background job: syncs DepVet watchlists from tenant SBOMs.

    Triggered when:
    - A new SBOM scan completes (on_sbom_scan_complete)
    - Periodically to refresh watchlists (refresh)

    The watchlist is maintained per-tenant.
    """

    def __init__(
        self,
        watchlist_manager: Optional[WatchlistManager] = None,
        sbom_parser: Optional[SBOMParser] = None,
        tenant_registry=None,  # Securify tenant store
    ):
        self._wl = watchlist_manager or WatchlistManager()
        self._parser = sbom_parser or SBOMParser()
        self._tenant_registry = tenant_registry
        # tenant_id -> set of (package_name, ecosystem, version)
        self._tenant_packages: dict[str, set[tuple[str, str, str]]] = {}

    async def on_sbom_scan_complete(
        self, tenant_id: str, sbom_path: str
    ) -> int:
        """
        Called when Securify completes a SBOM scan for a tenant.
        Returns number of packages added to watchlist.
        """
        entries = self._parser.parse(sbom_path)
        pkg_set: set[tuple[str, str, str]] = set()

        for entry in entries:
            self._wl.add(entry.name, entry.ecosystem)
            pkg_set.add((entry.name, entry.ecosystem, entry.current_version))

        self._tenant_packages[tenant_id] = pkg_set
        logger.info(f"[WatchlistSync] Tenant {tenant_id}: {len(entries)} packages synced from SBOM")
        return len(entries)

    async def find_tenants_using(
        self, package_name: str, ecosystem: str, version: str
    ) -> list[dict]:
        """
        Find tenants whose SBOM includes the specified package.
        Returns list of tenant dicts with at least {"id": str}.
        """
        affected = []
        for tenant_id, pkgs in self._tenant_packages.items():
            for (pkg, eco, ver) in pkgs:
                if pkg == package_name and eco == ecosystem:
                    # Version match: exact or wildcard
                    if ver == version or ver == "" or not ver:
                        affected.append({"id": tenant_id})
                        break
        return affected

    def tenant_package_count(self, tenant_id: str) -> int:
        return len(self._tenant_packages.get(tenant_id, set()))
