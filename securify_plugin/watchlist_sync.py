"""SBOM-to-watchlist synchronization job for Securify integration."""

from __future__ import annotations

import logging
import re
from pathlib import Path
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
        tenant_storage_dir: str | Path | None = None,
    ):
        self._watchlist_template = watchlist_manager
        self._parser = sbom_parser or SBOMParser()
        self._tenant_registry = tenant_registry
        self._tenant_storage_dir = self._resolve_storage_dir(watchlist_manager, tenant_storage_dir)
        # tenant_id -> set of (package_name, ecosystem, version)
        self._tenant_packages: dict[str, set[tuple[str, str, str]]] = {}
        self._tenant_watchlists: dict[str, WatchlistManager] = {}

    @staticmethod
    def _resolve_storage_dir(
        watchlist_manager: Optional[WatchlistManager],
        tenant_storage_dir: str | Path | None,
    ) -> Path:
        if tenant_storage_dir is not None:
            return Path(tenant_storage_dir)
        if watchlist_manager is not None:
            base = watchlist_manager.storage_path
            return base.parent / f"{base.stem}_tenants"
        return Path(".depvet_watchlists") / "tenants"

    @staticmethod
    def _tenant_filename(tenant_id: str) -> str:
        sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", tenant_id).strip("._")
        return sanitized or "tenant"

    def _manager_for_tenant(self, tenant_id: str) -> WatchlistManager:
        manager = self._tenant_watchlists.get(tenant_id)
        if manager is None:
            storage_path = self._tenant_storage_dir / f"{self._tenant_filename(tenant_id)}.yaml"
            manager = WatchlistManager(storage_path=str(storage_path))
            self._tenant_watchlists[tenant_id] = manager
        return manager

    async def on_sbom_scan_complete(
        self, tenant_id: str, sbom_path: str
    ) -> int:
        """
        Called when Securify completes a SBOM scan for a tenant.
        Returns number of packages added to watchlist.
        """
        entries = self._parser.parse(sbom_path)
        pkg_set: set[tuple[str, str, str]] = set()
        tenant_watchlist = self._manager_for_tenant(tenant_id)
        tenant_watchlist.replace(entries)

        for entry in entries:
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

    def tenant_watchlist_set(self, tenant_id: str, ecosystem: str) -> set[str]:
        return self._manager_for_tenant(tenant_id).as_set(ecosystem)
