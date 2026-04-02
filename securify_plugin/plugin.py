"""DepVet Securify Plugin entry point."""

from __future__ import annotations

import logging
from typing import Optional

from depvet.models.alert import AlertEvent
from depvet.models.verdict import VerdictType

logger = logging.getLogger(__name__)


class DepVetSecurifyPlugin:
    """
    Integrates DepVet malicious release alerts into the Securify platform.

    Responsibilities:
    1. Find affected tenants from SBOM (WatchlistSyncJob)
    2. Write MaliciousRelease node to SKG
    3. Find blast radius via graph traversal
    4. Register Finding in Securify
    5. Propagate risk scores
    6. Notify affected tenants

    Usage:
        plugin = DepVetSecurifyPlugin(config=securify_config)
        # Register as alert handler:
        alert_router.register(plugin)
    """

    def __init__(
        self,
        skg_writer=None,
        finding_creator=None,
        risk_propagator=None,
        notifier=None,
        watchlist_sync=None,
        enabled: bool = True,
    ):
        self.skg_writer = skg_writer
        self.finding_creator = finding_creator
        self.risk_propagator = risk_propagator
        self.notifier = notifier
        self.watchlist_sync = watchlist_sync
        self.enabled = enabled

    async def send(self, event: AlertEvent) -> None:
        """AlertRouter-compatible interface."""
        if not self.enabled:
            return
        if event.verdict.verdict not in (VerdictType.MALICIOUS, VerdictType.SUSPICIOUS):
            return
        await self.on_alert(event)

    async def on_alert(self, event: AlertEvent) -> None:
        """Process a malicious/suspicious release alert."""
        release = event.release
        verdict = event.verdict

        logger.info(
            f"[Securify] Processing {verdict.verdict.value} alert: "
            f"{release.ecosystem}/{release.name}@{release.version}"
        )

        # Step 1: Find affected tenants via SBOM matching
        affected_tenants = await self._find_affected_tenants(release)
        if not affected_tenants:
            logger.debug(f"No affected tenants for {release.name}@{release.version}")
            return

        event.affected_tenants = [t["id"] for t in affected_tenants]

        # Step 2: Write MaliciousRelease node to SKG
        skg_node_id = None
        if self.skg_writer:
            try:
                skg_node_id = await self.skg_writer.write_malicious_release(
                    release=release, verdict=verdict
                )
            except Exception as e:
                logger.error(f"SKG write failed: {e}")

        for tenant in affected_tenants:
            try:
                # Step 3: Find blast radius
                blast_radius = None
                if self.skg_writer:
                    blast_radius = await self.skg_writer.find_blast_radius(
                        tenant_id=tenant["id"],
                        package_name=release.name,
                        ecosystem=release.ecosystem,
                    )

                # Step 4: Register Finding
                finding = None
                if self.finding_creator:
                    finding = await self.finding_creator.create(
                        tenant_id=tenant["id"],
                        release=release,
                        verdict=verdict,
                        blast_radius=blast_radius,
                        skg_node_id=skg_node_id,
                    )

                # Step 5: Propagate risk scores
                if self.risk_propagator and finding and blast_radius:
                    await self.risk_propagator.propagate(
                        tenant_id=tenant["id"],
                        finding=finding,
                        blast_radius=blast_radius,
                    )

                # Step 6: Notify tenant
                if self.notifier and finding:
                    await self.notifier.notify(tenant, finding)

            except Exception as e:
                logger.error(f"Failed to process tenant {tenant.get('id')}: {e}")

    async def _find_affected_tenants(self, release) -> list[dict]:
        """Find tenants that use the affected package (via SBOM matching)."""
        if self.watchlist_sync:
            return await self.watchlist_sync.find_tenants_using(
                package_name=release.name,
                ecosystem=release.ecosystem,
                version=release.version,
            )
        return []
