"""Risk score propagator for DepVet findings."""

from __future__ import annotations

import logging

from depvet.models.verdict import Severity
from securify_plugin.skg_writer import BlastRadius, SEVERITY_SCORES

logger = logging.getLogger(__name__)


class RiskPropagator:
    """
    Propagates risk scores through the dependency graph for affected services.

    Propagation rules (from design spec):
    - CRITICAL: direct +40, indirect +20
    - HIGH:     direct +25, indirect +10
    - MEDIUM:   direct +10, indirect +5
    - LOW:      direct +3,  indirect +1
    """

    def __init__(self, risk_score_service=None):
        self._service = risk_score_service

    async def propagate(
        self,
        tenant_id: str,
        finding,
        blast_radius: BlastRadius,
    ) -> None:
        """Propagate risk scores to all affected services."""
        severity = finding.verdict.severity if hasattr(finding, 'verdict') else Severity.MEDIUM
        scores = SEVERITY_SCORES.get(severity, SEVERITY_SCORES[Severity.MEDIUM])

        for service in blast_radius.direct_dependencies:
            await self._add_score(
                target=service,
                delta=scores["direct"],
                reason=f"DepVet: {finding.package_name}@{finding.package_version} ({severity.value})",
                finding_id=finding.id,
            )

        for service in blast_radius.indirect_dependencies:
            await self._add_score(
                target=service,
                delta=scores["indirect"],
                reason=f"DepVet indirect: {finding.package_name}@{finding.package_version}",
                finding_id=finding.id,
            )

    async def _add_score(self, target: dict, delta: int, reason: str, finding_id: str) -> None:
        target_id = target.get("id", "unknown")
        if self._service:
            await self._service.add_score(
                target_id=target_id,
                delta=delta,
                reason=reason,
                finding_id=finding_id,
            )
        else:
            logger.debug(f"[RiskPropagator stub] {target_id}: +{delta} ({reason})")
