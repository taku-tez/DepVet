"""Securify Finding creator for DepVet alerts."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from depvet.models.package import Release
from depvet.models.verdict import Verdict, VerdictType
from securify_plugin.skg_writer import BlastRadius

logger = logging.getLogger(__name__)

# Securify Finding severity mapping
VERDICT_TO_FINDING_SEVERITY = {
    VerdictType.MALICIOUS:  "critical",
    VerdictType.SUSPICIOUS: "high",
}


@dataclass
class SecurifyFinding:
    id: str
    tenant_id: str
    title: str
    description: str
    severity: str
    category: str
    package_name: str
    package_version: str
    ecosystem: str
    affected_services: list[str]
    skg_node_id: Optional[str]
    created_at: str


class FindingCreator:
    """
    Creates Securify Findings from DepVet verdicts.

    Findings are created per-tenant and linked to the SKG.
    """

    def __init__(self, client=None):
        self._client = client

    async def create(
        self,
        tenant_id: str,
        release: Release,
        verdict: Verdict,
        blast_radius: Optional[BlastRadius] = None,
        skg_node_id: Optional[str] = None,
    ) -> SecurifyFinding:
        """Create a Securify Finding for a malicious/suspicious release."""
        severity = VERDICT_TO_FINDING_SEVERITY.get(verdict.verdict, "medium")

        affected = []
        if blast_radius:
            affected = [
                s.get("name", s.get("id", ""))
                for s in (blast_radius.direct_dependencies + blast_radius.indirect_dependencies)
            ]

        title = (
            f"[DepVet] {verdict.verdict.value}: {release.ecosystem}/{release.name}@{release.version}"
        )
        description = self._build_description(release, verdict, blast_radius)

        finding = SecurifyFinding(
            id=f"depvet-{release.ecosystem}-{release.name}-{release.version}-{tenant_id}",
            tenant_id=tenant_id,
            title=title,
            description=description,
            severity=severity,
            category="supply_chain",
            package_name=release.name,
            package_version=release.version,
            ecosystem=release.ecosystem,
            affected_services=affected,
            skg_node_id=skg_node_id,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        if self._client:
            await self._client.create_finding(finding)
        else:
            logger.debug(f"[Finding stub] {finding.title}")

        return finding

    def _build_description(
        self, release: Release, verdict: Verdict, blast_radius: Optional[BlastRadius]
    ) -> str:
        lines = [
            f"**DepVet が {release.ecosystem}/{release.name}@{release.version} に悪意あるコードを検出しました**",
            "",
            f"判定: {verdict.verdict.value} (確信度: {verdict.confidence:.0%})",
            f"深刻度: {verdict.severity.value}",
            "",
            f"**概要:** {verdict.summary}",
            "",
        ]
        if verdict.findings:
            lines.append("**検出項目:**")
            for i, f in enumerate(verdict.findings[:5], 1):
                cwe = f" ({f.cwe})" if f.cwe else ""
                lines.append(f"{i}. [{f.category.value}{cwe}] {f.file}: {f.description}")

        if blast_radius:
            direct_count = len(blast_radius.direct_dependencies)
            indirect_count = len(blast_radius.indirect_dependencies)
            lines.append("")
            lines.append(f"**影響範囲:** 直接依存 {direct_count} サービス, 間接依存 {indirect_count} サービス")

        lines.append("")
        lines.append(f"**参照:** {release.url}")
        return "\n".join(lines)
