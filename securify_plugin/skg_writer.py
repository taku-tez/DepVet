"""SKG (Security Knowledge Graph) writer for DepVet findings."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from depvet.models.package import Release
from depvet.models.verdict import Verdict, Severity

logger = logging.getLogger(__name__)

SEVERITY_SCORES = {
    Severity.CRITICAL: {"direct": 40, "indirect": 20},
    Severity.HIGH:     {"direct": 25, "indirect": 10},
    Severity.MEDIUM:   {"direct": 10, "indirect": 5},
    Severity.LOW:      {"direct": 3,  "indirect": 1},
}


@dataclass
class BlastRadius:
    """Services/containers affected by a malicious package."""
    direct_dependencies: list[dict] = field(default_factory=list)    # Services directly depending
    indirect_dependencies: list[dict] = field(default_factory=list)  # Transitive dependencies
    affected_containers: list[dict] = field(default_factory=list)


class SKGWriter:
    """
    Writes DepVet findings to the Securify Security Knowledge Graph.

    This is a stub/interface definition. The actual implementation
    connects to the Securify platform's graph database.

    SKG Schema additions (Phase 3):
    - PackageRelease node: pkg:pypi/requests@2.32.0
    - MaliciousRelease node: depvet detection record
    - HAS_VERDICT edge: PackageRelease → MaliciousRelease
    - HAS_RELEASE edge: Package → PackageRelease
    - DEPENDS_ON edge: Service/Container → PackageRelease (from SBOM)
    """

    def __init__(self, client=None, api_url: str = "", api_key: str = ""):
        self._client = client
        self._api_url = api_url
        self._api_key = api_key

    async def write_malicious_release(
        self, release: Release, verdict: Verdict
    ) -> str:
        """
        Create or update a MaliciousRelease node in the SKG.

        Returns the node ID.
        """
        node_id = f"depvet/{release.ecosystem}/{release.name}/{release.version}"
        payload = {
            "id": node_id,
            "node_type": "MaliciousRelease",
            "properties": {
                "verdict": verdict.verdict.value,
                "severity": verdict.severity.value,
                "confidence": verdict.confidence,
                "findings_count": len(verdict.findings),
                "summary": verdict.summary,
                "detected_at": verdict.analyzed_at,
                "model": verdict.model,
                "ecosystem": release.ecosystem,
                "package_name": release.name,
                "version": release.version,
            },
        }
        if self._client:
            await self._client.upsert_node(payload)
        else:
            logger.debug(f"[SKG stub] write_malicious_release: {node_id}")

        return node_id

    async def find_blast_radius(
        self, tenant_id: str, package_name: str, ecosystem: str
    ) -> BlastRadius:
        """
        Find services/containers in the tenant's graph that depend on the package.

        Cypher query (conceptual):
            MATCH (svc:Service)-[:DEPENDS_ON {direct: true}]->(pr:PackageRelease)
            WHERE pr.name = $name AND pr.ecosystem = $ecosystem
              AND svc.tenant_id = $tenant_id
            RETURN svc
        """
        if self._client:
            result = await self._client.query(
                """
                MATCH (target)-[:DEPENDS_ON]->(pr:PackageRelease)
                WHERE pr.name = $name AND pr.ecosystem = $ecosystem
                  AND target.tenant_id = $tenant_id
                RETURN target, pr.direct as direct
                """,
                name=package_name,
                ecosystem=ecosystem,
                tenant_id=tenant_id,
            )
            direct = [r["target"] for r in result if r.get("direct")]
            indirect = [r["target"] for r in result if not r.get("direct")]
            return BlastRadius(direct_dependencies=direct, indirect_dependencies=indirect)

        logger.debug(f"[SKG stub] find_blast_radius: {tenant_id}/{package_name}")
        return BlastRadius()
