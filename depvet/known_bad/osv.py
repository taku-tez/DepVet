"""OSV.dev API checker for known vulnerabilities in package releases."""

from __future__ import annotations

import asyncio
import logging

import aiohttp

from depvet.http import retry_request
from depvet.known_bad.database import KnownBadEntry

logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1"
OSV_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
}

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_BATCH_TIMEOUT = aiohttp.ClientTimeout(total=30)


class OSVChecker:
    """
    Checks package releases against OSV.dev vulnerability database.

    OSV covers malicious packages (MAL-*), CVEs, and other advisories.
    """

    async def check(
        self,
        name: str,
        version: str,
        ecosystem: str,
    ) -> list[KnownBadEntry]:
        """
        Query OSV.dev for advisories affecting a specific package version.
        Returns list of KnownBadEntry (may be empty if clean).
        """
        osv_eco = OSV_ECOSYSTEM_MAP.get(ecosystem)
        if not osv_eco:
            return []

        payload = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": osv_eco,
            },
        }

        try:
            async with aiohttp.ClientSession() as session:
                resp = await retry_request(
                    session,
                    "POST",
                    f"{OSV_API}/query",
                    json=payload,
                    timeout=_TIMEOUT,
                )
                async with resp:
                    if resp.status != 200:
                        logger.warning(f"OSV API returned {resp.status}")
                        return []
                    data = await resp.json()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"OSV API request failed: {e}")
            return []

        entries = []
        for vuln in data.get("vulns", []):
            osv_id = vuln.get("id", "")
            summary = vuln.get("summary", vuln.get("details", "")[:200])
            severity = self._map_severity(vuln)
            verdict = "MALICIOUS" if osv_id.startswith("MAL-") else "SUSPICIOUS"

            entries.append(
                KnownBadEntry(
                    name=name,
                    version=version,
                    ecosystem=ecosystem,
                    verdict=verdict,
                    severity=severity,
                    summary=summary,
                    source="osv",
                    reported_at=vuln.get("published", ""),
                    cve=next((a for a in vuln.get("aliases", []) if isinstance(a, str) and a.startswith("CVE-")), None)
                    if isinstance(vuln.get("aliases", []), list)
                    else None,
                    osv_id=osv_id,
                )
            )

        return entries

    async def batch_check(
        self,
        packages: list[tuple[str, str, str]],
        chunk_size: int = 100,
    ) -> dict[tuple[str, str, str], list[KnownBadEntry]]:
        """
        Batch check multiple packages against OSV.dev.

        Large lists are split into chunks of *chunk_size* to avoid
        payload limits and timeouts on the OSV batch endpoint.
        """
        results: dict[tuple[str, str, str], list[KnownBadEntry]] = {}
        all_queries: list[dict] = []
        all_keys: list[tuple[str, str, str]] = []
        for name, version, ecosystem in packages:
            osv_eco = OSV_ECOSYSTEM_MAP.get(ecosystem)
            if not osv_eco:
                continue
            all_queries.append(
                {
                    "version": version,
                    "package": {"name": name, "ecosystem": osv_eco},
                }
            )
            all_keys.append((name, version, ecosystem))

        if not all_queries:
            return results

        # Process in chunks
        async with aiohttp.ClientSession() as session:
            for start in range(0, len(all_queries), chunk_size):
                queries = all_queries[start : start + chunk_size]
                pkg_keys = all_keys[start : start + chunk_size]
                try:
                    resp = await retry_request(
                        session,
                        "POST",
                        f"{OSV_API}/querybatch",
                        json={"queries": queries},
                        timeout=_BATCH_TIMEOUT,
                    )
                    async with resp:
                        if resp.status != 200:
                            logger.warning(
                                f"OSV batch API returned {resp.status} (chunk {start}–{start + len(queries)})"
                            )
                            continue
                        data = await resp.json()
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.error(f"OSV batch API failed (chunk {start}–{start + len(queries)}): {e}")
                    continue

                self._process_batch_results(data, pkg_keys, results)

        return results

    def _process_batch_results(
        self,
        data: dict,
        pkg_keys: list[tuple[str, str, str]],
        results: dict[tuple[str, str, str], list[KnownBadEntry]],
    ) -> None:
        """Parse a single batch response and merge into results."""
        for i, result in enumerate(data.get("results", [])):
            key = pkg_keys[i]
            name, version, ecosystem = key
            entries = []
            for vuln in result.get("vulns", []):
                osv_id = vuln.get("id", "")
                summary = vuln.get("summary", vuln.get("details", "")[:200])
                severity = self._map_severity(vuln)
                verdict = "MALICIOUS" if osv_id.startswith("MAL-") else "SUSPICIOUS"
                aliases = vuln.get("aliases", [])
                cve = next((a for a in aliases if isinstance(a, str) and a.startswith("CVE-")), None)
                entries.append(
                    KnownBadEntry(
                        name=name,
                        version=version,
                        ecosystem=ecosystem,
                        verdict=verdict,
                        severity=severity,
                        summary=summary,
                        source="osv",
                        reported_at=vuln.get("published", ""),
                        cve=cve,
                        osv_id=osv_id,
                    )
                )
            results[key] = entries

    def _map_ecosystem(self, ecosystem: str) -> str | None:
        """Map DepVet ecosystem name to OSV ecosystem name."""
        return OSV_ECOSYSTEM_MAP.get(ecosystem)

    def _map_severity(self, vuln: dict) -> str:
        """Map OSV severity to DepVet severity."""
        for severity in vuln.get("severity", []):
            score = severity.get("score", "")
            if severity.get("type") == "CVSS_V3":
                try:
                    val = float(score.split("/")[0]) if "/" in score else float(score)
                    if val >= 9.0:
                        return "CRITICAL"
                    elif val >= 7.0:
                        return "HIGH"
                    elif val >= 4.0:
                        return "MEDIUM"
                    else:
                        return "LOW"
                except (ValueError, IndexError):
                    pass
        # Malicious packages default to HIGH
        if vuln.get("id", "").startswith("MAL-"):
            return "HIGH"
        return "MEDIUM"
