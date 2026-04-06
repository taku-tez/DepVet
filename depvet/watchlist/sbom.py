"""SBOM parser for CycloneDX and SPDX formats."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from depvet.watchlist.explicit import WatchlistEntry

logger = logging.getLogger(__name__)

PURL_RE = re.compile(r"pkg:(?P<ecosystem>[^/]+)/(?:(?P<namespace>[^/]+)/)?(?P<name>[^@?#]+)(?:@(?P<version>[^?#]+))?")

ECO_MAP = {
    "pypi": "pypi",
    "npm": "npm",
    "golang": "go",
    "cargo": "cargo",
    "maven": "maven",
}


def _parse_purl(purl: str) -> Optional[WatchlistEntry]:
    decoded = unquote(purl)
    m = PURL_RE.match(decoded)
    if not m:
        return None
    ecosystem = ECO_MAP.get(m.group("ecosystem").lower(), m.group("ecosystem").lower())
    name = m.group("name")
    ns = m.group("namespace")
    if ns:
        if ecosystem == "npm":
            scope = ns if ns.startswith("@") else f"@{ns}"
            name = f"{scope}/{name}"
        elif ecosystem == "go":
            name = f"{ns}/{name}"
        elif ecosystem == "maven":
            name = f"{ns}:{name}"
    return WatchlistEntry(name=name, ecosystem=ecosystem, current_version=m.group("version") or "")


def _infer_fallback_entry(
    *,
    name: str,
    version: str,
    group: str = "",
    bom_ref: str = "",
) -> Optional[WatchlistEntry]:
    if not name:
        return None
    if group:
        return WatchlistEntry(name=f"{group}:{name}", ecosystem="maven", current_version=version)
    if name.startswith("@") and "/" in name:
        return WatchlistEntry(name=name, ecosystem="npm", current_version=version)
    if "/" in name and "." in name.split("/", 1)[0]:
        return WatchlistEntry(name=name, ecosystem="go", current_version=version)
    if bom_ref.startswith("pkg:"):
        return _parse_purl(bom_ref)
    return WatchlistEntry(name=name, ecosystem="unknown", current_version=version)


class SBOMParser:
    def parse(self, path: str, fmt: Optional[str] = None) -> list[WatchlistEntry]:
        """Parse a SBOM file.

        Args:
            path: Path to the SBOM file.
            fmt: Explicit format override: 'cyclonedx' | 'spdx' | None (auto-detect).
        """
        p = Path(path)
        content = p.read_text(encoding="utf-8", errors="replace")
        is_xml = path.endswith(".xml") or content.strip().startswith("<")

        # Explicit format override
        if fmt:
            fmt_lower = fmt.lower()
            if is_xml:
                if fmt_lower == "spdx":
                    return self._parse_spdx_xml(content)
                else:  # cyclonedx or default
                    return self._parse_cyclonedx_xml(content)
            else:
                try:
                    data = json.loads(content)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse SBOM JSON: {e}")
                    return []
                if fmt_lower == "spdx":
                    return self._parse_spdx_json(data)
                else:
                    return self._parse_cyclonedx_json(data)

        # Auto-detect
        if is_xml:
            # Peek at root element to decide CycloneDX vs SPDX
            if "spdx" in content[:500].lower() or "SpdxDocument" in content[:500]:
                return self._parse_spdx_xml(content)
            return self._parse_cyclonedx_xml(content)
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse SBOM JSON: {e}")
            return []
        if "bomFormat" in data or "components" in data:
            return self._parse_cyclonedx_json(data)
        elif "SPDXID" in data or "packages" in data:
            return self._parse_spdx_json(data)
        logger.warning(f"Unknown SBOM format in {path}")
        return []

    def _parse_cyclonedx_json(self, data: dict) -> list[WatchlistEntry]:
        entries = []
        for comp in data.get("components", []):
            purl = comp.get("purl", "")
            if purl:
                entry = _parse_purl(purl)
                if entry:
                    entries.append(entry)
                    continue
            name = comp.get("name", "")
            if name and comp.get("type") == "library":
                entry = _infer_fallback_entry(
                    name=name,
                    version=comp.get("version", ""),
                    group=comp.get("group", ""),
                    bom_ref=comp.get("bom-ref", ""),
                )
                if entry:
                    entries.append(entry)
        return entries

    def _parse_cyclonedx_xml(self, content: str) -> list[WatchlistEntry]:
        import xml.etree.ElementTree as ET

        entries = []
        try:
            root = ET.fromstring(content)  # nosec B314 — SBOM XML from local file
            for ns_uri in [
                "http://cyclonedx.org/schema/bom/1.4",
                "http://cyclonedx.org/schema/bom/1.3",
                "http://cyclonedx.org/schema/bom/1.5",
                "",
            ]:
                prefix = f"{{{ns_uri}}}" if ns_uri else ""
                components = root.findall(f".//{prefix}component")
                if components:
                    for comp in components:
                        purl_el = comp.find(f"{prefix}purl")
                        if purl_el is not None and purl_el.text:
                            entry = _parse_purl(purl_el.text)
                            if entry:
                                entries.append(entry)
                                continue
                        # Fallback: group + name + version
                        name_el = comp.find(f"{prefix}name")
                        ver_el = comp.find(f"{prefix}version")
                        grp_el = comp.find(f"{prefix}group")
                        if name_el is not None and name_el.text:
                            name = name_el.text
                            version = ver_el.text if ver_el is not None else ""
                            group = grp_el.text if grp_el is not None else ""
                            entry = _infer_fallback_entry(name=name, version=version or "", group=group or "")
                            if entry:
                                entries.append(entry)
                    break
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
        return entries

    def _parse_spdx_xml(self, content: str) -> list[WatchlistEntry]:
        """Parse SPDX XML format."""
        import xml.etree.ElementTree as ET

        entries = []
        try:
            root = ET.fromstring(content)  # nosec B314 — SBOM XML from local file
            # SPDX XML namespaces vary — try common ones
            for ns_uri in [
                "http://spdx.org/spdx/v2.3/document",
                "http://spdx.org/spdx/v2.2/document",
                "",
            ]:
                prefix = f"{{{ns_uri}}}" if ns_uri else ""
                packages = root.findall(f".//{prefix}package")
                if not packages:
                    # Try without namespace
                    packages = root.findall(".//package")
                for pkg in packages:
                    # Try externalRef with purl
                    for ref in pkg.findall(f"{prefix}externalRef") or pkg.findall(".//externalRef"):
                        ref_type = ref.findtext(f"{prefix}referenceType") or ref.findtext("referenceType") or ""
                        if "purl" in ref_type.lower():
                            locator = (
                                ref.findtext(f"{prefix}referenceLocator") or ref.findtext("referenceLocator") or ""
                            )
                            if locator:
                                entry = _parse_purl(locator)
                                if entry:
                                    entries.append(entry)
                                    break
                    else:
                        # Fallback: name + versionInfo
                        name = pkg.findtext(f"{prefix}name") or pkg.findtext("name") or ""
                        version = pkg.findtext(f"{prefix}versionInfo") or pkg.findtext("versionInfo") or ""
                        if name and name not in ("NOASSERTION", "SPDXRef-DOCUMENT"):
                            entry = _infer_fallback_entry(name=name, version=version)
                            if entry:
                                entries.append(entry)
                if entries:
                    break
        except ET.ParseError as e:
            logger.error(f"SPDX XML parse error: {e}")
        return entries

    def _parse_spdx_json(self, data: dict) -> list[WatchlistEntry]:
        entries = []
        for pkg in data.get("packages", []):
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    entry = _parse_purl(ref.get("referenceLocator", ""))
                    if entry:
                        entries.append(entry)
                        break
            else:
                name = pkg.get("name", "")
                if name:
                    entry = _infer_fallback_entry(
                        name=name,
                        version=pkg.get("versionInfo", ""),
                        bom_ref=pkg.get("SPDXID", ""),
                    )
                    if entry:
                        entries.append(entry)
        return entries
