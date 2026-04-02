"""SBOM parser for CycloneDX and SPDX formats."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

from depvet.watchlist.explicit import WatchlistEntry

logger = logging.getLogger(__name__)

PURL_RE = re.compile(
    r"pkg:(?P<ecosystem>[^/]+)/(?:(?P<namespace>[^/]+)/)?(?P<name>[^@?#]+)(?:@(?P<version>[^?#]+))?"
)

ECO_MAP = {
    "pypi": "pypi", "npm": "npm", "golang": "go",
    "cargo": "cargo", "maven": "maven",
}


def _parse_purl(purl: str) -> Optional[WatchlistEntry]:
    m = PURL_RE.match(purl)
    if not m:
        return None
    ecosystem = ECO_MAP.get(m.group("ecosystem").lower(), m.group("ecosystem").lower())
    name = m.group("name")
    ns = m.group("namespace")
    if ns:
        if ecosystem == "npm":
            name = f"@{ns}/{name}"
        elif ecosystem == "maven":
            name = f"{ns}:{name}"
    return WatchlistEntry(name=name, ecosystem=ecosystem, current_version=m.group("version") or "")


class SBOMParser:
    def parse(self, path: str) -> list[WatchlistEntry]:
        p = Path(path)
        content = p.read_text(encoding="utf-8", errors="replace")
        if path.endswith(".xml") or content.strip().startswith("<"):
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
                entries.append(WatchlistEntry(name=name, ecosystem="pypi", current_version=comp.get("version", "")))
        return entries

    def _parse_cyclonedx_xml(self, content: str) -> list[WatchlistEntry]:
        import xml.etree.ElementTree as ET
        entries = []
        try:
            root = ET.fromstring(content)
            for ns_uri in ["http://cyclonedx.org/schema/bom/1.4", "http://cyclonedx.org/schema/bom/1.3", ""]:
                prefix = f"{{{ns_uri}}}" if ns_uri else ""
                components = root.findall(f".//{prefix}component")
                if components:
                    for comp in components:
                        purl_el = comp.find(f"{prefix}purl")
                        if purl_el is not None and purl_el.text:
                            entry = _parse_purl(purl_el.text)
                            if entry:
                                entries.append(entry)
                    break
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
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
                    entries.append(WatchlistEntry(name=name, ecosystem="pypi", current_version=pkg.get("versionInfo", "")))
        return entries
