"""Local known-bad release database."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).parent / "known_bad_releases.json"


@dataclass
class KnownBadEntry:
    name: str
    version: str
    ecosystem: str
    verdict: str  # MALICIOUS | SUSPICIOUS
    severity: str
    summary: str
    source: str  # "manual" | "osv" | "depvet"
    reported_at: str
    cve: Optional[str] = None
    osv_id: Optional[str] = None


class KnownBadDB:
    """
    Local database of known malicious/suspicious package releases.

    Sources:
    - Bundled hand-curated list (known_bad_releases.json)
    - OSV.dev API (queried at runtime)
    - Community reports
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or DEFAULT_DB_PATH
        self._entries: list[KnownBadEntry] = []
        self._index: dict[tuple[str, str, str], KnownBadEntry] = {}
        self._load()

    def _load(self) -> None:
        if not self._db_path.exists():
            logger.debug(f"Known-bad DB not found at {self._db_path}, starting empty")
            return
        try:
            with open(self._db_path) as f:
                data = json.load(f)
            for item in data.get("entries", []):
                entry = KnownBadEntry(**item)
                self._entries.append(entry)
                self._index[(entry.name, entry.version, entry.ecosystem)] = entry
            logger.info(f"Loaded {len(self._entries)} known-bad entries")
        except Exception as e:
            logger.error(f"Failed to load known-bad DB: {e}")

    def lookup(self, name: str, version: str, ecosystem: str) -> Optional[KnownBadEntry]:
        """Check if a specific release is known-bad."""
        return self._index.get((name, version, ecosystem))

    def all_entries(self) -> list[KnownBadEntry]:
        return list(self._entries)

    def count(self) -> int:
        return len(self._entries)

    def add(self, entry: KnownBadEntry) -> None:
        key = (entry.name, entry.version, entry.ecosystem)
        if key not in self._index:
            self._entries.append(entry)
            self._index[key] = entry

    def save(self, path: Optional[Path] = None) -> None:
        target = path or self._db_path
        target.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "entries": [
                {
                    "name": e.name,
                    "version": e.version,
                    "ecosystem": e.ecosystem,
                    "verdict": e.verdict,
                    "severity": e.severity,
                    "summary": e.summary,
                    "source": e.source,
                    "reported_at": e.reported_at,
                    "cve": e.cve,
                    "osv_id": e.osv_id,
                }
                for e in self._entries
            ],
        }
        with open(target, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
