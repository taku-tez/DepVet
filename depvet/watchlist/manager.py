"""Watchlist manager: unified interface for all watchlist sources."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from depvet.watchlist.explicit import ExplicitSource, WatchlistEntry

logger = logging.getLogger(__name__)

WATCHLIST_FILE = ".depvet_watchlist.yaml"


class WatchlistManager:
    def __init__(self, storage_path: str = WATCHLIST_FILE):
        self._path = Path(storage_path)
        self._explicit = ExplicitSource()
        self._load()

    @property
    def storage_path(self) -> Path:
        return self._path

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with open(self._path) as f:
                data = yaml.safe_load(f) or {}
            for entry in data.get("packages", []):
                self._explicit.add(entry["name"], entry.get("ecosystem", "pypi"))
        except Exception as e:
            logger.warning(f"Failed to load watchlist: {e}")

    def _save(self) -> None:
        packages = [
            {"name": e.name, "ecosystem": e.ecosystem}
            for e in self._explicit.entries()
        ]
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            yaml.dump({"packages": packages}, f, default_flow_style=False, allow_unicode=True)

    def add(self, name: str, ecosystem: str = "pypi") -> None:
        self._explicit.add(name, ecosystem)
        self._save()

    def replace(self, entries: list[WatchlistEntry]) -> None:
        self._explicit = ExplicitSource()
        for entry in entries:
            self._explicit.add(entry.name, entry.ecosystem)
        self._save()

    def remove(self, name: str, ecosystem: str = "pypi") -> bool:
        result = self._explicit.remove(name, ecosystem)
        if result:
            self._save()
        return result

    def import_from_sbom(self, path: str, fmt: str | None = None) -> int:
        from depvet.watchlist.sbom import SBOMParser
        parser = SBOMParser()
        entries = parser.parse(path, fmt=fmt)
        for entry in entries:
            self._explicit.add(entry.name, entry.ecosystem)
        self._save()
        return len(entries)

    def as_set(self, ecosystem: str) -> set[str]:
        return self._explicit.as_set(ecosystem)

    def all_entries(self) -> list[WatchlistEntry]:
        return self._explicit.entries()

    def stats(self) -> dict:
        entries = self.all_entries()
        by_eco: dict[str, int] = {}
        for e in entries:
            by_eco[e.ecosystem] = by_eco.get(e.ecosystem, 0) + 1
        return {"total": len(entries), "by_ecosystem": by_eco}
