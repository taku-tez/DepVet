"""Explicit/manual watchlist source."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class WatchlistEntry:
    name: str
    ecosystem: str
    current_version: str = ""


class ExplicitSource:
    """Manages manually specified packages."""

    def __init__(self) -> None:
        self._entries: list[WatchlistEntry] = []

    def add(self, name: str, ecosystem: str = "pypi") -> None:
        existing = {(e.name, e.ecosystem) for e in self._entries}
        if (name, ecosystem) not in existing:
            self._entries.append(WatchlistEntry(name=name, ecosystem=ecosystem))

    def remove(self, name: str, ecosystem: str = "pypi") -> bool:
        before = len(self._entries)
        self._entries = [e for e in self._entries if not (e.name == name and e.ecosystem == ecosystem)]
        return len(self._entries) < before

    def entries(self, ecosystem: str | None = None) -> list[WatchlistEntry]:
        if ecosystem:
            return [e for e in self._entries if e.ecosystem == ecosystem]
        return list(self._entries)

    def as_set(self, ecosystem: str) -> set[str]:
        return {e.name for e in self._entries if e.ecosystem == ecosystem}

    def load_from_file(self, path: str, ecosystem: str = "pypi") -> int:
        """Load package names from a plain text file (one per line)."""
        count = 0
        with open(path) as f:
            for line in f:
                name = line.strip()
                if name and not name.startswith("#"):
                    self.add(name, ecosystem)
                    count += 1
        return count

    def save_to_file(self, path: str, ecosystem: str = "pypi") -> None:
        """Save packages to a plain text file."""
        entries = self.as_set(ecosystem)
        Path(path).write_text("\n".join(sorted(entries)) + "\n")
