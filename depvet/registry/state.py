"""Polling state persistence (YAML-backed)."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


_MAX_ALERTED_PER_ECOSYSTEM = 5000


class PollingState:
    """Persists polling state for registry monitors.

    Tracks both the feed cursor (serial/seq/versions) and a set of
    ``(name, version)`` pairs that have already been alerted, so
    that a restart mid-batch does not produce duplicate alerts.
    """

    def __init__(self, path: str = "./depvet_state.yaml"):
        self._path = Path(path)
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path) as f:
                    self._data = yaml.safe_load(f) or {}
            except (yaml.YAMLError, OSError) as e:
                logger.warning(f"Failed to load state from {self._path}: {e}")
                self._data = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            yaml.dump(self._data, f, default_flow_style=False)

    def get(self, ecosystem: str) -> dict:
        return self._data.get(ecosystem, {})

    def set(self, ecosystem: str, state: dict) -> None:
        self._data[ecosystem] = state
        self._save()

    def clear(self, ecosystem: str) -> None:
        self._data.pop(ecosystem, None)
        self._save()

    # ── Alert deduplication ──────────────────────────────────────

    def is_alerted(self, ecosystem: str, name: str, version: str) -> bool:
        """Check if a release was already alerted."""
        alerted = self._data.get(ecosystem, {}).get("_alerted", [])
        return [name, version] in alerted

    def mark_alerted(self, ecosystem: str, name: str, version: str) -> None:
        """Record a release as alerted. Persists immediately."""
        eco_state = self._data.setdefault(ecosystem, {})
        alerted: list = eco_state.setdefault("_alerted", [])
        pair = [name, version]
        if pair not in alerted:
            alerted.append(pair)
            # FIFO eviction to prevent unbounded growth
            if len(alerted) > _MAX_ALERTED_PER_ECOSYSTEM:
                eco_state["_alerted"] = alerted[-_MAX_ALERTED_PER_ECOSYSTEM:]
            self._save()
