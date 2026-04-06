"""Polling state persistence (YAML-backed)."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


class PollingState:
    """Persists polling state for registry monitors."""

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
