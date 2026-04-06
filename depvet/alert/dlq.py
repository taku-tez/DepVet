"""Dead Letter Queue for failed alert deliveries."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from depvet.models.alert import AlertEvent

logger = logging.getLogger(__name__)

MAX_ENTRIES = 1000


def _serialize_event(event: AlertEvent) -> dict:
    """Serialize an AlertEvent to a plain dict for YAML storage."""
    v = event.verdict
    r = event.release
    return {
        "release": {
            "name": r.name,
            "version": r.version,
            "ecosystem": r.ecosystem,
            "previous_version": r.previous_version,
            "published_at": r.published_at,
            "url": r.url,
        },
        "verdict": {
            "verdict": v.verdict.value,
            "severity": v.severity.value,
            "confidence": v.confidence,
            "summary": v.summary,
            "findings_count": len(v.findings),
            "model": v.model,
            "analyzed_at": v.analyzed_at,
        },
    }


class DeadLetterQueue:
    """Persists failed alerts to a YAML file for later retry.

    Bounded to :data:`MAX_ENTRIES` entries with FIFO eviction.
    """

    def __init__(self, path: str = ".depvet_dlq.yaml"):
        self._path = Path(path)
        self._entries: list[dict] = []
        self._load()

    # -- persistence ----------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with open(self._path) as f:
                data = yaml.safe_load(f)
            self._entries = data if isinstance(data, list) else []
        except (yaml.YAMLError, OSError) as e:
            logger.warning("DLQ file corrupt, starting empty: %s", e)
            self._entries = []

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            yaml.dump(self._entries, f, default_flow_style=False, allow_unicode=True)

    # -- public API -----------------------------------------------------------

    def push(self, alerter_type: str, error: str, event: AlertEvent) -> None:
        """Add a failed alert to the queue."""
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alerter_type": alerter_type,
            "error_message": error,
            "event_data": _serialize_event(event),
            "retry_count": 0,
        }
        self._entries.append(entry)
        if len(self._entries) > MAX_ENTRIES:
            self._entries = self._entries[-MAX_ENTRIES:]
        self._save()
        logger.info(
            "Alert saved to DLQ (alerter=%s, package=%s)",
            alerter_type,
            event.release.name,
            extra={"alerter": alerter_type, "package": event.release.name},
        )

    def list_entries(self) -> list[dict]:
        return list(self._entries)

    def count(self) -> int:
        return len(self._entries)

    def clear(self) -> int:
        """Remove all entries. Returns count of removed entries."""
        n = len(self._entries)
        self._entries.clear()
        self._save()
        return n

    def pop_all(self) -> list[dict]:
        """Remove and return all entries."""
        entries = list(self._entries)
        self._entries.clear()
        self._save()
        return entries

    def remove(self, entry_id: str) -> bool:
        """Remove a single entry by ID. Returns True if found."""
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.get("id") != entry_id]
        if len(self._entries) < before:
            self._save()
            return True
        return False
