"""Logging configuration for DepVet."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

# Extra fields that JsonFormatter will extract from LogRecords
_STRUCTURED_FIELDS = (
    "ecosystem",
    "package",
    "version",
    "alerter",
    "dlq_id",
    "cycle",
    "releases_count",
    "duration_ms",
    "signal",
)


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects on stderr."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in _STRUCTURED_FIELDS:
            value = getattr(record, key, None)
            if value is not None:
                entry[key] = value

        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, ensure_ascii=False)


def setup_logging(verbose: bool, log_format: str = "text") -> None:
    """Configure root logging.

    Args:
        verbose: If True, set level to DEBUG; otherwise WARNING.
        log_format: ``"text"`` for human-readable (default),
                    ``"json"`` for structured JSON on stderr.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to avoid duplicates on re-init
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    if log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    root.addHandler(handler)
