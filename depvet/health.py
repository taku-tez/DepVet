"""Health check mechanism for DepVet monitor.

The running monitor periodically writes a status file (JSON).  External
tools — Docker HEALTHCHECK, Kubernetes liveness probes, ``depvet health``
— read the file and verify freshness.

Status file format (.depvet_health.json):
    {
        "status": "ok",
        "pid": 12345,
        "last_poll_at": "2026-04-06T12:00:00+00:00",
        "cycles_completed": 42,
        "releases_processed": 100,
        "uptime_seconds": 3600,
        "metrics": { ... }
    }
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from depvet.metrics import MonitorMetrics

logger = logging.getLogger(__name__)

DEFAULT_HEALTH_PATH = ".depvet_health.json"
# A health file older than this is considered stale (monitor probably dead)
STALE_THRESHOLD_SECONDS = 600  # 10 minutes


def write_health(
    path: str = DEFAULT_HEALTH_PATH,
    *,
    metrics: MonitorMetrics | None = None,
    status: str = "ok",
) -> None:
    """Write / update the health status file.  Called by the monitor loop."""
    data: dict[str, object] = {
        "status": status,
        "pid": os.getpid(),
        "last_poll_at": datetime.now(timezone.utc).isoformat(),
        "updated_epoch": time.time(),
    }
    if metrics is not None:
        data.update(metrics.to_dict())

    try:
        Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False))
    except OSError as e:
        logger.warning("Failed to write health file %s: %s", path, e)


def read_health(path: str = DEFAULT_HEALTH_PATH) -> dict | None:
    """Read the health status file.  Returns None if missing."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())  # type: ignore[no-any-return]
    except (json.JSONDecodeError, OSError):
        return None


def check_health(path: str = DEFAULT_HEALTH_PATH) -> None:
    """CLI / Docker HEALTHCHECK entry point.

    Exits 0 if the monitor is healthy, 1 otherwise.
    Healthy = status file exists, status == "ok", and file is not stale.
    If no health file exists (e.g. not running monitor), just verify
    that the package is importable (exit 0).
    """
    data = read_health(path)

    if data is None:
        # No health file — fall back to import check
        try:
            import depvet  # noqa: F401

            sys.exit(0)
        except ImportError:
            sys.exit(1)

    if data.get("status") != "ok":
        print(f"UNHEALTHY: status={data.get('status')}", file=sys.stderr)
        sys.exit(1)

    updated = data.get("updated_epoch", 0)
    age = time.time() - float(updated)
    if age > STALE_THRESHOLD_SECONDS:
        print(f"UNHEALTHY: health file stale ({age:.0f}s old)", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)
