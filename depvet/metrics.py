"""Runtime metrics collection for the DepVet monitor.

Tracks releases processed, tokens consumed, analysis durations, and
per-ecosystem statistics.  All data is kept in-memory and can be
serialised to a dict for JSON logging or the health endpoint.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class MonitorMetrics:
    """Accumulates runtime metrics for a single monitor session."""

    start_time: float = field(default_factory=time.monotonic)

    # Counters
    releases_processed: int = 0
    releases_skipped: int = 0
    alerts_sent: int = 0
    alerts_failed: int = 0
    cycles_completed: int = 0

    # LLM
    total_tokens_used: int = 0
    total_analysis_duration_ms: int = 0
    analyses_completed: int = 0

    # Per-ecosystem
    releases_by_ecosystem: dict[str, int] = field(default_factory=dict)

    # ── helpers ──────────────────────────────────────────────────

    def record_release(self, ecosystem: str) -> None:
        self.releases_processed += 1
        self.releases_by_ecosystem[ecosystem] = self.releases_by_ecosystem.get(ecosystem, 0) + 1

    def record_analysis(self, tokens: int, duration_ms: int) -> None:
        self.analyses_completed += 1
        self.total_tokens_used += tokens
        self.total_analysis_duration_ms += duration_ms

    def record_alert_sent(self) -> None:
        self.alerts_sent += 1

    def record_alert_failed(self) -> None:
        self.alerts_failed += 1

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def avg_analysis_ms(self) -> float:
        if self.analyses_completed == 0:
            return 0.0
        return self.total_analysis_duration_ms / self.analyses_completed

    @property
    def avg_tokens_per_analysis(self) -> float:
        if self.analyses_completed == 0:
            return 0.0
        return self.total_tokens_used / self.analyses_completed

    def to_dict(self) -> dict:
        """Serialise to a flat dict for JSON logging / health endpoint."""
        return {
            "uptime_seconds": round(self.uptime_seconds),
            "cycles_completed": self.cycles_completed,
            "releases_processed": self.releases_processed,
            "releases_skipped": self.releases_skipped,
            "releases_by_ecosystem": dict(self.releases_by_ecosystem),
            "alerts_sent": self.alerts_sent,
            "alerts_failed": self.alerts_failed,
            "analyses_completed": self.analyses_completed,
            "total_tokens_used": self.total_tokens_used,
            "total_analysis_duration_ms": self.total_analysis_duration_ms,
            "avg_analysis_ms": round(self.avg_analysis_ms, 1),
            "avg_tokens_per_analysis": round(self.avg_tokens_per_analysis, 1),
        }

    def log_summary(self) -> None:
        """Emit a structured log entry with current metrics."""
        logger.info(
            "Monitor metrics: %d releases, %d alerts, %d tokens in %ds",
            self.releases_processed,
            self.alerts_sent,
            self.total_tokens_used,
            round(self.uptime_seconds),
            extra=self.to_dict(),
        )
