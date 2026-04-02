"""Alert router: dispatches alerts to multiple backends."""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol, runtime_checkable

from depvet.models.alert import AlertEvent
from depvet.models.verdict import Severity, VerdictType

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
    Severity.LOW: 2, Severity.NONE: 1,
}


@runtime_checkable
class Alerter(Protocol):
    async def send(self, event: AlertEvent) -> None: ...


class AlertRouter:
    """Dispatches AlertEvents to registered alerters."""

    def __init__(self, min_severity: str = "MEDIUM"):
        self._alerters: list[Alerter] = []
        self._min_severity = Severity(min_severity)

    def register(self, alerter: Alerter) -> None:
        self._alerters.append(alerter)

    def _should_alert(self, event: AlertEvent) -> bool:
        v = event.verdict
        if v.verdict == VerdictType.BENIGN:
            return False
        return SEVERITY_ORDER.get(v.severity, 0) >= SEVERITY_ORDER.get(self._min_severity, 0)

    async def dispatch(self, event: AlertEvent) -> None:
        if not self._should_alert(event):
            return
        tasks = [alerter.send(event) for alerter in self._alerters]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Alerter {i} failed: {result}")
