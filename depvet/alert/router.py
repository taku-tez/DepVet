"""Alert router: dispatches alerts to multiple backends."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from depvet.exceptions import DepVetError
from depvet.models.alert import AlertEvent
from depvet.models.verdict import Severity, VerdictType

if TYPE_CHECKING:
    from depvet.alert.dlq import DeadLetterQueue

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.NONE: 1,
}


class AlertDeliveryError(DepVetError):
    """Raised when an alerter fails to deliver an alert after retries."""


@runtime_checkable
class Alerter(Protocol):
    async def send(self, event: AlertEvent) -> None: ...


class AlertRouter:
    """Dispatches AlertEvents to registered alerters."""

    def __init__(
        self,
        min_severity: str = "MEDIUM",
        dlq: DeadLetterQueue | None = None,
    ):
        self._alerters: list[Alerter] = []
        self._min_severity = Severity(min_severity)
        self._dlq = dlq
        self.dispatched_count: int = 0

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
        any_success = False
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                alerter_name = getattr(self._alerters[i], "name", f"alerter-{i}")
                logger.error(
                    "Alerter %s failed: %s",
                    alerter_name,
                    result,
                    extra={"alerter": alerter_name},
                )
                if self._dlq is not None:
                    self._dlq.push(alerter_name, str(result), event)
            else:
                any_success = True
        if any_success:
            self.dispatched_count += 1
