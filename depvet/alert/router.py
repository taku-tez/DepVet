"""Alert routing to configured destinations."""
from __future__ import annotations

import logging
from typing import Optional

from depvet.models.alert import AlertEvent
from depvet.models.verdict import Severity
from depvet.alert.stdout import StdoutAlert
from depvet.alert.slack import SlackAlert
from depvet.alert.webhook import WebhookAlert

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


class AlertRouter:
    """Routes alert events to configured alert destinations.

    The router always prints to stdout, and optionally sends to Slack
    and/or a generic webhook endpoint based on constructor arguments.
    Only events that meet the minimum severity threshold are dispatched.
    """

    def __init__(
        self,
        min_severity: str = "MEDIUM",
        slack_webhook: Optional[str] = None,
        webhook_url: Optional[str] = None,
    ) -> None:
        self.min_severity = min_severity
        self.stdout = StdoutAlert()
        self.slack = SlackAlert(webhook_url=slack_webhook) if slack_webhook else None
        self.webhook = WebhookAlert(url=webhook_url) if webhook_url else None

    def _should_alert(self, event: AlertEvent) -> bool:
        """Return True if the event's severity meets the minimum threshold."""
        sev = event.verdict.severity.value
        return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER.get(self.min_severity, 0)

    async def route(self, event: AlertEvent) -> None:
        """Route an alert event to all configured destinations."""
        if not self._should_alert(event):
            logger.debug(
                "AlertRouter: skipping event (severity=%s below min=%s)",
                event.verdict.severity.value,
                self.min_severity,
            )
            return

        # Stdout is synchronous
        self.stdout.send(event)

        # Slack and webhook are async
        if self.slack:
            await self.slack.send(event)
        if self.webhook:
            await self.webhook.send(event)
