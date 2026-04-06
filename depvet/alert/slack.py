"""Slack Webhook alerter."""

from __future__ import annotations

import logging
import os
from typing import Optional

import aiohttp

from depvet.http import retry_request
from depvet.models.alert import AlertEvent
from depvet.models.verdict import Severity, VerdictType

logger = logging.getLogger(__name__)

VERDICT_EMOJI = {
    VerdictType.MALICIOUS: ":rotating_light:",
    VerdictType.SUSPICIOUS: ":warning:",
    VerdictType.BENIGN: ":white_check_mark:",
    VerdictType.UNKNOWN: ":grey_question:",
}

SEVERITY_COLOR = {
    Severity.CRITICAL: "#FF0000",
    Severity.HIGH: "#FF6600",
    Severity.MEDIUM: "#FFAA00",
    Severity.LOW: "#0099FF",
    Severity.NONE: "#00CC00",
}

_TIMEOUT = aiohttp.ClientTimeout(total=10)


class SlackAlerter:
    """Sends alerts to Slack via Incoming Webhook."""

    name = "slack"

    def __init__(self, webhook_url: Optional[str] = None, webhook_env: str = "DEPVET_SLACK_WEBHOOK"):
        self._webhook_url = webhook_url or os.environ.get(webhook_env, "")

    async def send(self, event: AlertEvent) -> None:
        if not self._webhook_url:
            logger.warning("Slack webhook URL not configured")
            return

        v = event.verdict
        r = event.release
        emoji = VERDICT_EMOJI.get(v.verdict, "")
        color = SEVERITY_COLOR.get(v.severity, "#888888")

        findings_text = ""
        for i, f in enumerate(v.findings[:5], 1):
            cwe = f" ({f.cwe})" if f.cwe else ""
            findings_text += f"{i}. *{f.category.value}{cwe}* — {f.description}\n"

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"{emoji} {v.verdict.value}: {r.name} {r.version} ({r.ecosystem.upper()})",
                    "title_link": r.url,
                    "fields": [
                        {"title": "Severity", "value": v.severity.value, "short": True},
                        {"title": "Confidence", "value": f"{v.confidence:.0%}", "short": True},
                        {"title": "Previous", "value": r.previous_version or "N/A", "short": True},
                        {"title": "Findings", "value": str(len(v.findings)), "short": True},
                    ],
                    "text": f"*Summary:* {v.summary}\n\n*Findings:*\n{findings_text}" if v.findings else v.summary,
                    "footer": "DepVet",
                }
            ]
        }

        from depvet.alert.router import AlertDeliveryError

        async with aiohttp.ClientSession() as session:
            resp = await retry_request(
                session,
                "POST",
                self._webhook_url,
                json=payload,
                timeout=_TIMEOUT,
            )
            async with resp:
                if resp.status != 200:
                    raise AlertDeliveryError(f"Slack webhook returned {resp.status}")
