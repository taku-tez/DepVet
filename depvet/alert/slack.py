"""Slack webhook alert sender."""
from __future__ import annotations

import logging
from typing import Any, Optional

import aiohttp

from depvet.models.alert import AlertEvent
from depvet.models.verdict import VerdictType, Severity

logger = logging.getLogger(__name__)

_VERDICT_EMOJI = {
    VerdictType.MALICIOUS: ":rotating_light:",
    VerdictType.SUSPICIOUS: ":warning:",
    VerdictType.BENIGN: ":white_check_mark:",
    VerdictType.UNKNOWN: ":grey_question:",
}

_SEVERITY_EMOJI = {
    Severity.CRITICAL: ":red_circle:",
    Severity.HIGH: ":large_orange_circle:",
    Severity.MEDIUM: ":large_yellow_circle:",
    Severity.LOW: ":large_blue_circle:",
    Severity.NONE: ":white_circle:",
}


def _build_slack_blocks(event: AlertEvent) -> list[dict[str, Any]]:
    """Build Slack Block Kit blocks for the given alert event."""
    release = event.release
    verdict = event.verdict

    verdict_emoji = _VERDICT_EMOJI.get(verdict.verdict, ":package:")
    severity_emoji = _SEVERITY_EMOJI.get(verdict.severity, "")

    version_str = (
        f"{release.previous_version} -> {release.version}"
        if release.previous_version
        else release.version
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{verdict_emoji} {verdict.verdict.value} Release Detected",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Package:*\n<{release.url}|{release.name}> ({release.ecosystem})",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Version:*\n{version_str}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:*\n{severity_emoji} {verdict.severity.value}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Confidence:*\n{verdict.confidence:.2f}",
                },
            ],
        },
    ]

    # Summary section
    if verdict.summary:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Summary:*\n{verdict.summary}",
            },
        })

    # Diff stats
    ds = verdict.diff_stats
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": (
                    f"*Diff:* {ds.files_changed} files changed | "
                    f"+{ds.lines_added} / -{ds.lines_removed} | "
                    f"Model: {verdict.model} | "
                    f"Analyzed: {verdict.analyzed_at}"
                ),
            }
        ],
    })

    # Findings (up to 10 to avoid Slack block limits)
    if verdict.findings:
        findings_lines: list[str] = []
        for idx, finding in enumerate(verdict.findings[:10], start=1):
            cwe_str = f" ({finding.cwe})" if finding.cwe else ""
            loc_str = ""
            if finding.line_start is not None:
                loc_str = f" L{finding.line_start}"
                if finding.line_end is not None and finding.line_end != finding.line_start:
                    loc_str += f"-L{finding.line_end}"
            findings_lines.append(
                f"{idx}. *{finding.category.value}*{cwe_str} "
                f"[{finding.severity.value}] `{finding.file}{loc_str}`\n"
                f"    {finding.description}"
            )

        if len(verdict.findings) > 10:
            findings_lines.append(
                f"_...and {len(verdict.findings) - 10} more findings_"
            )

        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Findings:*\n" + "\n".join(findings_lines),
            },
        })

    # Affected tenants
    if event.affected_tenants:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*Affected tenants:* {', '.join(event.affected_tenants)}",
                }
            ],
        })

    return blocks


class SlackAlert:
    """Sends alert events to a Slack channel via an incoming webhook."""

    def __init__(self, webhook_url: Optional[str] = None, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url or ""
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def send(self, alert_event: AlertEvent) -> None:
        """Post the alert to Slack. Logs errors but does not raise."""
        if not self.webhook_url:
            logger.warning("SlackAlert: no webhook_url configured, skipping.")
            return

        blocks = _build_slack_blocks(alert_event)

        # Slack requires a top-level `text` as fallback for notifications.
        fallback_text = (
            f"{alert_event.verdict.verdict.value} release detected: "
            f"{alert_event.release.name} {alert_event.release.version} "
            f"({alert_event.verdict.severity.value})"
        )

        payload: dict[str, Any] = {
            "text": fallback_text,
            "blocks": blocks,
        }

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(
                            "SlackAlert: webhook returned %s: %s",
                            resp.status,
                            body,
                        )
                    else:
                        logger.debug("SlackAlert: posted successfully.")
        except aiohttp.ClientError as exc:
            logger.error("SlackAlert: request failed: %s", exc)
        except Exception:
            logger.exception("SlackAlert: unexpected error sending alert.")
