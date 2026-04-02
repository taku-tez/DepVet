"""Generic webhook alert sender."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import aiohttp

from depvet.models.alert import AlertEvent

logger = logging.getLogger(__name__)


def _serialize_alert_event(event: AlertEvent) -> dict[str, Any]:
    """Convert an AlertEvent to a JSON-serializable dictionary."""
    release = event.release
    verdict = event.verdict

    return {
        "event_type": "depvet.release_analyzed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "release": {
            "name": release.name,
            "version": release.version,
            "ecosystem": release.ecosystem,
            "previous_version": release.previous_version,
            "published_at": release.published_at,
            "url": release.url,
            "rank": release.rank,
        },
        "verdict": {
            "verdict": verdict.verdict.value,
            "severity": verdict.severity.value,
            "confidence": verdict.confidence,
            "summary": verdict.summary,
            "analysis_duration_ms": verdict.analysis_duration_ms,
            "model": verdict.model,
            "analyzed_at": verdict.analyzed_at,
            "chunks_analyzed": verdict.chunks_analyzed,
            "tokens_used": verdict.tokens_used,
            "diff_stats": {
                "files_changed": verdict.diff_stats.files_changed,
                "lines_added": verdict.diff_stats.lines_added,
                "lines_removed": verdict.diff_stats.lines_removed,
                "binary_files": verdict.diff_stats.binary_files,
                "new_files": verdict.diff_stats.new_files,
                "deleted_files": verdict.diff_stats.deleted_files,
            },
            "findings": [
                {
                    "category": f.category.value,
                    "description": f.description,
                    "file": f.file,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "evidence": f.evidence,
                    "cwe": f.cwe,
                    "severity": f.severity.value,
                }
                for f in verdict.findings
            ],
        },
        "affected_tenants": event.affected_tenants,
    }


class WebhookAlert:
    """Sends alert events as JSON to a generic HTTP webhook endpoint."""

    def __init__(self, url: Optional[str] = None, timeout: float = 15.0) -> None:
        self.url = url or ""
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def send(self, alert_event: AlertEvent) -> None:
        """POST the serialized alert event as JSON. Logs errors but does not raise."""
        if not self.url:
            logger.warning("WebhookAlert: no url configured, skipping.")
            return

        payload = _serialize_alert_event(alert_event)
        body = json.dumps(payload, ensure_ascii=False)

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "depvet-webhook/1.0",
        }

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    self.url,
                    data=body,
                    headers=headers,
                ) as resp:
                    if resp.status >= 400:
                        resp_body = await resp.text()
                        logger.error(
                            "WebhookAlert: endpoint returned %s: %s",
                            resp.status,
                            resp_body,
                        )
                    else:
                        logger.debug(
                            "WebhookAlert: posted successfully (status=%s).",
                            resp.status,
                        )
        except aiohttp.ClientError as exc:
            logger.error("WebhookAlert: request failed: %s", exc)
        except Exception:
            logger.exception("WebhookAlert: unexpected error sending alert.")
