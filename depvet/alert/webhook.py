"""Generic Webhook alerter."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from depvet.models.alert import AlertEvent

logger = logging.getLogger(__name__)


def _event_to_dict(event: AlertEvent) -> dict:
    v = event.verdict
    r = event.release
    return {
        "event_type": "depvet.release_analyzed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "release": {
            "name": r.name, "version": r.version, "ecosystem": r.ecosystem,
            "previous_version": r.previous_version, "published_at": r.published_at, "url": r.url,
        },
        "verdict": {
            "verdict": v.verdict.value, "severity": v.severity.value,
            "confidence": v.confidence, "summary": v.summary,
            "findings_count": len(v.findings),
            "findings": [
                {"category": f.category.value, "description": f.description, "file": f.file,
                 "line_start": f.line_start, "line_end": f.line_end, "evidence": f.evidence,
                 "cwe": f.cwe, "severity": f.severity.value}
                for f in v.findings
            ],
            "model": v.model, "analyzed_at": v.analyzed_at,
        },
    }


class WebhookAlerter:
    """Sends alerts to a generic HTTP webhook."""

    def __init__(self, url: Optional[str] = None, secret_env: str = "DEPVET_WEBHOOK_SECRET"):
        self._url = url or ""
        self._secret = os.environ.get(secret_env, "")

    def _sign(self, body: bytes) -> str:
        return hmac.new(self._secret.encode(), body, hashlib.sha256).hexdigest()

    async def send(self, event: AlertEvent) -> None:
        if not self._url:
            return
        payload = _event_to_dict(event)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._secret:
            headers["X-DepVet-Signature"] = f"sha256={self._sign(body)}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._url, data=body, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status >= 400:
                        logger.error(f"Webhook returned {resp.status}")
        except Exception as e:
            logger.error(f"Webhook request failed: {e}")
