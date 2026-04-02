"""Comprehensive alert tests — Slack, Webhook, router edge cases."""

import hashlib
import hmac
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from depvet.alert.router import AlertRouter
from depvet.alert.stdout import StdoutAlerter, format_alert_text
from depvet.alert.slack import SlackAlerter
from depvet.alert.webhook import WebhookAlerter, _event_to_dict
from depvet.models.alert import AlertEvent
from depvet.models.package import Release
from depvet.models.verdict import (
    DiffStats, Finding, FindingCategory, Severity, Verdict, VerdictType,
)


def make_verdict(
    verdict=VerdictType.MALICIOUS,
    severity=Severity.CRITICAL,
    confidence=0.95,
    findings=None,
    summary="テストサマリー",
):
    return Verdict(
        verdict=verdict, severity=severity, confidence=confidence,
        findings=findings or [],
        summary=summary,
        analysis_duration_ms=100,
        diff_stats=DiffStats(files_changed=2, lines_added=10, lines_removed=3),
        model="test-model",
        analyzed_at="2026-04-02T00:00:00+00:00",
        chunks_analyzed=1,
        tokens_used=200,
    )


def make_release(name="requests", version="2.32.0", ecosystem="pypi"):
    return Release(
        name=name, version=version, ecosystem=ecosystem,
        previous_version="2.31.0",
        published_at="2026-04-02T00:00:00+00:00",
        url=f"https://pypi.org/project/{name}/{version}/",
    )


def make_event(**kw):
    return AlertEvent(
        release=make_release(),
        verdict=make_verdict(**kw),
    )


def make_finding(cat=FindingCategory.EXFILTRATION, sev=Severity.CRITICAL,
                 file="auth.py", line=10):
    return Finding(
        category=cat,
        description="テスト検出内容",
        file=file,
        line_start=line,
        line_end=line + 5,
        evidence="os.environ.get('SECRET')",
        cwe="CWE-200",
        severity=sev,
    )


# ─── AlertRouter ─────────────────────────────────────────────────────────────

class TestAlertRouter:
    def test_register_multiple(self):
        router = AlertRouter()
        for _ in range(3):
            router.register(MagicMock())
        assert len(router._alerters) == 3

    @pytest.mark.asyncio
    async def test_dispatch_to_all_alerters(self):
        router = AlertRouter(min_severity="LOW")
        alerters = [MagicMock() for _ in range(3)]
        for a in alerters:
            a.send = AsyncMock()
            router.register(a)
        await router.dispatch(make_event(verdict=VerdictType.MALICIOUS, severity=Severity.LOW))
        for a in alerters:
            a.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_benign_never_dispatched(self):
        router = AlertRouter()
        alerter = MagicMock()
        alerter.send = AsyncMock()
        router.register(alerter)
        await router.dispatch(make_event(verdict=VerdictType.BENIGN, severity=Severity.NONE))
        alerter.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_min_severity_low_allows_all_non_benign(self):
        router = AlertRouter(min_severity="LOW")
        alerter = MagicMock()
        alerter.send = AsyncMock()
        router.register(alerter)
        for sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
            await router.dispatch(make_event(verdict=VerdictType.SUSPICIOUS, severity=sev))
        assert alerter.send.call_count == 4

    @pytest.mark.asyncio
    async def test_min_severity_critical_blocks_lower(self):
        router = AlertRouter(min_severity="CRITICAL")
        alerter = MagicMock()
        alerter.send = AsyncMock()
        router.register(alerter)
        await router.dispatch(make_event(verdict=VerdictType.MALICIOUS, severity=Severity.HIGH))
        alerter.send.assert_not_called()
        await router.dispatch(make_event(verdict=VerdictType.MALICIOUS, severity=Severity.CRITICAL))
        alerter.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_alerter_failure_does_not_block_others(self):
        router = AlertRouter(min_severity="LOW")
        failing = MagicMock()
        failing.send = AsyncMock(side_effect=RuntimeError("network down"))
        succeeding = MagicMock()
        succeeding.send = AsyncMock()
        router.register(failing)
        router.register(succeeding)
        await router.dispatch(make_event())
        succeeding.send.assert_called_once()

    def test_should_alert_all_verdicts_except_benign(self):
        router = AlertRouter(min_severity="LOW")
        for vt in (VerdictType.MALICIOUS, VerdictType.SUSPICIOUS, VerdictType.UNKNOWN):
            event = make_event(verdict=vt, severity=Severity.LOW)
            assert router._should_alert(event) is True
        assert router._should_alert(make_event(verdict=VerdictType.BENIGN, severity=Severity.NONE)) is False


# ─── StdoutAlerter ───────────────────────────────────────────────────────────

class TestStdoutAlerter:
    @pytest.mark.asyncio
    async def test_json_output_structure(self, capsys):
        alerter = StdoutAlerter(json_mode=True, min_severity="LOW")
        await alerter.send(make_event())
        data = json.loads(capsys.readouterr().out)
        assert data["verdict"] == "MALICIOUS"
        assert data["severity"] == "CRITICAL"
        assert data["package"] == "requests"
        assert "confidence" in data
        assert "url" in data

    @pytest.mark.asyncio
    async def test_plain_text_output(self, capsys):
        alerter = StdoutAlerter(json_mode=False, min_severity="LOW")
        await alerter.send(make_event())
        out = capsys.readouterr().out
        assert "MALICIOUS" in out
        assert "requests" in out

    @pytest.mark.asyncio
    async def test_min_severity_filters(self, capsys):
        alerter = StdoutAlerter(json_mode=True, min_severity="HIGH")
        await alerter.send(make_event(verdict=VerdictType.SUSPICIOUS, severity=Severity.MEDIUM))
        out = capsys.readouterr().out
        assert out.strip() == ""

    @pytest.mark.asyncio
    async def test_with_findings(self, capsys):
        finding = make_finding()
        alerter = StdoutAlerter(json_mode=False, min_severity="LOW")
        await alerter.send(make_event(findings=[finding]))
        out = capsys.readouterr().out
        assert "EXFILTRATION" in out or "auth.py" in out

    def test_format_alert_text_all_fields(self):
        finding = make_finding()
        event = AlertEvent(release=make_release(), verdict=make_verdict(findings=[finding]))
        text = format_alert_text(event)
        assert "MALICIOUS" in text
        assert "CRITICAL" in text
        assert "requests" in text
        assert "2.31.0" in text
        assert "2.32.0" in text
        assert "pypi.org" in text
        assert "EXFILTRATION" in text
        assert "auth.py" in text

    def test_format_alert_text_no_findings(self):
        event = make_event(findings=[])
        text = format_alert_text(event)
        assert "MALICIOUS" in text
        assert "Findings" not in text


# ─── SlackAlerter ────────────────────────────────────────────────────────────

class TestSlackAlerter:
    @pytest.mark.asyncio
    async def test_no_url_does_nothing(self):
        alerter = SlackAlerter(webhook_url=None, webhook_env="NONEXISTENT_VAR_12345")
        # Should not crash
        await alerter.send(make_event())

    @pytest.mark.asyncio
    async def test_posts_to_webhook_url(self):
        import aiohttp
        posted = []

        class MockResponse:
            status = 200
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass

        class MockSession:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            def post(self, url, json=None, timeout=None):
                posted.append({"url": url, "payload": json})
                return MockResponse()

        with patch("depvet.alert.slack.aiohttp.ClientSession", return_value=MockSession()):
            alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
            await alerter.send(make_event())

        assert len(posted) == 1
        payload = posted[0]["payload"]
        assert "attachments" in payload
        assert "MALICIOUS" in payload["attachments"][0]["title"]

    @pytest.mark.asyncio
    async def test_slack_with_findings(self):
        posted = []

        class MockResponse:
            status = 200
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass

        class MockSession:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            def post(self, url, json=None, timeout=None):
                posted.append(json)
                return MockResponse()

        with patch("depvet.alert.slack.aiohttp.ClientSession", return_value=MockSession()):
            alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
            findings = [make_finding(cat=FindingCategory.EXFILTRATION)]
            await alerter.send(make_event(findings=findings))

        text = posted[0]["attachments"][0].get("text", "")
        assert "EXFILTRATION" in text


# ─── WebhookAlerter ──────────────────────────────────────────────────────────

class TestWebhookAlerter:
    def test_event_to_dict_structure(self):
        event = make_event()
        d = _event_to_dict(event)
        assert d["event_type"] == "depvet.release_analyzed"
        assert "timestamp" in d
        assert d["release"]["name"] == "requests"
        assert d["verdict"]["verdict"] == "MALICIOUS"

    def test_event_to_dict_with_findings(self):
        finding = make_finding()
        event = AlertEvent(release=make_release(), verdict=make_verdict(findings=[finding]))
        d = _event_to_dict(event)
        assert len(d["verdict"]["findings"]) == 1
        f = d["verdict"]["findings"][0]
        assert f["category"] == "EXFILTRATION"
        assert f["cwe"] == "CWE-200"

    @pytest.mark.asyncio
    async def test_no_url_does_nothing(self):
        alerter = WebhookAlerter(url=None)
        await alerter.send(make_event())  # no crash

    @pytest.mark.asyncio
    async def test_posts_with_signature(self):
        posted_headers = {}
        secret = "test_secret_key"

        class MockResponse:
            status = 200
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass

        class MockSession:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            def post(self, url, data=None, headers=None, timeout=None):
                posted_headers.update(headers or {})
                return MockResponse()

        import os
        with patch.dict(os.environ, {"DEPVET_WEBHOOK_SECRET": secret}):
            with patch("depvet.alert.webhook.aiohttp.ClientSession", return_value=MockSession()):
                alerter = WebhookAlerter(url="https://example.com/hook")
                await alerter.send(make_event())

        assert "X-DepVet-Signature" in posted_headers
        sig = posted_headers["X-DepVet-Signature"]
        assert sig.startswith("sha256=")

    @pytest.mark.asyncio
    async def test_posts_without_signature_when_no_secret(self):
        posted_headers = {}

        class MockResponse:
            status = 200
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass

        class MockSession:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            def post(self, url, data=None, headers=None, timeout=None):
                posted_headers.update(headers or {})
                return MockResponse()

        import os
        env = {k: v for k, v in os.environ.items() if k != "DEPVET_WEBHOOK_SECRET"}
        with patch.dict(os.environ, env, clear=True):
            with patch("depvet.alert.webhook.aiohttp.ClientSession", return_value=MockSession()):
                alerter = WebhookAlerter(url="https://example.com/hook")
                await alerter.send(make_event())

        assert "X-DepVet-Signature" not in posted_headers
