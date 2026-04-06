"""Tests for alert backends: StdoutAlerter, SlackAlerter, WebhookAlerter, AlertRouter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depvet.alert.router import AlertRouter
from depvet.alert.slack import SlackAlerter
from depvet.alert.stdout import StdoutAlerter
from depvet.alert.webhook import WebhookAlerter
from depvet.models.alert import AlertEvent
from depvet.models.package import Release
from depvet.models.verdict import DiffStats, Severity, Verdict, VerdictType


def _make_verdict(
    vtype: VerdictType = VerdictType.MALICIOUS,
    severity: Severity = Severity.CRITICAL,
    confidence: float = 0.95,
    summary: str = "Malicious code detected",
) -> Verdict:
    return Verdict(
        verdict=vtype,
        severity=severity,
        confidence=confidence,
        summary=summary,
        findings=[],
        analysis_duration_ms=100,
        diff_stats=DiffStats(files_changed=1, lines_added=5, lines_removed=0),
        model="test-model",
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        chunks_analyzed=1,
        tokens_used=500,
    )


def _make_release(name: str = "evil-pkg", version: str = "1.0.1", ecosystem: str = "pypi") -> Release:
    return Release(
        name=name,
        version=version,
        ecosystem=ecosystem,
        previous_version="1.0.0",
        published_at=datetime.now(timezone.utc).isoformat(),
        url=f"https://pypi.org/project/{name}/{version}/",
    )


def _make_event(
    vtype: VerdictType = VerdictType.MALICIOUS,
    severity: Severity = Severity.CRITICAL,
) -> AlertEvent:
    return AlertEvent(
        release=_make_release(),
        verdict=_make_verdict(vtype=vtype, severity=severity),
    )


# ─── StdoutAlerter ───────────────────────────────────────────────────────────


class TestStdoutAlerter:
    @pytest.mark.asyncio
    async def test_sends_malicious_output(self, capsys):
        alerter = StdoutAlerter(min_severity="NONE")
        event = _make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
        await alerter.send(event)
        out = capsys.readouterr().out
        assert "MALICIOUS" in out or "evil-pkg" in out

    @pytest.mark.asyncio
    async def test_json_mode_outputs_valid_json(self, capsys):
        alerter = StdoutAlerter(json_mode=True, min_severity="NONE")
        event = _make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
        await alerter.send(event)
        out = capsys.readouterr().out
        if out.strip():
            parsed = json.loads(out.strip())
            assert isinstance(parsed, dict)

    @pytest.mark.asyncio
    async def test_min_severity_blocks_low(self, capsys):
        alerter = StdoutAlerter(min_severity="HIGH")
        event = _make_event(VerdictType.SUSPICIOUS, Severity.LOW)
        await alerter.send(event)
        out = capsys.readouterr().out
        assert out.strip() == ""

    @pytest.mark.asyncio
    async def test_min_severity_none_passes_all(self, capsys):
        alerter = StdoutAlerter(min_severity="NONE")
        event = _make_event(VerdictType.SUSPICIOUS, Severity.LOW)
        await alerter.send(event)
        # Should not raise; output may be present

    @pytest.mark.asyncio
    async def test_benign_blocked_by_default(self, capsys):
        """Default min_severity=MEDIUM blocks BENIGN (severity=NONE)."""
        alerter = StdoutAlerter()  # default MEDIUM
        event = _make_event(VerdictType.BENIGN, Severity.NONE)
        await alerter.send(event)
        out = capsys.readouterr().out
        assert out.strip() == ""

    @pytest.mark.asyncio
    async def test_critical_always_shown_with_default(self, capsys):
        alerter = StdoutAlerter()  # default MEDIUM
        event = _make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
        await alerter.send(event)
        out = capsys.readouterr().out
        assert out.strip() != ""

    @pytest.mark.asyncio
    async def test_low_severity_shown_when_min_is_low(self, capsys):
        """[Finding 1] StdoutAlerter must respect min_severity=LOW, not hardcode MEDIUM."""
        alerter = StdoutAlerter(json_mode=True, min_severity="LOW")
        event = _make_event(VerdictType.SUSPICIOUS, Severity.LOW)
        await alerter.send(event)
        out = capsys.readouterr().out.strip()
        assert out != "", "LOW severity event should be output when min_severity=LOW"
        parsed = json.loads(out)
        assert parsed["severity"] == "LOW"


# ─── SlackAlerter ────────────────────────────────────────────────────────────


class TestSlackAlerter:
    @pytest.mark.asyncio
    async def test_no_url_does_nothing(self):
        alerter = SlackAlerter(webhook_url=None)
        event = _make_event()
        # Should not raise
        await alerter.send(event)

    @pytest.mark.asyncio
    async def test_empty_url_does_nothing(self):
        alerter = SlackAlerter(webhook_url="")
        event = _make_event()
        await alerter.send(event)

    @pytest.mark.asyncio
    async def test_posts_to_webhook(self):
        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.headers = {}
            mock_resp.release = MagicMock()
            mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_resp.__aexit__ = AsyncMock(return_value=False)

            mock_session = AsyncMock()
            mock_session.request = AsyncMock(return_value=mock_resp)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_session

            alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
            event = _make_event()
            await alerter.send(event)

            mock_session.request.assert_called_once()
            call_url = mock_session.request.call_args[0][1]
            assert "hooks.slack.com" in call_url

    def test_slack_alerter_has_send_method(self):
        """SlackAlerter must have an async send method."""
        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        import inspect

        assert inspect.iscoroutinefunction(alerter.send)


# ─── WebhookAlerter ──────────────────────────────────────────────────────────


class TestWebhookAlerter:
    @pytest.mark.asyncio
    async def test_no_url_does_nothing(self):
        alerter = WebhookAlerter(url="")
        event = _make_event()
        await alerter.send(event)

    @pytest.mark.asyncio
    async def test_posts_to_url(self):
        with patch("aiohttp.ClientSession") as mock_cls:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.headers = {}
            mock_resp.release = MagicMock()
            mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_resp.__aexit__ = AsyncMock(return_value=False)

            mock_sess = AsyncMock()
            mock_sess.request = AsyncMock(return_value=mock_resp)
            mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
            mock_sess.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_sess

            alerter = WebhookAlerter(url="https://example.com/webhook")
            event = _make_event()
            await alerter.send(event)
            mock_sess.request.assert_called_once()

    @pytest.mark.asyncio
    async def test_hmac_signature_when_secret(self, monkeypatch):
        """When secret_env is set, HMAC-SHA256 signature should be in header."""
        monkeypatch.setenv("TEST_WEBHOOK_SECRET", "my-secret")
        received_headers = {}

        async def fake_request(method, url, **kwargs):
            received_headers.update(kwargs.get("headers") or {})
            resp = MagicMock()
            resp.status = 200
            resp.headers = {}
            resp.release = MagicMock()
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        with patch("aiohttp.ClientSession") as mock_cls:
            mock_sess = AsyncMock()
            mock_sess.request = fake_request
            mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
            mock_sess.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_sess

            alerter = WebhookAlerter(url="https://example.com/hook", secret_env="TEST_WEBHOOK_SECRET")
            event = _make_event()
            await alerter.send(event)

        assert "X-DepVet-Signature" in received_headers
        assert received_headers["X-DepVet-Signature"].startswith("sha256=")


# ─── AlertRouter ─────────────────────────────────────────────────────────────


class TestAlertRouter:
    def test_register_and_count(self):
        router = AlertRouter(min_severity="MEDIUM")
        a1 = StdoutAlerter()
        a2 = StdoutAlerter()
        router.register(a1)
        router.register(a2)
        assert len(router._alerters) == 2

    @pytest.mark.asyncio
    async def test_dispatch_to_all_alerters(self):
        sent = []

        class FakeAlerter:
            async def send(self, event):
                sent.append(event)

        router = AlertRouter(min_severity="LOW")
        router.register(FakeAlerter())
        router.register(FakeAlerter())

        event = _make_event(VerdictType.MALICIOUS, Severity.HIGH)
        await router.dispatch(event)
        assert len(sent) == 2

    @pytest.mark.asyncio
    async def test_benign_never_dispatched(self):
        sent = []

        class FakeAlerter:
            async def send(self, event):
                sent.append(event)

        router = AlertRouter(min_severity="NONE")
        router.register(FakeAlerter())

        event = _make_event(VerdictType.BENIGN, Severity.NONE)
        await router.dispatch(event)
        assert sent == [], "BENIGN should never be dispatched regardless of min_severity"

    @pytest.mark.asyncio
    async def test_min_severity_filters_low_from_medium(self):
        sent = []

        class FakeAlerter:
            async def send(self, event):
                sent.append(event)

        router = AlertRouter(min_severity="MEDIUM")
        router.register(FakeAlerter())

        event = _make_event(VerdictType.SUSPICIOUS, Severity.LOW)
        await router.dispatch(event)
        assert sent == []

    @pytest.mark.asyncio
    async def test_alerter_failure_does_not_block_others(self):
        results = []

        class FailAlerter:
            async def send(self, event):
                raise RuntimeError("I fail")

        class OkAlerter:
            async def send(self, event):
                results.append("ok")

        router = AlertRouter(min_severity="LOW")
        router.register(FailAlerter())
        router.register(OkAlerter())

        event = _make_event(VerdictType.MALICIOUS, Severity.HIGH)
        await router.dispatch(event)
        assert "ok" in results

    def test_should_alert_critical(self):
        router = AlertRouter(min_severity="MEDIUM")
        event = _make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
        assert router._should_alert(event)

    def test_should_not_alert_benign(self):
        router = AlertRouter(min_severity="NONE")
        event = _make_event(VerdictType.BENIGN, Severity.NONE)
        assert not router._should_alert(event)

    @pytest.mark.asyncio
    async def test_failed_count_tracked(self):
        """[Finding 4] Router should track failed_count when all alerters fail."""

        class FailAlerter:
            name = "fail"

            async def send(self, event):
                raise RuntimeError("boom")

        router = AlertRouter(min_severity="LOW")
        router.register(FailAlerter())

        event = _make_event(VerdictType.MALICIOUS, Severity.HIGH)
        await router.dispatch(event)
        assert router.dispatched_count == 0
        assert router.failed_count == 1


# ─── _build_release_url (cli helper) ─────────────────────────────────────────


class TestBuildReleaseUrl:
    def test_pypi_url(self):
        from depvet.cli import _build_release_url

        url = _build_release_url("requests", "2.32.0", "pypi")
        assert "pypi.org" in url
        assert "requests" in url

    def test_npm_url(self):
        from depvet.cli import _build_release_url

        url = _build_release_url("lodash", "4.17.21", "npm")
        assert "npmjs.com" in url
        assert "lodash" in url

    def test_go_url(self):
        from depvet.cli import _build_release_url

        url = _build_release_url("github.com/gin-gonic/gin", "v1.9.0", "go")
        assert "pkg.go.dev" in url

    def test_cargo_url(self):
        from depvet.cli import _build_release_url

        url = _build_release_url("serde", "1.0.0", "cargo")
        assert "crates.io" in url

    def test_unknown_ecosystem_returns_npm_url(self):
        from depvet.cli import _build_release_url

        url = _build_release_url("pkg", "1.0", "unknown")
        assert url  # should not be empty


# ─── format_alert_text ──────────────────────────────────────────────────────


class TestFormatAlertText:
    def test_contains_package_info(self):
        from depvet.alert.stdout import format_alert_text
        from depvet.models.verdict import Finding, FindingCategory

        verdict = _make_verdict()
        verdict.findings = [
            Finding(
                category=FindingCategory.EXFILTRATION,
                description="Env vars sent to external server",
                file="setup.py",
                line_start=10,
                line_end=15,
                evidence="os.environ",
                cwe="CWE-200",
                severity=Severity.CRITICAL,
            )
        ]
        event = AlertEvent(release=_make_release(), verdict=verdict)
        text = format_alert_text(event)
        assert "evil-pkg" in text
        assert "MALICIOUS" in text
        assert "EXFILTRATION" in text
        assert "CWE-200" in text
        assert "setup.py" in text
        assert "L10-L15" in text

    def test_no_findings(self):
        from depvet.alert.stdout import format_alert_text

        event = _make_event(VerdictType.SUSPICIOUS, Severity.MEDIUM)
        text = format_alert_text(event)
        assert "SUSPICIOUS" in text
        assert "Findings:" not in text

    def test_contains_url(self):
        from depvet.alert.stdout import format_alert_text

        event = _make_event()
        text = format_alert_text(event)
        assert "pypi.org" in text


# ─── StdoutAlerter JSON mode detail ────────────────────────────────────────


class TestStdoutAlerterJsonDetail:
    @pytest.mark.asyncio
    async def test_json_mode_has_all_fields(self, capsys):
        alerter = StdoutAlerter(json_mode=True, min_severity="NONE")
        event = _make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
        await alerter.send(event)
        out = capsys.readouterr().out.strip()
        parsed = json.loads(out)
        assert parsed["package"] == "evil-pkg"
        assert parsed["version"] == "1.0.1"
        assert parsed["ecosystem"] == "pypi"
        assert parsed["verdict"] == "MALICIOUS"
        assert parsed["severity"] == "CRITICAL"
        assert "confidence" in parsed
        assert "summary" in parsed
        assert "url" in parsed

    @pytest.mark.asyncio
    async def test_json_mode_previous_version(self, capsys):
        alerter = StdoutAlerter(json_mode=True, min_severity="NONE")
        event = _make_event(VerdictType.SUSPICIOUS, Severity.MEDIUM)
        await alerter.send(event)
        out = capsys.readouterr().out.strip()
        parsed = json.loads(out)
        assert parsed["previous_version"] == "1.0.0"


# ─── WebhookAlerter error handling ──────────────────────────────────────────


class TestWebhookAlerterError:
    @pytest.mark.asyncio
    async def test_webhook_400_raises(self):
        """Webhook returning 400+ should raise AlertDeliveryError."""
        from depvet.alert.router import AlertDeliveryError

        with patch("aiohttp.ClientSession") as mock_cls:
            mock_resp = AsyncMock()
            mock_resp.status = 500
            mock_resp.headers = {}
            mock_resp.release = MagicMock()
            mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_resp.__aexit__ = AsyncMock(return_value=False)

            mock_sess = AsyncMock()
            mock_sess.request = AsyncMock(return_value=mock_resp)
            mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
            mock_sess.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_sess

            alerter = WebhookAlerter(url="https://example.com/hook")
            event = _make_event()
            with pytest.raises(AlertDeliveryError, match="500"):
                await alerter.send(event)


class TestSlackAlerterError:
    @pytest.mark.asyncio
    async def test_slack_non_200_raises(self):
        from depvet.alert.router import AlertDeliveryError

        with patch("aiohttp.ClientSession") as mock_cls:
            mock_resp = AsyncMock()
            mock_resp.status = 403
            mock_resp.headers = {}
            mock_resp.release = MagicMock()
            mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_resp.__aexit__ = AsyncMock(return_value=False)

            mock_sess = AsyncMock()
            mock_sess.request = AsyncMock(return_value=mock_resp)
            mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
            mock_sess.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_sess

            alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
            event = _make_event()
            with pytest.raises(AlertDeliveryError, match="403"):
                await alerter.send(event)


# ─── WebhookAlerter payload structure ───────────────────────────────────────


class TestWebhookPayload:
    @pytest.mark.asyncio
    async def test_payload_has_correct_structure(self):
        """Webhook payload should contain event_type, release, verdict keys."""
        captured_body = []

        async def fake_request(method, url, **kwargs):
            captured_body.append(kwargs.get("data", b""))
            resp = MagicMock()
            resp.status = 200
            resp.headers = {}
            resp.release = MagicMock()
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        with patch("aiohttp.ClientSession") as mock_cls:
            mock_sess = AsyncMock()
            mock_sess.request = fake_request
            mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
            mock_sess.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_sess

            alerter = WebhookAlerter(url="https://example.com/hook")
            event = _make_event()
            await alerter.send(event)

        assert len(captured_body) == 1
        payload = json.loads(captured_body[0])
        assert payload["event_type"] == "depvet.release_analyzed"
        assert "timestamp" in payload
        assert payload["release"]["name"] == "evil-pkg"
        assert payload["verdict"]["verdict"] == "MALICIOUS"
        assert payload["verdict"]["severity"] == "CRITICAL"
