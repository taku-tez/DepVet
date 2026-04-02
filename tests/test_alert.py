"""Tests for alert router and stdout formatter."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from depvet.alert.router import AlertRouter
from depvet.alert.stdout import StdoutAlerter, format_alert_text
from depvet.models.alert import AlertEvent
from depvet.models.package import Release
from depvet.models.verdict import (
    DiffStats, Finding, FindingCategory, Severity, Verdict, VerdictType,
)


def make_verdict(verdict=VerdictType.MALICIOUS, severity=Severity.CRITICAL, findings=None):
    return Verdict(
        verdict=verdict,
        severity=severity,
        confidence=0.95,
        findings=findings or [],
        summary="テストサマリー",
        analysis_duration_ms=100,
        diff_stats=DiffStats(files_changed=1, lines_added=5, lines_removed=0),
        model="claude-test",
        analyzed_at="2026-01-01T00:00:00+00:00",
        chunks_analyzed=1,
        tokens_used=100,
    )


def make_release(name="requests", version="2.32.0", ecosystem="pypi"):
    return Release(
        name=name, version=version, ecosystem=ecosystem,
        previous_version="2.31.0",
        published_at="2026-01-01T00:00:00+00:00",
        url=f"https://pypi.org/project/{name}/{version}/",
    )


def make_event(verdict=VerdictType.MALICIOUS, severity=Severity.CRITICAL):
    return AlertEvent(
        release=make_release(),
        verdict=make_verdict(verdict, severity),
    )


# ─── AlertRouter._should_alert ────────────────────────────────────────────────

def test_should_alert_malicious_critical():
    router = AlertRouter(min_severity="MEDIUM")
    event = make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
    assert router._should_alert(event) is True


def test_should_alert_malicious_medium():
    router = AlertRouter(min_severity="MEDIUM")
    event = make_event(VerdictType.MALICIOUS, Severity.MEDIUM)
    assert router._should_alert(event) is True


def test_should_not_alert_benign():
    router = AlertRouter(min_severity="MEDIUM")
    event = make_event(VerdictType.BENIGN, Severity.NONE)
    assert router._should_alert(event) is False


def test_should_not_alert_below_min_severity():
    router = AlertRouter(min_severity="HIGH")
    event = make_event(VerdictType.SUSPICIOUS, Severity.MEDIUM)
    assert router._should_alert(event) is False


def test_should_alert_suspicious_high():
    router = AlertRouter(min_severity="MEDIUM")
    event = make_event(VerdictType.SUSPICIOUS, Severity.HIGH)
    assert router._should_alert(event) is True


def test_should_alert_unknown_critical():
    router = AlertRouter(min_severity="MEDIUM")
    event = make_event(VerdictType.UNKNOWN, Severity.CRITICAL)
    assert router._should_alert(event) is True


# ─── AlertRouter.dispatch ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dispatch_calls_registered_alerters():
    router = AlertRouter(min_severity="MEDIUM")
    alerter = MagicMock()
    alerter.send = AsyncMock()
    router.register(alerter)

    event = make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
    await router.dispatch(event)

    alerter.send.assert_called_once_with(event)


@pytest.mark.asyncio
async def test_dispatch_skips_benign():
    router = AlertRouter(min_severity="MEDIUM")
    alerter = MagicMock()
    alerter.send = AsyncMock()
    router.register(alerter)

    event = make_event(VerdictType.BENIGN, Severity.NONE)
    await router.dispatch(event)

    alerter.send.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_handles_alerter_failure():
    """Failed alerter should not crash the router."""
    router = AlertRouter(min_severity="MEDIUM")
    alerter = MagicMock()
    alerter.send = AsyncMock(side_effect=Exception("network error"))
    router.register(alerter)

    event = make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
    # Should not raise
    await router.dispatch(event)


@pytest.mark.asyncio
async def test_dispatch_calls_multiple_alerters():
    router = AlertRouter(min_severity="LOW")
    alerters = [MagicMock() for _ in range(3)]
    for a in alerters:
        a.send = AsyncMock()
        router.register(a)

    event = make_event(VerdictType.SUSPICIOUS, Severity.HIGH)
    await router.dispatch(event)

    for a in alerters:
        a.send.assert_called_once()


# ─── StdoutAlerter.format_alert_text ─────────────────────────────────────────

def test_format_alert_text_malicious():
    event = make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
    text = format_alert_text(event)
    assert "MALICIOUS" in text
    assert "CRITICAL" in text
    assert "requests" in text


def test_format_alert_text_includes_finding():
    finding = Finding(
        category=FindingCategory.EXFILTRATION,
        description="認証情報が外部送信される",
        file="auth.py",
        line_start=10,
        line_end=20,
        evidence="os.environ.get('SECRET')",
        cwe="CWE-200",
        severity=Severity.CRITICAL,
    )
    verdict = make_verdict(findings=[finding])
    event = AlertEvent(release=make_release(), verdict=verdict)
    text = format_alert_text(event)

    assert "EXFILTRATION" in text
    assert "auth.py" in text


def test_format_alert_text_includes_url():
    event = make_event()
    text = format_alert_text(event)
    assert "pypi.org" in text or "https://" in text


def test_format_alert_text_shows_versions():
    event = make_event()
    text = format_alert_text(event)
    assert "2.31.0" in text
    assert "2.32.0" in text


def test_format_alert_text_benign():
    event = make_event(VerdictType.BENIGN, Severity.NONE)
    text = format_alert_text(event)
    assert "BENIGN" in text


# ─── StdoutAlerter.send (JSON mode) ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_stdout_alerter_json_output(capsys):
    alerter = StdoutAlerter(json_mode=True, min_severity="LOW")
    event = make_event(VerdictType.MALICIOUS, Severity.CRITICAL)
    await alerter.send(event)

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["verdict"] == "MALICIOUS"
    assert data["severity"] == "CRITICAL"
    assert data["package"] == "requests"
    assert "confidence" in data


@pytest.mark.asyncio
async def test_stdout_alerter_skips_below_min_severity(capsys):
    alerter = StdoutAlerter(json_mode=True, min_severity="HIGH")
    event = make_event(VerdictType.SUSPICIOUS, Severity.LOW)
    await alerter.send(event)

    captured = capsys.readouterr()
    assert captured.out == ""
