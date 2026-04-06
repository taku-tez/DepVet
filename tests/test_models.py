"""Tests for data models."""

from depvet.models.verdict import VerdictType, Severity, FindingCategory, Finding, DiffStats, Verdict
from depvet.models.package import Release
from depvet.models.alert import AlertEvent


def make_verdict(**kwargs):
    defaults = dict(
        verdict=VerdictType.BENIGN,
        severity=Severity.NONE,
        confidence=0.9,
        findings=[],
        summary="No issues found",
        analysis_duration_ms=100,
        diff_stats=DiffStats(files_changed=1, lines_added=5, lines_removed=2),
        model="claude-test",
        analyzed_at="2026-01-01T00:00:00+00:00",
        chunks_analyzed=1,
        tokens_used=500,
    )
    defaults.update(kwargs)
    return Verdict(**defaults)


def make_release(**kwargs):
    defaults = dict(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        previous_version="2.31.0",
        published_at="2026-01-01T00:00:00+00:00",
        url="https://pypi.org/project/requests/2.32.0/",
    )
    defaults.update(kwargs)
    return Release(**defaults)


def test_verdict_type_values():
    assert VerdictType.MALICIOUS == "MALICIOUS"
    assert VerdictType.BENIGN == "BENIGN"
    assert VerdictType.SUSPICIOUS == "SUSPICIOUS"
    assert VerdictType.UNKNOWN == "UNKNOWN"


def test_severity_values():
    assert Severity.CRITICAL == "CRITICAL"
    assert Severity.HIGH == "HIGH"
    assert Severity.MEDIUM == "MEDIUM"
    assert Severity.LOW == "LOW"
    assert Severity.NONE == "NONE"


def test_finding_category_values():
    assert FindingCategory.OBFUSCATION == "OBFUSCATION"
    assert FindingCategory.EXFILTRATION == "EXFILTRATION"
    assert FindingCategory.BUILD_HOOK_ABUSE == "BUILD_HOOK_ABUSE"


def test_finding_creation():
    f = Finding(
        category=FindingCategory.EXFILTRATION,
        description="Test finding",
        file="auth.py",
        line_start=10,
        line_end=20,
        evidence="os.environ['SECRET']",
        cwe="CWE-200",
        severity=Severity.CRITICAL,
    )
    assert f.category == FindingCategory.EXFILTRATION
    assert f.cwe == "CWE-200"
    assert f.severity == Severity.CRITICAL


def test_diff_stats_defaults():
    stats = DiffStats(files_changed=2, lines_added=10, lines_removed=3)
    assert stats.binary_files == []
    assert stats.new_files == []
    assert stats.deleted_files == []


def test_verdict_creation():
    v = make_verdict()
    assert v.verdict == VerdictType.BENIGN
    assert v.confidence == 0.9
    assert v.chunks_analyzed == 1


def test_release_creation():
    r = make_release()
    assert r.name == "requests"
    assert r.ecosystem == "pypi"
    assert r.rank is None


def test_alert_event():
    v = make_verdict(verdict=VerdictType.MALICIOUS, severity=Severity.CRITICAL)
    r = make_release()
    event = AlertEvent(release=r, verdict=v)
    assert event.affected_tenants == []
    assert event.verdict.verdict == VerdictType.MALICIOUS
