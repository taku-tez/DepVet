"""Tests for OSV checker severity mapping and data parsing."""

import pytest
from depvet.known_bad.osv import OSVChecker


@pytest.fixture
def checker():
    return OSVChecker()


# ─── Severity mapping ────────────────────────────────────────────────────────


def test_severity_critical_cvss_10(checker):
    vuln = {"severity": [{"type": "CVSS_V3", "score": "10.0"}], "id": "CVE-2023-001"}
    assert checker._map_severity(vuln) == "CRITICAL"


def test_severity_critical_cvss_9(checker):
    vuln = {"severity": [{"type": "CVSS_V3", "score": "9.1"}], "id": "CVE-2023-001"}
    assert checker._map_severity(vuln) == "CRITICAL"


def test_severity_high_cvss_7(checker):
    vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}], "id": "CVE-2023-001"}
    assert checker._map_severity(vuln) == "HIGH"


def test_severity_medium_cvss_5(checker):
    vuln = {"severity": [{"type": "CVSS_V3", "score": "5.0"}], "id": "CVE-2023-001"}
    assert checker._map_severity(vuln) == "MEDIUM"


def test_severity_low_cvss_2(checker):
    vuln = {"severity": [{"type": "CVSS_V3", "score": "2.0"}], "id": "CVE-2023-001"}
    assert checker._map_severity(vuln) == "LOW"


def test_severity_malicious_package_default_high(checker):
    """MAL-* packages default to HIGH even without CVSS."""
    vuln = {"severity": [], "id": "MAL-2023-001"}
    assert checker._map_severity(vuln) == "HIGH"


def test_severity_unknown_cvss_type_malicious(checker):
    """Non-CVSS severity type + MAL prefix → HIGH."""
    vuln = {"severity": [{"type": "CVSS_V2", "score": "9.0"}], "id": "MAL-2022-123"}
    assert checker._map_severity(vuln) == "HIGH"


def test_severity_no_severity_field_default_medium(checker):
    """No severity info → MEDIUM default."""
    vuln = {"id": "CVE-2023-001"}
    assert checker._map_severity(vuln) == "MEDIUM"


# ─── Ecosystem mapping ───────────────────────────────────────────────────────


def test_ecosystem_map_pypi(checker):
    assert checker._map_ecosystem("pypi") == "PyPI"


def test_ecosystem_map_npm(checker):
    assert checker._map_ecosystem("npm") == "npm"


def test_ecosystem_map_go(checker):
    assert checker._map_ecosystem("go") == "Go"


def test_ecosystem_map_cargo(checker):
    assert checker._map_ecosystem("cargo") == "crates.io"


def test_ecosystem_map_unknown(checker):
    assert checker._map_ecosystem("unknown_eco") is None
