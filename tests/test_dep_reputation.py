"""Tests for dependency reputation evaluator."""

import pytest
from depvet.analyzer.dep_reputation import (
    _assess_signals,
    _days_since,
    DepReputationResult,
)


# ─── _days_since ─────────────────────────────────────────────────────────────

def test_days_since_recent():
    from datetime import datetime, timezone, timedelta
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    days = _days_since(recent)
    assert days is not None
    assert 2 <= days <= 4


def test_days_since_old():
    days = _days_since("2020-01-01T00:00:00+00:00")
    assert days is not None
    assert days > 365 * 5


def test_days_since_invalid():
    assert _days_since("not-a-date") is None


def test_days_since_with_z():
    days = _days_since("2026-01-01T00:00:00Z")
    assert days is not None
    assert days >= 0


# ─── _assess_signals ─────────────────────────────────────────────────────────

class TestAssessSignals:
    """Comprehensive signal assessment tests."""

    def test_brand_new_single_version_zero_dl_is_critical(self):
        """The axios attack pattern: 1 day old, 1 version, 0 downloads."""
        severity, signals, boost = _assess_signals(
            age_days=1,
            weekly_downloads=0,
            total_versions=1,
        )
        assert severity == "CRITICAL"
        assert boost >= 0.25
        assert len(signals) >= 2

    def test_7_days_old_single_version_is_critical(self):
        severity, signals, boost = _assess_signals(
            age_days=6,
            weekly_downloads=50,
            total_versions=1,
        )
        assert severity in ("CRITICAL", "HIGH")

    def test_fresh_package_high_downloads_is_high(self):
        """New package but popular could be legitimate (like a fork)."""
        severity, signals, boost = _assess_signals(
            age_days=3,
            weekly_downloads=50_000,
            total_versions=1,
        )
        # Age alone is HIGH, but downloads don't help much here
        assert severity in ("HIGH", "CRITICAL")

    def test_old_package_low_downloads_is_medium(self):
        severity, signals, boost = _assess_signals(
            age_days=200,
            weekly_downloads=500,
            total_versions=10,
        )
        assert severity in ("MEDIUM", "LOW", "NONE")

    def test_established_package_no_signals(self):
        """Well-established package should have no suspicious signals."""
        severity, signals, boost = _assess_signals(
            age_days=2000,   # ~5 years old
            weekly_downloads=1_000_000,
            total_versions=100,
        )
        assert severity == "NONE"
        assert boost == 0.0
        assert not signals

    def test_download_ratio_critical(self):
        """Parent has 100M DL/week, new dep has 0 → critical mismatch."""
        severity, signals, boost = _assess_signals(
            age_days=1,
            weekly_downloads=0,
            total_versions=1,
            parent_downloads=100_000_000,
        )
        assert severity == "CRITICAL"
        # Download ratio signal should be included
        ratio_signals = [s for s in signals if "DL" in s or "ダウンロード" in s]
        assert ratio_signals

    def test_download_ratio_high(self):
        severity, signals, boost = _assess_signals(
            age_days=100,
            weekly_downloads=10,
            total_versions=5,
            parent_downloads=100_000,
        )
        # ratio = 10000:1 → HIGH ratio signal
        assert severity in ("HIGH", "CRITICAL")

    def test_missing_metrics_handled(self):
        """None values should be handled gracefully."""
        severity, signals, boost = _assess_signals(
            age_days=None,
            weekly_downloads=None,
            total_versions=None,
        )
        assert severity == "NONE"
        assert not signals

    def test_only_age_signal(self):
        severity, signals, boost = _assess_signals(
            age_days=3,
            weekly_downloads=None,
            total_versions=None,
        )
        assert severity in ("HIGH", "CRITICAL")

    def test_signals_are_japanese_strings(self):
        _, signals, _ = _assess_signals(
            age_days=1,
            weekly_downloads=0,
            total_versions=1,
        )
        for s in signals:
            assert isinstance(s, str)
            assert len(s) > 5


# ─── DepReputationResult ─────────────────────────────────────────────────────

class TestDepReputationResult:
    def test_is_suspicious_critical(self):
        r = DepReputationResult("pkg", "npm", "^1.0", severity="CRITICAL")
        assert r.is_suspicious is True

    def test_is_suspicious_high(self):
        r = DepReputationResult("pkg", "npm", "^1.0", severity="HIGH")
        assert r.is_suspicious is True

    def test_is_suspicious_medium(self):
        r = DepReputationResult("pkg", "npm", "^1.0", severity="MEDIUM")
        assert r.is_suspicious is True

    def test_is_not_suspicious_none(self):
        r = DepReputationResult("pkg", "npm", "^1.0", severity="NONE")
        assert r.is_suspicious is False

    def test_default_values(self):
        r = DepReputationResult("pkg", "npm", "^1.0")
        assert r.age_days is None
        assert r.weekly_downloads is None
        assert r.signals == []
        assert r.severity == "NONE"


# ─── Zero-code-change signal ─────────────────────────────────────────────────

class TestZeroCodeChangeSignal:
    @pytest.mark.asyncio
    async def test_zero_lines_with_new_dep_is_critical(self):
        from depvet.analyzer.version_signal import analyze_zero_code_change_signal
        from depvet.analyzer.dep_extractor import NewDependency
        from depvet.models.verdict import DiffStats

        stats = DiffStats(files_changed=1, lines_added=0, lines_removed=0)
        deps = [NewDependency("evil-pkg", "^1.0.0", "npm", "package.json")]
        signals = await analyze_zero_code_change_signal(stats, deps, "npm")

        assert any(s.signal_id == "MANIFEST_ONLY_NEW_DEP" for s in signals)
        critical = [s for s in signals if s.severity == "CRITICAL"]
        assert critical
        assert any(s.confidence_boost >= 0.30 for s in critical)

    @pytest.mark.asyncio
    async def test_few_lines_with_new_dep_is_high(self):
        from depvet.analyzer.version_signal import analyze_zero_code_change_signal
        from depvet.analyzer.dep_extractor import NewDependency
        from depvet.models.verdict import DiffStats

        # 5 lines total (very few) + new dep
        stats = DiffStats(files_changed=1, lines_added=3, lines_removed=2)
        deps = [NewDependency("suspicious-pkg", "^2.0.0", "npm", "package.json")]
        signals = await analyze_zero_code_change_signal(stats, deps, "npm")

        assert any(s.signal_id == "ZERO_CODE_CHANGE_WITH_NEW_DEP" for s in signals)
        assert any(s.severity in ("HIGH", "CRITICAL") for s in signals)

    @pytest.mark.asyncio
    async def test_many_lines_with_new_dep_no_signal(self):
        from depvet.analyzer.version_signal import analyze_zero_code_change_signal
        from depvet.analyzer.dep_extractor import NewDependency
        from depvet.models.verdict import DiffStats

        # 200 lines changed + new dep → legitimate (added code that uses the dep)
        stats = DiffStats(files_changed=5, lines_added=150, lines_removed=50)
        deps = [NewDependency("lodash", "^4.0.0", "npm", "package.json")]
        signals = await analyze_zero_code_change_signal(stats, deps, "npm")

        # Large code change → no ZERO_CODE_CHANGE signal
        assert not any(s.signal_id == "MANIFEST_ONLY_NEW_DEP" for s in signals)
        assert not any(s.signal_id == "ZERO_CODE_CHANGE_WITH_NEW_DEP" for s in signals)

    @pytest.mark.asyncio
    async def test_no_deps_no_signal(self):
        from depvet.analyzer.version_signal import analyze_zero_code_change_signal
        from depvet.models.verdict import DiffStats

        stats = DiffStats(files_changed=1, lines_added=0, lines_removed=0)
        signals = await analyze_zero_code_change_signal(stats, [], "npm")
        assert not signals

    @pytest.mark.asyncio
    async def test_many_new_deps_flagged(self):
        from depvet.analyzer.version_signal import analyze_zero_code_change_signal
        from depvet.analyzer.dep_extractor import NewDependency
        from depvet.models.verdict import DiffStats

        stats = DiffStats(files_changed=1, lines_added=5, lines_removed=0)
        deps = [
            NewDependency(f"new-dep-{i}", "^1.0", "npm", "package.json")
            for i in range(5)
        ]
        signals = await analyze_zero_code_change_signal(stats, deps, "npm")
        assert any(s.signal_id == "MANY_NEW_DEPS_AT_ONCE" for s in signals)

    @pytest.mark.asyncio
    async def test_axios_attack_pattern(self):
        """Reproduces the exact axios 2026-03-30 pattern."""
        from depvet.analyzer.version_signal import analyze_zero_code_change_signal
        from depvet.analyzer.dep_extractor import NewDependency
        from depvet.models.verdict import DiffStats

        # axios 1.13.7 → 1.14.1: ONLY package.json changed, 1 line added
        stats = DiffStats(files_changed=1, lines_added=1, lines_removed=0)
        deps = [NewDependency("plain-crypto-js", "^4.2.1", "npm", "package.json")]
        signals = await analyze_zero_code_change_signal(stats, deps, "npm")

        # Should detect the zero/near-zero code change with new dep pattern
        assert signals
        assert any(s.severity in ("CRITICAL", "HIGH") for s in signals)
        assert any(s.confidence_boost >= 0.20 for s in signals)
        # Description should mention the package name
        desc_signals = [s for s in signals if "plain-crypto-js" in s.description]
        assert desc_signals


# ─── Evaluate functions (unit, no network) ────────────────────────────────────

def test_assess_signals_score_boundary_high_medium():
    """Test boundary between HIGH and MEDIUM (score 35 = HIGH)."""
    # age=30d (score 25) + downloads < 1000 (score 15) = 40 → HIGH
    severity, _, _ = _assess_signals(age_days=29, weekly_downloads=999, total_versions=10)
    assert severity in ("HIGH", "CRITICAL")


def test_assess_signals_score_medium_low():
    """MEDIUM score range."""
    # Only medium age (score 10)
    severity, signals, boost = _assess_signals(age_days=60, weekly_downloads=None, total_versions=None)
    assert severity in ("MEDIUM", "LOW")  # score=10 → borderline
    assert boost > 0
