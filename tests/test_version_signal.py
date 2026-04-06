"""Tests for version transition signals."""

from depvet.analyzer.version_signal import (
    VersionTransitionContext,
    VersionSignal,
)
from depvet.analyzer.deep import VerdictMerger
from depvet.models.verdict import DiffStats, VerdictType


def make_stats():
    return DiffStats(files_changed=1, lines_added=5, lines_removed=0)


def make_context_with_signals(*signals: VersionSignal) -> VersionTransitionContext:
    ctx = VersionTransitionContext(
        package_name="test-pkg",
        ecosystem="pypi",
        old_version="1.0.0",
        new_version="1.0.1",
    )
    ctx.signals.extend(signals)
    return ctx


# ─── VersionTransitionContext ────────────────────────────────────────────────


def test_no_signals_no_boost():
    ctx = VersionTransitionContext("pkg", "pypi", "1.0", "1.1")
    assert not ctx.has_high_risk_signals
    assert ctx.total_confidence_boost == 0.0


def test_high_signal_detected():
    ctx = make_context_with_signals(VersionSignal("MAINTAINER_CHANGE", "メンテナー変更", "HIGH", 0.20))
    assert ctx.has_high_risk_signals
    assert ctx.total_confidence_boost == 0.20


def test_multiple_signals_cumulative_boost():
    ctx = make_context_with_signals(
        VersionSignal("MAINTAINER_CHANGE", "メンテナー変更", "HIGH", 0.20),
        VersionSignal("LONG_DORMANCY", "365日ぶり更新", "HIGH", 0.15),
    )
    assert abs(ctx.total_confidence_boost - 0.35) < 0.01


def test_summary_format():
    ctx = make_context_with_signals(VersionSignal("MAINTAINER_CHANGE", "メンテナーが変更された", "HIGH", 0.20))
    assert "バージョン遷移シグナル" in ctx.summary()
    assert "メンテナーが変更された" in ctx.summary()


# ─── Escalation in VerdictMerger ─────────────────────────────────────────────


def test_benign_escalates_to_suspicious_with_high_signal():
    """LLM says BENIGN with low confidence (<0.90) + HIGH signal → SUSPICIOUS."""
    merger = VerdictMerger()
    # confidence=0.60: below 0.90 threshold → escalation applies
    raw = [{"verdict": "BENIGN", "severity": "NONE", "confidence": 0.60, "findings": [], "summary": "OK"}]
    ctx = make_context_with_signals(VersionSignal("MAINTAINER_CHANGE", "メンテナー変更", "HIGH", 0.20))
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0, version_context=ctx)
    assert result.verdict == VerdictType.SUSPICIOUS


def test_high_confidence_benign_not_overridden():
    """LLM says BENIGN with high confidence (>=0.90) + HIGH signal → keep BENIGN (Rule C)."""
    merger = VerdictMerger()
    # confidence=0.95: above 0.90 → LLM trusted, BENIGN preserved
    raw = [{"verdict": "BENIGN", "severity": "NONE", "confidence": 0.95, "findings": [], "summary": "OK"}]
    ctx = make_context_with_signals(VersionSignal("MAINTAINER_CHANGE", "メンテナー変更", "HIGH", 0.20))
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0, version_context=ctx)
    # High-confidence BENIGN should be preserved even with version signal
    assert result.verdict == VerdictType.BENIGN


def test_confidence_boosted_by_version_signals():
    merger = VerdictMerger()
    raw = [{"verdict": "SUSPICIOUS", "severity": "MEDIUM", "confidence": 0.5, "findings": [], "summary": "Suspicious"}]
    ctx = make_context_with_signals(
        VersionSignal("LONG_DORMANCY", "365日ぶり更新", "HIGH", 0.15),
        VersionSignal("MAINTAINER_CHANGE", "メンテナー変更", "HIGH", 0.20),
    )
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0, version_context=ctx)
    # 0.5 + 0.35 = 0.85
    assert result.confidence > 0.8


def test_no_escalation_without_signals():
    merger = VerdictMerger()
    raw = [{"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"}]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0, version_context=None)
    assert result.verdict == VerdictType.BENIGN


def test_summary_includes_version_signals():
    merger = VerdictMerger()
    raw = [{"verdict": "SUSPICIOUS", "severity": "MEDIUM", "confidence": 0.6, "findings": [], "summary": "怪しい"}]
    ctx = make_context_with_signals(VersionSignal("MAINTAINER_CHANGE", "メンテナーが変更された", "HIGH", 0.20))
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0, version_context=ctx)
    assert "メンテナー" in result.summary or "バージョン遷移" in result.summary


def test_new_install_hook_signal():
    ctx = VersionTransitionContext("pkg", "npm", "1.0.0", "1.0.1")
    ctx.new_install_hook = True
    ctx.signals.append(VersionSignal("NEW_INSTALL_HOOK", "postinstallが追加された", "CRITICAL", 0.30))
    assert ctx.has_high_risk_signals
    assert ctx.total_confidence_boost == 0.30
