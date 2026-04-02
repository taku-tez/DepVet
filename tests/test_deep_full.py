"""Comprehensive DeepAnalyzer and VerdictMerger tests."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from depvet.analyzer.deep import DeepAnalyzer, VerdictMerger
from depvet.analyzer.base import BaseAnalyzer
from depvet.analyzer.rules import RuleMatch
from depvet.analyzer.version_signal import VersionTransitionContext, VersionSignal
from depvet.differ.chunker import DiffChunk, DiffFile
from depvet.models.verdict import (
    DiffStats, FindingCategory, Severity, Verdict, VerdictType,
)


def make_stats(**kw):
    defaults = dict(files_changed=1, lines_added=5, lines_removed=2)
    defaults.update(kw)
    return DiffStats(**defaults)


def make_chunk(content: str = "+x=1", path: str = "test.py") -> DiffChunk:
    f = DiffFile(path=path, content=content)
    chunk = DiffChunk(chunk_index=0, total_files=1)
    chunk.add_file(f, 10)
    return chunk


def mock_analyzer(deep_result: dict | None = None, triage_result=(True, "analyze")):
    m = MagicMock(spec=BaseAnalyzer)
    m.triage = AsyncMock(return_value=triage_result)
    result = deep_result or {
        "verdict": "BENIGN", "severity": "NONE",
        "confidence": 0.9, "findings": [], "summary": "OK"
    }
    m.deep_analyze = AsyncMock(return_value=result)
    m.get_model_name = MagicMock(return_value="mock-model")
    return m


# ─── DeepAnalyzer.analyze ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_deep_analyze_single_chunk_benign():
    analyzer = mock_analyzer()
    deep = DeepAnalyzer(analyzer)
    chunks = [make_chunk()]
    result = await deep.analyze(
        chunks=chunks,
        package_name="pkg",
        old_version="1.0",
        new_version="1.1",
        ecosystem="pypi",
        diff_stats=make_stats(),
    )
    assert result.verdict == VerdictType.BENIGN
    assert result.model == "mock-model"


@pytest.mark.asyncio
async def test_deep_analyze_multiple_chunks():
    """Multiple chunks analyzed in parallel, results merged."""
    malicious = {
        "verdict": "MALICIOUS", "severity": "CRITICAL",
        "confidence": 0.95, "findings": [
            {"category": "EXFILTRATION", "description": "creds sent",
             "file": "auth.py", "line_start": 5, "line_end": 10,
             "evidence": "os.environ", "cwe": "CWE-200", "severity": "CRITICAL"}
        ], "summary": "Malicious"
    }
    benign = {"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"}

    analyzer = MagicMock(spec=BaseAnalyzer)
    analyzer.get_model_name = MagicMock(return_value="test")
    call_count = 0

    async def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return malicious if call_count == 1 else benign

    analyzer.deep_analyze = side_effect
    deep = DeepAnalyzer(analyzer)
    chunks = [make_chunk("+import os", "auth.py"), make_chunk("+x=1", "utils.py")]
    result = await deep.analyze(
        chunks=chunks,
        package_name="pkg", old_version="1.0", new_version="1.1",
        ecosystem="pypi", diff_stats=make_stats(),
    )
    assert result.verdict == VerdictType.MALICIOUS
    assert result.chunks_analyzed == 2


@pytest.mark.asyncio
async def test_deep_analyze_chunk_error_handled():
    """If one chunk fails, others should still be processed."""
    analyzer = MagicMock(spec=BaseAnalyzer)
    analyzer.get_model_name = MagicMock(return_value="test")
    call_count = 0

    async def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("API error on chunk 1")
        return {"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"}

    analyzer.deep_analyze = side_effect
    deep = DeepAnalyzer(analyzer)
    chunks = [make_chunk("+bad", "a.py"), make_chunk("+good", "b.py")]
    result = await deep.analyze(
        chunks=chunks,
        package_name="pkg", old_version="1.0", new_version="1.1",
        ecosystem="pypi", diff_stats=make_stats(),
    )
    # Should still return a result from the successful chunk
    assert isinstance(result, Verdict)
    assert result.chunks_analyzed >= 1


@pytest.mark.asyncio
async def test_deep_analyze_all_chunks_fail():
    """All chunks fail → return UNKNOWN verdict."""
    analyzer = MagicMock(spec=BaseAnalyzer)
    analyzer.get_model_name = MagicMock(return_value="test")
    analyzer.deep_analyze = AsyncMock(side_effect=Exception("timeout"))
    deep = DeepAnalyzer(analyzer)
    chunks = [make_chunk()]
    result = await deep.analyze(
        chunks=chunks,
        package_name="pkg", old_version="1.0", new_version="1.1",
        ecosystem="pypi", diff_stats=make_stats(),
    )
    assert result.verdict == VerdictType.UNKNOWN
    assert result.chunks_analyzed == 0


@pytest.mark.asyncio
async def test_deep_analyze_with_rule_matches():
    """Rule matches should be injected into findings."""
    analyzer = mock_analyzer({"verdict": "BENIGN", "severity": "NONE", "confidence": 0.5, "findings": [], "summary": "OK"})
    rule = RuleMatch(
        rule_id="GETATTR_EXEC",
        category=FindingCategory.OBFUSCATION,
        severity=Severity.CRITICAL,
        description="getattr exec detected",
        evidence="getattr(b, 'exec')",
        file="pkg.py",
        line_number=10,
        cwe="CWE-506",
    )
    deep = DeepAnalyzer(analyzer)
    result = await deep.analyze(
        chunks=[make_chunk()],
        package_name="pkg", old_version="1.0", new_version="1.1",
        ecosystem="pypi", diff_stats=make_stats(),
        rule_matches=[rule],
    )
    # CRITICAL rule should escalate BENIGN to MALICIOUS
    assert result.verdict == VerdictType.MALICIOUS
    assert len(result.findings) >= 1


@pytest.mark.asyncio
async def test_deep_analyze_with_version_context():
    """Version context with HIGH signal should affect confidence."""
    analyzer = mock_analyzer({"verdict": "SUSPICIOUS", "severity": "MEDIUM", "confidence": 0.5, "findings": [], "summary": "Suspicious"})
    ctx = VersionTransitionContext("pkg", "pypi", "1.0", "1.1")
    ctx.signals.append(VersionSignal("MAINTAINER_CHANGE", "メンテナー変更", "HIGH", 0.20))

    deep = DeepAnalyzer(analyzer)
    result = await deep.analyze(
        chunks=[make_chunk()],
        package_name="pkg", old_version="1.0", new_version="1.1",
        ecosystem="pypi", diff_stats=make_stats(),
        version_context=ctx,
    )
    # confidence boosted by 0.20
    assert result.confidence > 0.5
    assert "メンテナー" in result.summary


# ─── VerdictMerger edge cases ─────────────────────────────────────────────────

def test_merger_single_malicious():
    merger = VerdictMerger()
    raw = [{"verdict": "MALICIOUS", "severity": "CRITICAL", "confidence": 0.99, "findings": [], "summary": "Bad"}]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    assert result.verdict == VerdictType.MALICIOUS
    assert result.severity == Severity.CRITICAL
    assert result.confidence == 0.99


def test_merger_unknown_when_all_unknown():
    merger = VerdictMerger()
    raw = [{"verdict": "UNKNOWN", "severity": "NONE", "confidence": 0.3, "findings": [], "summary": ""}]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    assert result.verdict == VerdictType.UNKNOWN


def test_merger_confidence_capped_at_1():
    merger = VerdictMerger()
    ctx = VersionTransitionContext("pkg", "pypi", "1.0", "1.1")
    ctx.signals.extend([
        VersionSignal("A", "signal 1", "HIGH", 0.30),
        VersionSignal("B", "signal 2", "HIGH", 0.30),
        VersionSignal("C", "signal 3", "HIGH", 0.30),
    ])
    raw = [{"verdict": "SUSPICIOUS", "severity": "HIGH", "confidence": 0.8, "findings": [], "summary": "x"}]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0, version_context=ctx)
    assert result.confidence <= 1.0


def test_merger_analysis_duration_positive():
    """Analysis duration should be a non-negative integer."""
    import time
    start = int(time.time() * 1000) - 100  # 100ms ago
    merger = VerdictMerger()
    raw = [{"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"}]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=start)
    assert result.analysis_duration_ms >= 0


def test_merger_analyzed_at_iso8601():
    """analyzed_at should be a valid ISO 8601 timestamp."""
    from datetime import datetime
    merger = VerdictMerger()
    raw = [{"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"}]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    # Should parse without error
    parsed = datetime.fromisoformat(result.analyzed_at)
    assert parsed.year >= 2026


def test_merger_model_name_preserved():
    merger = VerdictMerger()
    raw = [{"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"}]
    result = merger.merge(raw, model="claude-opus-4-6", diff_stats=make_stats(), start_ms=0)
    assert result.model == "claude-opus-4-6"


def test_merger_invalid_finding_category_skipped():
    """Invalid finding category should be skipped gracefully."""
    merger = VerdictMerger()
    raw = [{
        "verdict": "SUSPICIOUS", "severity": "MEDIUM", "confidence": 0.6,
        "findings": [
            {"category": "INVALID_CATEGORY", "description": "x", "file": "f.py",
             "line_start": None, "line_end": None, "evidence": "x", "cwe": None, "severity": "MEDIUM"},
            {"category": "OBFUSCATION", "description": "valid", "file": "f.py",
             "line_start": 1, "line_end": 2, "evidence": "eval(x)", "cwe": "CWE-506", "severity": "HIGH"},
        ],
        "summary": "Suspicious"
    }]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    # Invalid category should be skipped, valid one kept
    assert len(result.findings) == 1
    assert result.findings[0].category == FindingCategory.OBFUSCATION


def test_merger_diff_stats_preserved():
    """DiffStats should pass through to Verdict unchanged."""
    stats = DiffStats(files_changed=5, lines_added=100, lines_removed=50,
                      binary_files=["lib.so"], new_files=["new.py"], deleted_files=[])
    merger = VerdictMerger()
    raw = [{"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"}]
    result = merger.merge(raw, model="test", diff_stats=stats, start_ms=0)
    assert result.diff_stats.files_changed == 5
    assert result.diff_stats.binary_files == ["lib.so"]
