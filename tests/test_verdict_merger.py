"""Tests for VerdictMerger."""

import pytest
from depvet.analyzer.deep import VerdictMerger
from depvet.models.verdict import DiffStats, Severity, VerdictType


def make_stats():
    return DiffStats(files_changed=1, lines_added=5, lines_removed=2)


def test_merge_empty():
    merger = VerdictMerger()
    result = merger.merge([], model="test", diff_stats=make_stats(), start_ms=0)
    assert result.verdict == VerdictType.UNKNOWN
    assert result.severity == Severity.NONE
    assert result.chunks_analyzed == 0


def test_merge_single_benign():
    merger = VerdictMerger()
    raw = [{"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"}]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    assert result.verdict == VerdictType.BENIGN
    assert result.severity == Severity.NONE
    assert result.confidence == 0.9


def test_merge_malicious_wins():
    merger = VerdictMerger()
    raw = [
        {"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"},
        {"verdict": "MALICIOUS", "severity": "CRITICAL", "confidence": 0.97, "findings": [
            {"category": "EXFILTRATION", "description": "Creds sent", "file": "auth.py",
             "line_start": 10, "line_end": 20, "evidence": "os.environ", "cwe": "CWE-200", "severity": "CRITICAL"}
        ], "summary": "Malicious code found"},
    ]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    assert result.verdict == VerdictType.MALICIOUS
    assert result.severity == Severity.CRITICAL


def test_merge_suspicious_over_benign():
    merger = VerdictMerger()
    raw = [
        {"verdict": "BENIGN", "severity": "NONE", "confidence": 0.8, "findings": [], "summary": "OK"},
        {"verdict": "SUSPICIOUS", "severity": "MEDIUM", "confidence": 0.6, "findings": [
            {"category": "OBFUSCATION", "description": "base64", "file": "init.py",
             "line_start": 1, "line_end": 5, "evidence": "b64decode", "cwe": None, "severity": "MEDIUM"}
        ], "summary": "Suspicious"},
    ]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    assert result.verdict == VerdictType.SUSPICIOUS


def test_merge_deduplicates_findings():
    merger = VerdictMerger()
    finding = {"category": "OBFUSCATION", "description": "base64", "file": "init.py",
               "line_start": 1, "line_end": 5, "evidence": "b64decode", "cwe": None, "severity": "MEDIUM"}
    raw = [
        {"verdict": "SUSPICIOUS", "severity": "MEDIUM", "confidence": 0.7, "findings": [finding], "summary": "A"},
        {"verdict": "SUSPICIOUS", "severity": "MEDIUM", "confidence": 0.7, "findings": [finding], "summary": "B"},
    ]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    # Duplicate (file, category) should be deduplicated
    assert len(result.findings) == 1


def test_merge_combines_chunks_count():
    merger = VerdictMerger()
    raw = [
        {"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK"},
        {"verdict": "BENIGN", "severity": "NONE", "confidence": 0.8, "findings": [], "summary": "OK"},
    ]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    assert result.chunks_analyzed == 2


def test_merge_tokens_summed():
    merger = VerdictMerger()
    raw = [
        {"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK", "_tokens_used": 100},
        {"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9, "findings": [], "summary": "OK", "_tokens_used": 200},
    ]
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0)
    assert result.tokens_used == 300
