"""Tests for VerdictMerger."""

from depvet.analyzer.deep import VerdictMerger
from depvet.models.verdict import FindingCategory
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


# ─── Rule injection into VerdictMerger ──────────────────────────────────────

def test_rule_match_injected_into_findings():
    """Rule match not covered by LLM findings should be injected."""
    from depvet.analyzer.rules import RuleMatch
    merger = VerdictMerger()
    raw = [{"verdict": "SUSPICIOUS", "severity": "MEDIUM", "confidence": 0.6,
            "findings": [], "summary": "Suspicious"}]
    rule = RuleMatch(
        rule_id="OS_SYSTEM",
        category=FindingCategory.EXECUTION,
        severity=Severity.HIGH,
        description="os.system call detected",
        evidence="os.system('curl')",
        file="setup.py",
        line_number=10,
        cwe="CWE-78",
    )
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0,
                          rule_matches=[rule])
    assert len(result.findings) == 1
    assert result.findings[0].file == "setup.py"
    assert result.findings[0].category == FindingCategory.EXECUTION


def test_rule_match_not_duplicated_if_already_in_llm():
    """Rule match with same file+category as LLM finding should not duplicate."""
    from depvet.analyzer.rules import RuleMatch
    merger = VerdictMerger()
    raw = [{"verdict": "MALICIOUS", "severity": "CRITICAL", "confidence": 0.9,
            "findings": [{
                "category": "EXECUTION", "description": "exec found",
                "file": "setup.py", "line_start": 10, "line_end": 10,
                "evidence": "os.system", "cwe": "CWE-78", "severity": "HIGH"
            }], "summary": "Malicious"}]
    rule = RuleMatch(
        rule_id="OS_SYSTEM",
        category=FindingCategory.EXECUTION,
        severity=Severity.HIGH,
        description="os.system call detected",
        evidence="os.system('curl')",
        file="setup.py",
        line_number=10,
        cwe="CWE-78",
    )
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0,
                          rule_matches=[rule])
    # Should not have duplicates for (setup.py, EXECUTION)
    execution_findings = [f for f in result.findings if f.category == FindingCategory.EXECUTION and f.file == "setup.py"]
    assert len(execution_findings) == 1


def test_rule_critical_escalates_benign_to_malicious():
    """BENIGN + CRITICAL rule → MALICIOUS."""
    from depvet.analyzer.rules import RuleMatch
    merger = VerdictMerger()
    raw = [{"verdict": "BENIGN", "severity": "NONE", "confidence": 0.9,
            "findings": [], "summary": "OK"}]
    rule = RuleMatch(
        rule_id="EXEC_BASE64",
        category=FindingCategory.OBFUSCATION,
        severity=Severity.CRITICAL,
        description="base64+exec",
        evidence="exec(b64decode(...))",
        file="__init__.py",
        line_number=5,
        cwe="CWE-506",
    )
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0,
                          rule_matches=[rule])
    assert result.verdict == VerdictType.MALICIOUS


def test_rule_severity_escalates_verdict_severity():
    """Rule match with CRITICAL severity should escalate overall severity."""
    from depvet.analyzer.rules import RuleMatch
    merger = VerdictMerger()
    raw = [{"verdict": "SUSPICIOUS", "severity": "LOW", "confidence": 0.5,
            "findings": [], "summary": "Low risk"}]
    rule = RuleMatch(
        rule_id="HARDCODED_IP",
        category=FindingCategory.NETWORK,
        severity=Severity.CRITICAL,
        description="hardcoded IP",
        evidence="connect('1.2.3.4')",
        file="net.py",
        line_number=20,
        cwe="CWE-913",
    )
    result = merger.merge(raw, model="test", diff_stats=make_stats(), start_ms=0,
                          rule_matches=[rule])
    assert result.severity == Severity.CRITICAL
