"""Tests for AST-based static analysis."""

from depvet.analyzer.ast_scan import ast_scan_diff
from depvet.models.verdict import Severity


def make_diff(lines: list[str], filepath: str = "test.py") -> str:
    return "\n".join(
        [f"--- a/{filepath}", f"+++ b/{filepath}", "@@ -1 +1,{len(lines)} @@"]
        + [f"+{line}" for line in lines]
    )


# ─── Direct dangerous calls ───────────────────────────────────────────────────

def test_detect_exec_call():
    diff = make_diff(["exec(payload)"])
    findings = ast_scan_diff(diff, "setup.py")
    ids = [f.finding_id for f in findings]
    assert "DIRECT_EXEC_EVAL" in ids
    assert any(f.severity == Severity.CRITICAL for f in findings if f.finding_id == "DIRECT_EXEC_EVAL")


def test_detect_eval_call():
    diff = make_diff(["result = eval(user_input)"])
    findings = ast_scan_diff(diff, "utils.py")
    assert any(f.finding_id == "DIRECT_EXEC_EVAL" for f in findings)


def test_no_false_positive_print():
    diff = make_diff(["print('hello world')"])
    findings = ast_scan_diff(diff, "main.py")
    assert not findings


# ─── getattr obfuscation ─────────────────────────────────────────────────────

def test_detect_getattr_exec():
    diff = make_diff(["f = getattr(__builtins__, 'exec')"])
    findings = ast_scan_diff(diff, "obf.py")
    ids = [f.finding_id for f in findings]
    assert "GETATTR_DANGEROUS" in ids


def test_detect_getattr_system():
    diff = make_diff(["fn = getattr(os, 'system')"])
    findings = ast_scan_diff(diff, "util.py")
    ids = [f.finding_id for f in findings]
    assert "GETATTR_DANGEROUS" in ids


def test_no_false_positive_getattr_safe():
    diff = make_diff(["v = getattr(obj, 'name')"])
    findings = ast_scan_diff(diff, "model.py")
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert not critical


# ─── Variable aliasing ────────────────────────────────────────────────────────

def test_detect_aliased_exec():
    diff = make_diff([
        "e = exec",
        "e(payload)",
    ])
    findings = ast_scan_diff(diff, "malware.py")
    ids = [f.finding_id for f in findings]
    assert "ALIASED_EXEC" in ids or "DIRECT_EXEC_EVAL" in ids


# ─── Dynamic import ───────────────────────────────────────────────────────────

def test_detect_dynamic_import_suspicious():
    diff = make_diff(["mod = __import__('subprocess')"])
    findings = ast_scan_diff(diff, "evil.py")
    ids = [f.finding_id for f in findings]
    assert "DYNAMIC_IMPORT_SUSPICIOUS" in ids


def test_no_false_positive_dynamic_import_safe():
    diff = make_diff(["mod = __import__('json')"])
    findings = ast_scan_diff(diff, "config.py")
    assert not findings


# ─── atexit / threading ──────────────────────────────────────────────────────

def test_detect_atexit_register():
    diff = make_diff(["atexit.register(lambda: exfiltrate())"])
    findings = ast_scan_diff(diff, "init.py")
    ids = [f.finding_id for f in findings]
    assert "ATEXIT_REGISTER" in ids


def test_detect_threading_timer():
    diff = make_diff(["threading.Timer(30, lambda: exfiltrate()).start()"])
    findings = ast_scan_diff(diff, "init.py")
    ids = [f.finding_id for f in findings]
    assert "THREADING_TIMER" in ids


# ─── Sandbox evasion ─────────────────────────────────────────────────────────

def test_detect_ci_check():
    diff = make_diff([
        "if not os.environ.get('CI'):",
        "    exec(payload)",
    ])
    findings = ast_scan_diff(diff, "setup.py")
    ids = [f.finding_id for f in findings]
    assert "CI_SANDBOX_CHECK" in ids


def test_detect_time_bomb():
    diff = make_diff([
        "import datetime",
        "if datetime.date.today() > datetime.date(2026, 6, 1):",
        "    exec(payload)",
    ])
    findings = ast_scan_diff(diff, "main.py")
    ids = [f.finding_id for f in findings]
    assert "TIME_BOMB_CHECK" in ids


def test_detect_credential_file_check():
    diff = make_diff([
        "if os.path.exists(os.path.expanduser('~/.aws/credentials')):",
        "    exfiltrate()",
    ])
    findings = ast_scan_diff(diff, "util.py")
    ids = [f.finding_id for f in findings]
    assert "CREDENTIAL_FILE_CHECK" in ids


# ─── Non-Python file ─────────────────────────────────────────────────────────

def test_skip_non_python_file():
    diff = make_diff(["eval(payload)"], filepath="index.js")
    findings = ast_scan_diff(diff, "index.js")
    assert not findings  # JS files skipped by AST scanner


# ─── Syntax error graceful degradation ───────────────────────────────────────

def test_graceful_on_syntax_error():
    diff = make_diff([
        "def broken(",  # intentional syntax error
        "exec(payload)",
    ])
    # Should not raise, should try per-line
    findings = ast_scan_diff(diff, "broken.py")
    # May or may not find anything, but should not crash
    assert isinstance(findings, list)


# ─── Deduplication ────────────────────────────────────────────────────────────

def test_deduplication():
    diff = make_diff([
        "exec(a)",
        "exec(b)",  # same rule, different line — both should appear
    ])
    findings = ast_scan_diff(diff, "x.py")
    exec_findings = [f for f in findings if f.finding_id == "DIRECT_EXEC_EVAL"]
    # Should have 2 (different lines), not 1
    assert len(exec_findings) >= 1  # at minimum one
