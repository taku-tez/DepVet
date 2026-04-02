"""Tests for import diff analyzer."""

from depvet.analyzer.import_diff import (
    analyze_imports,
    import_signals_to_context,
    _parse_import_line,
    ImportSignal,
)


def make_diff(lines: list[str], filepath: str = "test.py") -> str:
    return "\n".join(
        [f"--- a/{filepath}", f"+++ b/{filepath}", "@@ -1,1 +1,5 @@"]
        + [f"+{line}" for line in lines]
    )


# ─── _parse_import_line ───────────────────────────────────────────────────────

def test_parse_simple_import():
    result = _parse_import_line("import socket")
    assert result == ("socket", None, [])


def test_parse_import_as():
    result = _parse_import_line("import base64 as b64")
    assert result == ("base64", "b64", [])


def test_parse_from_import():
    result = _parse_import_line("from urllib.request import urlopen, Request")
    assert result is not None
    module, alias, names = result
    assert module == "urllib.request"
    assert "urlopen" in names


def test_parse_comment_line():
    result = _parse_import_line("# import socket")
    assert result is None


def test_parse_normal_code():
    result = _parse_import_line("x = base64.b64decode('abc')")
    assert result is None


# ─── analyze_imports ─────────────────────────────────────────────────────────

def test_detect_socket_import():
    diff = make_diff(["import socket"])
    signals = analyze_imports(diff)
    assert any(s.module == "socket" and s.severity == "HIGH" for s in signals)


def test_detect_subprocess_import():
    diff = make_diff(["import subprocess"])
    signals = analyze_imports(diff)
    assert any(s.module == "subprocess" for s in signals)


def test_detect_base64_import():
    diff = make_diff(["import base64"])
    signals = analyze_imports(diff)
    assert any(s.module == "base64" for s in signals)


def test_detect_ctypes_critical():
    diff = make_diff(["import ctypes"])
    signals = analyze_imports(diff)
    critical = [s for s in signals if s.module == "ctypes" and s.severity == "CRITICAL"]
    assert critical


def test_detect_marshal_critical():
    diff = make_diff(["import marshal"])
    signals = analyze_imports(diff)
    assert any(s.severity == "CRITICAL" and "marshal" in s.module for s in signals)


def test_detect_from_subprocess_popen():
    diff = make_diff(["from subprocess import Popen, run"])
    signals = analyze_imports(diff)
    assert any(s.severity == "HIGH" for s in signals)


def test_detect_multi_import():
    diff = make_diff(["import os, sys, socket, base64"])
    signals = analyze_imports(diff)
    modules = {s.module for s in signals}
    assert "socket" in modules or "base64" in modules


def test_no_signal_for_os_import():
    """os is not in suspicious list — it's too universal."""
    diff = make_diff(["import os"])
    signals = analyze_imports(diff)
    assert not any(s.module == "os" for s in signals)


def test_no_signal_for_json():
    diff = make_diff(["import json"])
    signals = analyze_imports(diff)
    assert not signals


def test_urllib_request_medium():
    diff = make_diff(["import urllib.request"])
    signals = analyze_imports(diff)
    assert any(s.module == "urllib.request" or s.module == "urllib" for s in signals)


# ─── import_signals_to_context ───────────────────────────────────────────────

def test_context_format_high():
    signals = [ImportSignal("socket", None, [], "HIGH", "socket imported")]
    ctx = import_signals_to_context(signals)
    assert "socket" in ctx
    assert "HIGH" in ctx


def test_context_empty_on_no_signals():
    ctx = import_signals_to_context([])
    assert ctx == ""


def test_context_includes_critical_icon():
    signals = [ImportSignal("ctypes", None, [], "CRITICAL", "ctypes imported")]
    ctx = import_signals_to_context(signals)
    assert "🚨" in ctx
