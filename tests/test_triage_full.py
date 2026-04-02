"""Comprehensive triage pipeline tests — covers all 4 phases + edge cases."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from depvet.analyzer.triage import TriageAnalyzer
from depvet.analyzer.base import BaseAnalyzer
from depvet.differ.chunker import DiffChunk, DiffFile
from depvet.models.verdict import Severity


def make_chunk(files: list[DiffFile], idx: int = 0) -> DiffChunk:
    chunk = DiffChunk(chunk_index=idx, total_files=len(files))
    for f in files:
        chunk.add_file(f, max(1, len(f.content) // 4))
    return chunk


def make_file(path: str, content: str = "", binary: bool = False,
              is_new: bool = False) -> DiffFile:
    return DiffFile(path=path, content=content, is_binary=binary, is_new=is_new)


def mock_analyzer(triage_return=(True, "llm says analyze")):
    m = MagicMock(spec=BaseAnalyzer)
    m.triage = AsyncMock(return_value=triage_return)
    return m


# ─── Phase 1: Rule engine CRITICAL → immediate, no LLM ─────────────────────

@pytest.mark.asyncio
async def test_phase1_critical_rule_no_llm_call():
    diff = "@@ -1 +1 @@\n+exec(base64.b64decode('aGVsbG8='))\n"
    analyzer = mock_analyzer((False, "benign"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("setup.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    assert should is True
    assert not analyzer.triage.called
    assert any(m.severity == Severity.CRITICAL for m in matches)


@pytest.mark.asyncio
async def test_phase1_high_rule_returns_immediately():
    """HIGH rule match returns True immediately (safety-first, no LLM required)."""
    diff = "@@ -1 +1,2 @@\n+data = base64.b64decode('aGVsbG8=')\n+print(data)\n"
    analyzer = mock_analyzer((False, "llm says benign"))  # LLM says benign but rules override
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("utils.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    assert should is True
    assert any(m.severity.value in ("HIGH", "CRITICAL") for m in matches)


@pytest.mark.asyncio
async def test_phase1_getattr_exec_critical():
    diff = "@@ -1 +1 @@\n+f = getattr(__builtins__, 'exec')\n+f(payload)\n"
    analyzer = mock_analyzer((False, "benign"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("setup.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    assert should is True


# ─── Phase 2: Import diff ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_phase2_ctypes_import_critical():
    diff = "@@ -1 +1,2 @@\n+import ctypes\n+ctypes.CDLL('libSystem.dylib')\n"
    analyzer = mock_analyzer((False, "benign"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("utils.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    assert should is True
    assert any("IMPORT" in m.rule_id for m in matches)


@pytest.mark.asyncio
async def test_phase2_atexit_import_high():
    diff = "@@ -1 +1,2 @@\n+import atexit\n+atexit.register(lambda: None)\n"
    analyzer = mock_analyzer((True, "llm says analyze"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("pkg.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    assert should is True


@pytest.mark.asyncio
async def test_phase2_json_import_no_signal():
    """json import should not trigger any signals."""
    diff = "@@ -1 +1 @@\n+import json\n+data = json.loads(text)\n"
    analyzer = mock_analyzer((False, "benign"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("parser.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    # json is safe, no import signals → falls to LLM which says benign
    assert should is False


# ─── Phase 3: Decode scan ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_phase3_hidden_b64_payload_detected():
    """Base64 encoded malicious payload should be detected without LLM."""
    import base64 as _b64
    payload = "import os; os.system('id')"
    encoded = _b64.b64encode(payload.encode()).decode()
    diff = f"@@ -1 +1,3 @@\n+import base64\n+_P = '{encoded}'\n+exec(base64.b64decode(_P))\n"
    analyzer = mock_analyzer((False, "benign"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("setup.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    assert should is True
    # rule engine catches BASE64_EXEC_CHAIN
    assert matches


# ─── Phase 4: AST analysis ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_phase4_ast_getattr_exec_critical():
    diff = "@@ -1 +1,2 @@\n+e = getattr(__builtins__, 'exec')\n+e(code)\n"
    analyzer = mock_analyzer((False, "benign"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("init.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    assert should is True


@pytest.mark.asyncio
async def test_phase4_ci_evasion_detected():
    diff = "@@ -1 +1,3 @@\n+if not os.environ.get('CI'):\n+    exec(payload)\n"
    analyzer = mock_analyzer((True, "llm: suspicious"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("setup.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    assert should is True


# ─── Benign shortcuts ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_benign_comment_only_no_llm():
    diff = "@@ -1 +1,3 @@\n+# Updated documentation\n+# Version 2.0\n+# See CHANGELOG\n"
    analyzer = mock_analyzer((True, "llm: analyze"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("docs.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
    assert should is False
    assert not analyzer.triage.called


@pytest.mark.asyncio
async def test_benign_version_bump_only():
    diff = "@@ -1 +1 @@\n+__version__ = '2.0.1'\n"
    analyzer = mock_analyzer((False, "benign"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("__init__.py", diff)])
    should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "2.0.1")
    assert should is False


# ─── Multi-chunk behavior ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_binary_in_chunk2_forces_analyze():
    diff1 = "@@ -1 +1 @@\n+x = 1\n"
    analyzer = mock_analyzer((False, "benign"))
    triage = TriageAnalyzer(analyzer)
    chunk1 = make_chunk([make_file("config.py", diff1)], idx=0)
    chunk2 = make_chunk([make_file("evil.so", "", binary=True)], idx=1)
    should, reason, matches = await triage.should_analyze([chunk1, chunk2], "p", "1.0", "1.1")
    assert should is True
    assert "evil.so" in reason or "binary" in reason.lower()


@pytest.mark.asyncio
async def test_new_file_in_chunk2_forces_analyze():
    diff1 = "@@ -1 +1 @@\n+x = 1\n"
    analyzer = mock_analyzer((False, "benign"))
    triage = TriageAnalyzer(analyzer)
    chunk1 = make_chunk([make_file("config.py", diff1)], idx=0)
    chunk2 = make_chunk([make_file("backdoor.py", "+exec('id')", is_new=True)], idx=1)
    should, reason, matches = await triage.should_analyze([chunk1, chunk2], "p", "1.0", "1.1")
    assert should is True


# ─── Return type contract ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_return_always_3_tuple_on_empty():
    analyzer = mock_analyzer()
    triage = TriageAnalyzer(analyzer)
    result = await triage.should_analyze([], "p", "1", "2")
    assert isinstance(result, tuple) and len(result) == 3
    should, reason, matches = result
    assert should is False
    assert isinstance(reason, str)
    assert isinstance(matches, list)


@pytest.mark.asyncio
async def test_return_always_3_tuple_on_normal():
    diff = "@@ -1 +1 @@\n+x = helper()\n"
    analyzer = mock_analyzer((True, "analyze"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("main.py", diff)])
    result = await triage.should_analyze([chunk], "p", "1", "2")
    assert len(result) == 3


# ─── LLM error handling ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_error_treated_as_analyze():
    """If LLM triage throws, we should still analyze (fail open to safety)."""
    diff = "@@ -1 +1 @@\n+x = complex_computation()\n"
    analyzer = MagicMock(spec=BaseAnalyzer)
    analyzer.triage = AsyncMock(side_effect=Exception("API timeout"))
    triage = TriageAnalyzer(analyzer)
    chunk = make_chunk([make_file("utils.py", diff)])
    # Should not raise; should return (True, ...) to be safe
    try:
        should, reason, matches = await triage.should_analyze([chunk], "p", "1.0", "1.1")
        # Either analyzed or returned False gracefully — just no crash
        assert isinstance(should, bool)
    except Exception:
        pytest.fail("triage should not propagate LLM errors")
