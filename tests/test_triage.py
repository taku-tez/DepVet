"""Tests for Stage 1 triage - rule-first, LLM-fallback pipeline."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from depvet.analyzer.triage import TriageAnalyzer
from depvet.analyzer.base import BaseAnalyzer
from depvet.differ.chunker import DiffChunk, DiffFile


def make_chunk(files: list[DiffFile], idx: int = 0) -> DiffChunk:
    chunk = DiffChunk(chunk_index=idx, total_files=len(files))
    for f in files:
        chunk.add_file(f, len(f.content) // 4)
    return chunk


def make_file(path: str, content: str = "", binary: bool = False,
              is_new: bool = False) -> DiffFile:
    return DiffFile(path=path, content=content, is_binary=binary, is_new=is_new)


def mock_analyzer(triage_result=(True, "suspicious")):
    analyzer = MagicMock(spec=BaseAnalyzer)
    analyzer.triage = AsyncMock(return_value=triage_result)
    return analyzer


# ─── Rule-first: CRITICAL immediate flag ─────────────────────────────────────

@pytest.mark.asyncio
async def test_critical_rule_skips_llm():
    """CRITICAL rule match → immediate analyze without calling LLM."""
    diff = "+exec(base64.b64decode('aGVsbG8='))"
    analyzer = mock_analyzer(triage_result=(False, "llm says benign"))
    triage = TriageAnalyzer(analyzer)

    chunk = make_chunk([make_file("setup.py", diff)])
    should, reason, rule_matches = await triage.should_analyze(
        [chunk], "evil-pkg", "1.0.0", "1.0.1"
    )

    assert should is True
    assert rule_matches  # rules found something
    # LLM triage should NOT have been called for CRITICAL
    assert not analyzer.triage.called or "ルールベース" in reason


@pytest.mark.asyncio
async def test_aws_creds_detected_without_llm():
    """AWS credential access → immediate flag."""
    diff = "+secret = os.environ.get('AWS_SECRET_ACCESS_KEY')"
    analyzer = mock_analyzer(triage_result=(False, "benign"))
    triage = TriageAnalyzer(analyzer)

    chunk = make_chunk([make_file("auth.py", diff)])
    should, reason, rule_matches = await triage.should_analyze(
        [chunk], "mypkg", "1.0", "1.1"
    )

    assert should is True
    assert any(m.rule_id in ("ENV_EXFIL", "AWS_CREDS") for m in rule_matches)


# ─── Benign shortcut ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_comment_only_diff_skip_llm():
    """Comment-only diff → skip LLM, return False."""
    diff = "+# This is just a comment\n+# Another comment"
    analyzer = mock_analyzer(triage_result=(True, "llm says analyze"))
    triage = TriageAnalyzer(analyzer)

    chunk = make_chunk([make_file("utils.py", diff)])
    should, reason, rule_matches = await triage.should_analyze(
        [chunk], "mypkg", "1.0", "1.1"
    )

    # Should skip without LLM call
    assert should is False
    assert not rule_matches


# ─── LLM fallback ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_called_when_no_rules_match():
    """No rule matches → falls through to LLM triage."""
    diff = "+def new_helper():\n+    return 42"
    analyzer = mock_analyzer(triage_result=(True, "llm: analyze"))
    triage = TriageAnalyzer(analyzer)

    chunk = make_chunk([make_file("helpers.py", diff)])
    should, reason, rule_matches = await triage.should_analyze(
        [chunk], "mypkg", "1.0", "1.1"
    )

    assert analyzer.triage.called
    assert should is True
    assert reason == "llm: analyze"


@pytest.mark.asyncio
async def test_llm_says_skip_benign():
    """LLM says skip → return False."""
    diff = "+x = 1"
    analyzer = mock_analyzer(triage_result=(False, "benign change"))
    triage = TriageAnalyzer(analyzer)

    chunk = make_chunk([make_file("config.py", diff)])
    should, reason, rule_matches = await triage.should_analyze(
        [chunk], "mypkg", "1.0", "1.1"
    )

    assert should is False


# ─── Binary/new file in later chunks ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_binary_file_in_later_chunk_forces_analyze():
    """LLM says skip on chunk 1, but chunk 2 has a binary file → analyze."""
    diff = "+x = 1"
    analyzer = mock_analyzer(triage_result=(False, "benign"))
    triage = TriageAnalyzer(analyzer)

    chunk1 = make_chunk([make_file("config.py", diff)], idx=0)
    chunk2 = make_chunk([make_file("evil.so", "", binary=True)], idx=1)

    should, reason, rule_matches = await triage.should_analyze(
        [chunk1, chunk2], "mypkg", "1.0", "1.1"
    )

    assert should is True
    assert "binary" in reason.lower() or "evil.so" in reason


@pytest.mark.asyncio
async def test_new_file_in_later_chunk_forces_analyze():
    """New file in chunk 2 → analyze even if LLM says skip."""
    diff = "+x = 1"
    analyzer = mock_analyzer(triage_result=(False, "benign"))
    triage = TriageAnalyzer(analyzer)

    chunk1 = make_chunk([make_file("config.py", diff)], idx=0)
    chunk2 = make_chunk([make_file("new_module.py", "+import os", is_new=True)], idx=1)

    should, reason, rule_matches = await triage.should_analyze(
        [chunk1, chunk2], "mypkg", "1.0", "1.1"
    )

    assert should is True


# ─── Empty input ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_empty_chunks_returns_false():
    analyzer = mock_analyzer()
    triage = TriageAnalyzer(analyzer)

    should, reason, rule_matches = await triage.should_analyze([], "pkg", "1.0", "1.1")
    assert should is False
    assert rule_matches == []


# ─── Return type ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_return_is_always_3_tuple():
    analyzer = mock_analyzer()
    triage = TriageAnalyzer(analyzer)

    chunk = make_chunk([make_file("x.py", "+pass")])
    result = await triage.should_analyze([chunk], "p", "1", "2")

    assert isinstance(result, tuple)
    assert len(result) == 3
    should, reason, rule_matches = result
    assert isinstance(should, bool)
    assert isinstance(reason, str)
    assert isinstance(rule_matches, list)
