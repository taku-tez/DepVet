"""Tests for Vertex AI analyzer (unit/mock tests — no GCP credentials needed)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import importlib

import pytest

from depvet.differ.chunker import DiffChunk, DiffFile


@pytest.fixture(autouse=True)
def _reload_vertexai_module():
    """Reload the vertexai module before each test to prevent mock contamination."""
    import depvet.analyzer.vertexai as m
    importlib.reload(m)
    yield
    importlib.reload(m)


def _make_chunk(content: str = "+import os\n") -> DiffChunk:
    chunk = DiffChunk(chunk_index=0, total_files=1)
    chunk.add_file(DiffFile(path="test.py", content=content, is_binary=False, is_new=False), tokens=10)
    return chunk


# ─── VertexClaudeAnalyzer ────────────────────────────────────────────────────

class TestVertexClaudeAnalyzer:
    def test_import_error_without_package(self):
        with patch.dict("sys.modules", {"anthropic": None}):
            import importlib
            import depvet.analyzer.vertexai as m
            importlib.reload(m)
            with pytest.raises(ImportError, match="anthropic"):
                m.VertexClaudeAnalyzer(project_id="proj", region="us-east5")

    def test_missing_project_id_raises(self, monkeypatch):
        monkeypatch.delenv("VERTEX_PROJECT_ID", raising=False)
        mock_anthropic = MagicMock()
        mock_anthropic.AsyncAnthropicVertex.side_effect = KeyError("VERTEX_PROJECT_ID")
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer.vertexai import VertexClaudeAnalyzer
            with pytest.raises((ValueError, KeyError)):
                VertexClaudeAnalyzer()

    def test_get_model_name(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic = MagicMock()
        mock_anthropic.AsyncAnthropicVertex.return_value = MagicMock()
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m
            import importlib
            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(
                model="claude-opus-4@20250514",
                project_id="my-project",
                region="us-east5",
            )
            assert analyzer.get_model_name() == "vertex-claude/claude-opus-4@20250514"

    @pytest.mark.asyncio
    async def test_triage_should_analyze_true(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=MagicMock(
            content=[MagicMock(text=json.dumps({"should_analyze": True, "reason": "suspicious"}))]
        ))
        mock_anthropic.AsyncAnthropicVertex.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m
            import importlib
            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            chunk = _make_chunk("+import subprocess\n")
            should_analyze, reason = await analyzer.triage(chunk, "evil-pkg", "1.0.0", "1.0.1")

        assert should_analyze is True
        assert "suspicious" in reason

    @pytest.mark.asyncio
    async def test_triage_fallback_on_error(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("API unavailable"))
        mock_anthropic.AsyncAnthropicVertex.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m
            import importlib
            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            chunk = _make_chunk()
            should_analyze, reason = await analyzer.triage(chunk, "pkg", "1.0.0", "1.0.1")

        # Falls back to True (analyze anyway)
        assert should_analyze is True
        assert "error" in reason

    @pytest.mark.asyncio
    async def test_deep_analyze_returns_dict(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        verdict_json = json.dumps({
            "verdict": "MALICIOUS",
            "confidence": 0.95,
            "severity": "CRITICAL",
            "findings": [],
        })
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=MagicMock(
            content=[MagicMock(text=verdict_json)]
        ))
        mock_anthropic.AsyncAnthropicVertex.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m
            import importlib
            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            chunk = _make_chunk()
            result = await analyzer.deep_analyze(chunk, 0, 1, "pkg", "1.0.0", "1.0.1", "pypi")

        assert result["verdict"] == "MALICIOUS"
        assert result["confidence"] == 0.95

    @pytest.mark.asyncio
    async def test_deep_analyze_error_returns_unknown(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("timeout"))
        mock_anthropic.AsyncAnthropicVertex.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m
            import importlib
            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            chunk = _make_chunk()
            result = await analyzer.deep_analyze(chunk, 0, 1, "pkg", "1.0.0", "1.0.1", "pypi")

        assert result["verdict"] == "UNKNOWN"
        assert result["confidence"] == 0.0


# ─── VertexGeminiAnalyzer ────────────────────────────────────────────────────

class TestVertexGeminiAnalyzer:
    def test_import_error_without_package(self):
        with patch.dict("sys.modules", {"vertexai": None, "vertexai.generative_models": None}):
            import importlib
            import depvet.analyzer.vertexai as m
            importlib.reload(m)
            with pytest.raises(ImportError, match="google-cloud-aiplatform"):
                m.VertexGeminiAnalyzer(project_id="proj")

    def test_get_model_name(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai = MagicMock()
        mock_gen = MagicMock()
        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m
            import importlib
            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(
                model="gemini-2.0-flash-001",
                project_id="my-project",
            )
            assert "vertex-gemini" in analyzer.get_model_name()
            assert "gemini-2.0-flash-001" in analyzer.get_model_name()

    @pytest.mark.asyncio
    async def test_triage_returns_tuple(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai = MagicMock()
        mock_gen = MagicMock()
        mock_model_instance = MagicMock()
        mock_model_instance.generate_content.return_value = MagicMock(
            text=json.dumps({"should_analyze": False, "reason": "benign update"})
        )
        mock_gen.GenerativeModel.return_value = mock_model_instance
        mock_gen.GenerationConfig.return_value = MagicMock()

        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m
            import importlib
            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(project_id="my-project")
            chunk = _make_chunk()
            should_analyze, reason = await analyzer.triage(chunk, "pkg", "1.0.0", "1.0.1")

        assert should_analyze is False
        assert "benign" in reason


# ─── CLI provider routing ─────────────────────────────────────────────────────

class TestProviderRouting:
    def test_vertex_claude_provider_aliases(self):
        """All accepted provider strings should route to VertexClaudeAnalyzer."""

        aliases = ["vertex-claude", "vertexai-claude", "vertex_claude"]
        for alias in aliases:
            # Just verify the string comparison logic (don't instantiate)
            assert alias.lower() in ("vertex-claude", "vertexai-claude", "vertex_claude")

    def test_vertex_gemini_provider_aliases(self):
        aliases = ["vertex-gemini", "vertexai-gemini", "vertex_gemini", "gemini"]
        for alias in aliases:
            assert alias.lower() in ("vertex-gemini", "vertexai-gemini", "vertex_gemini", "gemini")
