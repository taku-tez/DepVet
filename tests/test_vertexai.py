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


def _mock_anthropic_client(response_text: str = '{"should_analyze": true}'):
    """Create a mock anthropic module + client returning the given text."""
    mock_anthropic = MagicMock()
    mock_client = AsyncMock()
    mock_client.messages.create = AsyncMock(return_value=MagicMock(content=[MagicMock(text=response_text)]))
    mock_anthropic.AsyncAnthropicVertex.return_value = mock_client
    return mock_anthropic, mock_client


def _mock_gemini_client(response_text: str = '{"should_analyze": true}'):
    """Create mock vertexai + generative_models returning the given text."""
    mock_vertexai = MagicMock()
    mock_gen = MagicMock()
    mock_model = MagicMock()
    mock_model.generate_content.return_value = MagicMock(text=response_text)
    mock_gen.GenerativeModel.return_value = mock_model
    mock_gen.GenerationConfig.return_value = MagicMock()
    return mock_vertexai, mock_gen, mock_model


# ─── Helper functions ───────────────────────────────────────────────────────


class TestExtractJson:
    def test_plain_json(self):
        from depvet.analyzer.vertexai import _extract_json

        assert _extract_json('{"verdict": "BENIGN"}') == {"verdict": "BENIGN"}

    def test_markdown_code_block(self):
        from depvet.analyzer.vertexai import _extract_json

        text = '```json\n{"verdict": "MALICIOUS"}\n```'
        assert _extract_json(text) == {"verdict": "MALICIOUS"}

    def test_markdown_without_json_lang(self):
        from depvet.analyzer.vertexai import _extract_json

        text = '```\n{"verdict": "SUSPICIOUS"}\n```'
        assert _extract_json(text) == {"verdict": "SUSPICIOUS"}

    def test_json_embedded_in_text(self):
        from depvet.analyzer.vertexai import _extract_json

        text = 'Here is the result: {"verdict": "BENIGN", "confidence": 0.9}'
        result = _extract_json(text)
        assert result["verdict"] == "BENIGN"

    def test_invalid_json_raises(self):
        from depvet.analyzer.vertexai import _extract_json

        with pytest.raises(json.JSONDecodeError):
            _extract_json("not json at all")


class TestSafeFormat:
    def test_replaces_known_vars(self):
        from depvet.analyzer.vertexai import _safe_format

        result = _safe_format("Hello {name} v{version}", name="pkg", version="1.0")
        assert result == "Hello pkg v1.0"

    def test_leaves_unknown_braces(self):
        from depvet.analyzer.vertexai import _safe_format

        # JSON example in template should not be mangled
        result = _safe_format('{"example": {unknown}} {name}', name="test")
        assert "{unknown}" in result
        assert "test" in result


# ─── VertexClaudeAnalyzer ────────────────────────────────────────────────────


class TestVertexClaudeAnalyzer:
    def test_import_error_without_package(self):
        with patch.dict("sys.modules", {"anthropic": None}):
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

    def test_missing_project_id_error_message(self, monkeypatch):
        monkeypatch.delenv("VERTEX_PROJECT_ID", raising=False)
        mock_anthropic = MagicMock()
        mock_anthropic.AsyncAnthropicVertex.side_effect = KeyError("VERTEX_PROJECT_ID")
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer.vertexai import VertexClaudeAnalyzer

            with pytest.raises(ValueError, match="VERTEX_PROJECT_ID"):
                VertexClaudeAnalyzer()

    def test_get_model_name(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic, _ = _mock_anthropic_client()
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

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
        mock_anthropic, _ = _mock_anthropic_client(json.dumps({"should_analyze": True, "reason": "suspicious"}))
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            chunk = _make_chunk("+import subprocess\n")
            should_analyze, reason = await analyzer.triage(chunk, "evil-pkg", "1.0.0", "1.0.1")

        assert should_analyze is True
        assert "suspicious" in reason

    @pytest.mark.asyncio
    async def test_triage_should_analyze_false(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic, _ = _mock_anthropic_client(
            json.dumps({"should_analyze": False, "reason": "benign version bump"})
        )
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            should_analyze, reason = await analyzer.triage(_make_chunk(), "pkg", "1.0", "1.1")

        assert should_analyze is False
        assert "benign" in reason

    @pytest.mark.asyncio
    async def test_triage_fallback_on_error(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("API unavailable"))
        mock_anthropic.AsyncAnthropicVertex.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            should_analyze, reason = await analyzer.triage(_make_chunk(), "pkg", "1.0.0", "1.0.1")

        assert should_analyze is True
        assert "error" in reason

    @pytest.mark.asyncio
    async def test_triage_empty_content(self, monkeypatch):
        """Empty response.content should default to should_analyze=True."""
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=MagicMock(content=[]))
        mock_anthropic.AsyncAnthropicVertex.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            should_analyze, _ = await analyzer.triage(_make_chunk(), "pkg", "1.0", "1.1")

        assert should_analyze is True

    @pytest.mark.asyncio
    async def test_triage_malformed_json_defaults_to_analyze(self, monkeypatch):
        """Invalid JSON in response should fall back to analyze=True."""
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic, _ = _mock_anthropic_client("not valid json {{{")

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            should_analyze, reason = await analyzer.triage(_make_chunk(), "pkg", "1.0", "1.1")

        assert should_analyze is True
        assert "error" in reason

    @pytest.mark.asyncio
    async def test_deep_analyze_returns_dict(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        verdict_json = json.dumps({"verdict": "MALICIOUS", "confidence": 0.95, "severity": "CRITICAL", "findings": []})
        mock_anthropic, _ = _mock_anthropic_client(verdict_json)

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            result = await analyzer.deep_analyze(_make_chunk(), 0, 1, "pkg", "1.0.0", "1.0.1", "pypi")

        assert result["verdict"] == "MALICIOUS"
        assert result["confidence"] == 0.95

    @pytest.mark.asyncio
    async def test_deep_analyze_npm_ecosystem_uses_npm_template(self, monkeypatch):
        """npm ecosystem should use the npm-specific deep analysis template."""
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic, mock_client = _mock_anthropic_client(
            json.dumps({"verdict": "BENIGN", "confidence": 0.8, "findings": []})
        )

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            result = await analyzer.deep_analyze(_make_chunk(), 0, 1, "lodash", "4.17.20", "4.17.21", "npm")

        assert result["verdict"] == "BENIGN"
        mock_client.messages.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_deep_analyze_error_returns_unknown(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("timeout"))
        mock_anthropic.AsyncAnthropicVertex.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            result = await analyzer.deep_analyze(_make_chunk(), 0, 1, "pkg", "1.0.0", "1.0.1", "pypi")

        assert result["verdict"] == "UNKNOWN"
        assert result["confidence"] == 0.0
        assert "error" in result

    @pytest.mark.asyncio
    async def test_deep_analyze_empty_content_returns_unknown(self, monkeypatch):
        """Empty response.content should return UNKNOWN verdict."""
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        # Return empty content list — getattr fallback returns "{}"
        mock_client.messages.create = AsyncMock(return_value=MagicMock(content=[]))
        mock_anthropic.AsyncAnthropicVertex.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            result = await analyzer.deep_analyze(_make_chunk(), 0, 1, "pkg", "1.0", "1.1", "pypi")

        # "{}" parsed as empty dict — no verdict key
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_deep_analyze_with_pre_analysis_context(self, monkeypatch):
        """Pre-analysis context (import/decode/ast) should be included in the prompt."""
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_anthropic, mock_client = _mock_anthropic_client(
            json.dumps({"verdict": "SUSPICIOUS", "confidence": 0.7, "findings": []})
        )

        # Chunk with suspicious imports that trigger pre-analysis context
        suspicious_diff = "+import subprocess\n+import base64\n+exec(base64.b64decode('...'))\n"

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexClaudeAnalyzer(project_id="my-project", region="us-east5")
            result = await analyzer.deep_analyze(_make_chunk(suspicious_diff), 0, 1, "evil", "1.0", "1.1", "pypi")

        assert result["verdict"] == "SUSPICIOUS"
        # Verify the LLM was actually called
        mock_client.messages.create.assert_called_once()


# ─── VertexGeminiAnalyzer ────────────────────────────────────────────────────


class TestVertexGeminiAnalyzer:
    def test_import_error_without_package(self):
        with patch.dict("sys.modules", {"vertexai": None, "vertexai.generative_models": None}):
            import depvet.analyzer.vertexai as m

            importlib.reload(m)
            with pytest.raises(ImportError, match="google-cloud-aiplatform"):
                m.VertexGeminiAnalyzer(project_id="proj")

    def test_missing_project_id_raises(self, monkeypatch):
        monkeypatch.delenv("VERTEX_PROJECT_ID", raising=False)
        mock_vertexai, mock_gen, _ = _mock_gemini_client()
        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            with pytest.raises(ValueError, match="VERTEX_PROJECT_ID"):
                m.VertexGeminiAnalyzer()

    def test_get_model_name(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai, mock_gen, _ = _mock_gemini_client()
        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(model="gemini-2.0-flash-001", project_id="my-project")
            assert "vertex-gemini" in analyzer.get_model_name()
            assert "gemini-2.0-flash-001" in analyzer.get_model_name()

    @pytest.mark.asyncio
    async def test_triage_should_analyze_false(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai, mock_gen, _ = _mock_gemini_client(
            json.dumps({"should_analyze": False, "reason": "benign update"})
        )
        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(project_id="my-project")
            should_analyze, reason = await analyzer.triage(_make_chunk(), "pkg", "1.0.0", "1.0.1")

        assert should_analyze is False
        assert "benign" in reason

    @pytest.mark.asyncio
    async def test_triage_should_analyze_true(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai, mock_gen, _ = _mock_gemini_client(
            json.dumps({"should_analyze": True, "reason": "suspicious patterns"})
        )
        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(project_id="my-project")
            should_analyze, reason = await analyzer.triage(_make_chunk(), "pkg", "1.0", "1.1")

        assert should_analyze is True

    @pytest.mark.asyncio
    async def test_triage_fallback_on_error(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai, mock_gen, mock_model = _mock_gemini_client()
        mock_model.generate_content.side_effect = Exception("Gemini API down")

        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(project_id="my-project")
            should_analyze, reason = await analyzer.triage(_make_chunk(), "pkg", "1.0", "1.1")

        assert should_analyze is True
        assert "error" in reason

    @pytest.mark.asyncio
    async def test_triage_malformed_json(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai, mock_gen, _ = _mock_gemini_client("I think this is safe but {broken")

        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(project_id="my-project")
            should_analyze, reason = await analyzer.triage(_make_chunk(), "pkg", "1.0", "1.1")

        assert should_analyze is True
        assert "error" in reason

    @pytest.mark.asyncio
    async def test_deep_analyze_returns_verdict(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        verdict_json = json.dumps(
            {"verdict": "MALICIOUS", "confidence": 0.92, "severity": "HIGH", "findings": [{"category": "NETWORK"}]}
        )
        mock_vertexai, mock_gen, _ = _mock_gemini_client(verdict_json)

        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(project_id="my-project")
            result = await analyzer.deep_analyze(_make_chunk(), 0, 1, "evil-pkg", "1.0", "1.1", "pypi")

        assert result["verdict"] == "MALICIOUS"
        assert result["confidence"] == 0.92
        assert len(result["findings"]) == 1

    @pytest.mark.asyncio
    async def test_deep_analyze_npm_ecosystem(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai, mock_gen, _ = _mock_gemini_client(
            json.dumps({"verdict": "BENIGN", "confidence": 0.85, "findings": []})
        )

        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(project_id="my-project")
            result = await analyzer.deep_analyze(_make_chunk(), 0, 1, "lodash", "4.17.20", "4.17.21", "npm")

        assert result["verdict"] == "BENIGN"

    @pytest.mark.asyncio
    async def test_deep_analyze_error_returns_unknown(self, monkeypatch):
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai, mock_gen, mock_model = _mock_gemini_client()
        mock_model.generate_content.side_effect = Exception("quota exceeded")

        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(project_id="my-project")
            result = await analyzer.deep_analyze(_make_chunk(), 0, 1, "pkg", "1.0", "1.1", "pypi")

        assert result["verdict"] == "UNKNOWN"
        assert result["confidence"] == 0.0
        assert "error" in result

    @pytest.mark.asyncio
    async def test_deep_analyze_markdown_wrapped_json(self, monkeypatch):
        """Gemini often wraps JSON in markdown code blocks."""
        monkeypatch.setenv("VERTEX_PROJECT_ID", "my-project")
        mock_vertexai, mock_gen, _ = _mock_gemini_client(
            '```json\n{"verdict": "SUSPICIOUS", "confidence": 0.6, "findings": []}\n```'
        )

        with patch.dict("sys.modules", {"vertexai": mock_vertexai, "vertexai.generative_models": mock_gen}):
            from depvet.analyzer import vertexai as m

            importlib.reload(m)
            analyzer = m.VertexGeminiAnalyzer(project_id="my-project")
            result = await analyzer.deep_analyze(_make_chunk(), 0, 1, "pkg", "1.0", "1.1", "pypi")

        assert result["verdict"] == "SUSPICIOUS"


# ─── CLI provider routing ─────────────────────────────────────────────────────


class TestProviderRouting:
    def test_vertex_claude_provider_aliases(self):
        aliases = ["vertex-claude", "vertexai-claude", "vertex_claude"]
        for alias in aliases:
            assert alias.lower() in ("vertex-claude", "vertexai-claude", "vertex_claude")

    def test_vertex_gemini_provider_aliases(self):
        aliases = ["vertex-gemini", "vertexai-gemini", "vertex_gemini", "gemini"]
        for alias in aliases:
            assert alias.lower() in ("vertex-gemini", "vertexai-gemini", "vertex_gemini", "gemini")

    def test_default_models_are_set(self):
        from depvet.analyzer.vertexai import VertexClaudeAnalyzer, VertexGeminiAnalyzer

        assert VertexClaudeAnalyzer.DEFAULT_MODEL
        assert VertexClaudeAnalyzer.DEFAULT_TRIAGE_MODEL
        assert VertexGeminiAnalyzer.DEFAULT_MODEL
        assert VertexGeminiAnalyzer.DEFAULT_TRIAGE_MODEL
