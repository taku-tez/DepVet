"""Vertex AI analyzer — supports both Claude (via Anthropic Vertex SDK) and Gemini models."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

from depvet.analyzer.base import BaseAnalyzer
from depvet.analyzer.import_diff import analyze_imports, import_signals_to_context
from depvet.analyzer.decode_scan import decode_and_scan
from depvet.analyzer.ast_scan import ast_scan_diff
from depvet.differ.chunker import DiffChunk

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load_prompt(name: str) -> str:
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


def _safe_format(template: str, **kwargs: object) -> str:
    """Format prompt template replacing only known placeholders (safe for JSON examples)."""
    import re

    pattern = re.compile(r"\{(" + "|".join(re.escape(k) for k in kwargs) + r")\}")
    return pattern.sub(lambda m: str(kwargs[m.group(1)]), template)


def _extract_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = text.replace("```", "").strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(text)


# ─── Claude on Vertex AI ─────────────────────────────────────────────────────


class VertexClaudeAnalyzer(BaseAnalyzer):
    """
    Analyzer using Claude models via Vertex AI (anthropic[vertex]).

    Required env vars:
      VERTEX_PROJECT_ID     — GCP project id
      VERTEX_REGION         — e.g. us-east5 (must support Claude)
      GOOGLE_APPLICATION_CREDENTIALS — path to service account key (or use ADC)

    Optional:
      DEPVET_LLM_MODEL       — e.g. claude-opus-4@20250514 (default)
      DEPVET_LLM_TRIAGE_MODEL — e.g. claude-haiku-4-5@20251001
    """

    DEFAULT_MODEL = "claude-opus-4@20250514"
    DEFAULT_TRIAGE_MODEL = "claude-haiku-4-5@20251001"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        triage_model: str = DEFAULT_TRIAGE_MODEL,
        project_id: Optional[str] = None,
        region: Optional[str] = None,
        max_tokens: int = 4096,
        timeout: int = 60,
    ):
        try:
            import anthropic

            self._client = anthropic.AsyncAnthropicVertex(
                project_id=project_id or os.environ["VERTEX_PROJECT_ID"],
                region=region or os.environ.get("VERTEX_REGION", "us-east5"),
            )
        except ImportError:
            raise ImportError("anthropic[vertex] package is required: pip install 'anthropic[vertex]'")
        except KeyError as e:
            raise ValueError(
                f"Missing required env var for Vertex AI: {e}. Set VERTEX_PROJECT_ID and optionally VERTEX_REGION."
            )

        self.model = model
        self.triage_model = triage_model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._triage_template = _load_prompt("triage.txt")
        self._deep_template = _load_prompt("deep_analysis.txt")
        self._deep_npm_template = _load_prompt("deep_analysis_npm.txt")

    def get_model_name(self) -> str:
        return f"vertex-claude/{self.model}"

    async def triage(
        self,
        chunk: DiffChunk,
        package_name: str,
        old_version: str,
        new_version: str,
    ) -> tuple[bool, str]:
        prompt = _safe_format(
            self._triage_template,
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            diff_chunk=chunk.content,
        )
        try:
            response = await self._client.messages.create(
                model=self.triage_model,
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            text = getattr(response.content[0], "text", "{}") if response.content else "{}"
            data = _extract_json(text)
            return bool(data.get("should_analyze", True)), data.get("reason", "")
        except Exception as e:
            logger.warning(f"Vertex Claude triage failed, defaulting to analyze: {e}")
            return True, f"triage error: {e}"

    async def deep_analyze(
        self,
        chunk: DiffChunk,
        chunk_index: int,
        total_chunks: int,
        package_name: str,
        old_version: str,
        new_version: str,
        ecosystem: str,
    ) -> dict:
        template = self._deep_npm_template if ecosystem == "npm" else self._deep_template
        # Build pre-analysis context (same as ClaudeAnalyzer)
        pre_context_parts = []
        import_sigs = analyze_imports(chunk.content)
        if import_sigs:
            ctx = import_signals_to_context(import_sigs)
            if ctx:
                pre_context_parts.append(ctx)
        decoded_hits = decode_and_scan(chunk.content)
        if decoded_hits:
            lines = ["【デコードスキャン検出】"]
            for d in decoded_hits[:3]:
                lines.append(f"🚨 [{d.encoding}] {d.description[:80]}")
            pre_context_parts.append("\n".join(lines))
        if ecosystem == "pypi":
            ast_hits = ast_scan_diff(chunk.content)
            if ast_hits:
                lines = ["【AST解析検出】"]
                for a in ast_hits[:3]:
                    lines.append(f"⚠️  [{a.severity.value}] {a.finding_id}: {a.description[:80]}")
                pre_context_parts.append("\n".join(lines))
        pre_analysis_context = ("\n\n".join(pre_context_parts) + "\n") if pre_context_parts else ""

        prompt = _safe_format(
            template,
            chunk_index=chunk_index + 1,
            total_chunks=total_chunks,
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            diff_chunk=chunk.content,
            ecosystem=ecosystem,
            pre_analysis_context=pre_analysis_context,
        )
        try:
            response = await self._client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            text = getattr(response.content[0], "text", "{}") if response.content else "{}"
            return _extract_json(text)
        except Exception as e:
            logger.error(f"Vertex Claude deep analysis failed: {e}")
            return {"verdict": "UNKNOWN", "confidence": 0.0, "error": str(e)}


# ─── Gemini on Vertex AI ──────────────────────────────────────────────────────


class VertexGeminiAnalyzer(BaseAnalyzer):
    """
    Analyzer using Gemini models via Vertex AI (google-cloud-aiplatform).

    Required env vars:
      VERTEX_PROJECT_ID     — GCP project id
      VERTEX_REGION         — e.g. us-central1

    Optional:
      DEPVET_LLM_MODEL       — e.g. gemini-2.0-flash-001 (default)
      DEPVET_LLM_TRIAGE_MODEL — e.g. gemini-2.0-flash-lite-001
    """

    DEFAULT_MODEL = "gemini-2.0-flash-001"
    DEFAULT_TRIAGE_MODEL = "gemini-2.0-flash-lite-001"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        triage_model: str = DEFAULT_TRIAGE_MODEL,
        project_id: Optional[str] = None,
        region: Optional[str] = None,
        max_tokens: int = 4096,
        timeout: int = 60,
    ):
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel, GenerationConfig

            self._GenerativeModel = GenerativeModel
            self._GenerationConfig = GenerationConfig

            proj = project_id or os.environ.get("VERTEX_PROJECT_ID")
            loc = region or os.environ.get("VERTEX_REGION", "us-central1")
            if not proj:
                raise ValueError("VERTEX_PROJECT_ID env var is required for Gemini on Vertex AI")
            vertexai.init(project=proj, location=loc)
        except ImportError:
            raise ImportError(
                "google-cloud-aiplatform is required: pip install 'google-cloud-aiplatform[generativeai]'"
            )

        self.model = model
        self.triage_model = triage_model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._triage_template = _load_prompt("triage.txt")
        self._deep_template = _load_prompt("deep_analysis.txt")
        self._deep_npm_template = _load_prompt("deep_analysis_npm.txt")

    def get_model_name(self) -> str:
        return f"vertex-gemini/{self.model}"

    async def _call(self, model_name: str, prompt: str, max_tokens: int) -> str:
        """Call Gemini synchronously (SDK is not async-native)."""
        import asyncio

        loop = asyncio.get_running_loop()

        def _sync():
            m = self._GenerativeModel(model_name)
            cfg = self._GenerationConfig(max_output_tokens=max_tokens)
            resp = m.generate_content(prompt, generation_config=cfg)
            return resp.text

        return await loop.run_in_executor(None, _sync)

    async def triage(
        self,
        chunk: DiffChunk,
        package_name: str,
        old_version: str,
        new_version: str,
    ) -> tuple[bool, str]:
        prompt = _safe_format(
            self._triage_template,
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            diff_chunk=chunk.content,
        )
        try:
            text = await self._call(self.triage_model, prompt, 256)
            data = _extract_json(text)
            return bool(data.get("should_analyze", True)), data.get("reason", "")
        except Exception as e:
            logger.warning(f"Vertex Gemini triage failed: {e}")
            return True, f"triage error: {e}"

    async def deep_analyze(
        self,
        chunk: DiffChunk,
        chunk_index: int,
        total_chunks: int,
        package_name: str,
        old_version: str,
        new_version: str,
        ecosystem: str,
    ) -> dict:
        template = self._deep_npm_template if ecosystem == "npm" else self._deep_template
        # Build pre-analysis context
        pre_context_parts = []
        import_sigs = analyze_imports(chunk.content)
        if import_sigs:
            ctx = import_signals_to_context(import_sigs)
            if ctx:
                pre_context_parts.append(ctx)
        decoded_hits = decode_and_scan(chunk.content)
        if decoded_hits:
            lines = ["【デコードスキャン検出】"]
            for d in decoded_hits[:3]:
                lines.append(f"🚨 [{d.encoding}] {d.description[:80]}")
            pre_context_parts.append("\n".join(lines))
        if ecosystem == "pypi":
            ast_hits = ast_scan_diff(chunk.content)
            if ast_hits:
                lines = ["【AST解析検出】"]
                for a in ast_hits[:3]:
                    lines.append(f"⚠️  [{a.severity.value}] {a.finding_id}: {a.description[:80]}")
                pre_context_parts.append("\n".join(lines))
        pre_analysis_context = ("\n\n".join(pre_context_parts) + "\n") if pre_context_parts else ""

        prompt = _safe_format(
            template,
            chunk_index=chunk_index + 1,
            total_chunks=total_chunks,
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            diff_chunk=chunk.content,
            ecosystem=ecosystem,
            pre_analysis_context=pre_analysis_context,
        )
        try:
            text = await self._call(self.model, prompt, self.max_tokens)
            return _extract_json(text)
        except Exception as e:
            logger.error(f"Vertex Gemini deep analysis failed: {e}")
            return {"verdict": "UNKNOWN", "confidence": 0.0, "error": str(e)}
