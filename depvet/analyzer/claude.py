"""Claude API analyzer implementation."""

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


def _extract_json(text: str) -> dict:
    """Extract JSON from LLM response, handling markdown code blocks."""
    text = text.strip()
    # Remove markdown code blocks
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = text.replace("```", "").strip()
    # Try to find JSON object
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(text)


class ClaudeAnalyzer(BaseAnalyzer):
    """Analyzer using Anthropic Claude API."""

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        triage_model: str = "claude-haiku-4-5-20251001",
        api_key: Optional[str] = None,
        max_tokens: int = 4096,
        timeout: int = 60,
    ):
        try:
            import anthropic
            self._client = anthropic.AsyncAnthropic(
                api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"),
            )
        except ImportError:
            raise ImportError("anthropic package is required: pip install anthropic")

        self.model = model
        self.triage_model = triage_model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._triage_template = _load_prompt("triage.txt")
        self._deep_template_pypi = _load_prompt("deep_analysis.txt")
        self._deep_template_npm = _load_prompt("deep_analysis_npm.txt")

    def get_model_name(self) -> str:
        return self.model

    async def triage(
        self,
        chunk: DiffChunk,
        package_name: str,
        old_version: str,
        new_version: str,
    ) -> tuple[bool, str]:
        prompt = self._triage_template.format(
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
            text = response.content[0].text if response.content else "{}"
            data = _extract_json(text)
            return bool(data.get("should_analyze", True)), data.get("reason", "")
        except Exception as e:
            logger.warning(f"Triage failed, defaulting to analyze: {e}")
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
        # Build pre-analysis context from static analyzers
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

        # Use ecosystem-specific prompt
        template = self._deep_template_npm if ecosystem == "npm" else self._deep_template_pypi
        prompt = template.format(
            chunk_index=chunk_index + 1,
            total_chunks=total_chunks,
            ecosystem=ecosystem,
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            diff_chunk=chunk.content,
            pre_analysis_context=pre_analysis_context,
        )
        response = await self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text if response.content else "{}"
        usage = response.usage
        result = _extract_json(text)
        result["_tokens_used"] = (usage.input_tokens + usage.output_tokens) if usage else 0
        return result
