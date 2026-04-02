"""OpenAI API analyzer implementation."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

from depvet.analyzer.base import BaseAnalyzer
from depvet.differ.chunker import DiffChunk

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load_prompt(name: str) -> str:
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


def _extract_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = text.replace("```", "").strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(text)


class OpenAIAnalyzer(BaseAnalyzer):
    """Analyzer using OpenAI API."""

    def __init__(
        self,
        model: str = "gpt-4o",
        triage_model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        max_tokens: int = 4096,
        timeout: int = 60,
    ):
        try:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(
                api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            )
        except ImportError:
            raise ImportError("openai package is required: pip install openai")

        self.model = model
        self.triage_model = triage_model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._triage_template = _load_prompt("triage.txt")
        self._deep_template = _load_prompt("deep_analysis.txt")

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
            response = await self._client.chat.completions.create(
                model=self.triage_model,
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.choices[0].message.content or "{}"
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
        prompt = self._deep_template.format(
            chunk_index=chunk_index + 1,
            total_chunks=total_chunks,
            ecosystem=ecosystem,
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            diff_chunk=chunk.content,
        )
        response = await self._client.chat.completions.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.choices[0].message.content or "{}"
        usage = response.usage
        result = _extract_json(text)
        result["_tokens_used"] = (usage.prompt_tokens + usage.completion_tokens) if usage else 0
        return result
