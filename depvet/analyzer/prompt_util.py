"""Shared prompt utilities for LLM analyzers."""

from __future__ import annotations

import json
import re
from pathlib import Path

PROMPTS_DIR = Path(__file__).parent / "prompts"


def load_prompt(name: str) -> str:
    """Load a prompt template from the prompts directory."""
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


def safe_format(template: str, **kwargs: object) -> str:
    """Format a prompt template replacing only known placeholders.

    Unlike ``str.format()``, this leaves unknown ``{...}`` sequences
    intact — critical because prompt templates contain JSON examples
    with literal braces that must not be interpreted.
    """
    if not kwargs:
        return template
    pattern = re.compile(r"\{(" + "|".join(re.escape(k) for k in kwargs) + r")\}")
    return pattern.sub(lambda m: str(kwargs[m.group(1)]), template)


def extract_json(text: str) -> dict:
    """Extract a JSON object from LLM response text.

    Handles markdown code blocks and surrounding prose.
    """
    text = text.strip()
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = text.replace("```", "").strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(text)
