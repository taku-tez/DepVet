"""Tests for configuration management."""

import os
import tempfile
import pytest
from depvet.config.config import DepVetConfig, LLMConfig, load_config


def test_default_config():
    config = DepVetConfig()
    assert config.llm.provider == "claude"
    assert config.llm.model == "claude-sonnet-4-20250514"
    assert config.monitor.interval == 300
    assert config.diff.max_chunk_tokens == 8000
    assert config.alert.min_severity == "MEDIUM"


def test_llm_config_defaults():
    llm = LLMConfig()
    assert llm.triage_model == "claude-haiku-4-5-20251001"
    assert llm.max_tokens == 4096
    assert llm.timeout == 60


def test_load_config_no_file():
    # Should not raise, just return defaults
    config = load_config("/nonexistent/path.toml")
    assert config.llm.provider == "claude"


def test_load_config_from_toml():
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            pytest.skip("tomllib not available")

    toml_content = """
[llm]
provider = "openai"
model = "gpt-4o"

[monitor]
interval = 60

[alert]
min_severity = "HIGH"
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(toml_content)
        path = f.name
    try:
        config = load_config(path)
        assert config.llm.provider == "openai"
        assert config.llm.model == "gpt-4o"
        assert config.monitor.interval == 60
        assert config.alert.min_severity == "HIGH"
    finally:
        os.unlink(path)
