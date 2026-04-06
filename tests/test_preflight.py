"""Tests for pre-flight checks in depvet.cli._preflight_checks."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from depvet.config.config import AlertConfig, DepVetConfig, LLMConfig


def _make_config(**overrides) -> DepVetConfig:
    llm_kw = overrides.pop("llm", {})
    alert_kw = overrides.pop("alert", {})
    return DepVetConfig(
        llm=LLMConfig(**llm_kw),
        alert=AlertConfig(**alert_kw),
    )


class TestPreflightChecks:
    @pytest.mark.asyncio
    async def test_missing_api_key_errors(self, monkeypatch):
        """Should exit when LLM API key is not set and analysis is enabled."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        config = _make_config(llm={"provider": "claude"})

        from depvet.cli import _preflight_checks

        with pytest.raises(SystemExit):
            await _preflight_checks(config, no_analyze=False, slack=False, sbom=None)

    @pytest.mark.asyncio
    async def test_api_key_ok_with_no_analyze(self, monkeypatch):
        """Should not error when --no-analyze is set even without API key."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        config = _make_config(llm={"provider": "claude"})

        from depvet.cli import _preflight_checks

        # Should not raise
        await _preflight_checks(config, no_analyze=True, slack=False, sbom=None)

    @pytest.mark.asyncio
    async def test_missing_slack_webhook_errors(self, monkeypatch):
        """Should exit when --slack is set but webhook env is missing."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.delenv("DEPVET_SLACK_WEBHOOK", raising=False)
        config = _make_config()

        from depvet.cli import _preflight_checks

        with pytest.raises(SystemExit):
            await _preflight_checks(config, no_analyze=True, slack=True, sbom=None)

    @pytest.mark.asyncio
    async def test_sbom_not_found_errors(self, monkeypatch):
        """Should exit when SBOM file does not exist."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        config = _make_config()

        from depvet.cli import _preflight_checks

        with pytest.raises(SystemExit):
            await _preflight_checks(config, no_analyze=True, slack=False, sbom="/nonexistent/sbom.json")

    @pytest.mark.asyncio
    async def test_all_ok(self, monkeypatch, tmp_path):
        """Should pass when everything is configured correctly."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        config = _make_config()
        # Override state path to a writable location
        config.state.path = str(tmp_path / "state.yaml")

        from depvet.cli import _preflight_checks

        await _preflight_checks(config, no_analyze=True, slack=False, sbom=None)

    @pytest.mark.asyncio
    async def test_webhook_unreachable_warns_not_errors(self, monkeypatch, tmp_path):
        """Unreachable webhook should warn but not exit."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        config = _make_config(alert={"webhook_url": "https://unreachable.invalid/hook"})
        config.state.path = str(tmp_path / "state.yaml")

        from depvet.cli import _preflight_checks

        # Mock aiohttp to simulate connection error
        mock_session = AsyncMock()
        mock_session.head = AsyncMock(side_effect=Exception("Connection refused"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            # Should not raise — webhook check is a warning, not an error
            await _preflight_checks(config, no_analyze=True, slack=False, sbom=None)

    @pytest.mark.asyncio
    async def test_vertex_missing_project_id_errors(self, monkeypatch):
        """Should exit when Vertex AI provider lacks VERTEX_PROJECT_ID."""
        monkeypatch.delenv("VERTEX_PROJECT_ID", raising=False)
        config = _make_config(llm={"provider": "vertex-claude"})

        from depvet.cli import _preflight_checks

        with pytest.raises(SystemExit):
            await _preflight_checks(config, no_analyze=False, slack=False, sbom=None)
