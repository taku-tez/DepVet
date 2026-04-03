"""CLI smoke tests using click.testing.CliRunner.

Verifies that all top-level commands parse correctly and that the main
``scan`` path works end-to-end with mocked network/analyzer calls.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from depvet.cli import cli


runner = CliRunner()


# ── help / version ──────────────────────────────────────────────────

def test_version():
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "depvet" in result.output


def test_help():
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "monitor" in result.output


def test_scan_help():
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--no-triage" in result.output


def test_watchlist_help():
    result = runner.invoke(cli, ["watchlist", "--help"])
    assert result.exit_code == 0
    assert "add" in result.output
    assert "remove" in result.output


def test_monitor_help():
    result = runner.invoke(cli, ["monitor", "--help"])
    assert result.exit_code == 0
    assert "--interval" in result.output


# ── scan with mocked internals ──────────────────────────────────────

def test_scan_no_triage_mocked():
    """Full scan path with --no-triage, mocked so no network or LLM calls happen."""
    with patch("depvet.cli._scan", new_callable=AsyncMock, return_value=None) as mock_scan:
        result = runner.invoke(
            cli,
            ["scan", "requests", "2.31.0", "2.32.0", "--no-triage"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    mock_scan.assert_awaited_once()
    # Verify the correct arguments were forwarded
    _args, _kwargs = mock_scan.call_args
    assert _args[1] == "requests"       # package
    assert _args[2] == "2.31.0"         # old_version
    assert _args[3] == "2.32.0"         # new_version
    assert _args[6] is True             # no_triage flag
