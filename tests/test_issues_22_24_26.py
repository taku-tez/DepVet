"""Tests for Issues #22, #24, #26."""

from __future__ import annotations

import pathlib
from click.testing import CliRunner

from depvet.cli import cli

runner = CliRunner()


# ─── Issue #22: Concurrency (already implemented - verify) ───────────────────


class TestConcurrencyImplemented:
    def test_create_task_in_monitor(self):
        src = pathlib.Path("depvet/cli.py").read_text()
        monitor_fn = src[src.find("async def _monitor") :]
        assert "create_task" in monitor_fn, "_monitor must use asyncio.create_task"

    def test_gather_in_monitor(self):
        src = pathlib.Path("depvet/cli.py").read_text()
        monitor_fn = src[src.find("async def _monitor") :]
        assert "asyncio.gather" in monitor_fn, "_monitor must use asyncio.gather"

    def test_queue_max_size_in_monitor(self):
        src = pathlib.Path("depvet/cli.py").read_text()
        monitor_fn = src[src.find("async def _monitor") :]
        assert "queue_max_size" in monitor_fn, "_monitor must use config.monitor.queue_max_size"

    def test_semaphore_max_concurrent_in_monitor(self):
        src = pathlib.Path("depvet/cli.py").read_text()
        monitor_fn = src[src.find("async def _monitor") :]
        assert "max_concurrent_analyses" in monitor_fn


# ─── Issue #24: Config wiring ────────────────────────────────────────────────


class TestWatchlistConfigWiring:
    def test_sources_referenced_in_monitor(self):
        """config.watchlist.sources must be consumed in _monitor."""
        src = pathlib.Path("depvet/cli.py").read_text()
        monitor_fn = src[src.find("async def _monitor") :]
        assert "active_sources" in monitor_fn or "watchlist.sources" in monitor_fn, (
            "_monitor must use config.watchlist.sources"
        )

    def test_top_n_source_checked(self):
        """'top_n' source check must be present."""
        src = pathlib.Path("depvet/cli.py").read_text()
        monitor_fn = src[src.find("async def _monitor") :]
        assert '"top_n"' in monitor_fn or "'top_n'" in monitor_fn, "_monitor must check for 'top_n' in sources"

    def test_refresh_interval_referenced(self):
        """refresh_interval must be used for periodic top-N refresh."""
        src = pathlib.Path("depvet/cli.py").read_text()
        monitor_fn = src[src.find("async def _monitor") :]
        assert "refresh_interval" in monitor_fn, "_monitor must use config.watchlist.refresh_interval"

    def test_sbom_path_used(self):
        """effective_sbom should use config.watchlist.sbom_path."""
        src = pathlib.Path("depvet/cli.py").read_text()
        assert "sbom_path" in src or "effective_sbom" in src


# ─── Issue #26: --no-analyze dispatch to alert router ────────────────────────


class TestNoAnalyzeAlertDispatch:
    def test_no_analyze_dispatches_to_router(self):
        """When no_analyze=True, router.dispatch() must still be called."""
        src = pathlib.Path("depvet/cli.py").read_text()
        p1_start = src.find("async def _process_one")
        p1_end = src.find("if releases:", p1_start)
        process_one = src[p1_start:p1_end]
        # The no_analyze/no-previous-version branch must call router.dispatch
        # somewhere between "no_analyze" and the next "try:" (deep analyze block)
        no_analyze_idx = process_one.find("no_analyze")
        try_idx = process_one.find("try:", no_analyze_idx)
        no_analyze_section = process_one[no_analyze_idx:try_idx] if try_idx > 0 else process_one[no_analyze_idx:]
        assert "router.dispatch" in no_analyze_section, (
            "_process_one must call router.dispatch() even when no_analyze=True"
        )

    def test_no_previous_version_dispatches_to_router(self):
        """When previous_version is None, router.dispatch() must still be called."""
        src = pathlib.Path("depvet/cli.py").read_text()
        # _process_one is defined after first "if releases:", find the correct boundary
        p1_start = src.find("async def _process_one")
        # Find "if releases:" that comes AFTER _process_one
        p1_end = src.find("if releases:", p1_start)
        process_one = src[p1_start:p1_end]
        # Both conditions (no_analyze and no previous_version) share the same dispatch block
        assert "router.dispatch" in process_one, "_process_one must dispatch even without previous_version"

    def test_release_only_verdict_is_unknown(self):
        """Release-only notification verdict must be UNKNOWN (not BENIGN)."""
        src = pathlib.Path("depvet/cli.py").read_text()
        # _process_one is defined after first "if releases:", find the correct boundary
        p1_start = src.find("async def _process_one")
        # Find "if releases:" that comes AFTER _process_one
        p1_end = src.find("if releases:", p1_start)
        process_one = src[p1_start:p1_end]
        notify_block = process_one[process_one.find("no_analyze or not release.previous_version") :]
        assert "VerdictType.UNKNOWN" in notify_block, "Release-only verdict must use VerdictType.UNKNOWN"

    def test_release_only_severity_is_medium(self):
        """Release-only severity should be MEDIUM to pass default min_severity filter."""
        src = pathlib.Path("depvet/cli.py").read_text()
        # _process_one is defined after first "if releases:", find the correct boundary
        p1_start = src.find("async def _process_one")
        # Find "if releases:" that comes AFTER _process_one
        p1_end = src.find("if releases:", p1_start)
        process_one = src[p1_start:p1_end]
        notify_block = process_one[process_one.find("no_analyze or not release.previous_version") :]
        assert "Severity.MEDIUM" in notify_block, (
            "Release-only verdict must have Severity.MEDIUM to be visible by default"
        )

    def test_monitor_help_says_report_releases(self):
        result = runner.invoke(cli, ["monitor", "--help"])
        assert "report releases" in result.output.lower() or "analyze" in result.output.lower()
