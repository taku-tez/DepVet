"""Tests for depvet.metrics and depvet.health."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from depvet.health import check_health, read_health, write_health
from depvet.metrics import MonitorMetrics


class TestMonitorMetrics:
    def test_initial_state(self):
        m = MonitorMetrics()
        assert m.releases_processed == 0
        assert m.total_tokens_used == 0
        assert m.cycles_completed == 0

    def test_record_release(self):
        m = MonitorMetrics()
        m.record_release("pypi")
        m.record_release("pypi")
        m.record_release("npm")
        assert m.releases_processed == 3
        assert m.releases_by_ecosystem == {"pypi": 2, "npm": 1}

    def test_record_analysis(self):
        m = MonitorMetrics()
        m.record_analysis(tokens=500, duration_ms=1200)
        m.record_analysis(tokens=300, duration_ms=800)
        assert m.analyses_completed == 2
        assert m.total_tokens_used == 800
        assert m.total_analysis_duration_ms == 2000
        assert m.avg_tokens_per_analysis == 400.0
        assert m.avg_analysis_ms == 1000.0

    def test_avg_zero_division(self):
        m = MonitorMetrics()
        assert m.avg_analysis_ms == 0.0
        assert m.avg_tokens_per_analysis == 0.0

    def test_to_dict(self):
        m = MonitorMetrics()
        m.record_release("pypi")
        m.record_analysis(tokens=100, duration_ms=500)
        m.cycles_completed = 1
        d = m.to_dict()
        assert d["releases_processed"] == 1
        assert d["total_tokens_used"] == 100
        assert d["cycles_completed"] == 1
        assert "uptime_seconds" in d

    def test_uptime(self):
        m = MonitorMetrics()
        # uptime should be positive
        assert m.uptime_seconds >= 0


class TestHealthFile:
    def test_write_and_read(self, tmp_path):
        path = str(tmp_path / "health.json")
        m = MonitorMetrics()
        m.record_release("pypi")
        m.cycles_completed = 5
        write_health(path, metrics=m)

        data = read_health(path)
        assert data is not None
        assert data["status"] == "ok"
        assert data["cycles_completed"] == 5
        assert data["releases_processed"] == 1
        assert "pid" in data
        assert "last_poll_at" in data

    def test_read_missing_returns_none(self, tmp_path):
        assert read_health(str(tmp_path / "nonexistent.json")) is None

    def test_read_corrupt_returns_none(self, tmp_path):
        path = tmp_path / "corrupt.json"
        path.write_text("{{{bad json")
        assert read_health(str(path)) is None

    def test_write_shutdown_status(self, tmp_path):
        path = str(tmp_path / "health.json")
        write_health(path, status="shutdown")
        data = read_health(path)
        assert data is not None
        assert data["status"] == "shutdown"


class TestCheckHealth:
    def test_healthy(self, tmp_path):
        path = str(tmp_path / "health.json")
        write_health(path, metrics=MonitorMetrics())

        with pytest.raises(SystemExit) as exc_info:
            check_health(path)
        assert exc_info.value.code == 0

    def test_unhealthy_status(self, tmp_path):
        path = str(tmp_path / "health.json")
        write_health(path, status="error")

        with pytest.raises(SystemExit) as exc_info:
            check_health(path)
        assert exc_info.value.code == 1

    def test_stale_file(self, tmp_path):
        path = str(tmp_path / "health.json")
        # Write with an old timestamp
        data = {
            "status": "ok",
            "pid": 1,
            "last_poll_at": "2020-01-01T00:00:00+00:00",
            "updated_epoch": time.time() - 9999,
        }
        Path(path).write_text(json.dumps(data))

        with pytest.raises(SystemExit) as exc_info:
            check_health(path)
        assert exc_info.value.code == 1

    def test_no_file_import_ok(self, tmp_path):
        """No health file but package importable — exit 0."""
        with pytest.raises(SystemExit) as exc_info:
            check_health(str(tmp_path / "missing.json"))
        assert exc_info.value.code == 0
