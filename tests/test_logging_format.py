"""Tests for depvet.logging — JsonFormatter and setup_logging."""

from __future__ import annotations

import json
import logging

from depvet.logging import JsonFormatter, setup_logging


class TestJsonFormatter:
    def _make_record(self, msg: str = "hello", **extra) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test.logger",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_basic_fields(self):
        fmt = JsonFormatter()
        record = self._make_record("test message")
        output = fmt.format(record)
        data = json.loads(output)
        assert data["level"] == "WARNING"
        assert data["logger"] == "test.logger"
        assert data["message"] == "test message"
        assert "timestamp" in data

    def test_extra_structured_fields(self):
        fmt = JsonFormatter()
        record = self._make_record("pkg found", ecosystem="pypi", package="requests")
        output = fmt.format(record)
        data = json.loads(output)
        assert data["ecosystem"] == "pypi"
        assert data["package"] == "requests"

    def test_missing_extra_fields_omitted(self):
        fmt = JsonFormatter()
        record = self._make_record("plain")
        output = fmt.format(record)
        data = json.loads(output)
        assert "ecosystem" not in data
        assert "package" not in data

    def test_exception_info(self):
        fmt = JsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="error",
                args=(),
                exc_info=sys.exc_info(),
            )
        output = fmt.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "ValueError" in data["exception"]


class TestSetupLogging:
    def test_text_format_default(self):
        setup_logging(verbose=False, log_format="text")
        root = logging.getLogger()
        assert len(root.handlers) == 1
        assert not isinstance(root.handlers[0].formatter, JsonFormatter)

    def test_json_format(self):
        setup_logging(verbose=False, log_format="json")
        root = logging.getLogger()
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)

    def test_verbose_sets_debug(self):
        setup_logging(verbose=True, log_format="text")
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_idempotent(self):
        setup_logging(verbose=False, log_format="text")
        setup_logging(verbose=False, log_format="text")
        root = logging.getLogger()
        assert len(root.handlers) == 1

    def test_non_verbose_sets_warning(self):
        setup_logging(verbose=False, log_format="text")
        root = logging.getLogger()
        assert root.level == logging.WARNING


class TestJsonFormatterStructuredFields:
    """Test that all structured fields are captured when present."""

    def _make_record(self, msg: str = "test", **extra) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_ecosystem_field(self):
        fmt = JsonFormatter()
        record = self._make_record(ecosystem="npm")
        data = json.loads(fmt.format(record))
        assert data["ecosystem"] == "npm"

    def test_package_field(self):
        fmt = JsonFormatter()
        record = self._make_record(package="lodash")
        data = json.loads(fmt.format(record))
        assert data["package"] == "lodash"

    def test_version_field(self):
        fmt = JsonFormatter()
        record = self._make_record(version="4.17.21")
        data = json.loads(fmt.format(record))
        assert data["version"] == "4.17.21"

    def test_alerter_field(self):
        fmt = JsonFormatter()
        record = self._make_record(alerter="slack")
        data = json.loads(fmt.format(record))
        assert data["alerter"] == "slack"

    def test_dlq_id_field(self):
        fmt = JsonFormatter()
        record = self._make_record(dlq_id="abc-123")
        data = json.loads(fmt.format(record))
        assert data["dlq_id"] == "abc-123"

    def test_cycle_field(self):
        fmt = JsonFormatter()
        record = self._make_record(cycle=5)
        data = json.loads(fmt.format(record))
        assert data["cycle"] == 5

    def test_releases_count_field(self):
        fmt = JsonFormatter()
        record = self._make_record(releases_count=10)
        data = json.loads(fmt.format(record))
        assert data["releases_count"] == 10

    def test_duration_ms_field(self):
        fmt = JsonFormatter()
        record = self._make_record(duration_ms=1234)
        data = json.loads(fmt.format(record))
        assert data["duration_ms"] == 1234

    def test_signal_field(self):
        fmt = JsonFormatter()
        record = self._make_record(signal="maintainer_change")
        data = json.loads(fmt.format(record))
        assert data["signal"] == "maintainer_change"

    def test_multiple_structured_fields(self):
        fmt = JsonFormatter()
        record = self._make_record(
            ecosystem="pypi",
            package="requests",
            version="2.32.0",
            duration_ms=500,
        )
        data = json.loads(fmt.format(record))
        assert data["ecosystem"] == "pypi"
        assert data["package"] == "requests"
        assert data["version"] == "2.32.0"
        assert data["duration_ms"] == 500

    def test_output_is_single_line(self):
        fmt = JsonFormatter()
        record = self._make_record("multi\nline\nmessage")
        output = fmt.format(record)
        assert "\n" not in output  # JSON dumps should produce single line

    def test_unicode_preserved(self):
        fmt = JsonFormatter()
        record = self._make_record("悪意のあるパッケージ")
        output = fmt.format(record)
        assert "悪意のあるパッケージ" in output

    def test_timestamp_is_utc_iso(self):
        fmt = JsonFormatter()
        record = self._make_record("test")
        data = json.loads(fmt.format(record))
        assert "+00:00" in data["timestamp"]

    def test_metrics_fields_in_allowlist(self):
        """[Finding 5] MonitorMetrics.to_dict() keys must appear in JSON output."""
        fmt = JsonFormatter()
        record = self._make_record(
            "Monitor metrics summary",
            releases_processed=10,
            alerts_sent=3,
            alerts_failed=1,
            total_tokens_used=5000,
            avg_analysis_ms=250.0,
            cycles_completed=5,
            releases_skipped=2,
            analyses_completed=8,
            total_analysis_duration_ms=2000,
            avg_tokens_per_analysis=625.0,
            uptime_seconds=3600,
        )
        data = json.loads(fmt.format(record))
        assert data["releases_processed"] == 10
        assert data["alerts_sent"] == 3
        assert data["alerts_failed"] == 1
        assert data["total_tokens_used"] == 5000
        assert data["avg_analysis_ms"] == 250.0
        assert data["cycles_completed"] == 5
        assert data["uptime_seconds"] == 3600

    def test_log_summary_emits_structured_json(self):
        """[Finding 5] MonitorMetrics.log_summary() with JsonFormatter should
        include metrics keys in JSON output, not just message."""
        from depvet.metrics import MonitorMetrics
        from depvet.logging import setup_logging

        setup_logging(verbose=True, log_format="json")

        m = MonitorMetrics()
        m.record_release("pypi")
        m.record_analysis(tokens=100, duration_ms=500)
        m.record_alert_sent()

        # Capture log output
        import io

        handler = logging.StreamHandler(io.StringIO())
        handler.setFormatter(JsonFormatter())

        metrics_logger = logging.getLogger("depvet.metrics")
        metrics_logger.addHandler(handler)
        metrics_logger.setLevel(logging.INFO)
        try:
            m.log_summary()
            output = handler.stream.getvalue()
            data = json.loads(output.strip())
            assert data["releases_processed"] == 1
            assert data["alerts_sent"] == 1
            assert data["total_tokens_used"] == 100
        finally:
            metrics_logger.removeHandler(handler)
