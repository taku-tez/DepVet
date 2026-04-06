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
