"""Tests for depvet.alert.dlq — Dead Letter Queue."""

from __future__ import annotations

from depvet.alert.dlq import DeadLetterQueue, _serialize_event
from depvet.models.alert import AlertEvent
from depvet.models.package import Release
from depvet.models.verdict import DiffStats, Severity, Verdict, VerdictType


def _make_event(name: str = "requests", version: str = "2.32.0") -> AlertEvent:
    return AlertEvent(
        release=Release(
            name=name,
            version=version,
            ecosystem="pypi",
            previous_version="2.31.0",
            published_at="2026-04-02T00:00:00+00:00",
            url=f"https://pypi.org/project/{name}/{version}/",
        ),
        verdict=Verdict(
            verdict=VerdictType.MALICIOUS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            findings=[],
            summary="test",
            analysis_duration_ms=100,
            diff_stats=DiffStats(files_changed=1, lines_added=10, lines_removed=0),
            model="test",
            analyzed_at="2026-04-02T00:00:00+00:00",
            chunks_analyzed=1,
            tokens_used=100,
        ),
    )


class TestDeadLetterQueue:
    def test_push_and_list(self, tmp_path):
        q = DeadLetterQueue(path=str(tmp_path / "dlq.yaml"))
        q.push("slack", "timeout", _make_event())
        entries = q.list_entries()
        assert len(entries) == 1
        assert entries[0]["alerter_type"] == "slack"
        assert entries[0]["error_message"] == "timeout"
        assert "id" in entries[0]
        assert "timestamp" in entries[0]

    def test_count(self, tmp_path):
        q = DeadLetterQueue(path=str(tmp_path / "dlq.yaml"))
        assert q.count() == 0
        q.push("slack", "err", _make_event())
        assert q.count() == 1
        q.push("webhook", "err", _make_event())
        assert q.count() == 2

    def test_clear(self, tmp_path):
        q = DeadLetterQueue(path=str(tmp_path / "dlq.yaml"))
        q.push("slack", "err", _make_event())
        q.push("webhook", "err", _make_event())
        removed = q.clear()
        assert removed == 2
        assert q.count() == 0

    def test_pop_all(self, tmp_path):
        q = DeadLetterQueue(path=str(tmp_path / "dlq.yaml"))
        q.push("slack", "err1", _make_event())
        q.push("webhook", "err2", _make_event())
        entries = q.pop_all()
        assert len(entries) == 2
        assert q.count() == 0

    def test_remove_by_id(self, tmp_path):
        q = DeadLetterQueue(path=str(tmp_path / "dlq.yaml"))
        q.push("slack", "err", _make_event())
        entry_id = q.list_entries()[0]["id"]
        assert q.remove(entry_id) is True
        assert q.count() == 0
        assert q.remove("nonexistent") is False

    def test_fifo_eviction(self, tmp_path, monkeypatch):
        import depvet.alert.dlq as dlq_mod

        monkeypatch.setattr(dlq_mod, "MAX_ENTRIES", 10)
        q = DeadLetterQueue(path=str(tmp_path / "dlq.yaml"))
        for i in range(15):
            q.push("slack", f"err-{i}", _make_event())
        assert q.count() == 10
        # Oldest 5 entries should be evicted; newest 10 should remain
        entries = q.list_entries()
        assert entries[0]["error_message"] == "err-5"
        assert entries[-1]["error_message"] == "err-14"

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "dlq.yaml")
        q1 = DeadLetterQueue(path=path)
        q1.push("slack", "err", _make_event())
        # New instance from same file
        q2 = DeadLetterQueue(path=path)
        assert q2.count() == 1
        assert q2.list_entries()[0]["error_message"] == "err"

    def test_corrupt_file_recovery(self, tmp_path):
        path = tmp_path / "dlq.yaml"
        path.write_text("{{{{not yaml")
        q = DeadLetterQueue(path=str(path))
        assert q.count() == 0  # should not crash

    def test_serialize_event(self):
        event = _make_event("lodash", "4.17.21")
        data = _serialize_event(event)
        assert data["release"]["name"] == "lodash"
        assert data["release"]["version"] == "4.17.21"
        assert data["verdict"]["verdict"] == "MALICIOUS"
        assert data["verdict"]["severity"] == "CRITICAL"
