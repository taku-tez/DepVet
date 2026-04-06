"""Tests for graceful shutdown behavior."""

from __future__ import annotations

import asyncio

import pytest

from depvet.alert.dlq import DeadLetterQueue
from depvet.alert.router import AlertRouter


class TestShutdownEvent:
    @pytest.mark.asyncio
    async def test_shutdown_event_breaks_wait(self):
        """Setting shutdown_event should break wait_for before timeout."""
        shutdown = asyncio.Event()

        async def _set_soon():
            await asyncio.sleep(0.05)
            shutdown.set()

        asyncio.create_task(_set_soon())

        # wait_for should return before the 10s timeout because _set_soon fires
        try:
            await asyncio.wait_for(shutdown.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            pytest.fail("shutdown_event.wait() did not return in time")

    @pytest.mark.asyncio
    async def test_wait_for_timeout_on_no_signal(self):
        """Without signal, wait_for should timeout normally."""
        shutdown = asyncio.Event()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(shutdown.wait(), timeout=0.01)

    @pytest.mark.asyncio
    async def test_shutdown_during_sleep(self):
        """Shutdown event during sleep interval should exit promptly."""
        shutdown = asyncio.Event()

        async def _set_after_delay():
            await asyncio.sleep(0.05)
            shutdown.set()

        task = asyncio.create_task(_set_after_delay())
        # Simulate the monitor sleep with a long timeout
        try:
            await asyncio.wait_for(shutdown.wait(), timeout=10.0)
            exited = True
        except asyncio.TimeoutError:
            exited = False

        assert exited, "Loop should have exited due to shutdown event"
        await task


class TestRouterDispatchedCount:
    @pytest.mark.asyncio
    async def test_dispatched_count_increments(self):
        """Router should track successful dispatches."""
        from unittest.mock import AsyncMock

        router = AlertRouter(min_severity="NONE")
        mock_alerter = AsyncMock()
        mock_alerter.name = "test"
        router.register(mock_alerter)

        from tests.test_dlq import _make_event

        event = _make_event()
        await router.dispatch(event)
        assert router.dispatched_count == 1
        await router.dispatch(event)
        assert router.dispatched_count == 2


class TestRouterDLQIntegration:
    @pytest.mark.asyncio
    async def test_failed_alerter_pushed_to_dlq(self, tmp_path):
        """When an alerter fails, the event should be saved to DLQ."""
        from unittest.mock import AsyncMock, MagicMock

        dlq = DeadLetterQueue(path=str(tmp_path / "dlq.yaml"))
        router = AlertRouter(min_severity="NONE", dlq=dlq)

        failing_alerter = MagicMock()
        failing_alerter.name = "slack"
        failing_alerter.send = AsyncMock(side_effect=Exception("network error"))
        router.register(failing_alerter)

        from tests.test_dlq import _make_event

        event = _make_event()
        await router.dispatch(event)

        assert dlq.count() == 1
        entry = dlq.list_entries()[0]
        assert entry["alerter_type"] == "slack"
        assert "network error" in entry["error_message"]

    @pytest.mark.asyncio
    async def test_no_dlq_no_crash(self):
        """Router without DLQ should not crash on alerter failure."""
        from unittest.mock import AsyncMock, MagicMock

        router = AlertRouter(min_severity="NONE", dlq=None)
        failing = MagicMock()
        failing.name = "test"
        failing.send = AsyncMock(side_effect=Exception("fail"))
        router.register(failing)

        from tests.test_dlq import _make_event

        await router.dispatch(_make_event())  # should not raise
