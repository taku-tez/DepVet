"""Tests for registry monitors (unit tests only, no network)."""

import pytest
from depvet.registry.pypi import PyPIMonitor
from depvet.registry.npm import NpmMonitor
from depvet.registry.go import GoModulesMonitor
from depvet.registry.cargo import CargoMonitor


def test_pypi_monitor_ecosystem():
    monitor = PyPIMonitor()
    assert monitor.ecosystem == "pypi"


def test_npm_monitor_ecosystem():
    monitor = NpmMonitor()
    assert monitor.ecosystem == "npm"


def test_go_monitor_ecosystem():
    monitor = GoModulesMonitor()
    assert monitor.ecosystem == "go"


def test_cargo_monitor_ecosystem():
    monitor = CargoMonitor()
    assert monitor.ecosystem == "cargo"


@pytest.mark.asyncio
async def test_go_top_n():
    monitor = GoModulesMonitor()
    top = await monitor.load_top_n(5)
    assert len(top) == 5
    assert all(isinstance(p, str) for p in top)
