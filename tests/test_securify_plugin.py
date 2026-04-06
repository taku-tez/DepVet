"""Tests for Securify plugin components."""

import json
import os
import tempfile
import pytest

from securify_plugin.watchlist_sync import WatchlistSyncJob
from securify_plugin.plugin import DepVetSecurifyPlugin
from depvet.models.alert import AlertEvent
from depvet.models.package import Release
from depvet.models.verdict import DiffStats, Severity, Verdict, VerdictType


def make_verdict(verdict_type=VerdictType.MALICIOUS, severity=Severity.CRITICAL):
    return Verdict(
        verdict=verdict_type,
        severity=severity,
        confidence=0.95,
        findings=[],
        summary="Test",
        analysis_duration_ms=100,
        diff_stats=DiffStats(files_changed=1, lines_added=5, lines_removed=0),
        model="test",
        analyzed_at="2026-01-01T00:00:00+00:00",
        chunks_analyzed=1,
        tokens_used=100,
    )


def make_release(name="requests", version="2.32.0", ecosystem="pypi", prev="2.31.0"):
    return Release(
        name=name,
        version=version,
        ecosystem=ecosystem,
        previous_version=prev,
        published_at="2026-01-01T00:00:00+00:00",
        url=f"https://pypi.org/project/{name}/{version}/",
    )


# ─── WatchlistSyncJob ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_watchlist_sync_from_sbom():
    sbom_data = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            {"type": "library", "name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(sbom_data, f)
        sbom_path = f.name

    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        wl_path = f.name
    os.unlink(wl_path)

    try:
        from depvet.watchlist.manager import WatchlistManager

        wl = WatchlistManager(storage_path=wl_path)
        job = WatchlistSyncJob(watchlist_manager=wl)

        count = await job.on_sbom_scan_complete("tenant-1", sbom_path)
        assert count == 2
        assert job.tenant_watchlist_set("tenant-1", "pypi") == {"requests", "flask"}
        assert not os.path.exists(wl_path)
    finally:
        os.unlink(sbom_path)
        if os.path.exists(wl_path):
            os.unlink(wl_path)


@pytest.mark.asyncio
async def test_find_tenants_using():
    job = WatchlistSyncJob()
    job._tenant_packages = {
        "tenant-a": {("requests", "pypi", "2.31.0"), ("flask", "pypi", "3.0.0")},
        "tenant-b": {("django", "pypi", "4.2.0")},
        "tenant-c": {("requests", "pypi", "2.32.0")},
    }
    affected = await job.find_tenants_using("requests", "pypi", "2.31.0")
    tenant_ids = [t["id"] for t in affected]
    assert "tenant-a" in tenant_ids
    assert "tenant-b" not in tenant_ids


@pytest.mark.asyncio
async def test_watchlist_sync_isolates_tenants_and_replaces_stale_entries():
    tenant_one = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            {"type": "library", "name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
        ],
    }
    tenant_two = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "name": "django", "version": "4.2.0", "purl": "pkg:pypi/django@4.2.0"},
        ],
    }
    tenant_one_resync = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        tenant_dir = os.path.join(td, "tenant-watchlists")
        job = WatchlistSyncJob(tenant_storage_dir=tenant_dir)

        def write_sbom(data: dict) -> str:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
                json.dump(data, handle)
                return handle.name

        paths = [write_sbom(tenant_one), write_sbom(tenant_two), write_sbom(tenant_one_resync)]
        try:
            await job.on_sbom_scan_complete("tenant-1", paths[0])
            await job.on_sbom_scan_complete("tenant-2", paths[1])
            await job.on_sbom_scan_complete("tenant-1", paths[2])

            assert job.tenant_watchlist_set("tenant-1", "pypi") == {"requests"}
            assert job.tenant_watchlist_set("tenant-2", "pypi") == {"django"}
            assert sorted(os.listdir(tenant_dir)) == ["tenant-1.yaml", "tenant-2.yaml"]
        finally:
            for path in paths:
                if os.path.exists(path):
                    os.unlink(path)


# ─── DepVetSecurifyPlugin ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_plugin_skips_benign():
    plugin = DepVetSecurifyPlugin()
    event = AlertEvent(
        release=make_release(),
        verdict=make_verdict(VerdictType.BENIGN, Severity.NONE),
    )
    # Should not raise, just return early
    await plugin.send(event)


@pytest.mark.asyncio
async def test_plugin_disabled():
    plugin = DepVetSecurifyPlugin(enabled=False)
    event = AlertEvent(
        release=make_release(),
        verdict=make_verdict(VerdictType.MALICIOUS, Severity.CRITICAL),
    )
    await plugin.send(event)  # should skip without error


@pytest.mark.asyncio
async def test_plugin_no_affected_tenants():
    """When no tenants are affected, plugin should still not raise."""
    plugin = DepVetSecurifyPlugin(enabled=True)
    event = AlertEvent(
        release=make_release(),
        verdict=make_verdict(VerdictType.MALICIOUS, Severity.CRITICAL),
    )
    await plugin.on_alert(event)
    # No crash, affected_tenants stays empty


# ─── Maven monitor ─────────────────────────────────────────────────────────


def test_maven_ecosystem():
    from depvet.registry.maven import MavenMonitor

    m = MavenMonitor()
    assert m.ecosystem == "maven"


@pytest.mark.asyncio
async def test_maven_top_n():
    from depvet.registry.maven import MavenMonitor

    m = MavenMonitor()
    top = await m.load_top_n(5)
    assert len(top) == 5
    assert all(":" in p for p in top)  # groupId:artifactId format
