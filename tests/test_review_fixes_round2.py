"""Regression tests for remaining review fixes."""

from __future__ import annotations

import io
import tarfile
import tempfile
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest

from depvet.analyzer.deep import VerdictMerger
from depvet.models.verdict import DiffStats
from depvet.registry.versioning import sort_versions
from depvet.watchlist.sbom import SBOMParser, _parse_purl
from securify_plugin.risk_propagator import RiskPropagator
from securify_plugin.skg_writer import BlastRadius


def _stats() -> DiffStats:
    return DiffStats(files_changed=1, lines_added=5, lines_removed=2)


def test_sort_versions_pypi_uses_pep440_ordering():
    versions = ["1.9.0", "1.10.0", "1.11.0", "1.2.0", "2.0.0rc1", "2.0.0"]
    assert sort_versions(versions, "pypi") == [
        "1.2.0",
        "1.9.0",
        "1.10.0",
        "1.11.0",
        "2.0.0rc1",
        "2.0.0",
    ]


def test_sort_versions_npm_uses_semver_ordering():
    versions = ["1.9.0", "1.10.0", "1.11.0", "1.2.0", "2.0.0-alpha.1", "2.0.0"]
    assert sort_versions(versions, "npm") == [
        "1.2.0",
        "1.9.0",
        "1.10.0",
        "1.11.0",
        "2.0.0-alpha.1",
        "2.0.0",
    ]


def test_sort_versions_go_handles_v_prefix():
    versions = ["v1.9.0", "v1.10.0", "v1.2.0", "v1.11.0"]
    assert sort_versions(versions, "go") == ["v1.2.0", "v1.9.0", "v1.10.0", "v1.11.0"]


def test_parse_purl_decodes_scoped_npm_package():
    entry = _parse_purl("pkg:npm/%40babel%2Fcore@7.0.0")
    assert entry is not None
    assert entry.name == "@babel/core"
    assert entry.ecosystem == "npm"


def test_parse_purl_preserves_full_go_module_path():
    entry = _parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.0")
    assert entry is not None
    assert entry.name == "github.com/gin-gonic/gin"
    assert entry.ecosystem == "go"


def test_cyclonedx_fallback_infers_maven_from_group():
    parser = SBOMParser()
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "group": "org.springframework",
                "name": "spring-core",
                "version": "5.3.0",
            }
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
        import json

        json.dump(data, handle)
        path = handle.name
    try:
        entries = parser.parse(path)
    finally:
        Path(path).unlink()

    assert len(entries) == 1
    assert entries[0].name == "org.springframework:spring-core"
    assert entries[0].ecosystem == "maven"


async def _collect_scores(finding) -> list[dict]:
    class Service:
        def __init__(self):
            self.calls: list[dict] = []

        async def add_score(self, **kwargs):
            self.calls.append(kwargs)

    service = Service()
    propagator = RiskPropagator(risk_score_service=service)
    blast = BlastRadius(direct_dependencies=[{"id": "svc-1"}], indirect_dependencies=[{"id": "svc-2"}])
    await propagator.propagate("tenant-1", finding, blast)
    return service.calls


@pytest.mark.asyncio
async def test_risk_propagator_uses_string_severity_from_finding():
    finding = SimpleNamespace(
        id="finding-1",
        severity="critical",
        package_name="requests",
        package_version="2.32.0",
    )
    calls = await _collect_scores(finding)
    assert calls[0]["delta"] == 40
    assert calls[1]["delta"] == 20


def test_verdict_merger_keeps_distinct_findings_in_same_file_and_category():
    merger = VerdictMerger()
    raw = [
        {
            "verdict": "MALICIOUS",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "summary": "bad",
            "findings": [
                {
                    "category": "EXECUTION",
                    "description": "exec one",
                    "file": "setup.py",
                    "line_start": 10,
                    "line_end": 10,
                    "evidence": "exec(a)",
                    "cwe": "CWE-78",
                    "severity": "CRITICAL",
                },
                {
                    "category": "EXECUTION",
                    "description": "exec two",
                    "file": "setup.py",
                    "line_start": 20,
                    "line_end": 20,
                    "evidence": "exec(b)",
                    "cwe": "CWE-78",
                    "severity": "CRITICAL",
                },
            ],
        }
    ]
    result = merger.merge(raw, model="test", diff_stats=_stats(), start_ms=0)
    assert len(result.findings) == 2


def test_pyproject_wheel_includes_securify_plugin():
    try:
        import tomllib
    except ImportError:  # pragma: no cover
        import tomli as tomllib  # type: ignore

    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    packages = data["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert "securify_plugin" in packages


def test_unpack_tarball_avoids_deprecation_warning():
    from depvet.differ.unpacker import unpack

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        archive = tmp / "mypkg-1.0.0.tar.gz"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            content = b"print('ok')\n"
            info = tarfile.TarInfo(name="mypkg-1.0.0/module.py")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        archive.write_bytes(buf.getvalue())

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            unpack(archive, tmp / "out")

        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert not dep_warnings
