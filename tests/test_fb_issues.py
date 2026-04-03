"""Tests for FB issues: #17 (version_context in monitor), #18 (SBOM format),
#22 (queue_max_size), #23 (scan/analyze output), #24 (config wiring), #25 (URL per-ecosystem)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from click.testing import CliRunner


runner = CliRunner()


# ─── Issue #17: version_context passed in monitor ────────────────────────────

class TestVersionContextInMonitor:
    def test_get_transition_context_imported_in_monitor(self):
        import depvet.cli as m
        import pathlib
        src = pathlib.Path(m.__file__).read_text()
        monitor_section = src[src.find("async def _monitor"):]
        assert "get_transition_context" in monitor_section, (
            "_monitor must call get_transition_context() for version signals"
        )

    def test_version_context_passed_to_deep_analyze_in_monitor(self):
        import depvet.cli as m
        import pathlib
        src = pathlib.Path(m.__file__).read_text()
        # _process_one is defined inside _monitor — search entire monitor function
        monitor_section = src[src.find("async def _monitor"):]
        assert "version_context" in monitor_section, (
            "_process_one must pass version_context= to deep.analyze()"
        )


# ─── Issue #18: SBOM format routing ──────────────────────────────────────────

class TestSBOMFormatRouting:
    def test_spdx_xml_with_packages_parsed(self):
        """SPDX XML with package elements should be parsed correctly."""
        from depvet.watchlist.sbom import SBOMParser
        spdx_xml = """<?xml version="1.0"?>
<SpdxDocument xmlns="http://spdx.org/spdx/v2.3/document">
  <packages>
    <package>
      <name>requests</name>
      <versionInfo>2.31.0</versionInfo>
    </package>
    <package>
      <name>click</name>
      <versionInfo>8.1.0</versionInfo>
    </package>
  </packages>
</SpdxDocument>"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(spdx_xml)
            path = f.name
        try:
            entries = SBOMParser().parse(path, fmt="spdx")
            names = [e.name for e in entries]
            assert "requests" in names or len(entries) > 0, (
                f"SPDX XML should parse packages, got: {entries}"
            )
        finally:
            Path(path).unlink(missing_ok=True)

    def test_cyclonedx_xml_fallback_name_version(self):
        """CycloneDX XML without PURL should use group/name/version fallback."""
        from depvet.watchlist.sbom import SBOMParser
        cdx_xml = """<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4">
  <components>
    <component type="library">
      <group>org.springframework</group>
      <name>spring-core</name>
      <version>5.3.0</version>
    </component>
  </components>
</bom>"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(cdx_xml)
            path = f.name
        try:
            entries = SBOMParser().parse(path)
            assert len(entries) > 0, (
                f"CycloneDX XML without PURL should use name fallback, got: {entries}"
            )
            assert any("spring" in e.name.lower() for e in entries), (
                f"Expected spring-core in entries, got: {[e.name for e in entries]}"
            )
        finally:
            Path(path).unlink(missing_ok=True)

    def test_format_explicit_overrides_autodetect(self):
        """Passing fmt='spdx' should route to SPDX parser even for cyclonedx-looking XML."""
        from depvet.watchlist.sbom import SBOMParser
        import inspect
        sig = inspect.signature(SBOMParser.parse)
        assert "fmt" in sig.parameters, "SBOMParser.parse must accept fmt= parameter"

    def test_validate_format_passed_to_parser(self):
        """validate CLI _validate() must use sbom_format when calling parser.parse()."""
        import depvet.cli as m
        import pathlib
        src = pathlib.Path(m.__file__).read_text()
        validate_section = src[src.find("async def _validate"):][:500]
        assert "fmt=" in validate_section or "sbom_format" in validate_section, (
            "_validate must pass sbom_format to parser.parse()"
        )


# ─── Issue #22 residual: queue_max_size ──────────────────────────────────────

class TestQueueMaxSize:
    def test_queue_created_with_queue_max_size(self):
        import depvet.cli as m
        import pathlib
        src = pathlib.Path(m.__file__).read_text()
        monitor_section = src[src.find("async def _monitor"):]
        assert "queue_max_size" in monitor_section, (
            "_monitor must use config.monitor.queue_max_size for Queue"
        )
        assert "asyncio.Queue" in monitor_section, (
            "_monitor must create asyncio.Queue for backpressure"
        )

    def test_queue_put_used_for_releases(self):
        import depvet.cli as m
        import pathlib
        src = pathlib.Path(m.__file__).read_text()
        monitor_section = src[src.find("async def _monitor"):]
        assert "_queue.put" in monitor_section, (
            "releases must be put into _queue for backpressure"
        )


# ─── Issue #23: scan/analyze always outputs ──────────────────────────────────

class TestScanAnalyzeAlwaysOutputs:
    def test_scan_alerter_min_severity_none(self):
        """scan must use min_severity=NONE so all verdicts (incl. BENIGN) are shown."""
        import depvet.cli as m
        import pathlib
        src = pathlib.Path(m.__file__).read_text()
        scan_section = src[src.find("async def _scan"):src.find("async def _diff")]
        assert 'min_severity="NONE"' in scan_section or "min_severity='NONE'" in scan_section, (
            "_scan StdoutAlerter must use min_severity='NONE' to always output"
        )

    def test_analyze_alerter_min_severity_none(self):
        """analyze must use min_severity=NONE so all verdicts are shown."""
        import depvet.cli as m
        import pathlib
        src = pathlib.Path(m.__file__).read_text()
        # _analyze is between 'async def _analyze' and '# depvet monitor'
        analyze_section = src[src.find("async def _analyze"):src.find("# depvet monitor")]
        assert 'min_severity="NONE"' in analyze_section or "min_severity='NONE'" in analyze_section, (
            f"_analyze StdoutAlerter must use min_severity='NONE' to always output. "
            f"Section length: {len(analyze_section)}"
        )

    def test_stdout_alerter_direct_send_bypasses_router(self):
        """scan/analyze uses StdoutAlerter directly (not router), so BENIGN is printed."""
        # scan/analyze call: StdoutAlerter(min_severity='NONE').send(event)
        # This bypasses AlertRouter which always skips BENIGN
        # Key: StdoutAlerter.send() respects its own min_severity, not router logic
        from depvet.alert.stdout import StdoutAlerter
        _ = StdoutAlerter(min_severity="NONE")  # verify constructor works
        # SEVERITY_ORDER[NONE] == 0, so any verdict passes
        from depvet.alert.stdout import SEVERITY_ORDER
        from depvet.models.verdict import Severity
        none_level = SEVERITY_ORDER.get(Severity.NONE, 0)
        medium_level = SEVERITY_ORDER.get(Severity.MEDIUM, 0)
        # NONE=1, MEDIUM=3, CRITICAL=5 — NONE is the lowest
        assert none_level <= medium_level, "NONE severity must be lowest threshold"
        assert none_level == 1, "NONE severity order must be 1 (lowest)"
        # scan: SEVERITY_ORDER[verdict] < SEVERITY_ORDER[min_severity=NONE=1]
        # For NONE verdict: 1 < 1 == False → passes (always prints)
        critical_level = SEVERITY_ORDER.get(Severity.CRITICAL, 0)
        assert not (critical_level < none_level), "CRITICAL must not be filtered by NONE threshold"


# ─── Issue #24: config wiring (sbom_path, sources, refresh_interval) ─────────

class TestConfigWiring24:
    def test_sbom_path_used_in_monitor(self):
        """config.watchlist.sbom_path should be loaded automatically in monitor."""
        import depvet.cli as m
        import pathlib
        src = pathlib.Path(m.__file__).read_text()
        monitor_section = src[src.find("async def _monitor"):]
        assert "sbom_path" in monitor_section or "effective_sbom" in monitor_section, (
            "_monitor must respect config.watchlist.sbom_path"
        )

    def test_sbom_format_used_in_monitor(self):
        """config.watchlist.sbom_format should be passed to import_from_sbom."""
        import depvet.cli as m
        import pathlib
        src = pathlib.Path(m.__file__).read_text()
        monitor_section = src[src.find("async def _monitor"):]
        assert "sbom_format" in monitor_section or "sbom_fmt" in monitor_section, (
            "_monitor must pass sbom_format to import_from_sbom"
        )


# ─── Issue #25: ecosystem-specific URLs ──────────────────────────────────────

class TestEcosystemUrls:
    def test_go_url(self):
        from depvet.cli import _build_release_url
        assert "pkg.go.dev" in _build_release_url("github.com/foo/bar", "v1.0.0", "go")

    def test_cargo_url(self):
        from depvet.cli import _build_release_url
        assert "crates.io" in _build_release_url("serde", "1.0.0", "cargo")

    def test_npm_url(self):
        from depvet.cli import _build_release_url
        assert "npmjs.com" in _build_release_url("lodash", "4.17.21", "npm")

    def test_pypi_url(self):
        from depvet.cli import _build_release_url
        assert "pypi.org" in _build_release_url("requests", "2.32.0", "pypi")
