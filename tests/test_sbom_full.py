"""Comprehensive SBOM parser tests — CycloneDX JSON/XML, SPDX JSON."""

import json
import os
import tempfile
import pytest

from depvet.watchlist.sbom import SBOMParser, _parse_purl


# ─── purl parsing ────────────────────────────────────────────────────────────

class TestPurlParsing:
    def test_pypi_with_version(self):
        e = _parse_purl("pkg:pypi/requests@2.31.0")
        assert e.name == "requests"
        assert e.ecosystem == "pypi"
        assert e.current_version == "2.31.0"

    def test_npm_simple(self):
        e = _parse_purl("pkg:npm/lodash@4.17.21")
        assert e.name == "lodash"
        assert e.ecosystem == "npm"

    def test_npm_scoped_package(self):
        e = _parse_purl("pkg:npm/%40babel%2Fcore@7.0.0")
        assert e is not None

    def test_go_with_namespace(self):
        e = _parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.0")
        assert e is not None
        assert e.ecosystem == "go"

    def test_cargo(self):
        e = _parse_purl("pkg:cargo/serde@1.0.0")
        assert e.name == "serde"
        assert e.ecosystem == "cargo"

    def test_maven(self):
        e = _parse_purl("pkg:maven/org.springframework/spring-core@5.3.0")
        assert e is not None
        assert e.ecosystem == "maven"

    def test_no_version(self):
        e = _parse_purl("pkg:pypi/requests")
        assert e is not None
        assert e.current_version == ""

    def test_invalid_returns_none(self):
        assert _parse_purl("not-a-purl") is None
        assert _parse_purl("") is None
        assert _parse_purl("pkg:") is None


# ─── CycloneDX JSON ──────────────────────────────────────────────────────────

class TestCycloneDXJSON:
    @pytest.fixture
    def parser(self):
        return SBOMParser()

    def _write_and_parse(self, data: dict, parser: SBOMParser) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            return parser.parse(path)
        finally:
            os.unlink(path)

    def test_basic_components(self, parser):
        data = {
            "bomFormat": "CycloneDX",
            "components": [
                {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
                {"type": "library", "name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
                {"type": "library", "name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"},
            ]
        }
        entries = self._write_and_parse(data, parser)
        names = [e.name for e in entries]
        assert "requests" in names
        assert "flask" in names
        assert "axios" in names

    def test_empty_components(self, parser):
        data = {"bomFormat": "CycloneDX", "components": []}
        entries = self._write_and_parse(data, parser)
        assert entries == []

    def test_component_without_purl_uses_fallback(self, parser):
        data = {
            "bomFormat": "CycloneDX",
            "components": [
                {"type": "library", "name": "mypkg", "version": "1.0.0"},
            ]
        }
        entries = self._write_and_parse(data, parser)
        assert len(entries) == 1
        assert entries[0].name == "mypkg"

    def test_non_library_components_included(self, parser):
        """application/container types should also be included if they have purls."""
        data = {
            "bomFormat": "CycloneDX",
            "components": [
                {"type": "application", "name": "app", "purl": "pkg:pypi/app@1.0.0"},
            ]
        }
        entries = self._write_and_parse(data, parser)
        # purl-based parsing includes all types
        assert any(e.name == "app" for e in entries)

    def test_mixed_ecosystems(self, parser):
        data = {
            "bomFormat": "CycloneDX",
            "components": [
                {"type": "library", "name": "serde", "purl": "pkg:cargo/serde@1.0.0"},
                {"type": "library", "name": "spring", "purl": "pkg:maven/org.springframework/spring-core@5.3.0"},
            ]
        }
        entries = self._write_and_parse(data, parser)
        ecosystems = {e.ecosystem for e in entries}
        assert "cargo" in ecosystems
        assert "maven" in ecosystems

    def test_version_preserved(self, parser):
        data = {
            "bomFormat": "CycloneDX",
            "components": [
                {"type": "library", "name": "pkg", "purl": "pkg:pypi/pkg@3.14.159"}
            ]
        }
        entries = self._write_and_parse(data, parser)
        assert entries[0].current_version == "3.14.159"


# ─── CycloneDX XML ───────────────────────────────────────────────────────────

class TestCycloneDXXML:
    @pytest.fixture
    def parser(self):
        return SBOMParser()

    def test_xml_v14_parse(self, parser):
        xml = """<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components>
    <component type="library">
      <name>requests</name>
      <version>2.31.0</version>
      <purl>pkg:pypi/requests@2.31.0</purl>
    </component>
    <component type="library">
      <name>flask</name>
      <version>3.0.0</version>
      <purl>pkg:pypi/flask@3.0.0</purl>
    </component>
  </components>
</bom>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            path = f.name
        try:
            entries = parser.parse(path)
        finally:
            os.unlink(path)
        names = [e.name for e in entries]
        assert "requests" in names
        assert "flask" in names

    def test_xml_empty_components(self, parser):
        xml = """<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4">
  <components></components>
</bom>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            path = f.name
        try:
            entries = parser.parse(path)
        finally:
            os.unlink(path)
        assert entries == []

    def test_xml_malformed_does_not_crash(self, parser):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write("<broken xml")
            path = f.name
        try:
            entries = parser.parse(path)
            assert isinstance(entries, list)
        finally:
            os.unlink(path)


# ─── SPDX JSON ───────────────────────────────────────────────────────────────

class TestSPDXJSON:
    @pytest.fixture
    def parser(self):
        return SBOMParser()

    def test_spdx_with_purl(self, parser):
        data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-requests",
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}
                    ]
                },
                {
                    "SPDXID": "SPDXRef-axios",
                    "name": "axios",
                    "versionInfo": "1.6.0",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:npm/axios@1.6.0"}
                    ]
                }
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            entries = parser.parse(path)
        finally:
            os.unlink(path)
        names = [e.name for e in entries]
        assert "requests" in names
        assert "axios" in names

    def test_spdx_fallback_without_purl(self, parser):
        data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkg",
                    "name": "mypkg",
                    "versionInfo": "1.0.0",
                    "externalRefs": []
                }
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            entries = parser.parse(path)
        finally:
            os.unlink(path)
        assert any(e.name == "mypkg" for e in entries)

    def test_spdx_empty_packages(self, parser):
        data = {"SPDXID": "SPDXRef-DOCUMENT", "packages": []}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            entries = parser.parse(path)
        finally:
            os.unlink(path)
        assert entries == []


# ─── Error handling ───────────────────────────────────────────────────────────

class TestParserErrors:
    @pytest.fixture
    def parser(self):
        return SBOMParser()

    def test_invalid_json_returns_empty(self, parser):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("this is not json {{{")
            path = f.name
        try:
            entries = parser.parse(path)
            assert entries == []
        finally:
            os.unlink(path)

    def test_unknown_format_returns_empty(self, parser):
        data = {"unknown_key": "unknown_value", "data": []}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            entries = parser.parse(path)
            assert isinstance(entries, list)
        finally:
            os.unlink(path)
