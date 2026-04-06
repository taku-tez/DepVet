"""Tests for depvet.exceptions — domain exception hierarchy."""

from __future__ import annotations

import pytest

from depvet.exceptions import (
    AnalysisError,
    ConfigError,
    DepVetError,
    DownloadError,
    RegistryError,
    SBOMParseError,
    StateError,
    TriageError,
)


class TestExceptionHierarchy:
    """Verify that all exceptions are subclasses of DepVetError."""

    @pytest.mark.parametrize(
        "exc_cls",
        [
            RegistryError,
            DownloadError,
            AnalysisError,
            TriageError,
            ConfigError,
            StateError,
            SBOMParseError,
        ],
    )
    def test_subclass_of_depvet_error(self, exc_cls):
        assert issubclass(exc_cls, DepVetError)

    def test_triage_error_is_analysis_error(self):
        """TriageError is a specialization of AnalysisError."""
        assert issubclass(TriageError, AnalysisError)

    def test_triage_error_is_depvet_error(self):
        """TriageError should be catchable as DepVetError."""
        assert issubclass(TriageError, DepVetError)


class TestExceptionCatch:
    """Verify that exceptions can be caught by parent types."""

    def test_catch_registry_as_depvet(self):
        with pytest.raises(DepVetError):
            raise RegistryError("PyPI 503")

    def test_catch_download_as_depvet(self):
        with pytest.raises(DepVetError):
            raise DownloadError("404 Not Found")

    def test_catch_triage_as_analysis(self):
        with pytest.raises(AnalysisError):
            raise TriageError("LLM timeout")

    def test_catch_triage_as_depvet(self):
        with pytest.raises(DepVetError):
            raise TriageError("LLM timeout")

    def test_catch_config_as_depvet(self):
        with pytest.raises(DepVetError):
            raise ConfigError("missing toml key")

    def test_catch_state_as_depvet(self):
        with pytest.raises(DepVetError):
            raise StateError("corrupt YAML")

    def test_catch_sbom_as_depvet(self):
        with pytest.raises(DepVetError):
            raise SBOMParseError("invalid CycloneDX")


class TestExceptionMessage:
    """Verify that exception messages are preserved."""

    def test_message_preserved(self):
        err = RegistryError("npm CouchDB unreachable")
        assert str(err) == "npm CouchDB unreachable"

    def test_empty_message(self):
        err = DepVetError()
        assert str(err) == ""

    def test_multi_arg(self):
        err = DownloadError("status", 404)
        assert "status" in str(err)


class TestExceptionDistinctness:
    """Verify that sibling exceptions are distinct (not caught as each other)."""

    def test_registry_not_download(self):
        with pytest.raises(RegistryError):
            raise RegistryError("test")
        # Should NOT catch DownloadError
        with pytest.raises(DownloadError):
            raise DownloadError("test")

    def test_config_not_state(self):
        try:
            raise ConfigError("bad config")
        except StateError:
            pytest.fail("ConfigError should not be caught as StateError")
        except ConfigError:
            pass
