"""Domain-specific exceptions for DepVet.

Hierarchy:
    DepVetError
    ├── RegistryError          — registry polling / API failures
    ├── DownloadError          — package download failures
    ├── AnalysisError          — LLM triage / deep analysis failures
    │   └── TriageError        — specifically triage stage
    ├── AlertDeliveryError     — alert sending failures (re-exported from router)
    ├── ConfigError            — configuration loading / validation
    ├── StateError             — polling state persistence
    └── SBOMParseError         — SBOM file parsing failures
"""

from __future__ import annotations


class DepVetError(Exception):
    """Base exception for all DepVet errors."""


class RegistryError(DepVetError):
    """Failure communicating with a package registry."""


class DownloadError(DepVetError):
    """Failure downloading a package artifact."""


class AnalysisError(DepVetError):
    """Failure during LLM analysis."""


class TriageError(AnalysisError):
    """Failure during triage stage."""


class ConfigError(DepVetError):
    """Invalid or missing configuration."""


class StateError(DepVetError):
    """Failure reading/writing polling state."""


class SBOMParseError(DepVetError):
    """Failure parsing an SBOM file."""
