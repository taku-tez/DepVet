"""Tests for Issues #11-#15 fixes."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from depvet.analyzer.dep_extractor import _extract_pypi_deps
from depvet.analyzer.version_signal import _is_security_package
from depvet.cli import cli


runner = CliRunner()


# ─── Issue #11: PyPI metadata key false positives ────────────────────────────


class TestPypiMetadataFalsePositives:
    def test_name_key_not_extracted(self):
        diff = '--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1 +1,3 @@\n+name = "depvet"\n+version = "0.1.0"\n'
        deps = _extract_pypi_deps(diff)
        names = [d.name for d in deps]
        assert "depvet" not in names, "metadata 'name' key must not be extracted as dep"
        assert "version" not in names

    def test_requires_python_not_extracted(self):
        diff = '--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1 +1 @@\n+requires-python = ">=3.11"\n'
        deps = _extract_pypi_deps(diff)
        assert not any(d.name == "requires-python" for d in deps)
        assert not deps, f"Expected no deps, got: {[d.name for d in deps]}"

    def test_dependencies_key_not_extracted(self):
        diff = "--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1 +1 @@\n+dependencies = [\n"
        deps = _extract_pypi_deps(diff)
        assert not any(d.name == "dependencies" for d in deps)

    def test_description_not_extracted(self):
        diff = '--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1 +1 @@\n+description = "A great tool"\n'
        deps = _extract_pypi_deps(diff)
        assert not deps

    def test_real_dep_still_extracted(self):
        """Legitimate packages inside the dependencies list must still be detected."""
        diff = (
            "--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1 +1,4 @@\n"
            "+dependencies = [\n"
            '+"requests>=2.28",\n'
            '+"click>=8.0",\n'
            "+]\n"
        )
        deps = _extract_pypi_deps(diff)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "click" in names

    def test_requirements_txt_dep_extracted(self):
        diff = "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1,2 @@\n+flask>=2.0\n+sqlalchemy\n"
        deps = _extract_pypi_deps(diff, "requirements.txt")
        names = [d.name for d in deps]
        assert "flask" in names
        assert "sqlalchemy" in names


# ─── Issue #12: ecosystem CLI flags ──────────────────────────────────────────


class TestEcosystemFlags:
    def test_scan_help_has_go_flag(self):
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--go" in result.output

    def test_scan_help_has_cargo_flag(self):
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--cargo" in result.output

    def test_diff_help_has_go_flag(self):
        result = runner.invoke(cli, ["diff", "--help"])
        assert "--go" in result.output

    def test_diff_help_has_cargo_flag(self):
        result = runner.invoke(cli, ["diff", "--help"])
        assert "--cargo" in result.output


# ─── Issue #13: validate --format passed through ─────────────────────────────


class TestValidateFmt:
    def test_validate_help_has_format(self):
        result = runner.invoke(cli, ["validate", "--help"])
        assert "--format" in result.output or "-format" in result.output or "fmt" in result.output

    def test_validate_called_with_fmt(self):
        """_validate should receive sbom_format argument."""
        import inspect
        from depvet import cli as cli_module

        sig = inspect.signature(cli_module._validate)
        params = list(sig.parameters.keys())
        assert "sbom_format" in params, f"_validate must accept sbom_format, got: {params}"


# ─── Issue #14: security package dormancy exemption ─────────────────────────


class TestSecurityPackageDormancy:
    def test_cryptography_is_security(self):
        assert _is_security_package("cryptography")

    def test_pyopenssl_is_security(self):
        assert _is_security_package("pyopenssl")

    def test_certifi_is_security(self):
        assert _is_security_package("certifi")

    def test_requests_not_security(self):
        assert not _is_security_package("requests")

    def test_flask_not_security(self):
        assert not _is_security_package("flask")

    @pytest.mark.asyncio
    async def test_security_package_skips_dormancy_signal(self):
        """cryptography should not get LONG_DORMANCY even after 400+ day gap."""
        from depvet.analyzer.version_signal import analyze_pypi_transition

        fake_pypi_data = {
            "releases": {
                "41.0.0": [{"upload_time_iso_8601": "2022-01-01T00:00:00Z"}],
                "42.0.0": [{"upload_time_iso_8601": "2023-06-01T00:00:00Z"}],  # 516 days later
            },
            "info": {"author": "PyCA", "home_page": ""},
        }

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=fake_pypi_data)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp

        with patch("depvet.analyzer.version_signal._get_version_info_pypi", AsyncMock(return_value=None)):
            ctx = await analyze_pypi_transition("cryptography", "41.0.0", "42.0.0", mock_session)

        dormancy_signals = [s for s in ctx.signals if "DORMANCY" in s.signal_id]
        assert not dormancy_signals, f"cryptography should not get DORMANCY signal, got: {dormancy_signals}"

    def test_security_package_dormancy_logic(self):
        """_detect_dormancy() skips security packages via _is_security_package()."""
        import inspect
        from depvet.analyzer import version_signal as vs_mod

        # Now dormancy is centralized in _detect_dormancy()
        src = inspect.getsource(vs_mod._detect_dormancy)
        assert "_is_security_package" in src, "_detect_dormancy must call _is_security_package"


# ─── Issue #15: config wiring ────────────────────────────────────────────────


class TestConfigWiring:
    def test_monitor_uses_config_interval(self):
        """monitor() CLI callback reads config.monitor.interval."""
        # monitor is a click Command; check its callback source
        # interval is passed from CLI, and config default is used in monitor()
        # check in the overall cli.py source
        import depvet.cli
        import pathlib

        cli_path = pathlib.Path(depvet.cli.__file__).read_text()
        assert "config.monitor.interval" in cli_path

    def test_monitor_config_ecosystems_used(self):
        """_monitor should use config.monitor.ecosystems to decide which monitors to start."""
        import inspect
        from depvet import cli as cli_module

        src = inspect.getsource(cli_module._monitor)
        assert "config.monitor.ecosystems" in src
