"""Tests for dependency extractor - new dependency detection from manifest diffs."""

from depvet.analyzer.dep_extractor import (
    extract_new_dependencies,
    deps_to_watchlist_entries,
    _extract_npm_deps,
    _extract_pypi_deps,
    NewDependency,
)


# ─── npm / package.json ───────────────────────────────────────────────────────


def make_pkg_diff(added_lines: list[str]) -> str:
    """Create a minimal package.json diff."""
    return "\n".join(
        ["--- a/package.json", "+++ b/package.json", "@@ -1,5 +1,6 @@"] + [f"+{line}" for line in added_lines]
    )


class TestNpmDeps:
    def test_detect_single_new_dep(self):
        diff = make_pkg_diff(['"plain-crypto-js": "^4.2.1"'])
        deps = _extract_npm_deps(diff, "package.json")
        assert any(d.name == "plain-crypto-js" and d.version_spec == "^4.2.1" for d in deps)

    def test_detect_multiple_new_deps(self):
        diff = make_pkg_diff(
            [
                '"evil-pkg": "1.0.0"',
                '"another-bad": "^2.0.0"',
            ]
        )
        deps = _extract_npm_deps(diff, "package.json")
        names = [d.name for d in deps]
        assert "evil-pkg" in names
        assert "another-bad" in names

    def test_scoped_package(self):
        diff = make_pkg_diff(['"@evil/payload": "^1.0.0"'])
        deps = _extract_npm_deps(diff, "package.json")
        assert any(d.name == "@evil/payload" for d in deps)

    def test_dev_dependency_flagged(self):
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -1,5 +1,7 @@",
                ' "devDependencies": {',
                '+"evil-dev": "^1.0.0"',
            ]
        )
        deps = _extract_npm_deps(diff, "package.json")
        dev_deps = [d for d in deps if d.name == "evil-dev"]
        assert dev_deps
        assert dev_deps[0].is_dev is True

    def test_removed_dep_not_detected(self):
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -1,5 +1,4 @@",
                '-"old-package": "^1.0.0"',
            ]
        )
        deps = _extract_npm_deps(diff, "package.json")
        assert not any(d.name == "old-package" for d in deps)

    def test_ecosystem_is_npm(self):
        diff = make_pkg_diff(['"some-pkg": "1.0.0"'])
        deps = _extract_npm_deps(diff, "package.json")
        assert all(d.ecosystem == "npm" for d in deps)

    def test_axios_attack_pattern(self):
        """Reproduces the axios 2026-03-30 attack: plain-crypto-js injected."""
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -8,6 +8,7 @@",
                '   "dependencies": {',
                '     "follow-redirects": "^1.15.4",',
                '+    "plain-crypto-js": "^4.2.1",',
                '     "proxy-from-env": "^1.1.0"',
                "   }",
            ]
        )
        deps = _extract_npm_deps(diff, "package.json")
        malicious = [d for d in deps if d.name == "plain-crypto-js"]
        assert malicious
        assert malicious[0].version_spec == "^4.2.1"
        assert malicious[0].is_dev is False


# ─── PyPI / pyproject.toml ────────────────────────────────────────────────────


def make_toml_diff(added_lines: list[str]) -> str:
    return "\n".join(
        ["--- a/pyproject.toml", "+++ b/pyproject.toml", "@@ -1,5 +1,6 @@", " [project]", " dependencies = ["]
        + [f"+{line}" for line in added_lines]
        + [" ]"]
    )


class TestPyPIDeps:
    def test_detect_simple_dep(self):
        diff = make_toml_diff(['"evil-package>=1.0.0"'])
        deps = _extract_pypi_deps(diff, "pyproject.toml")
        assert any(d.name == "evil-package" for d in deps)

    def test_detect_dep_without_version(self):
        diff = make_toml_diff(['"suspicious-pkg"'])
        deps = _extract_pypi_deps(diff, "pyproject.toml")
        assert any(d.name == "suspicious-pkg" for d in deps)

    def test_ecosystem_is_pypi(self):
        diff = make_toml_diff(['"mypkg>=2.0"'])
        deps = _extract_pypi_deps(diff, "pyproject.toml")
        pypi_deps = [d for d in deps if d.name == "mypkg"]
        assert all(d.ecosystem == "pypi" for d in pypi_deps)

    def test_comment_not_extracted(self):
        diff = make_toml_diff(["# this is a comment"])
        deps = _extract_pypi_deps(diff)
        assert not deps

    def test_requirements_txt_style(self):
        diff = "\n".join(
            [
                "--- a/requirements.txt",
                "+++ b/requirements.txt",
                "@@ -1,2 +1,3 @@",
                " requests==2.31.0",
                "+malicious-pkg==1.0.0",
            ]
        )
        deps = _extract_pypi_deps(diff, "requirements.txt")
        assert any(d.name == "malicious-pkg" for d in deps)


# ─── Unified extractor ────────────────────────────────────────────────────────


class TestExtractNewDependencies:
    def test_routes_to_npm_for_package_json(self):
        diff = make_pkg_diff(['"test-pkg": "1.0.0"'])
        deps = extract_new_dependencies(diff, "package.json")
        assert all(d.ecosystem == "npm" for d in deps)

    def test_routes_to_pypi_for_toml(self):
        diff = make_toml_diff(['"test-pkg>=1.0"'])
        deps = extract_new_dependencies(diff, "pyproject.toml")
        assert any(d.ecosystem == "pypi" for d in deps)

    def test_empty_diff_returns_empty(self):
        deps = extract_new_dependencies("", "package.json")
        assert deps == []


# ─── deps_to_watchlist_entries ────────────────────────────────────────────────


class TestDepsToWatchlistEntries:
    def test_known_safe_filtered(self):
        deps = [
            NewDependency("lodash", "^4.0", "npm", "package.json"),
            NewDependency("plain-crypto-js", "^4.2.1", "npm", "package.json"),
        ]
        entries = deps_to_watchlist_entries(deps)
        names = [e[0] for e in entries]
        assert "lodash" not in names
        assert "plain-crypto-js" in names

    def test_dev_deps_filtered(self):
        deps = [
            NewDependency("evil-dev", "^1.0", "npm", "package.json", is_dev=True),
            NewDependency("evil-prod", "^1.0", "npm", "package.json", is_dev=False),
        ]
        entries = deps_to_watchlist_entries(deps)
        names = [e[0] for e in entries]
        assert "evil-dev" not in names
        assert "evil-prod" in names

    def test_returns_name_and_ecosystem_tuples(self):
        deps = [NewDependency("new-pkg", "^1.0", "npm", "package.json")]
        entries = deps_to_watchlist_entries(deps)
        assert entries == [("new-pkg", "npm")]

    def test_empty_input(self):
        assert deps_to_watchlist_entries([]) == []


# ─── Known-bad DB integration ─────────────────────────────────────────────────


class TestKnownBadLookup:
    def test_axios_1141_in_db(self):
        from depvet.known_bad.database import KnownBadDB

        db = KnownBadDB()
        hit = db.lookup("axios", "1.14.1", "npm")
        assert hit is not None
        assert hit.verdict == "MALICIOUS"
        assert hit.severity == "CRITICAL"

    def test_axios_0304_in_db(self):
        from depvet.known_bad.database import KnownBadDB

        db = KnownBadDB()
        hit = db.lookup("axios", "0.30.4", "npm")
        assert hit is not None
        assert hit.verdict == "MALICIOUS"

    def test_plain_crypto_js_in_db(self):
        from depvet.known_bad.database import KnownBadDB

        db = KnownBadDB()
        hit = db.lookup("plain-crypto-js", "4.2.1", "npm")
        assert hit is not None
        assert hit.verdict == "MALICIOUS"
        assert hit.severity == "CRITICAL"

    def test_axios_safe_versions_not_in_db(self):
        from depvet.known_bad.database import KnownBadDB

        db = KnownBadDB()
        # Safe versions should NOT be in Known-bad DB
        assert db.lookup("axios", "1.6.0", "npm") is None
        assert db.lookup("axios", "1.7.9", "npm") is None
        assert db.lookup("axios", "0.27.2", "npm") is None
