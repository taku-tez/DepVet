"""Tests for Go and Cargo dependency extraction."""

from __future__ import annotations

from depvet.analyzer.dep_extractor import (
    _extract_go_deps,
    _extract_cargo_deps,
    extract_new_dependencies,
)


# ─── Go / go.mod ─────────────────────────────────────────────────────────────

class TestGoModExtractor:
    def test_require_block_single(self):
        diff = "+\tgithub.com/stretchr/testify v1.8.4\n"
        deps = _extract_go_deps(diff)
        assert len(deps) == 1
        assert deps[0].name == "github.com/stretchr/testify"
        assert deps[0].version_spec == "1.8.4"
        assert deps[0].ecosystem == "go"

    def test_require_block_multiple(self):
        diff = (
            "--- a/go.mod\n+++ b/go.mod\n@@ -1 +1,5 @@\n"
            "+require (\n"
            "+\tgithub.com/gin-gonic/gin v1.9.1\n"
            "+\tgithub.com/go-sql-driver/mysql v1.7.1\n"
            "+)\n"
        )
        deps = _extract_go_deps(diff)
        assert len(deps) == 2
        assert deps[0].name == "github.com/gin-gonic/gin"
        assert deps[1].name == "github.com/go-sql-driver/mysql"

    def test_single_line_require(self):
        diff = "+require github.com/google/uuid v1.3.0\n"
        deps = _extract_go_deps(diff)
        assert len(deps) == 1
        assert deps[0].name == "github.com/google/uuid"

    def test_indirect_marked_as_dev(self):
        diff = "+\tgolang.org/x/crypto v0.14.0 // indirect\n"
        deps = _extract_go_deps(diff)
        assert len(deps) == 1
        assert deps[0].is_dev is True

    def test_direct_not_dev(self):
        diff = "+\tgithub.com/user/repo v1.0.0\n"
        deps = _extract_go_deps(diff)
        assert len(deps) == 1
        assert deps[0].is_dev is False

    def test_skips_go_directive(self):
        """'go 1.21' is not a dependency."""
        diff = "+go 1.21\n+toolchain go1.21.0\n"
        deps = _extract_go_deps(diff)
        assert len(deps) == 0

    def test_skips_comments(self):
        diff = "+// this is a comment\n+\tgithub.com/foo/bar v1.0.0\n"
        deps = _extract_go_deps(diff)
        assert len(deps) == 1

    def test_removed_lines_ignored(self):
        diff = "-\tgithub.com/old/dep v1.0.0\n+\tgithub.com/new/dep v2.0.0\n"
        deps = _extract_go_deps(diff)
        assert len(deps) == 1
        assert deps[0].name == "github.com/new/dep"

    def test_typosquatting_candidate(self):
        """Modules like github.com/g0ogle/uuid should still be extracted."""
        diff = "+\tgithub.com/g0ogle/uuid v0.0.1\n"
        deps = _extract_go_deps(diff)
        assert len(deps) == 1
        assert deps[0].name == "github.com/g0ogle/uuid"


# ─── Cargo / Cargo.toml ──────────────────────────────────────────────────────

class TestCargoTomlExtractor:
    def test_simple_dep(self):
        diff = (
            "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1 +1,3 @@\n"
            "+[dependencies]\n"
            '+serde = "1.0"\n'
        )
        deps = _extract_cargo_deps(diff)
        assert len(deps) == 1
        assert deps[0].name == "serde"
        assert deps[0].version_spec == "1.0"
        assert deps[0].ecosystem == "cargo"

    def test_table_dep_with_features(self):
        diff = (
            "+[dependencies]\n"
            '+tokio = { version = "1.28", features = ["full"] }\n'
        )
        deps = _extract_cargo_deps(diff)
        assert len(deps) == 1
        assert deps[0].name == "tokio"
        assert deps[0].version_spec == "1.28"

    def test_dev_dependencies(self):
        diff = "+[dev-dependencies]\n" '+mockall = "0.11"\n'
        deps = _extract_cargo_deps(diff)
        assert len(deps) == 1
        assert deps[0].is_dev is True

    def test_build_dependencies_flagged_dev(self):
        diff = "+[build-dependencies]\n" '+cc = "1.0"\n'
        deps = _extract_cargo_deps(diff)
        assert len(deps) == 1
        assert deps[0].is_dev is True

    def test_regular_deps_not_dev(self):
        diff = "+[dependencies]\n" '+reqwest = "0.11"\n'
        deps = _extract_cargo_deps(diff)
        assert deps[0].is_dev is False

    def test_skips_metadata_keys(self):
        """name, version, edition should not be extracted as deps."""
        diff = "+[package]\n" '+name = "my-crate"\n' '+version = "0.1.0"\n' '+edition = "2021"\n'
        deps = _extract_cargo_deps(diff)
        assert len(deps) == 0

    def test_outside_dep_section_ignored(self):
        diff = "+[package]\n" '+serde = "1.0"\n'
        deps = _extract_cargo_deps(diff)
        assert len(deps) == 0

    def test_multiple_deps(self):
        diff = (
            "+[dependencies]\n"
            '+serde = "1.0"\n'
            '+serde_json = "1.0"\n'
            '+tokio = { version = "1.28" }\n'
        )
        deps = _extract_cargo_deps(diff)
        assert len(deps) == 3
        names = [d.name for d in deps]
        assert "serde" in names
        assert "serde_json" in names
        assert "tokio" in names

    def test_removed_lines_ignored(self):
        diff = "+[dependencies]\n" '-old-crate = "0.1"\n' '+new-crate = "0.2"\n'
        deps = _extract_cargo_deps(diff)
        assert len(deps) == 1
        assert deps[0].name == "new-crate"


# ─── Unified extractor routing ───────────────────────────────────────────────

class TestUnifiedExtractorRouting:
    def test_routes_to_go_for_go_mod(self):
        diff = "+\tgithub.com/foo/bar v1.0.0\n"
        deps = extract_new_dependencies(diff, "go.mod")
        assert len(deps) == 1
        assert deps[0].ecosystem == "go"

    def test_routes_to_go_for_go_sum(self):
        diff = "+github.com/foo/bar v1.0.0 h1:abc=\n"
        deps = extract_new_dependencies(diff, "go.sum")
        # go.sum uses the same parser; module lines have h1: hashes
        assert all(d.ecosystem == "go" for d in deps)

    def test_routes_to_cargo_for_cargo_toml(self):
        diff = "+[dependencies]\n" '+serde = "1.0"\n'
        deps = extract_new_dependencies(diff, "Cargo.toml")
        assert len(deps) == 1
        assert deps[0].ecosystem == "cargo"

    def test_npm_still_routes_correctly(self):
        diff = '+    "lodash": "^4.17.21"\n'
        deps = extract_new_dependencies(diff, "package.json")
        assert any(d.ecosystem == "npm" for d in deps)

    def test_pypi_still_routes_correctly(self):
        diff = '+"requests>=2.28"\n'
        deps = extract_new_dependencies(diff, "requirements.txt")
        assert any(d.ecosystem == "pypi" for d in deps)
