"""Tests for depvet.watchlist.lockfile — lockfile parsers."""

from __future__ import annotations

import json

from depvet.watchlist.lockfile import parse_lockfile


class TestPackageLockJson:
    def test_v3_packages(self, tmp_path):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/express/node_modules/debug": {"version": "2.6.9"},
            },
        }
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps(data))
        entries = parse_lockfile(str(path))
        names = {e.name for e in entries}
        assert "lodash" in names
        assert "express" in names
        assert "debug" in names
        assert all(e.ecosystem == "npm" for e in entries)
        # Root package should be excluded
        assert "my-app" not in names

    def test_v1_dependencies(self, tmp_path):
        data = {
            "lockfileVersion": 1,
            "dependencies": {
                "axios": {"version": "1.7.0"},
                "react": {"version": "18.3.0"},
            },
        }
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps(data))
        entries = parse_lockfile(str(path))
        assert len(entries) == 2
        names = {e.name for e in entries}
        assert "axios" in names
        assert "react" in names

    def test_scoped_package(self, tmp_path):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/@babel/core": {"version": "7.24.0", "name": "@babel/core"},
            },
        }
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps(data))
        entries = parse_lockfile(str(path))
        assert len(entries) == 1
        assert entries[0].name == "@babel/core"

    def test_empty_lockfile(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text("{}")
        assert parse_lockfile(str(path)) == []


class TestYarnLock:
    def test_v1_format(self, tmp_path):
        content = '''\
# yarn lockfile v1

"lodash@^4.17.21":
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"express@^4.18.0":
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
'''
        path = tmp_path / "yarn.lock"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        assert len(entries) == 2
        names = {e.name for e in entries}
        assert "lodash" in names
        assert "express" in names
        assert entries[0].ecosystem == "npm"

    def test_berry_format(self, tmp_path):
        content = '''\
__metadata:
  version: 8

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"@babel/core@npm:^7.24.0":
  version: 7.24.0
  resolution: "@babel/core@npm:7.24.0"
'''
        path = tmp_path / "yarn.lock"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        names = {e.name for e in entries}
        assert "lodash" in names
        assert "@babel/core" in names

    def test_deduplicates(self, tmp_path):
        content = '''\
"lodash@^4.17.20", "lodash@^4.17.21":
  version "4.17.21"
'''
        path = tmp_path / "yarn.lock"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        assert len(entries) == 1


class TestPipfileLock:
    def test_default_and_develop(self, tmp_path):
        data = {
            "_meta": {"hash": {"sha256": "abc"}},
            "default": {
                "requests": {"version": "==2.32.0"},
                "flask": {"version": "==3.0.0"},
            },
            "develop": {
                "pytest": {"version": "==8.0.0"},
            },
        }
        path = tmp_path / "Pipfile.lock"
        path.write_text(json.dumps(data))
        entries = parse_lockfile(str(path))
        assert len(entries) == 3
        names = {e.name for e in entries}
        assert "requests" in names
        assert "pytest" in names
        assert all(e.ecosystem == "pypi" for e in entries)
        # Version should strip leading ==
        req = next(e for e in entries if e.name == "requests")
        assert req.current_version == "2.32.0"


class TestPoetryLock:
    def test_parse_packages(self, tmp_path):
        content = '''\
[[package]]
name = "requests"
version = "2.32.0"
description = "Python HTTP"

[[package]]
name = "flask"
version = "3.0.0"
description = "Micro framework"
'''
        path = tmp_path / "poetry.lock"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        assert len(entries) == 2
        names = {e.name for e in entries}
        assert "requests" in names
        assert "flask" in names
        req = next(e for e in entries if e.name == "requests")
        assert req.current_version == "2.32.0"
        assert req.ecosystem == "pypi"


class TestGoSum:
    def test_parse_modules(self, tmp_path):
        content = """\
github.com/google/uuid v1.6.0 h1:abcdef==
github.com/google/uuid v1.6.0/go.mod h1:ghijkl==
github.com/spf13/cobra v1.8.0 h1:mnopqr==
github.com/spf13/cobra v1.8.0/go.mod h1:stuvwx==
"""
        path = tmp_path / "go.sum"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        # Should deduplicate (module appears twice: once for source, once for go.mod)
        assert len(entries) == 2
        names = {e.name for e in entries}
        assert "github.com/google/uuid" in names
        assert "github.com/spf13/cobra" in names
        assert all(e.ecosystem == "go" for e in entries)


class TestCargoLock:
    def test_parse_packages(self, tmp_path):
        content = '''\
[[package]]
name = "serde"
version = "1.0.203"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.38.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
'''
        path = tmp_path / "Cargo.lock"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        assert len(entries) == 2
        names = {e.name for e in entries}
        assert "serde" in names
        assert "tokio" in names
        assert all(e.ecosystem == "cargo" for e in entries)
        serde = next(e for e in entries if e.name == "serde")
        assert serde.current_version == "1.0.203"


class TestUnknownLockfile:
    def test_unknown_filename(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("requests==2.32.0\n")
        entries = parse_lockfile(str(path))
        assert entries == []


class TestCorruptFiles:
    def test_corrupt_package_lock(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text("{{{not json")
        entries = parse_lockfile(str(path))
        assert entries == []

    def test_corrupt_pipfile_lock(self, tmp_path):
        path = tmp_path / "Pipfile.lock"
        path.write_text("invalid json content!!!")
        entries = parse_lockfile(str(path))
        assert entries == []

    def test_missing_yarn_lock(self, tmp_path):
        path = tmp_path / "yarn.lock"
        # Write empty content
        path.write_text("")
        entries = parse_lockfile(str(path))
        assert entries == []

    def test_missing_go_sum(self, tmp_path):
        path = tmp_path / "go.sum"
        path.write_text("")
        entries = parse_lockfile(str(path))
        assert entries == []


class TestPackageLockEdgeCases:
    def test_v3_with_name_field(self, tmp_path):
        """When package has explicit 'name' field, it should be used."""
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/@scope/pkg": {
                    "name": "@scope/pkg",
                    "version": "1.0.0",
                },
            },
        }
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps(data))
        entries = parse_lockfile(str(path))
        assert len(entries) == 1
        assert entries[0].name == "@scope/pkg"

    def test_v1_with_non_dict_version(self, tmp_path):
        """Gracefully handle non-dict dependency values."""
        data = {
            "lockfileVersion": 1,
            "dependencies": {
                "normal": {"version": "1.0.0"},
                "weird": "1.0.0",  # string instead of dict
            },
        }
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps(data))
        entries = parse_lockfile(str(path))
        names = {e.name for e in entries}
        assert "normal" in names
        assert "weird" in names

    def test_deduplicates_nested(self, tmp_path):
        """Same package at different nesting levels should be deduplicated."""
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/express/node_modules/lodash": {"version": "4.17.20"},
            },
        }
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps(data))
        entries = parse_lockfile(str(path))
        lodash_entries = [e for e in entries if e.name == "lodash"]
        assert len(lodash_entries) == 1


class TestPoetryLockEdgeCases:
    def test_single_package_no_trailing_section(self, tmp_path):
        """Single package without a subsequent [[package]] marker."""
        content = '[[package]]\nname = "solo"\nversion = "1.0.0"\n'
        path = tmp_path / "poetry.lock"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        assert len(entries) == 1
        assert entries[0].name == "solo"

    def test_deduplicates(self, tmp_path):
        content = '[[package]]\nname = "dup"\nversion = "1.0"\n[[package]]\nname = "dup"\nversion = "2.0"\n'
        path = tmp_path / "poetry.lock"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        assert len(entries) == 1


class TestCargoLockEdgeCases:
    def test_deduplicates(self, tmp_path):
        content = '[[package]]\nname = "serde"\nversion = "1.0.203"\n[[package]]\nname = "serde"\nversion = "1.0.204"\n'
        path = tmp_path / "Cargo.lock"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        serde = [e for e in entries if e.name == "serde"]
        assert len(serde) == 1


class TestGoSumEdgeCases:
    def test_ignores_malformed_lines(self, tmp_path):
        content = "this is not a valid go.sum line\ngithub.com/pkg/errors v0.9.1 h1:abc==\n"
        path = tmp_path / "go.sum"
        path.write_text(content)
        entries = parse_lockfile(str(path))
        assert len(entries) == 1
        assert entries[0].name == "github.com/pkg/errors"


class TestManagerImportLockfile:
    def test_import_adds_to_watchlist(self, tmp_path):
        from depvet.watchlist.manager import WatchlistManager

        lockdata = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/express": {"version": "4.18.2"},
            },
        }
        lock_path = tmp_path / "package-lock.json"
        lock_path.write_text(json.dumps(lockdata))

        wl = WatchlistManager(storage_path=str(tmp_path / "watchlist.yaml"))
        count = wl.import_from_lockfile(str(lock_path))
        assert count == 2
        npm_set = wl.as_set("npm")
        assert "lodash" in npm_set
        assert "express" in npm_set
