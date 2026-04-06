"""Tests for depvet.registry.versioning — version sorting across ecosystems."""

from __future__ import annotations

from depvet.registry.versioning import sort_versions, _pep440_key, _semver_key


class TestPyPIVersionSorting:
    def test_simple_semver(self):
        versions = ["1.0.0", "2.0.0", "1.5.0"]
        assert sort_versions(versions, "pypi") == ["1.0.0", "1.5.0", "2.0.0"]

    def test_with_pre_release(self):
        versions = ["1.0.0", "1.0.0a1", "1.0.0b1", "1.0.0rc1"]
        result = sort_versions(versions, "pypi")
        assert result == ["1.0.0a1", "1.0.0b1", "1.0.0rc1", "1.0.0"]

    def test_post_release(self):
        versions = ["1.0.0", "1.0.0.post1", "1.0.0.post2"]
        result = sort_versions(versions, "pypi")
        assert result == ["1.0.0", "1.0.0.post1", "1.0.0.post2"]

    def test_dev_release(self):
        versions = ["1.0.0", "1.0.0.dev1", "1.0.0a1"]
        result = sort_versions(versions, "pypi")
        # dev < alpha < release
        assert result.index("1.0.0.dev1") < result.index("1.0.0a1")
        assert result.index("1.0.0a1") < result.index("1.0.0")

    def test_epoch(self):
        versions = ["1.0.0", "1!0.0.1"]
        result = sort_versions(versions, "pypi")
        # epoch 1 > no epoch
        assert result[-1] == "1!0.0.1"

    def test_invalid_version_sorted_after_valid(self):
        versions = ["1.0.0", "not-a-version", "2.0.0"]
        result = sort_versions(versions, "pypi")
        assert result[0] == "1.0.0"
        assert result[1] == "2.0.0"
        # Invalid versions sort after valid ones
        assert result[-1] == "not-a-version"

    def test_empty_list(self):
        assert sort_versions([], "pypi") == []

    def test_single_version(self):
        assert sort_versions(["1.0.0"], "pypi") == ["1.0.0"]


class TestNpmVersionSorting:
    def test_simple_semver(self):
        versions = ["4.17.21", "4.17.20", "4.18.0"]
        assert sort_versions(versions, "npm") == ["4.17.20", "4.17.21", "4.18.0"]

    def test_with_v_prefix(self):
        versions = ["v1.0.0", "v2.0.0", "v1.5.0"]
        assert sort_versions(versions, "npm") == ["v1.0.0", "v1.5.0", "v2.0.0"]

    def test_prerelease(self):
        versions = ["1.0.0", "1.0.0-alpha", "1.0.0-beta"]
        result = sort_versions(versions, "npm")
        # pre-release versions sort before release
        assert result.index("1.0.0-alpha") < result.index("1.0.0")
        assert result.index("1.0.0-beta") < result.index("1.0.0")

    def test_prerelease_numeric(self):
        versions = ["1.0.0-alpha.1", "1.0.0-alpha.2", "1.0.0-alpha.10"]
        result = sort_versions(versions, "npm")
        assert result == ["1.0.0-alpha.1", "1.0.0-alpha.2", "1.0.0-alpha.10"]

    def test_major_minor_only(self):
        versions = ["1.0", "2.0", "1.5"]
        result = sort_versions(versions, "npm")
        assert result == ["1.0", "1.5", "2.0"]

    def test_major_only(self):
        versions = ["1", "3", "2"]
        result = sort_versions(versions, "npm")
        assert result == ["1", "2", "3"]


class TestGoVersionSorting:
    def test_go_semver(self):
        versions = ["v1.8.0", "v1.9.0", "v1.7.1"]
        assert sort_versions(versions, "go") == ["v1.7.1", "v1.8.0", "v1.9.0"]

    def test_go_prerelease(self):
        versions = ["v0.1.0", "v0.1.0-rc1", "v0.1.0-beta"]
        result = sort_versions(versions, "go")
        # pre-releases sort before release
        assert result.index("v0.1.0-rc1") < result.index("v0.1.0")

    def test_go_v0_vs_v1(self):
        versions = ["v0.9.0", "v1.0.0"]
        result = sort_versions(versions, "go")
        assert result == ["v0.9.0", "v1.0.0"]


class TestCargoVersionSorting:
    def test_cargo_semver(self):
        versions = ["1.0.203", "1.0.100", "1.0.204"]
        assert sort_versions(versions, "cargo") == ["1.0.100", "1.0.203", "1.0.204"]

    def test_cargo_prerelease(self):
        versions = ["1.0.0", "1.0.0-rc.1", "1.0.0-alpha.1"]
        result = sort_versions(versions, "cargo")
        assert result.index("1.0.0-alpha.1") < result.index("1.0.0")


class TestUnknownEcosystem:
    def test_falls_back_to_lexicographic(self):
        versions = ["b", "a", "c"]
        assert sort_versions(versions, "maven") == ["a", "b", "c"]


class TestPep440Key:
    def test_valid_version(self):
        key = _pep440_key("1.0.0")
        assert key[0] == 0  # valid

    def test_invalid_version(self):
        key = _pep440_key("not-valid")
        assert key[0] == 1  # invalid


class TestSemverKey:
    def test_valid_semver(self):
        key = _semver_key("1.2.3")
        assert key[0] == 0  # valid match
        assert key[1] == (1, 2, 3)

    def test_invalid_semver(self):
        key = _semver_key("not.valid.version.at.all")
        assert key[0] == 1  # no match

    def test_v_prefix_stripped(self):
        key = _semver_key("v3.0.0")
        assert key[0] == 0
        assert key[1] == (3, 0, 0)

    def test_with_build_metadata(self):
        key = _semver_key("1.0.0+build.123")
        assert key[0] == 0
        assert key[1] == (1, 0, 0)
