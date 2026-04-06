"""Tests for depvet.watchlist.explicit — ExplicitSource and WatchlistEntry."""

from __future__ import annotations

from depvet.watchlist.explicit import ExplicitSource, WatchlistEntry


class TestWatchlistEntry:
    def test_defaults(self):
        entry = WatchlistEntry(name="requests", ecosystem="pypi")
        assert entry.name == "requests"
        assert entry.ecosystem == "pypi"
        assert entry.current_version == ""

    def test_with_version(self):
        entry = WatchlistEntry(name="lodash", ecosystem="npm", current_version="4.17.21")
        assert entry.current_version == "4.17.21"


class TestExplicitSource:
    def test_add_and_entries(self):
        src = ExplicitSource()
        src.add("requests", "pypi")
        src.add("flask", "pypi")
        assert len(src.entries()) == 2
        names = {e.name for e in src.entries()}
        assert "requests" in names
        assert "flask" in names

    def test_add_deduplicates(self):
        src = ExplicitSource()
        src.add("requests", "pypi")
        src.add("requests", "pypi")
        assert len(src.entries()) == 1

    def test_same_name_different_ecosystem_allowed(self):
        src = ExplicitSource()
        src.add("debug", "npm")
        src.add("debug", "pypi")
        assert len(src.entries()) == 2

    def test_default_ecosystem_is_pypi(self):
        src = ExplicitSource()
        src.add("requests")
        assert src.entries()[0].ecosystem == "pypi"

    def test_remove_existing(self):
        src = ExplicitSource()
        src.add("requests", "pypi")
        assert src.remove("requests", "pypi") is True
        assert len(src.entries()) == 0

    def test_remove_nonexistent(self):
        src = ExplicitSource()
        assert src.remove("requests", "pypi") is False

    def test_remove_does_not_affect_other_ecosystems(self):
        src = ExplicitSource()
        src.add("debug", "npm")
        src.add("debug", "pypi")
        src.remove("debug", "npm")
        assert len(src.entries()) == 1
        assert src.entries()[0].ecosystem == "pypi"

    def test_entries_filter_by_ecosystem(self):
        src = ExplicitSource()
        src.add("requests", "pypi")
        src.add("lodash", "npm")
        src.add("flask", "pypi")

        pypi = src.entries("pypi")
        assert len(pypi) == 2
        assert all(e.ecosystem == "pypi" for e in pypi)

        npm = src.entries("npm")
        assert len(npm) == 1
        assert npm[0].name == "lodash"

    def test_entries_none_returns_all(self):
        src = ExplicitSource()
        src.add("requests", "pypi")
        src.add("lodash", "npm")
        assert len(src.entries(None)) == 2
        assert len(src.entries()) == 2

    def test_as_set(self):
        src = ExplicitSource()
        src.add("requests", "pypi")
        src.add("flask", "pypi")
        src.add("lodash", "npm")
        s = src.as_set("pypi")
        assert s == {"requests", "flask"}
        assert src.as_set("npm") == {"lodash"}
        assert src.as_set("cargo") == set()

    def test_load_from_file(self, tmp_path):
        f = tmp_path / "packages.txt"
        f.write_text("requests\nflask\n# comment\n\nnumpy\n")
        src = ExplicitSource()
        count = src.load_from_file(str(f), "pypi")
        assert count == 3
        names = {e.name for e in src.entries()}
        assert names == {"requests", "flask", "numpy"}

    def test_load_from_file_skips_comments_and_blanks(self, tmp_path):
        f = tmp_path / "packages.txt"
        f.write_text("# This is a comment\n\n  \nrequests\n")
        src = ExplicitSource()
        count = src.load_from_file(str(f), "pypi")
        assert count == 1

    def test_save_to_file(self, tmp_path):
        f = tmp_path / "saved.txt"
        src = ExplicitSource()
        src.add("flask", "pypi")
        src.add("requests", "pypi")
        src.save_to_file(str(f), "pypi")
        content = f.read_text()
        lines = content.strip().split("\n")
        assert sorted(lines) == ["flask", "requests"]

    def test_save_only_matching_ecosystem(self, tmp_path):
        f = tmp_path / "saved.txt"
        src = ExplicitSource()
        src.add("requests", "pypi")
        src.add("lodash", "npm")
        src.save_to_file(str(f), "pypi")
        content = f.read_text()
        assert "requests" in content
        assert "lodash" not in content

    def test_load_from_file_dedup_count(self, tmp_path):
        """[Finding 6] load_from_file must return newly added count, not total lines."""
        f = tmp_path / "packages.txt"
        f.write_text("requests\nflask\n")
        src = ExplicitSource()
        count1 = src.load_from_file(str(f), "pypi")
        assert count1 == 2
        # Loading same file again should return 0 (all duplicates)
        count2 = src.load_from_file(str(f), "pypi")
        assert count2 == 0
        assert len(src.entries()) == 2

    def test_load_from_file_partial_dedup(self, tmp_path):
        """Partial overlap: only new packages counted."""
        f1 = tmp_path / "p1.txt"
        f1.write_text("requests\nflask\n")
        f2 = tmp_path / "p2.txt"
        f2.write_text("flask\nnumpy\n")
        src = ExplicitSource()
        assert src.load_from_file(str(f1), "pypi") == 2
        assert src.load_from_file(str(f2), "pypi") == 1  # only numpy is new
        assert len(src.entries()) == 3

    def test_load_and_save_roundtrip(self, tmp_path):
        f = tmp_path / "packages.txt"
        f.write_text("alpha\nbeta\ngamma\n")
        src = ExplicitSource()
        src.load_from_file(str(f), "pypi")

        out = tmp_path / "output.txt"
        src.save_to_file(str(out), "pypi")
        content = out.read_text().strip().split("\n")
        assert sorted(content) == ["alpha", "beta", "gamma"]
