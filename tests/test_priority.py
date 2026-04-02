"""Tests for priority file control."""

from depvet.differ.priority import is_priority, should_skip, priority_sort_key


def test_priority_setup_py():
    assert is_priority("setup.py") is True
    assert is_priority("some/path/setup.py") is True


def test_priority_init_py():
    assert is_priority("__init__.py") is True
    assert is_priority("depvet/__init__.py") is True


def test_priority_auth_py():
    assert is_priority("auth.py") is True
    assert is_priority("depvet/auth.py") is True


def test_not_priority():
    assert is_priority("helper.py") is False
    assert is_priority("utils/crypto.py") is False


def test_skip_test_files():
    assert should_skip("test_something.py") is True
    assert should_skip("something_test.py") is True
    assert should_skip("app.test.js") is True
    assert should_skip("app.spec.js") is True


def test_skip_docs_dir():
    assert should_skip("docs/index.rst") is True


def test_skip_changelog():
    assert should_skip("CHANGELOG.md") is True
    assert should_skip("CHANGELOG.rst") is True


def test_not_skip_normal():
    assert should_skip("depvet/analyzer.py") is False
    assert should_skip("src/main.py") is False


def test_sort_key_priority_first():
    files = ["helper.py", "setup.py", "auth.py", "utils.py"]
    sorted_files = sorted(files, key=priority_sort_key)
    # setup.py and auth.py should come before helper.py
    setup_idx = sorted_files.index("setup.py")
    helper_idx = sorted_files.index("helper.py")
    auth_idx = sorted_files.index("auth.py")
    assert setup_idx < helper_idx
    assert auth_idx < helper_idx
