"""Tests for registry polling state persistence."""

import os
import tempfile

from depvet.registry.state import PollingState


def test_empty_state():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    os.unlink(path)
    try:
        state = PollingState(path)
        assert state.get("pypi") == {}
        assert state.get("npm") == {}
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_set_and_get():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    os.unlink(path)
    try:
        state = PollingState(path)
        state.set("pypi", {"serial": 12345678})
        assert state.get("pypi") == {"serial": 12345678}
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_persist_and_reload():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    os.unlink(path)
    try:
        state = PollingState(path)
        state.set("pypi", {"serial": 99999})
        state.set("npm", {"seq": "abc123", "epoch": 0})

        state2 = PollingState(path)
        assert state2.get("pypi") == {"serial": 99999}
        assert state2.get("npm") == {"seq": "abc123", "epoch": 0}
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_clear():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    os.unlink(path)
    try:
        state = PollingState(path)
        state.set("pypi", {"serial": 100})
        state.clear("pypi")
        assert state.get("pypi") == {}

        # Reload and verify cleared
        state2 = PollingState(path)
        assert state2.get("pypi") == {}
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_multiple_ecosystems():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    os.unlink(path)
    try:
        state = PollingState(path)
        state.set("pypi", {"serial": 1})
        state.set("npm", {"seq": "x"})
        state.set("go", {"modules": {"github.com/gin-gonic/gin": "v1.9.0"}})

        assert state.get("pypi")["serial"] == 1
        assert state.get("npm")["seq"] == "x"
        assert "github.com/gin-gonic/gin" in state.get("go")["modules"]
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_overwrite_same_ecosystem():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    os.unlink(path)
    try:
        state = PollingState(path)
        state.set("pypi", {"serial": 1000})
        state.set("pypi", {"serial": 2000})
        assert state.get("pypi")["serial"] == 2000
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_handles_corrupted_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("not: valid: yaml: !!!!!!")
        path = f.name
    try:
        # Should not raise, just start empty
        state = PollingState(path)
        assert state.get("pypi") == {}
    finally:
        os.unlink(path)
