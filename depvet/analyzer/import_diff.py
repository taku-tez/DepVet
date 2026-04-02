"""
Import diff analyzer: detects newly imported suspicious modules.

Why imports matter:
- A package that never used 'socket' suddenly importing it is suspicious
- The import list reveals the attack surface before reading any code
- Supply chain attacks routinely add imports alongside their payload

Attack pattern examples:
  OLD: import os, sys
  NEW: import os, sys, socket, base64  ← new suspicious imports

This runs on the diff level (added lines only), so it only flags
imports that appeared in the new version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ImportSignal:
    """A suspicious newly-imported module."""
    module: str
    alias: Optional[str]       # import X as Y
    imported_names: list[str]  # from X import a, b, c
    severity: str              # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    line_number: Optional[int] = None


# ─── Module risk tiers ────────────────────────────────────────────────────────

# CRITICAL: These modules are almost exclusively used for malicious purposes
# when added unexpectedly to a stable package
CRITICAL_MODULES = frozenset({
    "ctypes",       # arbitrary memory / DLL loading
    "cffi",         # C FFI (can load arbitrary shared libraries)
    "marshal",      # serialized bytecode (often used to hide payloads)
    "atexit",       # delayed execution at interpreter exit
})

# HIGH: Commonly used in supply chain attacks, rarely needed by most libs
HIGH_MODULES = frozenset({
    "subprocess",
    "socket",
    "base64",
    "codecs",
    "zlib",
    "gzip",
    "threading",
    "multiprocessing",
    "importlib",
    "imp",
    "pickle",
    "shelve",
    "xmlrpc",       # can be C2
})

# MEDIUM: Suspicious when added without obvious reason
MEDIUM_MODULES = frozenset({
    "urllib",
    "urllib.request",
    "urllib.parse",
    "http",
    "http.client",
    "requests",
    "httpx",
    "aiohttp",
    "websocket",
    "websockets",
    "tempfile",
    "shutil",      # can copy/delete files
    "glob",
    "fnmatch",
    "ssl",         # might be for custom cert validation bypass
})

# HIGH-risk names imported FROM a module (e.g., "from subprocess import Popen")
HIGH_FROM_NAMES = frozenset({
    "Popen", "run", "call", "check_output", "check_call",  # subprocess
    "system", "popen", "execvp", "execvpe",                # os
    "urlopen", "Request", "urlretrieve",                   # urllib
    "b64decode", "b64encode", "decodebytes",               # base64
    "exec_module", "import_module",                        # importlib
    "exec_", "execute",                                    # generic
})

# ─── Import parsing ───────────────────────────────────────────────────────────

_IMPORT_RE = re.compile(
    r"^\s*import\s+([\w.,\s]+?)(?:\s+as\s+(\w+))?\s*$"
)
_FROM_IMPORT_RE = re.compile(
    r"^\s*from\s+([\w.]+)\s+import\s+(.+)"
)


def _parse_import_line(line: str) -> Optional[tuple[str, Optional[str], list[str]]]:
    """
    Parse an import line. Returns (module, alias, imported_names) or None.

    Handles:
      import os
      import os as operating_system
      from os import path, getcwd
      from os import (path, getcwd)
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # "import X" or "import X as Y"
    m = _IMPORT_RE.match(line)
    if m:
        modules_str = m.group(1)
        alias = m.group(2)
        # Handle "import os, sys, base64"
        modules = [mod.strip() for mod in modules_str.split(",") if mod.strip()]
        # Return the first suspicious one (will iterate in caller)
        return (modules[0], alias, [])

    # "from X import a, b, c"
    m = _FROM_IMPORT_RE.match(line)
    if m:
        module = m.group(1).strip()
        names_str = m.group(2).strip().strip("()")
        names = [n.strip() for n in names_str.split(",") if n.strip() and n.strip() != "*"]
        return (module, None, names)

    return None


def _module_severity(module: str, imported_names: list[str]) -> Optional[tuple[str, str]]:
    """
    Return (severity, description) for a module, or None if not suspicious.
    """
    root = module.split(".")[0]

    if module in CRITICAL_MODULES or root in CRITICAL_MODULES:
        return ("CRITICAL", f"危険度の高いモジュール '{module}' が新たにインポートされた（攻撃コードでよく使われる）")

    # Check specific high-risk names from import
    if imported_names:
        suspicious_names = [n for n in imported_names if n in HIGH_FROM_NAMES]
        if suspicious_names:
            return ("HIGH", f"危険な名前 {suspicious_names} が '{module}' からインポートされた")

    if module in HIGH_MODULES or root in HIGH_MODULES:
        return ("HIGH", f"不審なモジュール '{module}' が新たにインポートされた")

    if module in MEDIUM_MODULES or root in MEDIUM_MODULES:
        return ("MEDIUM", f"ネットワーク/外部通信モジュール '{module}' が新たにインポートされた")

    return None


# ─── Main function ────────────────────────────────────────────────────────────

def analyze_imports(diff_content: str) -> list[ImportSignal]:
    """
    Analyze import statements in diff added lines.

    Returns ImportSignal for each newly-imported suspicious module.
    """
    signals: list[ImportSignal] = []
    seen_modules: set[str] = set()

    current_line = 0

    for raw_line in diff_content.splitlines():
        if raw_line.startswith("@@"):
            m = re.search(r"\+(\d+)", raw_line)
            if m:
                current_line = int(m.group(1)) - 1
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_line += 1
            line = raw_line[1:]

            parsed = _parse_import_line(line)
            if not parsed:
                continue

            module, alias, imported_names = parsed

            # Handle multi-module "import os, sys, base64" by re-parsing
            if "," in raw_line[1:] and not raw_line[1:].strip().startswith("from"):
                # Multiple imports on one line
                parts = raw_line[1:].replace("import", "").split(",")
                for part in parts:
                    mod = part.strip().split(" as ")[0].strip()
                    if mod and mod not in seen_modules:
                        result = _module_severity(mod, [])
                        if result:
                            sev, desc = result
                            signals.append(ImportSignal(
                                module=mod,
                                alias=None,
                                imported_names=[],
                                severity=sev,
                                description=desc,
                                line_number=current_line,
                            ))
                            seen_modules.add(mod)
                continue

            if module in seen_modules:
                continue
            seen_modules.add(module)

            result = _module_severity(module, imported_names)
            if result:
                sev, desc = result
                signals.append(ImportSignal(
                    module=module,
                    alias=alias,
                    imported_names=imported_names,
                    severity=sev,
                    description=desc,
                    line_number=current_line,
                ))

    return signals


def import_signals_to_context(signals: list[ImportSignal]) -> str:
    """Format import signals as a text block for LLM context."""
    if not signals:
        return ""
    lines = ["【新規インポート検出】"]
    for s in signals:
        icon = "🚨" if s.severity == "CRITICAL" else "⚠️" if s.severity == "HIGH" else "🔶"
        lines.append(f"{icon} [{s.severity}] {s.module}: {s.description}")
    return "\n".join(lines)
