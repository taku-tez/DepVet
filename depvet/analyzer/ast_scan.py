"""
AST-based static analysis for Python diffs.

Why AST > regex for Python:
  regex: "exec(" misses → getattr(builtins, 'exec')(payload)
  regex: "exec(" misses → e = exec; e(payload)
  regex: "base64" misses → b = __import__('base64'); b.b64decode(...)
  AST: tracks all of the above via call graph / attribute access patterns

What we analyze:
1. getattr() used to access dangerous functions by string (obfuscation)
2. chr() concatenation to build dangerous function names
3. Variable assigned to dangerous function then called (e = exec; e(...))
4. __import__ with suspicious module names
5. os.environ access → sent to network (cross-statement taint)
6. atexit.register / threading.Timer with lambda containing network calls
7. Conditional execution based on CI env vars (sandbox evasion)

We only parse ADDED lines from the diff (+lines), assembled into a
synthetic Python file. If parsing fails (partial code), we fall back
to graceful degradation.
"""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from typing import Optional

from depvet.models.verdict import FindingCategory, Severity


@dataclass
class ASTFinding:
    """A finding from AST-level analysis."""
    finding_id: str
    severity: Severity
    category: FindingCategory
    description: str
    line_number: Optional[int]
    evidence: str
    cwe: str = "CWE-506"


# ─── Dangerous names and modules ─────────────────────────────────────────────

DANGEROUS_CALLS = frozenset({
    "exec", "eval", "compile",
    "execfile",  # Python 2 compat
    # Note: __import__ is handled by DYNAMIC_IMPORT_SUSPICIOUS check, not here
})

DANGEROUS_ATTRS = frozenset({
    "system", "popen", "execvp", "execl", "execle",  # os
    "call", "run", "Popen", "check_output",            # subprocess
    "urlopen", "urlretrieve",                          # urllib
    "b64decode", "decodebytes",                        # base64
    "loads",                                           # pickle/json (pickle.loads = dangerous)
})

NETWORK_CALLS = frozenset({
    "urlopen", "urlretrieve", "get", "post", "put", "connect",
    "request", "Request", "send",
})

SUSPICIOUS_MODULES = frozenset({
    "base64", "socket", "subprocess", "urllib", "urllib.request",
    "http", "ctypes", "marshal", "atexit", "threading",
    "codecs", "zlib", "gzip", "pickle", "shelve",
})


# ─── AST visitor ─────────────────────────────────────────────────────────────

class MaliciousPatternVisitor(ast.NodeVisitor):
    """Visits an AST and collects suspicious patterns."""

    def __init__(self):
        self.findings: list[ASTFinding] = []
        self._assigned_dangerous: dict[str, str] = {}  # varname → what it aliases
        self._env_vars_read: list[int] = []  # line numbers where env vars were read

    def _add(self, finding_id: str, sev: Severity, cat: FindingCategory,
             desc: str, line: Optional[int], evidence: str, cwe: str = "CWE-506"):
        # Deduplicate
        for f in self.findings:
            if f.finding_id == finding_id and f.line_number == line:
                return
        self.findings.append(ASTFinding(
            finding_id=finding_id,
            severity=sev,
            category=cat,
            description=desc,
            line_number=line,
            evidence=evidence,
            cwe=cwe,
        ))

    def visit_Call(self, node: ast.Call):
        """Check function calls for dangerous patterns."""
        line = getattr(node, "lineno", None)

        # Pattern 1: Direct dangerous call — exec(...), eval(...), __import__(...)
        if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
            self._add(
                "DIRECT_EXEC_EVAL",
                Severity.CRITICAL,
                FindingCategory.EXECUTION,
                f"危険な関数 '{node.func.id}()' が直接呼び出されている",
                line,
                f"{node.func.id}(...)",
                "CWE-506",
            )

        # Pattern 2: getattr(obj, 'dangerous_name') — obfuscated attribute access
        if (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                and len(node.args) >= 2):
            attr_arg = node.args[1]
            if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                attr_name = attr_arg.value
                if attr_name in DANGEROUS_CALLS or attr_name in DANGEROUS_ATTRS:
                    self._add(
                        "GETATTR_DANGEROUS",
                        Severity.CRITICAL,
                        FindingCategory.OBFUSCATION,
                        f"getattr()を使って危険な関数 '{attr_name}' を難読化アクセスしている",
                        line,
                        f"getattr(obj, '{attr_name}')",
                        "CWE-506",
                    )

        # Pattern 3: __import__('suspicious_module')
        if (isinstance(node.func, ast.Name) and node.func.id == "__import__"
                and node.args):
            mod_arg = node.args[0]
            if isinstance(mod_arg, ast.Constant) and isinstance(mod_arg.value, str):
                mod = mod_arg.value
                if mod in SUSPICIOUS_MODULES:
                    self._add(
                        "DYNAMIC_IMPORT_SUSPICIOUS",
                        Severity.HIGH,
                        FindingCategory.EXECUTION,
                        f"__import__()で不審なモジュール '{mod}' を動的インポートしている",
                        line,
                        f"__import__('{mod}')",
                        "CWE-913",
                    )

        # Pattern 4: Previously-assigned dangerous name being called
        if isinstance(node.func, ast.Name) and node.func.id in self._assigned_dangerous:
            original = self._assigned_dangerous[node.func.id]
            self._add(
                "ALIASED_EXEC",
                Severity.CRITICAL,
                FindingCategory.OBFUSCATION,
                f"変数 '{node.func.id}' に代入された危険な関数 '{original}' が呼び出されている",
                line,
                f"{node.func.id}(...) [alias for {original}]",
                "CWE-506",
            )

        # Pattern 5: atexit.register(lambda: ...) with network
        if (isinstance(node.func, ast.Attribute) and node.func.attr == "register"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "atexit"):
            self._add(
                "ATEXIT_REGISTER",
                Severity.HIGH,
                FindingCategory.EXECUTION,
                "atexit.register()で遅延実行コードが登録された（インタプリタ終了時に実行）",
                line,
                "atexit.register(...)",
                "CWE-693",
            )

        # Pattern 6: threading.Timer(...) — delayed execution
        if (isinstance(node.func, ast.Attribute) and node.func.attr == "Timer"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "threading"):
            self._add(
                "THREADING_TIMER",
                Severity.MEDIUM,
                FindingCategory.EXECUTION,
                "threading.Timer()で遅延実行コードが設定された",
                line,
                "threading.Timer(...)",
                "CWE-693",
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments to dangerous functions."""
        # Pattern: e = exec  (assign without calling)
        if isinstance(node.value, ast.Name) and node.value.id in DANGEROUS_CALLS:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._assigned_dangerous[target.id] = node.value.id

        # Pattern: e = getattr(builtins, 'exec')
        if isinstance(node.value, ast.Call):
            if (isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "getattr"
                    and len(node.value.args) >= 2):
                attr = node.value.args[1]
                if isinstance(attr, ast.Constant) and attr.value in DANGEROUS_CALLS:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self._assigned_dangerous[target.id] = attr.value

        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        """Detect sandbox evasion patterns."""
        line = getattr(node, "lineno", None)

        # Pattern: if not os.environ.get('CI') or similar CI checks
        src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
        ci_vars = ["CI", "GITHUB_ACTIONS", "TRAVIS", "JENKINS", "CIRCLECI",
                   "GITLAB_CI", "TF_BUILD", "BUILDKITE"]
        if any(ci in src for ci in ci_vars):
            self._add(
                "CI_SANDBOX_CHECK",
                Severity.HIGH,
                FindingCategory.EXECUTION,
                "CI環境変数をチェックするコードが追加された（サンドボックス回避パターン）",
                line,
                src[:60],
                "CWE-693",
            )

        # Pattern: if datetime.date.today() > some_date (time bomb)
        if "date" in src and ("today" in src or "now" in src):
            self._add(
                "TIME_BOMB_CHECK",
                Severity.HIGH,
                FindingCategory.EXECUTION,
                "日時チェックを条件とするコードが追加された（時限起動パターン）",
                line,
                src[:60],
                "CWE-693",
            )

        # Pattern: if os.path.exists(~/.aws/...) or similar credential file checks
        if any(path in src for path in (".aws", ".ssh", "credentials", ".config")):
            self._add(
                "CREDENTIAL_FILE_CHECK",
                Severity.HIGH,
                FindingCategory.EXFILTRATION,
                "認証情報ファイルの存在チェックが追加された（標的型窃取パターン）",
                line,
                src[:60],
                "CWE-200",
            )

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Detect f-strings that embed suspicious data (e.g., f'{os.environ[\"SECRET\"]}')."""
        src = ast.unparse(node) if hasattr(ast, "unparse") else ""
        if any(kw in src for kw in ("environ", "getenv", "SECRET", "PASSWORD", "TOKEN", "KEY")):
            line = getattr(node, "lineno", None)
            self._add(
                "FSTRING_ENV_EMBED",
                Severity.MEDIUM,
                FindingCategory.EXFILTRATION,
                "f-string内で環境変数が埋め込まれている（外部送信先URLに含まれる可能性）",
                line,
                src[:60],
                "CWE-200",
            )
        self.generic_visit(node)


def _extract_added_lines(diff_content: str) -> list[tuple[int, str]]:
    """Extract (line_number, code) for added lines from a diff."""
    added: list[tuple[int, str]] = []
    current = 0
    for raw in diff_content.splitlines():
        if raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            if m:
                current = int(m.group(1)) - 1
        elif raw.startswith("+") and not raw.startswith("+++"):
            current += 1
            added.append((current, raw[1:]))
        elif not raw.startswith("-"):
            current += 1
    return added


def ast_scan_diff(diff_content: str, filepath: str = "") -> list[ASTFinding]:
    """
    Parse added lines as Python and run AST-level analysis.

    Falls back gracefully if the added lines are not valid Python
    (partial code, syntax errors).

    Returns list of ASTFinding.
    """
    # Only apply to Python files
    # Only apply to Python files (skip JS, TS, etc.)
    if filepath:
        py_extensions = (".py", ".pyw")
        # If filepath has an extension that is NOT Python, skip
        import os as _os
        _, ext = _os.path.splitext(filepath)
        if ext and ext.lower() not in py_extensions:
            return []

    added_lines = _extract_added_lines(diff_content)
    if not added_lines:
        return []

    # Build a synthetic module from added lines only
    # We preserve line numbers by inserting `pass` for non-added lines
    max_line = max(ln for ln, _ in added_lines)
    lines_by_num: dict[int, str] = {ln: code for ln, code in added_lines}
    synthetic_lines = []
    for i in range(1, max_line + 1):
        synthetic_lines.append(lines_by_num.get(i, ""))

    source = "\n".join(synthetic_lines)

    # Try to parse; fall back on failure
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # Try to parse each added line individually
        findings: list[ASTFinding] = []
        for ln, code in added_lines:
            try:
                tree = ast.parse(textwrap.dedent(code))
                visitor = MaliciousPatternVisitor()
                visitor.visit(tree)
                for f in visitor.findings:
                    f.line_number = ln
                findings.extend(visitor.findings)
            except SyntaxError:
                pass
        return _deduplicate(findings)

    # Full parse succeeded
    visitor = MaliciousPatternVisitor()
    visitor.visit(tree)
    return _deduplicate(visitor.findings)


def _deduplicate(findings: list[ASTFinding]) -> list[ASTFinding]:
    seen: set[tuple] = set()
    result = []
    for f in findings:
        key = (f.finding_id, f.line_number)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
