"""Rule-based pre-screening for high-confidence malicious patterns.

This runs BEFORE LLM analysis and can:
1. Immediately flag obvious malware (base64+exec combos, hardcoded IPs)
2. Skip LLM for clearly benign diffs (doc/comment-only changes)
3. Prioritize chunks containing high-risk patterns

All patterns are based on real-world malicious packages found in the wild.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from depvet.models.verdict import FindingCategory, Severity


@dataclass
class RuleMatch:
    rule_id: str
    category: FindingCategory
    severity: Severity
    description: str
    evidence: str
    file: str
    line_number: Optional[int] = None
    cwe: Optional[str] = None


# ─── Regex patterns (applied to added lines in diff) ──────────────────────

MALICIOUS_PATTERNS: list[dict] = [
    # base64 + exec/eval combo (most common attack vector)
    {
        "id": "EXEC_BASE64",
        "pattern": re.compile(
            r"(exec|eval)\s*\(\s*(base64|b64decode|decode)\s*\(",
            re.IGNORECASE,
        ),
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.CRITICAL,
        "description": "base64デコード後にexec/evalで実行するコードが追加された",
        "cwe": "CWE-506",
    },
    # base64 decode + compile/exec pattern (split across lines)
    {
        "id": "BASE64_DECODE_EXEC",
        "pattern": re.compile(
            r"base64\.(b64decode|decodebytes|decodestring)\s*\(",
            re.IGNORECASE,
        ),
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.HIGH,
        "description": "base64デコード処理が追加された（実行コードの隠蔽に使われる可能性）",
        "cwe": "CWE-506",
    },
    # Hardcoded non-RFC1918 IP address in networking context
    {
        "id": "HARDCODED_IP",
        "pattern": re.compile(
            r"""["'](?:https?://)?(?:[a-z]+://)?"""
            r"""((?!(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168|127|0|255)\.))"""
            r"""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.NETWORK,
        "severity": Severity.CRITICAL,
        "description": "非プライベートIPアドレスへのハードコード接続が追加された",
        "cwe": "CWE-913",
    },
    # Environment variable exfiltration
    {
        "id": "ENV_EXFIL",
        "pattern": re.compile(
            r"""os\.(environ|getenv)\s*[.\[(].*?(?:KEY|SECRET|TOKEN|PASSWORD|PASS|PWD|CRED|API)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "認証情報に関わる環境変数の読み取りが追加された",
        "cwe": "CWE-200",
    },
    # AWS credential access
    {
        "id": "AWS_CREDS",
        "pattern": re.compile(
            r"""os\.(environ|getenv).*?(?:AWS_|aws_)(?:SECRET|ACCESS|DEFAULT)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "AWSクレデンシャルを読み取るコードが追加された",
        "cwe": "CWE-200",
    },
    # SSH key access
    {
        "id": "SSH_KEY_ACCESS",
        "pattern": re.compile(
            r"""(?:open|read|load)\s*\(.*?(?:\.ssh|id_rsa|id_ed25519|authorized_keys)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "SSH鍵ファイルへのアクセスが追加された",
        "cwe": "CWE-200",
    },
    # subprocess shell execution in setup
    {
        "id": "SUBPROCESS_SHELL",
        "pattern": re.compile(
            r"""subprocess\.(call|run|Popen|check_output)\s*\(.*?shell\s*=\s*True""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "subprocess shell=Trueによるシェルコマンド実行が追加された",
        "cwe": "CWE-78",
    },
    # os.system execution
    {
        "id": "OS_SYSTEM",
        "pattern": re.compile(r"""os\.system\s*\(""", re.IGNORECASE),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "os.systemによるシェルコマンド実行が追加された",
        "cwe": "CWE-78",
    },
    # HTTP request to non-standard endpoints (C2 pattern)
    {
        "id": "SUSPICIOUS_HTTP",
        "pattern": re.compile(
            r"""(?:urllib|requests|httpx|aiohttp|http\.client).*?(?:get|post|put|open)\s*\(.*?http[s]?://(?!(?:pypi\.org|npmjs\.com|github\.com|api\.github\.com|files\.pythonhosted\.org|registry\.npmjs\.org))""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.NETWORK,
        "severity": Severity.MEDIUM,
        "description": "既知サービス以外へのHTTPリクエストが追加された",
        "cwe": "CWE-913",
    },
    # Discord webhook (common exfil channel)
    {
        "id": "DISCORD_WEBHOOK",
        "pattern": re.compile(
            r"""discord(?:app)?\.com/api/webhooks/""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.HIGH,
        "description": "Discord Webhookへのデータ送信が検出された（情報窃取によく使われる）",
        "cwe": "CWE-200",
    },
    # Telegram bot API (common exfil channel)
    {
        "id": "TELEGRAM_BOT",
        "pattern": re.compile(
            r"""api\.telegram\.org/bot""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.HIGH,
        "description": "Telegram Bot APIへのデータ送信が検出された（情報窃取によく使われる）",
        "cwe": "CWE-200",
    },
    # Dynamic import (potential code loading)
    {
        "id": "DYNAMIC_IMPORT",
        "pattern": re.compile(
            r"""__import__\s*\(|importlib\.import_module\s*\(""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.MEDIUM,
        "description": "動的インポートが追加された（実行時コードロードの可能性）",
        "cwe": "CWE-913",
    },
    # postinstall / setup hooks
    {
        "id": "SETUP_HOOK",
        "pattern": re.compile(
            r"""(?:postinstall|preinstall|install_requires|cmdclass|entry_points).*?(?:subprocess|os\.system|exec|eval)""",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.BUILD_HOOK_ABUSE,
        "severity": Severity.HIGH,
        "description": "パッケージインストール時に実行されるフックにコード実行が追加された",
        "cwe": "CWE-829",
    },
    # Crypto miner patterns (xmrig, monero)
    {
        "id": "CRYPTO_MINER",
        "pattern": re.compile(
            r"""(?:xmrig|monero|stratum\+tcp|cryptonight|nicehash)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.CRITICAL,
        "description": "暗号通貨マイナーのパターンが検出された",
        "cwe": "CWE-400",
    },
    # urllib.request with external URL (common in PyPI malware)
    {
        "id": "URLLIB_EXTERNAL",
        "pattern": re.compile(
            r"""urllib\.request\.(urlopen|Request|urlretrieve)\s*\(""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.NETWORK,
        "severity": Severity.MEDIUM,
        "description": "urllib.requestによる外部通信が追加された",
        "cwe": "CWE-913",
    },
    # Direct IP connection via socket
    {
        "id": "SOCKET_CONNECT_IP",
        "pattern": re.compile(
            r"""socket.*?connect\s*\(\s*\(\s*["']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["']""",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.NETWORK,
        "severity": Severity.CRITICAL,
        "description": "IPアドレスへの直接ソケット接続が追加された",
        "cwe": "CWE-913",
    },
    # Reverse shell patterns
    {
        "id": "REVERSE_SHELL",
        "pattern": re.compile(
            r"""(?:bash\s+-i|/dev/tcp/|nc\s+-e|ncat\s+-e|socat\s+exec)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.CRITICAL,
        "description": "リバースシェルのパターンが検出された",
        "cwe": "CWE-78",
    },
]

# Patterns that suggest a diff is likely benign (skip LLM)
BENIGN_INDICATORS = [
    re.compile(r"^[+\-]\s*#", re.MULTILINE),          # comment changes
    re.compile(r"^[+\-]\s*\"\"\"", re.MULTILINE),      # docstring changes
    re.compile(r"^[+\-]\s*version\s*=", re.MULTILINE), # version bumps
    re.compile(r"^[+\-]\s*__version__", re.MULTILINE), # version string
]

BENIGN_ONLY_PATTERNS = [
    # All changes are comments, docstrings, or version strings
    re.compile(r"^[+\-]", re.MULTILINE),
]


def scan_diff(diff_content: str, filepath: str = "") -> list[RuleMatch]:
    """
    Scan a diff for high-confidence malicious patterns.
    Only scans added lines (starting with '+').
    """
    matches: list[RuleMatch] = []
    added_lines: list[tuple[int, str]] = []

    current_line = 0
    for line in diff_content.splitlines():
        if line.startswith("@@"):
            # Parse line number from hunk header: @@ -a,b +c,d @@
            m = re.search(r"\+(\d+)", line)
            if m:
                current_line = int(m.group(1)) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            current_line += 1
            added_lines.append((current_line, line[1:]))
        elif not line.startswith("-"):
            current_line += 1

    # Scan added content
    added_content = "\n".join(l for _, l in added_lines)

    for pattern_def in MALICIOUS_PATTERNS:
        for m in pattern_def["pattern"].finditer(added_content):
            # Find which line this match is on
            line_num = added_content[:m.start()].count("\n") + 1
            actual_line = added_lines[line_num - 1][0] if line_num <= len(added_lines) else None

            evidence = m.group(0)[:50]

            # Avoid duplicate matches for same rule+line
            existing = any(
                r.rule_id == pattern_def["id"] and r.line_number == actual_line
                for r in matches
            )
            if not existing:
                matches.append(RuleMatch(
                    rule_id=pattern_def["id"],
                    category=pattern_def["category"],
                    severity=pattern_def["severity"],
                    description=pattern_def["description"],
                    evidence=evidence,
                    file=filepath,
                    line_number=actual_line,
                    cwe=pattern_def.get("cwe"),
                ))

    return matches


def is_likely_benign(diff_content: str) -> bool:
    """
    Quick check if a diff is likely benign (docs/comments/version only).
    Used to skip LLM triage for obviously safe changes.
    """
    added_lines = [
        line[1:].strip()
        for line in diff_content.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    if not added_lines:
        return True

    benign_count = sum(
        1 for line in added_lines
        if not line or line.startswith("#") or line.startswith('"""') or
        line.startswith("'''") or re.match(r"^version\s*=", line, re.IGNORECASE) or
        re.match(r"^__version__", line) or re.match(r"^#", line)
    )
    return benign_count / len(added_lines) > 0.9
