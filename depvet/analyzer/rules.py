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
from depvet.analyzer.extended_rules import EXTENDED_PATTERNS as _EXTENDED


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
        "severity": Severity.LOW,
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
            r"""socket\b.*?connect\s*\(\s*\(\s*["']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["']""",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.NETWORK,
        "severity": Severity.CRITICAL,
        "description": "IPアドレスへの直接ソケット接続が追加された",
        "cwe": "CWE-913",
    },
    # npm install hooks (postinstall/preinstall/install with code execution)
    {
        "id": "NPM_INSTALL_HOOK",
        "pattern": re.compile(
            r'"(?:postinstall|preinstall|install)"\s*:\s*"(?:node\s+-e|nodejs\s+-e|sh\s+-c|bash\s+-c|python\s+-c)',
            re.IGNORECASE,
        ),
        "category": FindingCategory.BUILD_HOOK_ABUSE,
        "severity": Severity.CRITICAL,
        "description": "package.jsonのインストールフックに直接コード実行コマンドが設定された",
        "cwe": "CWE-829",
    },
    # CI/Sandbox evasion: check for CI env vars before executing
    {
        "id": "CI_EVASION",
        "pattern": re.compile(
            r"""os\.(environ|getenv)\s*[.(].*?(?:CI|GITHUB_ACTIONS|TRAVIS|JENKINS|CIRCLECI|GITLAB_CI|BUILDKITE)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "CI環境変数をチェックするコードが追加された（サンドボックス回避の典型パターン）",
        "cwe": "CWE-693",
    },
    # Time bomb: conditional execution based on date
    {
        "id": "TIME_BOMB",
        "pattern": re.compile(
            r"""datetime\.date\.today\(\)|datetime\.datetime\.now\(\)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.MEDIUM,
        "description": "日時チェックを含むコードが追加された（時限起動パターンの可能性）",
        "cwe": "CWE-693",
    },
    # atexit delayed execution
    {
        "id": "ATEXIT_DELAYED",
        "pattern": re.compile(r"""atexit\.register\s*\(""", re.IGNORECASE),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "atexit.register()による遅延実行が追加された（インタプリタ終了時に実行）",
        "cwe": "CWE-693",
    },
    # Credential file check (targeted attack pattern)
    {
        "id": "CREDENTIAL_PATH_CHECK",
        "pattern": re.compile(
            r"""os\.path\.(exists|isfile|expanduser)\s*\(.*?(?:\.aws|\.ssh|credentials|id_rsa)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.HIGH,
        "description": "認証情報ファイルパスの存在確認が追加された（標的型攻撃パターン）",
        "cwe": "CWE-200",
    },
    # getattr obfuscation
    {
        "id": "GETATTR_EXEC",
        "pattern": re.compile(
            r"""getattr\s*\(.*?['"](exec|eval|system|popen|urlopen|b64decode)['"]\s*\)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.CRITICAL,
        "description": "getattr()を使って危険な関数に難読化アクセスしている",
        "cwe": "CWE-506",
    },
    # chr() concatenation to build exec/eval
    {
        "id": "CHR_CONCAT_EXEC",
        "pattern": re.compile(
            r"""chr\s*\(\d+\)\s*\+\s*chr\s*\(\d+\)""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.HIGH,
        "description": "chr()連結による文字列難読化が検出された（exec/evalなどの関数名隠蔽に使われる）",
        "cwe": "CWE-506",
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
    # ── Type 5: Intentional sabotage patterns ─────────────────────────────────
    # Mass file destruction: glob/walk + write/delete (node-ipc/peacenotwar)
    {
        "id": "MASS_FILE_OVERWRITE",
        "pattern": re.compile(
            r"(?:glob\.sync|readdirSync|fs\.readdir|os\.walk|glob\()"
            r".{0,200}"
            r"(?:writeFileSync|write_text|\.write\s*\(|fs\.unlink|os\.remove)",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.CRITICAL,
        "description": "ファイル一覧取得と一括書込み/削除の組み合わせが検出された（ファイル大量破壊パターン）",
        "cwe": "CWE-732",
    },
    # IP/CIDR-based conditional destruction (node-ipc)
    {
        "id": "IP_BASED_CONDITIONAL_EXEC",
        "pattern": re.compile(
            r"(?:cidr|ipaddr|ip\.address\(\)|geoip|ipinfo\.io)"
            r".{0,200}"
            r"(?:exec|writeFile|unlink|rmdir|system\()",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.CRITICAL,
        "description": "IPアドレス判定と処理実行の組み合わせが検出された（地理的条件付き破壊パターン）",
        "cwe": "CWE-693",
    },
    # Overwriting files with peace/political string (peacenotwar style)
    {
        "id": "POLITICAL_STRING_OVERWRITE",
        "pattern": re.compile(
            r"(?:writeFileSync|write_text|open\(.+['\"]w['\"])"
            r"[^)]{0,100}"
            r"(?:peace|PEACE|NO WAR|love|heart)",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "政治的メッセージによるファイル上書きパターンが検出された（peacenotwar型破壊）",
        "cwe": "CWE-732",
    },
    # unconditional non-zero process.exit (crash injection)
    {
        "id": "CRASH_INJECTION",
        "pattern": re.compile(
            r"(?:process\.exit|sys\.exit|os\._exit)\s*\(\s*[1-9]",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.MEDIUM,
        "description": "非ゼロ終了コードでのプロセス強制終了が追加された（クラッシュ注入の可能性）",
        "cwe": "CWE-400",
    },
] + _EXTENDED  # Type 7/8/10 patterns

# Patterns that suggest a diff is likely benign (skip LLM)
BENIGN_INDICATORS = [
    re.compile(r"^[+\-]\s*#", re.MULTILINE),  # comment changes
    re.compile(r"^[+\-]\s*\"\"\"", re.MULTILINE),  # docstring changes
    re.compile(r"^[+\-]\s*version\s*=", re.MULTILINE),  # version bumps
    re.compile(r"^[+\-]\s*__version__", re.MULTILINE),  # version string
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
    added_content = "\n".join(line for _, line in added_lines)

    for pattern_def in MALICIOUS_PATTERNS:
        for m in pattern_def["pattern"].finditer(added_content):
            # Find which line this match is on
            line_num = added_content[: m.start()].count("\n") + 1
            actual_line = added_lines[line_num - 1][0] if line_num <= len(added_lines) else None

            evidence = m.group(0)[:50]

            # Avoid duplicate matches for same rule+line
            existing = any(r.rule_id == pattern_def["id"] and r.line_number == actual_line for r in matches)
            if not existing:
                matches.append(
                    RuleMatch(
                        rule_id=pattern_def["id"],
                        category=pattern_def["category"],
                        severity=pattern_def["severity"],
                        description=pattern_def["description"],
                        evidence=evidence,
                        file=filepath,
                        line_number=actual_line,
                        cwe=pattern_def.get("cwe"),
                    )
                )

    return matches


def is_likely_benign(diff_content: str) -> bool:
    """
    Quick check if a diff is likely benign (docs/comments/version only).
    Used to skip LLM triage for obviously safe changes.
    """
    added_lines = [
        line[1:].strip() for line in diff_content.splitlines() if line.startswith("+") and not line.startswith("+++")
    ]
    if not added_lines:
        return True

    benign_count = sum(
        1
        for line in added_lines
        if not line
        or line.startswith("#")
        or line.startswith('"""')
        or line.startswith("'''")
        or re.match(r"^version\s*=", line, re.IGNORECASE)
        or re.match(r"^__version__", line)
        or re.match(r"^#", line)
    )
    return benign_count / len(added_lines) > 0.9


# ─── Window-based multi-line pattern scanner ──────────────────────────────────

WINDOW_PATTERNS: list[dict] = [
    # base64 decode + exec/eval within 5 lines (most common supply chain attack)
    {
        "id": "BASE64_EXEC_CHAIN",
        "patterns": [
            re.compile(r"base64\.(b64decode|decodebytes|urlsafe_b64decode)\s*\(", re.IGNORECASE),
            re.compile(r"\b(exec|eval|compile)\s*\(", re.IGNORECASE),
        ],
        "window": 5,
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.CRITICAL,
        "description": "base64デコード＋exec/evalの組み合わせが近接行に存在する（典型的難読化攻撃）",
        "cwe": "CWE-506",
    },
    # env var read + network request within 8 lines (exfiltration pattern)
    {
        "id": "ENV_EXFIL_CHAIN",
        "patterns": [
            re.compile(r"os\.(environ|getenv)\s*[\[(.]", re.IGNORECASE),
            re.compile(
                r"(urllib|requests|http\.client|socket|aiohttp|httpx).*?(open|get|post|connect|urlopen)",
                re.IGNORECASE,
            ),
        ],
        "window": 8,
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "環境変数読み取りと外部ネットワーク送信が近接行に存在する（認証情報窃取パターン）",
        "cwe": "CWE-200",
    },
    # subprocess + hardcoded command (execute phase)
    {
        "id": "SUBPROCESS_HARDCODED",
        "patterns": [
            re.compile(r"(subprocess\.(run|Popen|call|check_output)|os\.system)\s*\(", re.IGNORECASE),
            re.compile(r"""["'](curl|wget|bash|sh|powershell|cmd\.exe)\s""", re.IGNORECASE),
        ],
        "window": 3,
        "category": FindingCategory.EXECUTION,
        "severity": Severity.CRITICAL,
        "description": "subprocess/os.systemとダウンロード/シェルコマンドの組み合わせが検出された",
        "cwe": "CWE-78",
    },
    # Dynamic import + exec (code loading pattern)
    {
        "id": "DYNAMIC_IMPORT_EXEC",
        "patterns": [
            re.compile(r"(__import__|importlib\.import_module)\s*\(", re.IGNORECASE),
            re.compile(r"\b(exec|eval)\s*\(", re.IGNORECASE),
        ],
        "window": 5,
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "動的インポートとexec/evalの組み合わせが検出された",
        "cwe": "CWE-913",
    },
    # npm: Buffer hex decode + exec (common npm attack)
    {
        "id": "NPM_HEX_EXEC",
        "patterns": [
            re.compile(
                r"Buffer[.](from|alloc)\s*[(]|atob\s*[(]|btoa\s*[(]",
                re.IGNORECASE,
            ),
            re.compile(
                r"(eval|Function\s*[(]|child_process|require\s*[(])",
                re.IGNORECASE,
            ),
        ],
        "window": 5,
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.CRITICAL,
        "description": "Bufferデコード（hex/base64）とeval/require/child_processの組み合わせ（npm典型攻撃）",
        "cwe": "CWE-506",
    },
]


def scan_diff_windowed(diff_content: str, filepath: str = "") -> list[RuleMatch]:
    """
    Multi-line window scanner: detects attack patterns that span multiple lines.

    More accurate than single-line scan because it:
    - Requires BOTH parts of an attack chain to be present
    - Reduces false positives from innocent base64 or os.environ usage
    """
    matches: list[RuleMatch] = []

    # Extract added lines with numbers
    added_lines: list[tuple[int, str]] = []
    current_line = 0
    for line in diff_content.splitlines():
        if line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            if m:
                current_line = int(m.group(1)) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            current_line += 1
            added_lines.append((current_line, line[1:]))
        elif not line.startswith("-"):
            current_line += 1

    if not added_lines:
        return matches

    lines_only = [line for _, line in added_lines]

    for pattern_def in WINDOW_PATTERNS:
        window = pattern_def["window"]
        patterns = pattern_def["patterns"]

        # Slide a window over added lines
        for i in range(len(lines_only)):
            window_lines = lines_only[i : i + window]
            window_text = "\n".join(window_lines)

            # All patterns must match within the window
            all_match = all(p.search(window_text) for p in patterns)
            if not all_match:
                continue

            # Avoid duplicate matches at same location
            actual_line = added_lines[i][0]
            already = any(r.rule_id == pattern_def["id"] and r.line_number == actual_line for r in matches)
            if already:
                continue

            # Best evidence: the first matching line
            evidence = lines_only[i][:50]
            matches.append(
                RuleMatch(
                    rule_id=pattern_def["id"],
                    category=pattern_def["category"],
                    severity=pattern_def["severity"],
                    description=pattern_def["description"],
                    evidence=evidence,
                    file=filepath,
                    line_number=actual_line,
                    cwe=pattern_def.get("cwe"),
                )
            )

    return matches


SEVERITY_ORDER_RULES: dict = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.NONE: 1,
}


def scan_diff_full(diff_content: str, filepath: str = "") -> list[RuleMatch]:
    """
    Full scanner: combines single-line rules + window-based chain detection.

    Single-line rules catch obvious atomic IOCs.
    Window rules catch multi-line attack chains with higher confidence.
    Window CRITICAL results override single-line MEDIUM results for same category.
    """
    single = scan_diff(diff_content, filepath)
    window = scan_diff_windowed(diff_content, filepath)

    # Window results have higher confidence; if window found CRITICAL for a category,
    # remove lower-severity single-line hits for the same category (reduce noise)
    window_critical_cats = {m.category for m in window if m.severity == Severity.CRITICAL}
    filtered_single = [
        m for m in single if not (m.category in window_critical_cats and m.severity.value in ("LOW", "MEDIUM"))
    ]

    combined = filtered_single + window

    # Deduplicate: keep highest severity per (rule_id, file, line) combination
    seen: dict[tuple, RuleMatch] = {}
    for m in combined:
        key = (m.rule_id, m.file, m.line_number)
        if key not in seen or (
            SEVERITY_ORDER_RULES.get(m.severity, 0) > SEVERITY_ORDER_RULES.get(seen[key].severity, 0)
        ):
            seen[key] = m

    # Sort: CRITICAL first, then HIGH, then by line number
    result = sorted(
        seen.values(),
        key=lambda m: (-SEVERITY_ORDER_RULES.get(m.severity, 0), m.line_number or 0),
    )
    return result
