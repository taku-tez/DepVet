"""
Type 5 sabotage detection rules.
These are injected into MALICIOUS_PATTERNS in rules.py at import time.

Real-world incidents covered:
- colors/faker 2022: Infinite loop injection (intentional DOS by maintainer)
- node-ipc 2022: IP-geofence-based file destruction
- peacenotwar 2022: Same pattern as node-ipc
"""

from __future__ import annotations

import re
from depvet.models.verdict import FindingCategory, Severity

SABOTAGE_PATTERNS = [
    # Mass file destruction: glob/walk + write/delete (node-ipc/peacenotwar)
    {
        "id": "MASS_FILE_OVERWRITE",
        "pattern": re.compile(
            r"(?:glob\.sync|readdirSync|fs\.readdir|os\.walk|glob\()"
            r".{0,200}"
            r"(?:writeFileSync|write_text|open\(.+['\"]w['\"]|fs\.unlink|os\.remove)",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.CRITICAL,
        "description": "ファイル一覧取得+一括書込み/削除の組み合わせが検出された（意図的ファイル破壊パターン）",
        "cwe": "CWE-732",
    },
    # Infinite loop with network/side-effects (colors/faker style)
    {
        "id": "INFINITE_LOOP_SIDE_EFFECT",
        "pattern": re.compile(
            r"while\s*[\(\s]*(?:true|True|1)[\)\s]*"
            r"[:\{][^}]{0,300}"
            r"(?:zalgo|require|fetch|http|console\.log|process\.stdout)",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "無限ループと副作用（出力/ネットワーク）の組み合わせが検出された（意図的DoSパターン）",
        "cwe": "CWE-400",
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
        "description": "IPアドレス判定と処理実行の組み合わせが検出された（node-ipc型地理的条件破壊パターン）",
        "cwe": "CWE-693",
    },
    # Overwriting files with empty/peace string (peacenotwar style)
    {
        "id": "POLITICAL_STRING_OVERWRITE",
        "pattern": re.compile(
            r"(?:writeFileSync|write_text|\.write\s*\()"
            r"[^)]{0,100}"
            r"(?:peace|love|heart|\u2764|\u2665|PEACE|NO WAR)",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "政治的メッセージによるファイル上書きパターンが検出された（peacenotwar型破壊）",
        "cwe": "CWE-732",
    },
    # process.exit/sys.exit injected unconditionally
    {
        "id": "UNCONDITIONAL_EXIT",
        "pattern": re.compile(
            r"^[+].*?(?:process\.exit|sys\.exit|os\._exit)\s*\(\s*[1-9]",
            re.MULTILINE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.MEDIUM,
        "description": "非ゼロ終了コードでのプロセス強制終了が追加された（クラッシュ注入の可能性）",
        "cwe": "CWE-400",
    },
]
