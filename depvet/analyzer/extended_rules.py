"""
Extended detection rules for Types 7-10:
  Type 7: Credential/Token harvesting (browser, Discord, crypto wallet)
  Type 8: DNS exfiltration
  Type 10: Native binding injection
  + Webhook exfil channel expansion

These are merged into MALICIOUS_PATTERNS via rules.py import.
"""

from __future__ import annotations

import re
from depvet.models.verdict import FindingCategory, Severity

EXTENDED_PATTERNS = [
    # ── Type 7: Credential harvesting ──────────────────────────────────────
    # Browser credential path access (Chrome/Chromium/Firefox/Brave)
    {
        "id": "BROWSER_CREDENTIAL_ACCESS",
        "pattern": re.compile(
            r"(?:Local State|Login Data|Cookies|Web Data|Level\s?DB|places\.sqlite"
            r"|logins\.json|key[34]\.db|profiles?\.ini)"
            r".*?"
            r"(?:chrome|chromium|firefox|brave|opera|edge|vivaldi)",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "ブラウザの認証情報/Cookie/パスワードストアへのアクセスが追加された",
        "cwe": "CWE-200",
    },
    # Discord token theft (path-based)
    {
        "id": "DISCORD_TOKEN_THEFT",
        "pattern": re.compile(
            r"(?:discord|discordcanary|discordptb)"
            r".*?"
            r"(?:Local Storage|leveldb|\.ldb)",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "Discordトークンファイルへのアクセスが追加された（Token窃取パターン）",
        "cwe": "CWE-200",
    },
    # Cryptocurrency wallet file access
    {
        "id": "CRYPTO_WALLET_ACCESS",
        "pattern": re.compile(
            r"wallet\.dat|\.ethereum|\.bitcoin|\.solana"
            r"|electrum|exodus|metamask|phantom"
            r"|solflare|keystore.UTC",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "暗号通貨ウォレットファイルへのアクセスが追加された",
        "cwe": "CWE-200",
    },
    # macOS Keychain / Linux keyring access
    {
        "id": "KEYCHAIN_ACCESS",
        "pattern": re.compile(
            r"login\.keychain|find-generic-password|SecKeychainItem|keyrings",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "macOSキーチェーン/Linuxキーリングへのアクセスが追加された",
        "cwe": "CWE-200",
    },
    # ── Webhook exfil channel expansion ────────────────────────────────────
    # Pipedream, RequestBin, ngrok, Interactsh, Burp Collaborator etc.
    {
        "id": "EXFIL_WEBHOOK_SERVICE",
        "pattern": re.compile(
            r"pipedream\.net|requestbin|webhook\.site|ngrok\.io|ngrok-free\.app"
            r"|interact\.sh|burpcollaborator\.net|hookbin\.com|beeceptor\.com"
            r"|canarytokens\.com|requestcatcher\.com",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "データ窃取用Webhookサービス（pipedream/ngrok/requestbin等）へのURLが追加された",
        "cwe": "CWE-200",
    },
    # ── Type 8: DNS exfiltration ───────────────────────────────────────────
    # dns.resolve/lookup calls (Python/Node)
    {
        "id": "DNS_RESOLVE_CALL",
        "pattern": re.compile(
            r"dns\.(?:resolve|lookup|query|getHostByName)\s*\(",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.MEDIUM,
        "description": "DNSクエリ関数の呼び出しが追加された（DNSトンネリングの可能性）",
        "cwe": "CWE-200",
    },
    # nslookup/dig command with variable (shell-based DNS exfil)
    {
        "id": "DNS_COMMAND_EXFIL",
        "pattern": re.compile(
            r"(?:nslookup|dig|host)\s+.*?(?:\$\(|\$\{|`)",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.HIGH,
        "description": "DNS CLIコマンドに変数/コマンド置換が含まれている（DNSエクスフィルトレーション）",
        "cwe": "CWE-200",
    },
    # ── Type 10: Native binding injection ──────────────────────────────────
    # binding.gyp / node-gyp / node-pre-gyp references
    {
        "id": "BINDING_GYP_ADDED",
        "pattern": re.compile(
            r"binding\.gyp|node-gyp\s|node-pre-gyp|prebuild-install",
            re.IGNORECASE,
        ),
        "category": FindingCategory.BUILD_HOOK_ABUSE,
        "severity": Severity.HIGH,
        "description": "ネイティブアドオンビルド設定（binding.gyp/node-gyp）が追加された",
        "cwe": "CWE-829",
    },
    # Dynamic library loading (ctypes, dlopen, LoadLibrary, ffi)
    {
        "id": "DYNAMIC_LIBRARY_LOAD",
        "pattern": re.compile(
            r"ctypes\.(?:CDLL|cdll|WinDLL|windll)\s*\("
            r"|dlopen\s*\("
            r"|LoadLibrary[AW]?\s*\("
            r"|ffi\.Library\s*\(",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "動的ライブラリロード（ctypes/dlopen/LoadLibrary）が追加された",
        "cwe": "CWE-829",
    },
    # ── CommonJS / npm obfuscation patterns ────────────────────────────────
    # String concatenation to build require() path (e.g. require('ch'+'ild_pr'+'ocess'))
    {
        "id": "CJS_REQUIRE_CONCAT",
        "pattern": re.compile(
            r"""require\s*\(\s*['"][^'"]*['"]\s*\+\s*['"]""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.HIGH,
        "description": "require()パスが文字列連結で構築されている（モジュール名難読化）",
        "cwe": "CWE-506",
    },
    # Array/charCode decoding to build strings (common in npm malware)
    {
        "id": "CJS_CHARCODE_BUILD",
        "pattern": re.compile(
            r"String\.fromCharCode\s*\(\s*(?:\d+\s*,?\s*){3,}",
            re.IGNORECASE,
        ),
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.HIGH,
        "description": "String.fromCharCode()による文字列構築が検出された（難読化手法）",
        "cwe": "CWE-506",
    },
    # Hex/unicode escape sequences in require or function calls
    {
        "id": "CJS_HEX_ESCAPE",
        "pattern": re.compile(
            r"""(?:require|eval|Function)\s*\(\s*['"](?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}){3,}""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.CRITICAL,
        "description": "hex/unicodeエスケープシーケンスで難読化されたrequire/eval呼び出しが検出された",
        "cwe": "CWE-506",
    },
    # new Function() constructor (eval equivalent in JS)
    {
        "id": "CJS_NEW_FUNCTION",
        "pattern": re.compile(
            r"""new\s+Function\s*\(\s*['"`]""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.EXECUTION,
        "severity": Severity.HIGH,
        "description": "new Function()コンストラクタが使用されている（evalと同等の動的コード実行）",
        "cwe": "CWE-506",
    },
    # process.env exfiltration via http/https in Node.js
    {
        "id": "CJS_ENV_EXFIL",
        "pattern": re.compile(
            r"""process\.env\b.{0,100}(?:https?\.(?:get|request)|fetch\s*\(|axios|node-fetch)""",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": FindingCategory.EXFILTRATION,
        "severity": Severity.CRITICAL,
        "description": "process.envの内容をHTTPで外部送信するパターンが検出された",
        "cwe": "CWE-200",
    },
    # Obfuscated child_process access via string indexing
    {
        "id": "CJS_CHILD_PROCESS_OBFUSCATED",
        "pattern": re.compile(
            r"""require\s*\(\s*['"]child_process['"]\s*\)\s*\[""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.HIGH,
        "description": "child_processモジュールにブラケット記法でアクセスしている（難読化）",
        "cwe": "CWE-506",
    },
    # eval(Buffer.from(...).toString()) — common npm attack
    {
        "id": "CJS_EVAL_BUFFER",
        "pattern": re.compile(
            r"""eval\s*\(\s*Buffer\.from\s*\(""",
            re.IGNORECASE,
        ),
        "category": FindingCategory.OBFUSCATION,
        "severity": Severity.CRITICAL,
        "description": "eval(Buffer.from(...))による難読化コード実行が検出された（npm典型攻撃）",
        "cwe": "CWE-506",
    },
]
