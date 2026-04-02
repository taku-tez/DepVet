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
]
