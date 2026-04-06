"""Tests for sabotage detection rules (Type 5) in rules.py.

Tests the actual patterns registered in MALICIOUS_PATTERNS:
- MASS_FILE_OVERWRITE: glob/walk + write/delete (node-ipc/peacenotwar)
- IP_BASED_CONDITIONAL_EXEC: IP/CIDR check + exec (node-ipc)
- POLITICAL_STRING_OVERWRITE: political message file overwrite (peacenotwar)
- CRASH_INJECTION: unconditional non-zero process.exit/sys.exit
"""

from __future__ import annotations

from depvet.analyzer.rules import scan_diff_full


def make_diff(lines: list[str], path: str = "test.py") -> str:
    header = [f"--- a/{path}", f"+++ b/{path}", f"@@ -1 +1,{len(lines)} @@"]
    return "\n".join(header + [f"+{line}" for line in lines])


# ─── MASS_FILE_OVERWRITE ────────────────────────────────────────────────────


class TestMassFileOverwrite:
    def test_glob_sync_with_writefile(self):
        """node-ipc style: glob.sync() + writeFileSync()"""
        diff = make_diff(
            [
                "const files = glob.sync('/**/*');",
                "files.forEach(f => fs.writeFileSync(f, '♥'));",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "MASS_FILE_OVERWRITE" for r in m)

    def test_os_walk_with_write_text(self):
        """Python: os.walk() + write_text()"""
        diff = make_diff(
            [
                "for root, dirs, files in os.walk('/'):",
                "    for f in files:",
                "        Path(f).write_text('')",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "MASS_FILE_OVERWRITE" for r in m)

    def test_readdir_with_unlink(self):
        """Node.js: fs.readdir + fs.unlink"""
        diff = make_diff(
            [
                "fs.readdir(dir, (err, files) => {",
                "  files.forEach(f => fs.unlink(f, () => {}));",
                "});",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "MASS_FILE_OVERWRITE" for r in m)

    def test_os_walk_with_os_remove(self):
        """Python: os.walk() + os.remove()"""
        diff = make_diff(
            [
                "for root, dirs, files in os.walk('/tmp'):",
                "    for fname in files:",
                "        os.remove(os.path.join(root, fname))",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "MASS_FILE_OVERWRITE" for r in m)

    def test_glob_with_write(self):
        """Python: glob() + .write()"""
        diff = make_diff(
            [
                "for p in glob('*.py'):",
                "    f = open(p, 'wb')",
                "    f.write(b'')",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "MASS_FILE_OVERWRITE" for r in m)

    def test_no_false_positive_single_file_write(self):
        """Normal single file write without glob/walk should not trigger."""
        diff = make_diff(
            [
                "with open('output.txt', 'w') as f:",
                "    f.write(result)",
            ]
        )
        m = scan_diff_full(diff)
        assert not any(r.rule_id == "MASS_FILE_OVERWRITE" for r in m)

    def test_readdirSync_with_writefile(self):
        diff = make_diff(
            [
                "const files = fs.readdirSync('/home');",
                "files.forEach(f => fs.writeFileSync(f, 'pwned'));",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "MASS_FILE_OVERWRITE" for r in m)


# ─── IP_BASED_CONDITIONAL_EXEC ──────────────────────────────────────────────


class TestIPBasedConditionalExec:
    def test_cidr_exec(self):
        """node-ipc style: cidr check + exec()"""
        diff = make_diff(
            [
                "const { cidr } = require('cidr-matcher');",
                "if (cidr.contains(ip, '100.0.0.0/8')) {",
                "  exec('rm -rf /')",
                "}",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "IP_BASED_CONDITIONAL_EXEC" for r in m)

    def test_ipinfo_with_writefile(self):
        """ipinfo.io lookup + writeFileSync"""
        diff = make_diff(
            [
                "fetch('https://ipinfo.io/json')",
                "  .then(r => r.json())",
                "  .then(data => {",
                "    if (data.country === 'RU') writeFileSync('/etc/hosts', '');",
                "  });",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "IP_BASED_CONDITIONAL_EXEC" for r in m)

    def test_geoip_with_system(self):
        """Python: geoip check + system()"""
        diff = make_diff(
            [
                "import geoip",
                "loc = geoip.lookup(ip)",
                "if loc.country == 'UA':",
                "    os.system('rm -rf /home/*')",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "IP_BASED_CONDITIONAL_EXEC" for r in m)

    def test_no_false_positive_plain_ip(self):
        """Simple IP string without exec should not trigger."""
        diff = make_diff(
            [
                "ip = '127.0.0.1'",
                "print(f'Connecting to {ip}')",
            ]
        )
        m = scan_diff_full(diff)
        assert not any(r.rule_id == "IP_BASED_CONDITIONAL_EXEC" for r in m)

    def test_ipaddr_with_unlink(self):
        diff = make_diff(
            [
                "addr = ipaddr.parse(user_ip);",
                "if (addr.inRange('10.0.0.0/8')) { fs.unlink('/etc/passwd'); }",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "IP_BASED_CONDITIONAL_EXEC" for r in m)


# ─── POLITICAL_STRING_OVERWRITE ─────────────────────────────────────────────


class TestPoliticalStringOverwrite:
    def test_writefile_peace(self):
        """peacenotwar style: writeFileSync with peace message"""
        diff = make_diff(
            [
                "fs.writeFileSync(file, '❤ PEACE ❤');",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "POLITICAL_STRING_OVERWRITE" for r in m)

    def test_write_text_with_love(self):
        """Python: write_text with love message"""
        diff = make_diff(
            [
                "Path(f).write_text('love and peace')",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "POLITICAL_STRING_OVERWRITE" for r in m)

    def test_no_war_message(self):
        diff = make_diff(
            [
                "fs.writeFileSync(readme, 'NO WAR');",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "POLITICAL_STRING_OVERWRITE" for r in m)

    def test_heart_via_write_text(self):
        diff = make_diff(
            [
                "Path(file).write_text('heart of gold')",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "POLITICAL_STRING_OVERWRITE" for r in m)


# ─── CRASH_INJECTION ────────────────────────────────────────────────────────


class TestCrashInjection:
    def test_process_exit_nonzero(self):
        """process.exit(1) should be detected."""
        diff = make_diff(
            [
                "process.exit(1);",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CRASH_INJECTION" for r in m)

    def test_sys_exit_nonzero(self):
        """sys.exit(1) should be detected."""
        diff = make_diff(
            [
                "sys.exit(1)",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CRASH_INJECTION" for r in m)

    def test_os_exit_nonzero(self):
        """os._exit(1) should be detected."""
        diff = make_diff(
            [
                "os._exit(1)",
            ]
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CRASH_INJECTION" for r in m)

    def test_exit_zero_not_triggered(self):
        """process.exit(0) should NOT trigger (normal exit)."""
        diff = make_diff(
            [
                "process.exit(0);",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert not any(r.rule_id == "CRASH_INJECTION" for r in m)

    def test_process_exit_higher_code(self):
        """process.exit(42) should be detected."""
        diff = make_diff(
            [
                "process.exit(42);",
            ],
            "index.js",
        )
        m = scan_diff_full(diff)
        assert any(r.rule_id == "CRASH_INJECTION" for r in m)


# ─── Integration: patterns loaded correctly ─────────────────────────────────


def test_sabotage_patterns_registered():
    """All inline Type 5 sabotage patterns should be in MALICIOUS_PATTERNS."""
    from depvet.analyzer.rules import MALICIOUS_PATTERNS

    sabotage_ids = {
        "MASS_FILE_OVERWRITE",
        "IP_BASED_CONDITIONAL_EXEC",
        "POLITICAL_STRING_OVERWRITE",
        "CRASH_INJECTION",
    }
    pattern_ids = {p["id"] for p in MALICIOUS_PATTERNS}
    assert sabotage_ids.issubset(pattern_ids), f"Missing: {sabotage_ids - pattern_ids}"
