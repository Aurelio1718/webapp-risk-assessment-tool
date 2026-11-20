"""Unit tests for the core (standard library only): python3 -m unittest discover -s tests -v"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wra.config import ConfigError, load_config  # noqa: E402
from wra.correlate import merge  # noqa: E402
from wra.finding import PT_CONFIRMED, PT_NOT_CONFIRMED, Finding, normalize_element, not_assessed  # noqa: E402
from wra.report import build_report  # noqa: E402
from wra.runner import RunnerError, ToolRunner  # noqa: E402
from wra.scope import ScopeError, enforce_scope, host_in_scope  # noqa: E402
from wra.scoring import score  # noqa: E402
from wra.store import RunStore  # noqa: E402

EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.ini"


def write_config(tmp, **replace):
    text = EXAMPLE.read_text()
    for old, new in replace.items():
        text = text.replace(old, new)
    p = Path(tmp) / "config.ini"
    p.write_text(text)
    os.chmod(p, 0o600)
    return str(p)


def F(**kw):
    base = dict(title="t", element="https://h/", category="CWE-693", check_id="missing-csp", phase="external",
                sources=["a"], factors={"external": True})
    base.update(kw)
    return Finding(**base)


class ScopeTests(unittest.TestCase):
    def test_ip_in_cidr(self):
        self.assertTrue(host_in_scope("192.168.122.93", ["192.168.122.0/24"])[0])

    def test_ip_out_of_scope(self):
        self.assertFalse(host_in_scope("10.0.0.1", ["192.168.122.93"])[0])

    def test_hostname_listed(self):
        self.assertTrue(host_in_scope("Chess.Lab", ["chess.lab"])[0])

    def test_hostname_must_resolve_inside(self):
        ok, _ = host_in_scope("evil.example", ["192.168.122.0/24"], resolver=lambda h: ["192.168.122.5", "8.8.8.8"])
        self.assertFalse(ok)
        ok, _ = host_in_scope("vm.lab", ["192.168.122.0/24"], resolver=lambda h: ["192.168.122.5"])
        self.assertTrue(ok)

    def test_wildcard_rejected(self):
        self.assertFalse(host_in_scope("a.b", ["*.b"])[0])

    def test_enforce_requires_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(write_config(tmp))
            with self.assertRaises(ScopeError):
                enforce_scope(cfg)
            cfg.scope.authorized = True
            enforce_scope(cfg)
            cfg.target.url = "https://10.9.9.9/"
            with self.assertRaises(ScopeError):
                enforce_scope(cfg)


class ConfigTests(unittest.TestCase):
    def test_example_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(write_config(tmp))
            self.assertEqual(cfg.target.host, "192.168.122.93")
            self.assertEqual(cfg.runtime.extra_args, ["--network", "host"])
            self.assertFalse(cfg.ssh.enabled)

    def test_password_in_config_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_config(tmp, **{"password_file =": "password = hunter2\npassword_file ="})
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_password_file_must_be_600(self):
        with tempfile.TemporaryDirectory() as tmp:
            pw = Path(tmp) / "pw"
            pw.write_text("s3cret\n")
            os.chmod(pw, 0o644)
            cfg = load_config(write_config(tmp, **{"password_file =": f"password_file = {pw}"}))
            os.environ.pop("WRA_DB_PASSWORD", None)
            with self.assertRaises(ConfigError):
                cfg.db.password()
            os.chmod(pw, 0o600)
            self.assertEqual(cfg.db.password(), "s3cret")


class RunnerTests(unittest.TestCase):
    def runtime(self, **kw):
        base = dict(engine="podman", mode="container", extra_args=["--network", "host"], volume_opts="Z",
                    allow_unpinned=False)
        base.update(kw)
        return SimpleNamespace(**base)

    def test_container_command_is_list_and_pinned(self):
        r = ToolRunner(self.runtime(), {"nmap": "docker.io/x/nmap@sha256:" + "a" * 64}, {"nmap": ["--cap-add", "NET_RAW"]})
        import shutil
        orig = shutil.which
        shutil.which = lambda name: "/usr/bin/" + name
        try:
            cmd = r.build("nmap", ["-sV", "/out/x.xml"], mounts=[("/tmp/o", "/out")])
        finally:
            shutil.which = orig
        self.assertEqual(cmd[:5], ["podman", "run", "--rm", "--network", "host"])
        self.assertIn("/tmp/o:/out:Z", cmd)
        self.assertIn("NET_RAW", cmd)
        self.assertEqual(cmd[-2:], ["-sV", "/out/x.xml"])

    def test_unpinned_refused(self):
        r = ToolRunner(self.runtime(), {"nmap": "docker.io/x/nmap:latest"}, {})
        with self.assertRaises(RunnerError):
            r.image("nmap")
        r2 = ToolRunner(self.runtime(allow_unpinned=True), {"nmap": "docker.io/x/nmap:latest"}, {})
        self.assertEqual(r2.image("nmap"), "docker.io/x/nmap:latest")

    def test_placeholder_refused(self):
        r = ToolRunner(self.runtime(allow_unpinned=True), {"nmap": "x@sha256:REPLACE_ME"}, {})
        with self.assertRaises(RunnerError):
            r.image("nmap")


class ScoringTests(unittest.TestCase):
    def test_matrix_and_external(self):
        f = score(F(category="CWE-89", check_id="sqli"))
        self.assertEqual((f.impact, f.likelihood, f.risk, f.band), (5, 4, 20, "high"))
        self.assertTrue(any("CWE-89" in r for r in f.rationale))

    def test_pt_confirmed_raises_likelihood(self):
        f = score(F(category="CWE-79", factors={"external": False}, pt_outcome=PT_CONFIRMED))
        self.assertEqual(f.likelihood, 4)

    def test_pt_not_confirmed_and_localhost(self):
        f = score(F(category="CWE-319", pt_outcome=PT_NOT_CONFIRMED, factors={"external": True, "localhost_only": True}))
        self.assertEqual(f.likelihood, 2)

    def test_cvss_and_privilege(self):
        f = score(F(category="CWE-1104", factors={"external": False, "cvss": 9.8, "excessive_privilege": True}))
        self.assertEqual(f.impact, 5)

    def test_unknown_category_placeholder(self):
        f = score(F(category="CWE-99999"))
        self.assertTrue(any("PLACEHOLDER" in r for r in f.rationale))

    def test_idempotent(self):
        f = score(F())
        first = (f.impact, f.likelihood, list(f.rationale))
        f = score(f)
        self.assertEqual(first, (f.impact, f.likelihood, f.rationale))

    def test_not_assessed_unscored(self):
        f = score(not_assessed("https://h/", "nmap", "external", "nmap", "requires --active"))
        self.assertIsNone(f.risk)


class CorrelationTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_element("HTTPS://Host:443/"), "https://host")
        self.assertEqual(normalize_element("http://h:8080/a/"), "http://h:8080/a")

    def test_merge_sources(self):
        a = F(sources=["wra-http"], evidence=["evidence/a"])
        b = F(element="https://H:443", sources=["zap"], evidence=["evidence/b"], phase="external",
              pt_outcome=PT_NOT_CONFIRMED)
        c = F(check_id="missing-xcto")
        out = merge([a, b, c])
        self.assertEqual(len(out), 2)
        m = next(x for x in out if x.check_id == "missing-csp")
        self.assertEqual(m.confidence, 2)
        self.assertEqual(m.evidence, ["evidence/a", "evidence/b"])
        self.assertEqual(m.pt_outcome, PT_NOT_CONFIRMED)


class ReportTests(unittest.TestCase):
    def test_report_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = RunStore(tmp).ensure()
            st.save_findings("external", [F(title="pipe | in title", sources=["zap"])])
            st.save_findings("internal", [F(category="CWE-250", check_id="root-container", element="container:db",
                                            phase="internal", factors={}),
                                          not_assessed("host", "lynis", "internal", "lynis", "requires access: privileged")])
            st.update_meta(scope={"url": "https://h/", "hosts": ["h"]}, access={"effective": "user"})
            md, csv_path, n = build_report(st)
            self.assertEqual(n, 3)
            text = (Path(tmp) / md).read_text()
            self.assertIn("pipe \\| in title", text)
            self.assertIn("Not assessed", text)
            rows = (Path(tmp) / csv_path).read_text().splitlines()
            self.assertTrue(rows[0].startswith("id,element,category"))
            self.assertEqual(oct(os.stat(Path(tmp) / md).st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
