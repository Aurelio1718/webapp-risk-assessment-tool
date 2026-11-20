"""Parser tests on real tool outputs (tests/fixtures) + probe plumbing with a stub runner."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wra.correlate import merge  # noqa: E402
from wra.parsers import nmap, nuclei, ssh_audit, zap  # noqa: E402
from wra.probes.nmap_scan import NmapProbe  # noqa: E402
from wra.probes.nuclei_scan import NucleiProbe  # noqa: E402
from wra.runner import ToolResult  # noqa: E402
from wra.scoring import score  # noqa: E402
from wra.store import RunStore  # noqa: E402

FX = ROOT / "tests" / "fixtures"
VM = "192.168.122.93"


def fx(name: str) -> str:
    return (FX / name).read_text(encoding="utf-8")


def ids(findings):
    return {(f.check_id, f.element) for f in findings}


class NmapParserTests(unittest.TestCase):
    def test_inventory(self):
        inv = nmap.inventory(fx("nmap-vm.xml"))
        self.assertIn("22/tcp ssh OpenSSH 10.2p1", inv)
        self.assertIn("443/tcp http nginx", inv)

    def test_vm_findings(self):
        got = ids(nmap.parse(fx("nmap-vm.xml"), ["evidence/nmap.xml"], {443}))
        self.assertIn(("tls-untrusted-certificate", f"https://{VM}"), got)
        self.assertIn(("tls-hostname-mismatch", f"https://{VM}"), got)
        self.assertIn(("exposed-service", f"ssh://{VM}:22"), got)
        # only TLS 1.2/1.3 with grade A ciphers, nginx without version
        self.assertFalse({c for c, _ in got} & {"tls-weak-cipher", "tls-deprecated-protocol",
                                                "server-version-disclosure"})

    def test_target_port_not_reported_as_exposed(self):
        got = ids(nmap.parse(fx("nmap-juiceshop.xml"), ["e"], {3000}))
        self.assertNotIn("exposed-service", {c for c, _ in got})


class ZapParserTests(unittest.TestCase):
    def test_vm_only_low_coep(self):
        got = zap.parse(fx("zap-vm.json"), ["evidence/zap.json"])
        self.assertEqual(ids(got), {("missing-coep", f"https://{VM}")})   # informational alerts skipped

    def test_juiceshop(self):
        got = {f.check_id: f for f in zap.parse(fx("zap-juiceshop.json"), ["e"])}
        self.assertIn("missing-csp", got)
        self.assertEqual(got["cors-wildcard"].category, "CWE-942")
        self.assertEqual(got["missing-csp"].element, "http://127.0.0.1:3000")
        self.assertIn("Access-Control-Allow-Origin: *", got["cors-wildcard"].description)


class NucleiParserTests(unittest.TestCase):
    def test_vm(self):
        got = ids(nuclei.parse(fx("nuclei-vm.jsonl"), lambda r, i: [f"ev{i}"]))
        self.assertIn(("tls-untrusted-certificate", f"https://{VM}"), got)
        self.assertIn(("ssh-password-auth", f"ssh://{VM}:22"), got)
        self.assertIn(("ssh-weak-mac", f"ssh://{VM}:22"), got)
        self.assertIn(("missing-coep", f"https://{VM}"), got)
        # fingerprinting templates (tech-detect, tls-version, waf-detect...) are dropped
        self.assertFalse(any(c.startswith("nuclei:") for c, _ in got))
        self.assertNotIn("missing-x-permitted-cross-domain-policies", {c for c, _ in got})

    def test_juiceshop_no_hsts_on_http(self):
        got = {c for c, _ in ids(nuclei.parse(fx("nuclei-juiceshop.jsonl"), lambda r, i: []))}
        self.assertTrue({"missing-csp", "metrics-exposed", "api-docs-exposed"} <= got)
        self.assertNotIn("missing-hsts", got)


class SshAuditParserTests(unittest.TestCase):
    def test_fails_grouped(self):
        got = {f.check_id: f for f in ssh_audit.parse(fx("ssh-audit-vm.json"), ["e"], VM)}
        self.assertEqual(set(got), {"ssh-weak-kex", "ssh-weak-hostkey", "ssh-weak-mac"})
        self.assertIn("hmac-sha1", got["ssh-weak-mac"].description)
        self.assertNotIn("ssh-weak-cipher", got)          # ciphers only have warnings


class CorrelationTests(unittest.TestCase):
    def test_sources_merge_into_one_row(self):
        allf = (nmap.parse(fx("nmap-vm.xml"), ["n"], {443}) + nuclei.parse(fx("nuclei-vm.jsonl"), lambda r, i: ["u"])
                + ssh_audit.parse(fx("ssh-audit-vm.json"), ["s"], VM) + zap.parse(fx("zap-vm.json"), ["z"]))
        rows = {(f.check_id, f.element): f for f in (score(m) for m in merge(allf))}
        cert = rows[("tls-untrusted-certificate", f"https://{VM}")]
        self.assertEqual(set(cert.sources), {"nmap", "nuclei"})
        self.assertEqual(cert.confidence, 2)
        mac = rows[("ssh-weak-mac", f"ssh://{VM}:22")]
        self.assertEqual(set(mac.sources), {"nuclei", "ssh-audit"})
        self.assertEqual(set(rows[("missing-coep", f"https://{VM}")].sources), {"zap", "nuclei"})
        for f in rows.values():
            self.assertTrue(f.risk and f.rationale, f.check_id)


class StubRunner:
    """Pretends to run a tool: copies the fixture where the tool would have written its output."""

    def __init__(self, outputs):
        self.outputs, self.calls = outputs, []

    def uses_local(self, tool):
        return False

    def run(self, tool, args, mounts=None, **kw):
        self.calls.append((tool, args))
        mounts = dict((c, h) for h, c in (mounts or []))
        if "-ut" in args:
            Path(mounts["/root"], "nuclei-templates").mkdir(parents=True, exist_ok=True)
        elif tool in self.outputs:
            src, dst = self.outputs[tool]
            shutil.copy(FX / src, Path(mounts["/out"]) / dst)
        return ToolResult([tool, *args], 0, "", "", 0.1)


class ProbePlumbingTests(unittest.TestCase):
    def test_nmap_and_nuclei_probes(self):
        with tempfile.TemporaryDirectory() as tmp:
            import os
            os.environ["XDG_CACHE_HOME"] = str(Path(tmp) / "cache")
            target = SimpleNamespace(url=f"https://{VM}/", host=VM, port=443, scheme="https")
            runner = StubRunner({"nmap": ("nmap-vm.xml", "nmap.xml"), "nuclei": ("nuclei-vm.jsonl", "nuclei.jsonl")})
            ctx = SimpleNamespace(config=SimpleNamespace(target=target), store=RunStore(Path(tmp) / "run").ensure(),
                                  runner=runner)
            nm = NmapProbe().run(ctx)
            nu = NucleiProbe().run(ctx)
            self.assertIn("tls-untrusted-certificate", {f.check_id for f in nm})
            self.assertTrue(all((Path(tmp) / "run" / e).is_file() for f in nm + nu for e in f.evidence))
            nuclei_args = next(a for t, a in runner.calls if t == "nuclei" and "-u" in a)
            self.assertIn("-ni", nuclei_args)                  # no Interactsh callbacks
            self.assertIn("-duc", nuclei_args)
            self.assertTrue(any("-ut" in a for t, a in runner.calls))   # templates installed first
            self.assertTrue((Path(tmp) / "run" / "external" / "raw" / "nmap-services.txt").is_file())
            del os.environ["XDG_CACHE_HOME"]


if __name__ == "__main__":
    unittest.main()
