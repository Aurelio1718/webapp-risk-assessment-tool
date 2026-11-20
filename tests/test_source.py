"""Source acquisition, SAST/SCA/secret parsers and probes (fake runner fed with real fixtures)."""
import base64
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wra import source  # noqa: E402
from wra.finding import PT_CONFIRMED, PT_NOT_TESTED  # noqa: E402
from wra.parsers import semgrep, trivy, trufflehog  # noqa: E402
from wra.phases import run_phase  # noqa: E402
from wra.probes.src_semgrep import rulesets  # noqa: E402
from wra.runner import ToolResult, ToolRunner  # noqa: E402
from wra.scoring import score  # noqa: E402
from wra.store import RunStore  # noqa: E402

FX = Path(__file__).parent / "fixtures"
FAKE = "FAKE-SECRET-VALUE-DO-NOT-REPORT"


def ev(*_):
    return ["evidence/x"]


class FakeRunner:
    def __init__(self, outputs):
        self.outputs, self.calls = outputs, []

    def image_status(self, tool):
        return "PASS", "fake"

    def uses_local(self, tool):
        return False

    def run(self, tool, args, mounts=None, entrypoint=None, timeout=900, workdir=None):
        self.calls.append((tool, args, mounts, entrypoint))
        code, out = self.outputs[tool]
        return ToolResult([tool, *args], code, out, "", 0.1)


def make_ctx(tmp, src, runner):
    cfg = SimpleNamespace(ssh=SimpleNamespace(host="", enabled=False), target=SimpleNamespace(url="https://t/"),
                          app=SimpleNamespace(source_path="", compose_path=""))
    return SimpleNamespace(config=cfg, store=RunStore(Path(tmp) / "run").ensure(), ssh=None, level="none",
                           active=False, runner=runner, source_path=str(src))


def git_repo(root: Path) -> Path:
    repo = root / "app"
    (repo / "secrets").mkdir(parents=True)
    (repo / "app.py").write_text("import flask\n")
    (repo / "requirements.txt").write_text("Flask==3.1.3\n")
    (repo / ".gitignore").write_text(".env\nsecrets/*\n!secrets/.gitkeep\n")
    (repo / "secrets" / ".gitkeep").write_text("")
    (repo / ".env").write_text("SECRET=untracked\n")
    (repo / "secrets" / "db_password").write_text("untracked\n")
    g = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-qm", "init"], check=True)
    return repo


class ParserTests(unittest.TestCase):
    def test_semgrep_real_fixture(self):
        got = semgrep.parse((FX / "semgrep-chesscoach.json").read_text(), ev)
        self.assertEqual(len(got), 2)
        f = score(got[0])
        self.assertEqual(f.category, "CWE-532")
        self.assertEqual(f.owasp, "A09")
        self.assertEqual(f.element, "src://app/chesscoach/auth/routes.py:105")
        self.assertEqual((f.impact, f.likelihood), (2, 2))          # matrix CWE-532, Semgrep likelihood LOW
        self.assertTrue(any("reachability not verified" in r for r in f.rationale))

    def test_trivy_real_fixture_misconfig_only(self):
        text = (FX / "trivy-fs-chesscoach.json").read_text()
        got = trivy.parse(text, ev)
        self.assertEqual({f.check_id for f in got}, {"trivy:DS-0026"})
        self.assertEqual({f.element for f in got}, {"src://db/Dockerfile", "src://nginx/Dockerfile"})
        self.assertEqual(score(got[0]).risk, 1)                       # LOW: impact 1 x likelihood 1
        s = trivy.summary(text)
        self.assertEqual((s["packages"], s["vulnerabilities"], s["misconfig_failures"]), (34, 0, 2))

    def test_trivy_synthetic_vulns(self):
        got = {f.check_id: score(f) for f in trivy.parse((FX / "trivy-fs-synthetic-vuln.json").read_text(), ev)}
        w = got["vuln:CVE-2024-34069"]
        self.assertEqual(w.element, "pkg:pip/werkzeug@3.0.1")
        self.assertEqual((w.category, w.impact, w.likelihood), ("CWE-352", 4, 3))   # ceil(7.5/2), HIGH
        self.assertIn("3.0.3", w.remediation)
        low = got["vuln:GHSA-0000-synthetic"]
        self.assertEqual(low.category, "CWE-1104")
        self.assertIn("No fixed version", low.remediation)
        self.assertEqual(got["trivy:DS-0002"].category, "CWE-250")
        self.assertNotIn("trivy:DS-0001", got)                         # PASS is not a finding

    def test_trufflehog_never_keeps_secret(self):
        records = trufflehog.sanitize((FX / "trufflehog-synthetic.jsonl").read_text())
        self.assertEqual(len(records), 2)
        got = trufflehog.parse(records, ev)
        blob = json.dumps(records) + json.dumps([f.to_dict() for f in got])
        self.assertNotIn(FAKE, blob)
        self.assertNotIn("FAKE-SE", blob)
        self.assertEqual(got[0].element, "src://app/settings.py:12")
        self.assertEqual((got[0].pt_outcome, got[1].pt_outcome), (PT_NOT_TESTED, PT_CONFIRMED))
        self.assertEqual(score(got[1]).risk, 20)                      # CWE-798 impact 5 x confirmed 4
        self.assertEqual(trufflehog.sanitize((FX / "trufflehog-chesscoach.jsonl").read_text()), [])

    def test_semgrep_and_trufflehog_merge_on_hardcoded_secret(self):
        r = {"check_id": "x.hardcoded", "path": "/src/app/settings.py", "start": {"line": 12},
             "extra": {"message": "m", "metadata": {"cwe": ["CWE-798: Use of Hard-coded Credentials"]}}}
        sg = semgrep.parse(json.dumps({"results": [r]}), ev)[0]
        th = trufflehog.parse(trufflehog.sanitize((FX / "trufflehog-synthetic.jsonl").read_text()), ev)[0]
        self.assertEqual((sg.check_id, sg.element), (th.check_id, th.element))


class SourceTests(unittest.TestCase):
    def test_tar_traversal_blocked(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"x"
            ti = tarfile.TarInfo("../escape.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(tarfile.TarError):
                source.extract_tar(buf.getvalue(), Path(tmp) / "src", "r:gz")
            self.assertFalse((Path(tmp) / "escape.txt").exists())

    def test_parse_remote(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo("app/a.py")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
        out = f"##repo /opt/app\nb80ecca\n##archive\n{base64.b64encode(buf.getvalue()).decode()}\n"
        repo, rev, data = source.parse_remote(out)
        self.assertEqual((repo, rev), ("/opt/app", "b80ecca"))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(source.extract_tar(data, Path(tmp) / "s", "r:gz"), 1)
        with self.assertRaises(source.SourceError):
            source.parse_remote("##norepo /opt/x\n")

    def test_remote_script_constant_and_validated(self):
        with self.assertRaises(ValueError):
            source.build_remote_script("/opt/x; rm -rf /")
        s = source.build_remote_script("/opt/chess-coach")
        self.assertIn("DIRS=/opt/chess-coach", s)
        self.assertIn("archive --format=tar.gz HEAD", s)

    def test_ro_mount_with_selinux_suffix(self):
        r = ToolRunner.__new__(ToolRunner)
        r.runtime = SimpleNamespace(mode="container", engine=sys.executable, extra_args=[], volume_opts="Z",
                                    allow_unpinned=False)
        r.tool_args, r.images = {}, {"semgrep": "img@sha256:" + "0" * 64}
        cmd = r.build("semgrep", ["/src"], mounts=[("/tmp/x", "/src", "ro"), ("/tmp/c", "/c")])
        self.assertIn("/tmp/x:/src:ro,Z", cmd)
        self.assertIn("/tmp/c:/c:Z", cmd)

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_phase_with_local_source_tracked_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = git_repo(Path(tmp))
            runner = FakeRunner({
                "semgrep": (1, (FX / "semgrep-chesscoach.json").read_text()),
                "trivy": (0, (FX / "trivy-fs-synthetic-vuln.json").read_text()),
                "trufflehog": (183, (FX / "trufflehog-synthetic.jsonl").read_text()),
            })
            c = make_ctx(tmp, repo, runner)
            res = [f for f in run_phase(c, "internal") if f.sources[0] in ("semgrep", "trivy", "trufflehog")]
            self.assertFalse([f for f in res if f.not_assessed], [f.title for f in res if f.not_assessed])
            self.assertEqual({f.sources[0] for f in res}, {"semgrep", "trivy", "trufflehog"})
            exported = Path(tmp) / "run" / "internal" / "source"
            self.assertTrue((exported / "app.py").is_file())
            self.assertFalse((exported / ".env").exists())
            self.assertFalse((exported / "secrets" / "db_password").exists())
            sg = next(call for call in runner.calls if call[0] == "semgrep")
            self.assertEqual(sg[3], "semgrep")
            self.assertIn("p/flask", sg[1])
            self.assertEqual(sg[2][0], (str(exported), "/src", "ro"))
            for p in (Path(tmp) / "run").rglob("*"):          # secret value never written anywhere
                if p.is_file() and "source" not in p.parts:
                    self.assertNotIn(FAKE, p.read_text(errors="replace"), str(p))

    def test_not_assessed_without_source_or_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = make_ctx(tmp, "", FakeRunner({}))
            old = c.store.raw_dir("internal") / "src-semgrep.error.txt"
            old.write_text("stale error from a previous run")
            res = [f for f in run_phase(c, "internal") if f.check_id.startswith("not-assessed:src-")]
            self.assertEqual(len(res), 3)
            self.assertTrue(all("--source PATH" in f.title for f in res))
            self.assertFalse(old.exists())

    def test_rulesets(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.py").write_text("")
            (Path(tmp) / "Dockerfile").write_text("")
            (Path(tmp) / "requirements.txt").write_text("Flask==3\n")
            self.assertEqual(rulesets(Path(tmp)), ["p/python", "p/dockerfile", "p/flask"])
            empty = Path(tmp) / "e"
            empty.mkdir()
            self.assertEqual(rulesets(empty), ["p/default"])


if __name__ == "__main__":
    unittest.main()
