"""Internal probes with a stub SSH client returning canned (realistic) remote outputs."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wra.correlate import merge  # noqa: E402
from wra.finding import PT_CONFIRMED, PT_NOT_CONFIRMED, Finding  # noqa: E402
from wra.phases import run_phase  # noqa: E402
from wra.probes import int_containers, int_db, int_files, int_host  # noqa: E402
from wra.runner import ToolResult  # noqa: E402
from wra.scoring import score  # noqa: E402
from wra.store import RunStore  # noqa: E402

VM = "192.168.122.93"
HOST_OUT = """##os
Ubuntu 26.04.1 LTS
7.0.0-15-generic
##ps
root                     1 systemd
t                     1200 dockerd
##listen
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*
##services
ssh.service
docker.service
##sshd
KbdInteractiveAuthentication no
UsePAM yes
PasswordAuthentication yes
Match User backup
PermitRootLogin yes
##firewall
ufw inactive
firewalld inactive
nftables inactive
##ufwconf
ENABLED=no
##updates
3
"""
FILES_OUT = """##user wra-priv
##composes /opt/chess-coach/docker-compose.yml
##app /opt/chess-coach
755 t t /opt/chess-coach
##sensitive /opt/chess-coach
READ_OK 644 t t /opt/chess-coach/nginx/certs/server.key
READ_OK 644 t t /opt/chess-coach/nginx/certs/server.crt.pem
DENIED 600 t t /opt/chess-coach/.env
##unlistable /opt/chess-coach
700 t t /opt/chess-coach/secrets
##compose-secrets /opt/chess-coach
DENIED /opt/chess-coach/secrets/secret_key
"""
CONTAINERS = [
    {"Name": "/chess-coach-nginx-1", "Config": {"User": "101", "Image": "nginx:1.30.6"},
     "HostConfig": {"Privileged": False, "ReadonlyRootfs": True, "CapAdd": None,
                    "PortBindings": {"8443/tcp": [{"HostIp": "", "HostPort": "443"}]}}, "Mounts": []},
    {"Name": "/bad", "Config": {"User": "", "Image": "x:latest"},
     "HostConfig": {"Privileged": True, "ReadonlyRootfs": False, "CapAdd": ["SYS_ADMIN"],
                    "PortBindings": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}},
     "Mounts": [{"Source": "/var/run/docker.sock"}]},
]
DB_OUT = """##container chess-coach-db-1
##roles
chesscoach|t|t|t|t|t
chesscoach_app|f|f|f|t|f
##settings
password_encryption|scram-sha-256
ssl|off
##hba
local|all|all||trust
host|all|all|all|scram-sha-256
##owners
chesscoach|7
"""


class StubSSH:
    def run(self, script, timeout=120, input_text=None):
        self.last_input = input_text
        if "docker inspect" in script:
            out = json.dumps(CONTAINERS)
        elif "pg_roles" in script:
            out = DB_OUT
        elif "##sensitive" in script:
            out = FILES_OUT
        else:
            out = HOST_OUT
        return ToolResult(["ssh"], 0, out, "", 0.1)


class NoImagesRunner:
    """Third-party tools are not available in unit tests: source probes are reported as not assessed."""
    def image_status(self, tool):
        return "FAIL", "no images in unit tests"


def ctx(tmp, level="privileged"):
    cfg = SimpleNamespace(
        ssh=SimpleNamespace(host=VM, port=22, user="wra-priv"), target=SimpleNamespace(port=443, host=VM, url=f"https://{VM}/"),
        app=SimpleNamespace(source_path="", compose_path=""),
        db=SimpleNamespace(access="docker_exec", engine="postgresql", container="chess-coach-db-1",
                           user="chesscoach_app", database="chesscoach", password=lambda: "pw"))
    facts = {"user": "wra-priv", "groups": ["wra-priv", "docker"], "docker": True}
    return SimpleNamespace(config=cfg, store=RunStore(Path(tmp) / "run").ensure(), ssh=StubSSH(), level=level,
                           active=False, runner=NoImagesRunner(), source_path="", access=lambda refresh=False: {"facts": facts})


class InternalTests(unittest.TestCase):
    def test_host(self):
        got = {f.check_id: f for f in int_host.parse(HOST_OUT, VM, 22, f"host://{VM}", ["e"])[0]}
        self.assertEqual(got["ssh-password-auth"].element, f"ssh://{VM}:22")
        self.assertNotIn("ssh-root-login", got)               # only inside a Match block
        self.assertIn("host-firewall-inactive", got)
        self.assertIn("host-pending-updates", got)

    def test_files_confirmed_and_not_confirmed(self):
        got = {f.element: f.pt_outcome for f in int_files.parse(FILES_OUT, lambda p: "file://vm" + p, ["e"])}
        self.assertEqual(got["file://vm/opt/chess-coach/nginx/certs/server.key"], PT_CONFIRMED)
        self.assertEqual(got["file://vm/opt/chess-coach/secrets/secret_key"], PT_NOT_CONFIRMED)
        self.assertNotIn("file://vm/opt/chess-coach/.env", got)   # 600 and denied: correctly protected

    def test_unsafe_app_path_rejected(self):
        with self.assertRaises(ValueError):
            int_files.build_script("/opt/x; rm -rf /")
        with self.assertRaises(ValueError):
            int_db.build_script("db; reboot")

    def test_containers(self):
        f, _ = int_containers.parse(json.dumps(CONTAINERS), VM, {443, 80}, ["e"])
        got = {(x.check_id, x.element.rsplit("/", 1)[1]) for x in f}
        self.assertFalse({c for c, n in got if n == "chess-coach-nginx-1"})
        self.assertTrue({"container-runs-as-root", "container-privileged", "container-dangerous-caps",
                         "container-docker-socket", "container-writable-rootfs", "container-port-exposed"}
                        <= {c for c, n in got if n == "bad"})

    def test_db(self):
        got = {f.check_id for f in int_db.parse(DB_OUT, VM, "chesscoach_app", "chesscoach", ["e"])}
        self.assertEqual(got, {"db-no-tls"})          # app role is least-privilege and does not own tables

    def test_phase_and_correlation_with_external(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = ctx(tmp)
            internal = run_phase(c, "internal")
            self.assertIn("docker-group-root-equivalent", {f.check_id for f in internal})
            ext = Finding(title="SSH password authentication enabled", element=f"ssh://{VM}:22", category="CWE-307",
                          check_id="ssh-password-auth", phase="external", sources=["nuclei"],
                          factors={"external": True})
            rows = {(f.check_id, f.element): score(f) for f in merge([ext] + internal)}
            row = rows[("ssh-password-auth", f"ssh://{VM}:22")]
            self.assertEqual(set(row.sources), {"nuclei", "wra-internal"})
            self.assertIn("external", row.phase)
            self.assertIn("internal", row.phase)
            self.assertTrue((Path(tmp) / "run" / "internal" / "raw" / "host-inventory.txt").is_file())

    def test_db_password_only_on_stdin_and_auth_error(self):
        script = int_db.build_script("chess-coach-db-1", "chesscoach_app")
        self.assertNotIn("pw", script.replace("WRA_PW", "").replace("PGPASSWORD", "").replace("psql", ""))
        self.assertIn("read -r WRA_PW", script)
        with tempfile.TemporaryDirectory() as tmp:
            c = ctx(tmp)
            c.ssh.run = lambda s, timeout=120, input_text=None: ToolResult(
                ["ssh"], 0, "##container db\n##roles\npsql: error: fe_sendauth: no password supplied\n", "", 0.1)
            res = int_db.DatabaseProbe().run(c)
            self.assertTrue(res[0].not_assessed)

    def test_firewall_ufw_conf_wins(self):
        out = HOST_OUT.replace("ufw inactive", "ufw active")
        got = {f.check_id for f in int_host.parse(out, VM, 22, f"host://{VM}", ["e"])[0]}
        self.assertIn("host-firewall-inactive", got)

    def test_user_level_skips_privileged(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = run_phase(ctx(tmp, level="user"), "internal")
            na = {f.check_id for f in res if f.not_assessed}
            self.assertTrue(any("requires access: privileged" in (f.description + " ".join(f.rationale))
                                for f in res if f.not_assessed), na)


if __name__ == "__main__":
    unittest.main()
