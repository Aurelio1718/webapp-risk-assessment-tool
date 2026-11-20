"""Internal probe: permissions of keys/secrets in the application directory, with a real access test.

For each sensitive file the remote script reports its mode/owner and whether the audit user (not the
owner) can open it (head -c0: opens the file, reads 0 bytes - the content is never transferred).
Secret files referenced by the compose file are tested even when their directory cannot be listed.
"""
from __future__ import annotations

import re
import shlex

from ..finding import PT_CONFIRMED, PT_NOT_CONFIRMED
from ..internal import host_el, file_el, ifinding, remote, sections
from .base import Probe

SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
FIND_APPS = ("find /opt /srv /var/www /home -maxdepth 3 \\( -name docker-compose.yml -o -name docker-compose.yaml "
             "-o -name compose.yml -o -name compose.yaml \\) -type f 2>/dev/null | grep -v /node_modules/ | head -5")
PER_APP = r"""
for c in $COMPOSES; do
  d=$(dirname "$c"); echo "##app $d"; stat -c '%a %U %G %n' "$d" "$c" 2>/dev/null
  echo "##sensitive $d"
  find "$d" -maxdepth 5 -type f \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \
     -o -name '.env' -o -name '*.env' -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -path '*/secrets/*' \) \
     -not -path '*/.git/*' -not -path '*/node_modules/*' -printf '%m %u %g %p\n' 2>/dev/null | while read m u g p; do
       if head -c0 "$p" 2>/dev/null; then a=READ_OK; else a=DENIED; fi; echo "$a $m $u $g $p"; done
  echo "##unlistable $d"
  find "$d" -maxdepth 5 -type d ! -perm -o=x -printf '%m %u %g %p\n' 2>/dev/null
  echo "##compose-secrets $d"
  grep -E '^\s*file:\s*' "$c" 2>/dev/null | sed -E 's/^\s*file:\s*//; s/["'"'"']//g' | while read p; do
       case "$p" in /*) f="$p";; *) f="$d/${p#./}";; esac
       if head -c0 "$f" 2>/dev/null; then a=READ_OK; else a=DENIED; fi; echo "$a $f"; done
done
""".strip()


def build_script(app_path: str = "") -> str:
    if app_path:
        if not SAFE_PATH.match(app_path):
            raise ValueError(f"unsafe [app] path {app_path!r}")
        composes = f"COMPOSES=$(ls {shlex.quote(app_path)}/docker-compose.y*ml {shlex.quote(app_path)}/compose.y*ml 2>/dev/null)"
    else:
        composes = f"COMPOSES=$({FIND_APPS})"
    return f"echo \"##user $(id -un)\"\n{composes}\necho \"##composes $COMPOSES\"\n{PER_APP}"


def _others_can_read(mode: str) -> bool:
    return mode.isdigit() and int(mode[-1]) & 4 == 4


def parse(stdout: str, el, evidence: list[str]) -> list:
    sec = sections(stdout)
    user = next((k.split(" ", 1)[1] for k in sec if k.startswith("user ")), "audit user")
    out, seen = [], set()
    for key, lines in sec.items():
        if key.startswith("sensitive "):
            for line in lines:
                parts = line.split(" ", 4)
                if len(parts) < 5:
                    continue
                access, mode, owner, group, path = parts
                seen.add(path)
                if owner == user:
                    continue
                readable = access == "READ_OK"
                if not readable and not _others_can_read(mode):
                    continue                      # correctly protected: nothing to report
                out.append(ifinding(
                    "wra-internal", title="Sensitive file readable by other local users", element=el(path),
                    category="CWE-732", owasp="A01", check_id="sensitive-file-permissions", evidence=evidence,
                    pt_outcome=PT_CONFIRMED if readable else PT_NOT_CONFIRMED,
                    description=f"{path}: mode {mode} owner {owner}:{group}. Access test as '{user}' "
                                f"(not the owner): {'opened' if readable else 'denied by a parent directory'}.",
                    remediation="chmod 600 (or 640 with a dedicated group) on keys/secrets; keep them in a "
                                "700 directory owned by the service account.",
                    rationale=[f"Access test as {user}: {'Confirmed (file can be opened)' if readable else 'Not confirmed (parent directory blocks traversal)'}"]))
        if key.startswith("compose-secrets "):
            for line in lines:
                parts = line.split(" ", 1)
                if len(parts) < 2 or parts[1] in seen:
                    continue
                access, path = parts
                readable = access == "READ_OK"
                out.append(ifinding(
                    "wra-internal", title="File referenced by the compose file readable by other local users", element=el(path),
                    category="CWE-732", owasp="A01", check_id="sensitive-file-permissions", evidence=evidence,
                    pt_outcome=PT_CONFIRMED if readable else PT_NOT_CONFIRMED,
                    description=f"{path} (referenced by the compose file). Access test as '{user}': "
                                f"{'opened' if readable else 'denied (directory not traversable)'}. "
                                "File mode not visible from this account.",
                    remediation="Keep secret files 600 inside a 700 directory owned by the service account.",
                    rationale=[f"Access test as {user}: {'Confirmed' if readable else 'Not confirmed'}"]))
    return out


class FilePermissionsProbe(Probe):
    name = "int-file-permissions"
    phase = "internal"
    source = "wra-internal"
    requires_access = "user"
    order = 20

    def element(self, ctx):
        return host_el(ctx) if ctx.config.ssh.host else super().element(ctx)

    def run(self, ctx):
        app = ctx.config.app.source_path or (ctx.config.app.compose_path.rsplit("/", 1)[0]
                                             if ctx.config.app.compose_path else "")
        stdout = remote(ctx, self, build_script(app))
        ev = ctx.store.write_evidence("int-file-permissions.txt", stdout)
        if "##app " not in stdout:
            ctx.store.write_raw(self.phase, "int-file-permissions-note.txt",
                                "No compose-based application directory found; set [app] source_path.\n")
        return parse(stdout, lambda p: file_el(ctx, p), [ev])
