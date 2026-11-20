"""Acquisition of the application source code for SAST / SCA / secret scanning.

The heavy tools run on the auditor's machine, never on the target. The source comes from:
1. --source PATH (copy supplied by the client): if PATH is a git work tree only tracked files are
   exported (git archive), so untracked .env / secrets/ never reach the scanners; otherwise PATH is
   scanned as is (read-only mount).
2. SSH (access level >= user): a constant remote script locates the application repository
   ([app] source_path, validated, or the directory of a compose file) and streams `git archive HEAD`
   base64-encoded. The archive is untrusted data: it is size-limited and extracted with the tarfile
   'data' filter (no absolute paths, no '..', no links outside the destination, no special files).
"""
from __future__ import annotations

import base64
import io
import re
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

from .access import rank
from .internal import host_el, remote, sections
from .probes.base import Probe

SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
MAX_ARCHIVE = 200 * 1024 * 1024          # decoded bytes
MAX_MEMBERS = 50_000

FIND_COMPOSE_DIRS = ("find /opt /srv /var/www /home -maxdepth 3 \\( -name docker-compose.yml -o -name "
                     "docker-compose.yaml -o -name compose.yml -o -name compose.yaml \\) -type f 2>/dev/null "
                     "| grep -v /node_modules/ | head -5 | while read c; do dirname \"$c\"; done")
ARCHIVE = r"""
for d in $DIRS; do
  [ -d "$d/.git" ] || continue
  echo "##repo $d"
  git -c safe.directory="$d" -C "$d" rev-parse --short HEAD 2>&1 | head -1
  echo "##archive"
  git -c safe.directory="$d" -C "$d" archive --format=tar.gz HEAD | base64 -w0
  echo
  exit 0
done
echo "##norepo $DIRS"
""".strip()


class SourceError(RuntimeError):
    pass


def build_remote_script(app_path: str = "") -> str:
    if app_path:
        if not SAFE_PATH.match(app_path):
            raise ValueError(f"unsafe [app] path {app_path!r}")
        dirs = f"DIRS={shlex.quote(app_path)}"
    else:
        dirs = f"DIRS=$({FIND_COMPOSE_DIRS})"
    return f"{dirs}\n{ARCHIVE}"


def extract_tar(data: bytes, dest: Path, mode: str = "r:*") -> int:
    if len(data) > MAX_ARCHIVE:
        raise SourceError(f"source archive too large ({len(data)} bytes)")
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise SourceError(f"source archive has too many entries ({len(members)})")
        tf.extractall(dest, filter="data")
    return sum(1 for m in members if m.isfile())


def parse_remote(stdout: str) -> tuple[str, str, bytes]:
    """-> (repo_dir, revision, archive bytes). Raises SourceError when no repository was found."""
    sec = sections(stdout)
    repo = next((k for k in sec if k.startswith("repo ")), "")
    if not repo:
        dirs = next((k.split(" ", 1)[1] for k in sec if k.startswith("norepo ")), "").strip()
        raise SourceError("no git repository found on the target"
                          + (f" (checked: {dirs})" if dirs else " (no compose file found)")
                          + "; set [app] source_path or use --source PATH")
    rev = (sec[repo] or ["?"])[0].strip()
    b64 = "".join(sec.get("archive", [])).strip()
    if not b64:
        raise SourceError(f"git archive returned no data for {repo.split(' ', 1)[1]} ({rev})")
    try:
        data = base64.b64decode(b64, validate=True)
    except ValueError as exc:
        raise SourceError(f"invalid archive encoding: {exc}") from exc
    return repo.split(" ", 1)[1], rev, data


def _from_local(ctx, dest: Path) -> dict:
    src = Path(ctx.source_path).expanduser().resolve()
    if not src.is_dir():
        raise SourceError(f"--source {src} is not a directory")
    git = shutil.which("git")
    if git and (src / ".git").exists():
        rev = subprocess.run([git, "-C", str(src), "rev-parse", "--short", "HEAD"], capture_output=True,
                             text=True, check=False, timeout=60).stdout.strip() or "?"
        res = subprocess.run([git, "-C", str(src), "archive", "--format=tar", "HEAD"], capture_output=True,
                             check=False, timeout=300)
        if res.returncode != 0:
            raise SourceError(f"git archive failed: {res.stderr.decode(errors='replace').strip()[-200:]}")
        n = extract_tar(res.stdout, dest, "r:")
        return {"path": dest, "origin": f"--source {src} (git archive HEAD {rev}, tracked files only)",
                "files": n}
    return {"path": src, "origin": f"--source {src} (not a git work tree: scanned as is, untracked files included)",
            "files": sum(1 for p in src.rglob("*") if p.is_file())}


def _from_ssh(ctx, probe, dest: Path) -> dict:
    app = ctx.config.app.source_path or (ctx.config.app.compose_path.rsplit("/", 1)[0]
                                         if ctx.config.app.compose_path else "")
    stdout = remote(ctx, probe, build_remote_script(app), timeout=600)
    repo, rev, data = parse_remote(stdout)
    n = extract_tar(data, dest, "r:gz")
    return {"path": dest, "origin": f"ssh {ctx.config.ssh.host}:{repo} (git archive HEAD {rev}, tracked files only)",
            "files": n}


def acquire(ctx, probe) -> dict:
    """Return {'path', 'origin', 'files'} once per run (cached on ctx; failures are cached too)."""
    cached = getattr(ctx, "_source_info", None)
    if cached is not None:
        if isinstance(cached, Exception):
            raise SourceError(str(cached))
        return cached
    dest = ctx.store.root / "internal" / "source"
    try:
        info = _from_local(ctx, dest) if ctx.source_path else _from_ssh(ctx, probe, dest)
    except Exception as exc:
        ctx._source_info = exc
        raise
    ctx._source_info = info
    ctx.store.write_raw("internal", "source-origin.txt", f"{info['origin']}\nfiles: {info['files']}\n")
    return info


def src_el(rel: str, line: int | str | None = None) -> str:
    rel = rel.lstrip("/")
    if rel.startswith("src/"):
        rel = rel[4:]
    return f"src://{rel}" + (f":{line}" if line else "")


class SourceProbe(Probe):
    """Base for probes that scan the source code on the auditor's machine."""
    phase = "internal"
    requires_access = "none"            # gated in applicable(): --source, or SSH with level >= user

    def element(self, ctx):
        if ctx.source_path:
            return "src://(--source)"
        return host_el(ctx) if ctx.config.ssh.host else super().element(ctx)

    def applicable(self, ctx):
        if ctx.source_path:
            return (True, "--source") if Path(ctx.source_path).expanduser().is_dir() \
                else (False, f"--source {ctx.source_path} is not a directory")
        if ctx.ssh is None or rank(ctx.level) < rank("user"):
            return False, f"requires access: user or --source PATH (available: {ctx.level})"
        return True, "source via ssh"

    def mounts(self, info: dict) -> list[tuple[str, str, str]]:
        return [(str(info["path"]), "/src", "ro")]
