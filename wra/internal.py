"""Helpers for the internal (white-box, agentless) phase.

Remote scripts are constants in wra's code; anything discovered on the target (paths, container names)
is used only inside the remote shell script itself, never interpolated by wra into a new command.
"""
from __future__ import annotations

import re

from .finding import Finding

SECTION = re.compile(r"^##(\S+)\s*(.*)$")


class RemoteError(RuntimeError):
    pass


def remote(ctx, probe, script: str, timeout: int = 180, secret_stdin: str | None = None) -> str:
    """Run a constant read-only script over SSH; keep command + output in internal/raw/.
    secret_stdin is sent on stdin and never written to disk."""
    res = ctx.ssh.run(script, timeout=timeout, input_text=secret_stdin)
    ctx.store.write_raw(probe.phase, f"{probe.name}.txt",
                        f"# remote script ({res.summary()})\n{script}\n\n--- stdout ---\n{res.stdout}"
                        f"\n--- stderr ---\n{res.stderr}")
    if res.returncode == 255 or res.timed_out:
        raise RemoteError(f"ssh failed ({res.summary()}): {(res.stderr or '').strip()[-200:]}")
    return res.stdout


def sections(stdout: str) -> dict[str, list[str]]:
    """Split output on '##name [arg]' marker lines. Repeated names get keys name, name#2, ..."""
    out: dict[str, list[str]] = {}
    key = "_"
    for line in stdout.splitlines():
        m = SECTION.match(line)
        if m:
            base = m.group(1) + (f" {m.group(2)}" if m.group(2) else "")
            key, n = base, 2
            while key in out:
                key, n = f"{base}#{n}", n + 1
            out[key] = []
        else:
            out.setdefault(key, []).append(line)
    return out


def host_el(ctx) -> str:
    return f"host://{ctx.config.ssh.host}"


def file_el(ctx, path: str) -> str:
    return f"file://{ctx.config.ssh.host}{path}"


def ifinding(source: str, chain: bool = False, **kw) -> Finding:
    factors = {"external": False, "requires_chain": chain}
    factors.update(kw.pop("factors", {}))
    kw.setdefault("phase", "internal")
    return Finding(sources=[source], factors=factors, **kw)
