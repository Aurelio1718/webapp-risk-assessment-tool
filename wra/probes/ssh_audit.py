"""External probe: ssh-audit against the target host's SSH service (banner + algorithm negotiation only)."""
from __future__ import annotations

from ..parsers import ssh_audit
from ._tools import save_run, tail, tcp_open
from .base import Probe


class SshAuditProbe(Probe):
    name = "ssh-audit"
    phase = "external"
    source = "ssh-audit"
    tool = "ssh-audit"
    order = 40

    def _port(self, ctx) -> int:
        s = ctx.config.ssh
        return int(s.port) if s.host and s.host == ctx.config.target.host and s.port else 22

    def element(self, ctx) -> str:
        return f"ssh://{ctx.config.target.host}:{self._port(ctx)}"

    def applicable(self, ctx):
        host, port = ctx.config.target.host, self._port(ctx)
        if not tcp_open(host, port):
            return False, f"no SSH service reachable on {host}:{port}"
        return True, "applicable"

    def run(self, ctx):
        host, port = ctx.config.target.host, self._port(ctx)
        res = ctx.runner.run("ssh-audit", ["-j", "-p", str(port), host], timeout=300)
        save_run(ctx, self.phase, "ssh-audit", res)
        if res.returncode not in (0, 1, 2, 3) or not res.stdout.strip().startswith("{"):
            raise RuntimeError(f"ssh-audit failed ({res.summary()}): {tail(res.stderr or res.stdout, 5)}")
        ctx.store.write_raw(self.phase, "ssh-audit.json", res.stdout)
        ev = ctx.store.write_evidence("ssh-audit.json", res.stdout)
        return ssh_audit.parse(res.stdout, [ev], host, port)
