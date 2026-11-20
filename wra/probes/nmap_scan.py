"""External probe: nmap TCP connect scan, service/version detection and TLS scripts (non-intrusive)."""
from __future__ import annotations

from ..parsers import nmap
from ._tools import save_run, tail
from .base import Probe

SCRIPTS = "ssl-cert,ssl-enum-ciphers,http-title,http-server-header"


class NmapProbe(Probe):
    name = "nmap"
    phase = "external"
    source = "nmap"
    tool = "nmap"
    order = 20

    def run(self, ctx):
        cfg = ctx.config.target
        raw = ctx.store.raw_dir(self.phase)
        ports = "1-10000" + (f",{cfg.port}" if cfg.port > 10000 else "")
        # -sT: connect scan, works unprivileged/rootless; -Pn: host may drop ping
        args = ["-sT", "-sV", "-Pn", "-T4", "--open", "-p", ports, "--script", SCRIPTS,
                "-oX", "/out/nmap.xml", cfg.host]
        res = ctx.runner.run("nmap", args, mounts=[(str(raw), "/out")], timeout=1800)
        save_run(ctx, self.phase, "nmap", res)
        xml_path = raw / "nmap.xml"
        if res.returncode != 0 or not xml_path.is_file():
            raise RuntimeError(f"nmap failed ({res.summary()}): {tail(res.stderr or res.stdout, 5)}")
        xml = xml_path.read_text(encoding="utf-8", errors="replace")
        ctx.store.write_raw(self.phase, "nmap-services.txt", nmap.inventory(xml) + "\n")
        ev = ctx.store.write_evidence("nmap.xml", xml)
        return nmap.parse(xml, [ev], target_ports={cfg.port})
