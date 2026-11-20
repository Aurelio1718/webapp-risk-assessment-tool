"""External probe: OWASP ZAP baseline (spider + passive scan only, no attacks)."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ..parsers import zap
from ._tools import save_run, tail
from .base import Probe


class ZapBaselineProbe(Probe):
    name = "zap-baseline"
    phase = "external"
    source = "zap"
    tool = "zap"
    order = 30

    def applicable(self, ctx):
        if ctx.runner.uses_local("zap"):
            return False, "ZAP baseline is supported in container mode only (writes to /zap/wrk)"
        return True, "applicable"

    def run(self, ctx):
        url = ctx.config.target.url
        # ZAP writes as its own user inside the container: dedicated, temporary, world-writable work dir
        work = Path(tempfile.mkdtemp(prefix="zap-", dir=ctx.store.root))
        try:
            work.chmod(0o777)
            args = ["zap-baseline.py", "-t", url, "-m", "1", "-I", "-J", "zap.json"]
            res = ctx.runner.run("zap", args, mounts=[(str(work), "/zap/wrk")], timeout=1500)
            save_run(ctx, self.phase, "zap-baseline", res)
            report = work / "zap.json"
            if not report.is_file():
                raise RuntimeError(f"ZAP produced no report ({res.summary()}): {tail(res.stdout + res.stderr, 5)}")
            text = report.read_text(encoding="utf-8", errors="replace")
        finally:
            shutil.rmtree(work, ignore_errors=True)
        ctx.store.write_raw(self.phase, "zap-baseline.json", text)
        ev = ctx.store.write_evidence("zap-baseline.json", text)
        return zap.parse(text, [ev])
