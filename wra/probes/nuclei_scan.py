"""External probe: Nuclei templates (CVE/misconfiguration/exposure), non-intrusive tags excluded.

-ni disables Interactsh: no out-of-band callbacks to third-party OAST servers (target data would leave
the lab). Trade-off: blind/OOB detections (e.g. blind SSRF) are not covered.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..parsers import nuclei
from ._tools import cache_dir, save_run, tail
from .base import Probe

EXCLUDE_TAGS = "dos,intrusive,fuzz,brute-force,bruteforce"


class NucleiProbe(Probe):
    name = "nuclei"
    phase = "external"
    source = "nuclei"
    tool = "nuclei"
    order = 35

    def _ensure_templates(self, ctx, cache: Path):
        installed = (cache / "nuclei-templates").is_dir() if not ctx.runner.uses_local("nuclei") \
            else (Path.home() / "nuclei-templates").is_dir()
        if installed:
            return
        # -duc would also block the template download: run -ut without it, once
        res = ctx.runner.run("nuclei", ["-ut", "-nc"], mounts=[(str(cache), "/root")], timeout=900)
        save_run(ctx, self.phase, "nuclei-update-templates", res)
        if res.returncode != 0:
            raise RuntimeError(f"nuclei template download failed: {tail(res.stderr or res.stdout, 5)}")

    def run(self, ctx):
        url = ctx.config.target.url
        raw = ctx.store.raw_dir(self.phase)
        cache = cache_dir("nuclei")
        self._ensure_templates(ctx, cache)
        out_file = raw / "nuclei.jsonl"
        out_file.unlink(missing_ok=True)
        args = ["-u", url, "-jsonl", "-o", "/out/nuclei.jsonl", "-duc", "-ni", "-nc",
                "-exclude-tags", EXCLUDE_TAGS, "-rl", "50", "-timeout", "10"]
        res = ctx.runner.run("nuclei", args, mounts=[(str(cache), "/root"), (str(raw), "/out")], timeout=2400)
        save_run(ctx, self.phase, "nuclei", res)
        if res.returncode != 0:
            raise RuntimeError(f"nuclei failed ({res.summary()}): {tail(res.stderr, 5)}")
        if "no templates provided" in res.stderr:
            raise RuntimeError("nuclei ran without templates (template cache empty)")
        text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.is_file() else ""

        def evidence_for(r: dict, i: int) -> list[str]:
            body = {k: r.get(k) for k in ("template-id", "matched-at", "matcher-name", "extracted-results",
                                          "curl-command", "timestamp")}
            req, resp = r.get("request") or "", r.get("response") or ""
            content = (json.dumps(body, indent=2, ensure_ascii=False) + "\n\n--- request ---\n" + req[:8000]
                       + "\n\n--- response ---\n" + resp[:20000])
            return [ctx.store.write_evidence(f"nuclei-{i:03d}-{r.get('template-id', 'x')}.txt", content)]

        return nuclei.parse(text, evidence_for, ctx.config.target.scheme)
