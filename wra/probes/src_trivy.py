"""Internal probe: Trivy fs on the application source - vulnerable dependencies and Dockerfile/compose
misconfigurations. The vulnerability DB is cached in ~/.cache/wra/trivy (first run downloads it)."""
from __future__ import annotations

import json

from ..parsers import trivy
from ..source import SourceProbe, acquire
from ._tools import cache_dir, save_run, tail


class TrivyFsProbe(SourceProbe):
    name = "src-trivy"
    source = "trivy"
    tool = "trivy"
    order = 61

    def run(self, ctx):
        info = acquire(ctx, self)
        args = ["fs", "--scanners", "vuln,misconfig", "--format", "json", "--quiet", "/src"]
        res = ctx.runner.run("trivy", args, timeout=1800,
                             mounts=self.mounts(info) + [(str(cache_dir("trivy")), "/root/.cache/trivy")])
        ctx.store.write_raw(self.phase, "trivy-fs.json", res.stdout)
        save_run(ctx, self.phase, "trivy-fs", res)
        if res.returncode != 0:
            raise RuntimeError(f"trivy failed ({res.summary()}): {tail(res.stderr, 5)}")
        s = trivy.summary(res.stdout)
        ctx.store.write_raw(self.phase, "trivy-fs-summary.txt",
                            f"source: {info['origin']}\ntrivy {s['version']}\ntargets: {', '.join(s['targets'])}\n"
                            f"packages: {s['packages']}\nvulnerabilities: {s['vulnerabilities']}\n"
                            f"misconfiguration failures: {s['misconfig_failures']}\n")

        def evidence_for(item: dict, i: int) -> list[str]:
            keep = ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "CVSS",
                    "CweIDs", "PrimaryURL", "ID", "Title", "Message", "Resolution", "CauseMetadata", "Status")
            body = {k: item[k] for k in keep if k in item}
            body["source"] = info["origin"]
            return [ctx.store.write_evidence(f"trivy-fs-{i:03d}.json", json.dumps(body, indent=2))]

        return trivy.parse(res.stdout, evidence_for)
