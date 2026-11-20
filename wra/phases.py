"""Run all probes of a phase, with gating, error isolation and coverage tracking."""
from __future__ import annotations

import logging
import traceback

from .finding import Finding, not_assessed
from .probes import discover

log = logging.getLogger("wra.phase")


def run_phase(ctx, phase: str) -> list[Finding]:
    probes = discover(phase)
    if phase == "pentest":
        ctx.pt_entries = []          # filled by verifiers (wra/pentest.py), saved below
    findings: list[Finding] = []
    coverage: list[dict] = []
    if not probes:
        log.warning("[%s] no probes available yet", phase)
    stale = ctx.store.root / phase / "raw"
    for p in probes:                 # error files of a previous run must not survive into this report
        (stale / f"{p.name}.error.txt").unlink(missing_ok=True)
    for p in probes:
        ok, reason = p.gate(ctx)
        if not ok:
            log.info("[%s] %s: skipped (%s)", phase, p.name, reason)
            findings.append(not_assessed(p.element(ctx), p.name, phase, p.source, reason))
            coverage.append({"probe": p.name, "source": p.source, "status": "not assessed", "reason": reason})
            continue
        log.info("[%s] %s: running", phase, p.name)
        try:
            res = p.run(ctx) or []
            findings += res
            coverage.append({"probe": p.name, "source": p.source, "status": "done",
                             "reason": f"{len(res)} finding(s)"})
        except Exception as exc:  # one failing probe must not stop the assessment
            log.error("[%s] %s failed: %s", phase, p.name, exc)
            log.debug(traceback.format_exc())
            ctx.store.write_raw(phase, f"{p.name}.error.txt", traceback.format_exc())
            findings.append(not_assessed(p.element(ctx), p.name, phase, p.source, f"probe error: {exc}"))
            coverage.append({"probe": p.name, "source": p.source, "status": "error", "reason": str(exc)})
    ctx.store.save_findings(phase, findings)
    if phase == "pentest":
        ctx.store.save_pt_log(getattr(ctx, "pt_entries", []))
    ctx.store.set_coverage(phase, coverage)
    return findings
