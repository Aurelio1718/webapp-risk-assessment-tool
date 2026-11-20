"""Semgrep JSON (--json) parser -> internal findings on the source code.

Impact comes from the CWE impact matrix (or Semgrep's own impact metadata for unknown CWEs);
likelihood from Semgrep's likelihood metadata. SAST results are static: reachability is not verified,
which is stated in every rationale.
"""
from __future__ import annotations

import json
import re

from ..internal import ifinding
from ..scoring import IMPACT_MATRIX
from ..source import src_el

SOURCE = "semgrep"
LEVEL = {"LOW": 2, "MEDIUM": 3, "HIGH": 4}
SEVERITY_LIKELIHOOD = {"INFO": 2, "WARNING": 2, "ERROR": 3}
_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_OWASP = re.compile(r"^(A\d{2}):2021")


def first_cwe(values) -> str:
    for v in values if isinstance(values, list) else [values]:
        m = _CWE.search(str(v or ""))
        if m:
            return f"CWE-{int(m.group(1))}"
    return "CWE-16"


def owasp2021(values) -> str:
    for v in values if isinstance(values, list) else [values]:
        m = _OWASP.match(str(v or ""))
        if m:
            return m.group(1)
    return ""


def load(text: str) -> dict:
    return json.loads(text) if text.strip() else {"results": [], "errors": []}


def parse(text: str, evidence_for) -> list:
    """evidence_for(result, index) -> list of evidence paths."""
    out = []
    for i, r in enumerate(load(text).get("results", [])):
        ex = r.get("extra", {})
        meta = ex.get("metadata", {})
        rule = r.get("check_id", "semgrep-rule")
        line = (r.get("start") or {}).get("line")
        category = first_cwe(meta.get("cwe"))
        lk = str(meta.get("likelihood", "")).upper()
        im = str(meta.get("impact", "")).upper()
        conf = str(meta.get("confidence", "")).upper()
        factors = {"likelihood": LEVEL.get(lk, SEVERITY_LIKELIHOOD.get(ex.get("severity", ""), 2))}
        if category not in IMPACT_MATRIX:
            factors["impact"] = LEVEL.get(im, 3)
        rationale = [f"Semgrep metadata: likelihood {lk or 'n/a'}, impact {im or 'n/a'}, confidence {conf or 'n/a'}, "
                     f"severity {ex.get('severity', 'n/a')}; static finding, reachability not verified"]
        if conf == "LOW":
            rationale.append("Semgrep confidence LOW: manual review required (possible false positive)")
        out.append(ifinding(
            SOURCE, title=f"SAST: {rule.rsplit('.', 1)[-1]}",
            element=src_el(r.get("path", ""), line), category=category, owasp=owasp2021(meta.get("owasp")),
            check_id="hardcoded-secret" if category == "CWE-798" else f"semgrep:{rule}",
            evidence=evidence_for(r, i), factors=factors, rationale=rationale,
            description=f"{(ex.get('message') or '').strip()}\nRule: {rule}\n"
                        f"Reference: {meta.get('source') or meta.get('shortlink') or 'n/a'}",
            remediation="Review the flagged code; fix it or document why it is a false positive "
                        "(e.g. a log message that only mentions the word 'password')."))
    return out
