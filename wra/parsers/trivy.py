"""Trivy JSON (fs --format json) parser: vulnerable dependencies and IaC misconfigurations."""
from __future__ import annotations

import json

from ..internal import ifinding
from ..source import src_el
from .semgrep import first_cwe

SOURCE = "trivy"
SEV_IMPACT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 1, "UNKNOWN": 2}
SEV_LIKELIHOOD = {"CRITICAL": 3, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 2}
# Dockerfile/compose checks with a meaningful CWE (others: CWE-16 insecure configuration)
MISCONF_CWE = {"DS-0002": "CWE-250", "DS-0004": "CWE-668", "DS-0031": "CWE-798"}


def load(text: str) -> dict:
    return json.loads(text) if text.strip() else {"Results": []}


def cvss_score(cvss: dict) -> float | None:
    for vendor in ("nvd", "ghsa", "redhat", *cvss.keys()):
        v = cvss.get(vendor) or {}
        s = v.get("V3Score") or v.get("V40Score")
        if isinstance(s, (int, float)) and s > 0:
            return float(s)
    return None


def summary(text: str) -> dict:
    """Coverage numbers for the raw notes (positive results are worth reporting too)."""
    d = load(text)
    s = {"version": (d.get("Trivy") or {}).get("Version", "?"), "targets": [], "packages": 0,
         "vulnerabilities": 0, "misconfig_failures": 0}
    for r in d.get("Results") or []:
        s["targets"].append(f"{r.get('Target')} ({r.get('Type')})")
        s["packages"] += len(r.get("Packages") or [])
        s["vulnerabilities"] += len(r.get("Vulnerabilities") or [])
        s["misconfig_failures"] += (r.get("MisconfSummary") or {}).get("Failures", 0)
    return s


def parse(text: str, evidence_for) -> list:
    out = []
    i = 0
    for r in load(text).get("Results") or []:
        target, rtype = r.get("Target", ""), r.get("Type", "")
        for v in r.get("Vulnerabilities") or []:
            vid, sev = v.get("VulnerabilityID", "?"), (v.get("Severity") or "UNKNOWN").upper()
            pkg, ver, fixed = v.get("PkgName", "?"), v.get("InstalledVersion", "?"), v.get("FixedVersion", "")
            factors = {"likelihood": SEV_LIKELIHOOD.get(sev, 2)}
            score = cvss_score(v.get("CVSS") or {})
            if score:
                factors["cvss"] = score
            out.append(ifinding(
                SOURCE, title=f"Vulnerable dependency {pkg} {ver}: {vid}",
                element=f"pkg:{rtype}/{pkg.lower()}@{ver}", category=first_cwe(v.get("CweIDs") or []) if v.get("CweIDs") else "CWE-1104",
                owasp="A06", check_id=f"vuln:{vid}", evidence=evidence_for(v, i), factors=factors,
                rationale=[f"Trivy severity {sev}" + (f", CVSS {score}" if score else "") +
                           f" (declared in {target}); reachability of the vulnerable code not verified"],
                description=f"{(v.get('Title') or '').strip()}\n{(v.get('Description') or '').strip()[:600]}\n"
                            f"Declared in: {target}\nReference: {v.get('PrimaryURL', 'n/a')}",
                remediation=f"Upgrade {pkg} to {fixed}." if fixed else
                            f"No fixed version of {pkg} yet: assess exposure, mitigate or replace the component."))
            i += 1
        for m in r.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            mid, sev = m.get("ID", "?"), (m.get("Severity") or "UNKNOWN").upper()
            line = (m.get("CauseMetadata") or {}).get("StartLine")
            out.append(ifinding(
                SOURCE, title=f"Misconfiguration ({rtype}): {m.get('Title', mid)}",
                element=src_el(target, line), category=MISCONF_CWE.get(mid, "CWE-16"), owasp="A05",
                check_id=f"trivy:{mid}", evidence=evidence_for(m, i),
                factors={"impact": SEV_IMPACT.get(sev, 2), "likelihood": SEV_LIKELIHOOD.get(sev, 2)},
                rationale=[f"Trivy misconfiguration {mid}, severity {sev}"],
                description=f"{(m.get('Description') or '').strip()}\n{(m.get('Message') or '').strip()}\n"
                            f"Reference: {m.get('PrimaryURL', 'n/a')}",
                remediation=(m.get("Resolution") or "See reference.").strip()))
            i += 1
    return out
