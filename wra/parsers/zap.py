"""ZAP baseline JSON report (-J) parser. Passive alerts only; informational/false-positive alerts skipped."""
from __future__ import annotations

import html
import json
import re

from .common import cwe, finding, url_origin

SOURCE = "zap"
RISK = {0: "info", 1: "low", 2: "medium", 3: "high"}

# pluginid -> canonical check_id (shared with the native http-headers probe and Nuclei)
CHECK_IDS = {
    "10038": "missing-csp",
    "10035": "missing-hsts",
    "10021": "missing-xcto",
    "10020": "missing-anti-clickjacking",
    "10036": "server-version-disclosure",
    "10037": "server-version-disclosure",
    "10098": "cors-wildcard",
    "10202": "missing-anti-csrf",
    "10063": "deprecated-feature-policy",
}
COOKIE_CHECKS = {"10010": "cookie-no-httponly", "10011": "cookie-no-secure", "10054": "cookie-no-samesite"}
CWE_OVERRIDE = {"10098": "CWE-942"}         # ZAP still reports the legacy CWE-264 for CORS
CROSS_ORIGIN = {"Embedder": "missing-coep", "Opener": "missing-coop", "Resource": "missing-corp"}
TAGS = re.compile(r"<[^>]+>")


def _text(s: str) -> str:
    return html.unescape(TAGS.sub(" ", s or "")).strip()


def _check_id(a: dict, param: str = "") -> str:
    pid = str(a.get("pluginid"))
    if pid in CHECK_IDS:
        return CHECK_IDS[pid]
    if pid in COOKIE_CHECKS:
        return f"{COOKIE_CHECKS[pid]}:{param}" if param else COOKIE_CHECKS[pid]
    if pid == "90004":
        for word, cid in CROSS_ORIGIN.items():
            if word in a.get("alert", ""):
                return cid
    return f"zap:{pid}"


def parse(json_text: str, evidence: list[str], min_risk: int = 1) -> list:
    data = json.loads(json_text)
    out = []
    for site in data.get("site", []):
        origin = url_origin(site.get("@name", ""))
        for a in site.get("alerts", []):
            risk, conf = int(a.get("riskcode", 0)), int(a.get("confidence", 1))
            if risk < min_risk or conf == 0:          # informational or flagged false positive
                continue
            pid = str(a.get("pluginid"))
            instances = a.get("instances", [])
            groups: dict[str, list[dict]] = {}
            for inst in instances or [{}]:
                param = inst.get("param", "") if pid in COOKIE_CHECKS else ""
                groups.setdefault(param, []).append(inst)
            for param, insts in groups.items():
                uris = sorted({i.get("uri", "") for i in insts if i.get("uri")})
                ev_lines = sorted({i.get("evidence", "") for i in insts if i.get("evidence")})
                desc = _text(a.get("desc", ""))
                if uris:
                    desc += f"\nInstances ({len(uris)}): " + ", ".join(uris[:5]) + (" ..." if len(uris) > 5 else "")
                if ev_lines:
                    desc += "\nEvidence: " + " | ".join(e[:120] for e in ev_lines[:3])
                title = a.get("alert") or a.get("name", f"ZAP alert {pid}")
                out.append(finding(
                    SOURCE, severity=RISK.get(risk, "medium"), chain=risk < 3,
                    title=f"{title} ({param})" if param else title,
                    element=origin, category=CWE_OVERRIDE.get(pid, cwe(a.get("cweid"))), owasp="A05",
                    check_id=_check_id(a, param), evidence=evidence, description=desc,
                    remediation=_text(a.get("solution", "")),
                    factors={"zap_risk": RISK.get(risk), "zap_confidence": conf}))
    return out
