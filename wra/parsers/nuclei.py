"""Nuclei JSONL (-jsonl) parser.

Info-severity templates are mostly fingerprinting: only a curated list is kept (mapped to canonical
check_ids so they merge with the other sources); low+ severities are always kept.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from .common import cwe, finding, ssh_element, url_origin, web_origin

SOURCE = "nuclei"

# template-id -> (check_id, CWE, title, remediation); kept even at severity "info"
INFO_KEEP = {
    "self-signed-ssl": ("tls-untrusted-certificate", "CWE-295", "Self-signed TLS certificate",
                        "Use a certificate issued by a trusted (or internal, distributed) CA."),
    "ssh-password-auth": ("ssh-password-auth", "CWE-307", "SSH password authentication enabled",
                          "Set 'PasswordAuthentication no' in sshd_config; use keys only (and fail2ban)."),
    "ssh-sha1-hmac-algo": ("ssh-weak-mac", "CWE-327", "SSH server offers SHA-1 HMAC algorithms",
                           "Remove hmac-sha1* from the sshd 'MACs' directive."),
    "swagger-api": ("api-docs-exposed", "CWE-200", "API documentation publicly exposed",
                    "Do not publish API specs in production, or protect them with authentication."),
    "prometheus-metrics": ("metrics-exposed", "CWE-200", "Prometheus metrics endpoint exposed",
                           "Restrict /metrics to the monitoring network or require authentication."),
}
# http-missing-security-headers matcher-name -> canonical check_id (None = ignored, legacy/low value)
HEADER_MATCHERS = {
    "content-security-policy": "missing-csp",
    "strict-transport-security": "missing-hsts",
    "x-content-type-options": "missing-xcto",
    "x-frame-options": "missing-anti-clickjacking",
    "referrer-policy": "missing-referrer-policy",
    "cross-origin-embedder-policy": "missing-coep",
    "cross-origin-opener-policy": "missing-coop",
    "cross-origin-resource-policy": "missing-corp",
    "permissions-policy": "missing-permissions-policy",
    "x-permitted-cross-domain-policies": None,      # Flash/PDF legacy header
    "clear-site-data": None,
}


def element(r: dict) -> str:
    host, port = r.get("host") or "", r.get("port") or ""
    if r.get("type") == "http" and r.get("url"):
        return url_origin(r["url"])
    if r.get("type") == "javascript" and str(port) == "22" or "ssh" in r.get("template-id", ""):
        return ssh_element(host, port or 22)
    if r.get("type") == "ssl" and port:
        return web_origin(host, port, "https")
    if r.get("matched-at", "").startswith(("http://", "https://")):
        return url_origin(r["matched-at"])
    return f"{host}:{port}" if port else host


def parse_records(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def parse(jsonl_text: str, evidence_for, scheme: str = "https") -> list:
    """evidence_for(record, index) -> list of evidence paths (lets the probe store request/response)."""
    out = []
    for i, r in enumerate(parse_records(jsonl_text)):
        info = r.get("info", {})
        tid = r.get("template-id", "")
        sev = (info.get("severity") or "info").lower()
        cls = info.get("classification") or {}
        el = element(r)
        where = r.get("matched-at", "")
        extracted = r.get("extracted-results") or []
        desc = (info.get("description") or info.get("name") or "").strip()
        desc += f"\nMatched at: {where}" + (f"\nExtracted: {', '.join(map(str, extracted))[:300]}" if extracted else "")
        desc += f"\nTemplate: {tid} (severity {sev})"

        if tid == "http-missing-security-headers":
            cid = HEADER_MATCHERS.get(r.get("matcher-name", ""), f"missing-{r.get('matcher-name')}")
            if cid is None or (cid == "missing-hsts" and urlsplit(r.get("url", "")).scheme != "https"):
                continue
            out.append(finding(SOURCE, title=f"Missing security header: {r.get('matcher-name')}", element=el,
                               category="CWE-693", owasp="A05", check_id=cid, evidence=evidence_for(r, i),
                               description=desc, remediation=f"Set the {r.get('matcher-name')} response header."))
            continue
        if tid in INFO_KEEP:
            cid, category, title, fix = INFO_KEEP[tid]
            out.append(finding(SOURCE, severity=sev, chain=tid not in ("self-signed-ssl", "ssh-password-auth"),
                               title=title, element=el, category=category, owasp="A05", check_id=cid,
                               evidence=evidence_for(r, i), description=desc,
                               remediation=fix or (info.get("remediation") or "").strip()))
            continue
        if sev == "info":
            continue
        factors = {}
        cvss = cls.get("cvss-score")
        if isinstance(cvss, (int, float)):
            factors["cvss"] = cvss
        cves = [c for c in (cls.get("cve-id") or []) if c]
        if cves:
            factors["public_exploit"] = True
        cwes = cls.get("cwe-id") or []
        out.append(finding(SOURCE, severity=sev, chain=sev in ("low", "medium"),
                           title=info.get("name", tid) + (f" ({', '.join(cves)})" if cves else ""),
                           element=el, category=cwe(cwes[0] if cwes else ""), owasp="",
                           check_id=f"nuclei:{tid}", evidence=evidence_for(r, i), description=desc,
                           remediation=(info.get("remediation") or "See template references.").strip(),
                           factors=factors))
    return out
