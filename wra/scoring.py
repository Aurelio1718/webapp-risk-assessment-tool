"""Deterministic scoring: risk = impact x likelihood (1-5 each, risk 1-25).

Every value and every modifier is written into the finding's rationale.
"""
from __future__ import annotations

import math

from .finding import PT_CONFIRMED, PT_NOT_CONFIRMED, Finding

# category -> (impact 1-5, effect on Confidentiality/Integrity/Availability)
IMPACT_MATRIX: dict[str, tuple[int, str]] = {
    "CWE-78":   (5, "C/I/A: OS command execution on the host"),
    "CWE-89":   (5, "C/I: read/modify the application database"),
    "CWE-94":   (5, "C/I/A: code execution"),
    "CWE-502":  (5, "C/I/A: unsafe deserialization can lead to code execution"),
    "CWE-798":  (5, "C/I: hard-coded credentials grant direct access"),
    "CWE-22":   (4, "C: read arbitrary files"),
    "CWE-287":  (4, "C/I: authentication can be bypassed or brute-forced"),
    "CWE-306":  (4, "C/I: function reachable without authentication"),
    "CWE-250":  (4, "C/I/A: process runs with excessive privileges, compromise impact is amplified"),
    "CWE-522":  (4, "C: credentials insufficiently protected"),
    "CWE-1104": (4, "C/I/A: vulnerable third-party component (default when CVSS is unknown)"),
    "CWE-639":  (4, "C/I: access to other users' objects (IDOR)"),
    "CWE-79":   (3, "I/C: script injection in the user's browser, session theft"),
    "CWE-352":  (3, "I: actions forged on behalf of an authenticated user"),
    "CWE-319":  (3, "C: data transmitted in cleartext"),
    "CWE-295":  (3, "C/I: certificate cannot be validated, enables man-in-the-middle"),
    "CWE-284":  (3, "C/I: improper access control on a resource"),
    "CWE-732":  (3, "C/I: incorrect permissions on a sensitive resource"),
    "CWE-400":  (3, "A: uncontrolled resource consumption"),
    "CWE-307":  (3, "C/I: no limit on authentication attempts"),
    "CWE-916":  (3, "C: weak password hashing eases offline cracking of stolen hashes"),
    "CWE-942":  (3, "C: permissive CORS policy lets other origins read responses"),
    "CWE-297":  (2, "C/I: certificate name mismatch, clients learn to ignore TLS errors"),
    "CWE-327":  (2, "C/I: weak or deprecated cryptographic algorithm offered"),
    "CWE-668":  (2, "C/I/A: service exposed to a wider network than needed (attack surface)"),
    "CWE-749":  (2, "I: dangerous function exposed to untrusted input"),
    "CWE-693":  (2, "I/C: missing defence-in-depth protection mechanism"),
    "CWE-1021": (2, "I: UI redressing / clickjacking"),
    "CWE-200":  (2, "C: information disclosure useful for an attacker"),
    "CWE-497":  (2, "C: system/version information disclosure"),
    "CWE-614":  (2, "C: cookie may be sent over cleartext"),
    "CWE-1004": (2, "C: cookie readable by scripts"),
    "CWE-1275": (2, "I: cookie sent cross-site (CSRF aid)"),
    "CWE-16":   (2, "C/I/A: insecure configuration"),
    "CWE-1188": (2, "C/I/A: insecure default setting"),
}
DEFAULT_IMPACT = 3


def clamp(v: int) -> int:
    return max(1, min(5, int(v)))


def band(risk: int | None, low_max: int, medium_max: int) -> str:
    if risk is None:
        return "n/a"
    if risk <= low_max:
        return "low"
    if risk <= medium_max:
        return "medium"
    return "high"


def _impact(f: Finding, why: list[str]) -> int:
    cvss = f.factors.get("cvss")
    if f.factors.get("impact") is not None:
        v = clamp(f.factors["impact"])
        why.append(f"Impact {v}: set by source ({', '.join(f.sources)})")
        return v
    if isinstance(cvss, (int, float)) and cvss > 0:
        v = clamp(math.ceil(float(cvss) / 2))
        why.append(f"Impact {v}: from CVSS {cvss} (ceil(CVSS/2))")
        return v
    if f.category in IMPACT_MATRIX:
        v, effect = IMPACT_MATRIX[f.category]
        why.append(f"Impact {v}: {f.category} - {effect}")
        return v
    why.append(f"Impact {DEFAULT_IMPACT}: PLACEHOLDER - {f.category or 'unknown category'} not in impact matrix")
    return DEFAULT_IMPACT


def _likelihood(f: Finding, why: list[str]) -> int:
    fx = f.factors
    if fx.get("likelihood") is not None:
        v = clamp(fx["likelihood"])
        why.append(f"Likelihood {v}: set by source ({', '.join(f.sources)})")
        return v
    if fx.get("external"):
        v = 4
        why.append("Likelihood base 4: reachable from the auditor's network")
    else:
        v = 2
        why.append("Likelihood base 2: requires access to the host or its internal network")
    if fx.get("auth_required"):
        v -= 1
        why.append("Likelihood -1: requires authentication")
    if fx.get("requires_chain"):
        v -= 1
        why.append("Likelihood -1: exploitation requires chaining with another weakness (defence-in-depth issue)")
    if fx.get("public_exploit"):
        v += 1
        why.append("Likelihood +1: public exploit/template available")
    return v


def score(f: Finding, low_max: int = 6, medium_max: int = 12) -> Finding:
    """Fill impact, likelihood, risk, band and rationale. Not-assessed findings get no score."""
    if f.not_assessed:
        f.impact = f.likelihood = f.risk = None
        f.band = "n/a"
        return f
    why: list[str] = [r for r in f.rationale if not r.startswith(("Impact", "Likelihood", "Risk"))]
    impact = _impact(f, why)
    if f.factors.get("excessive_privilege"):
        impact += 1
        why.append("Impact +1: excessive privileges/exposure")
    likelihood = _likelihood(f, why)
    if f.factors.get("localhost_only"):
        likelihood -= 1
        why.append("Likelihood -1: reachable only from localhost")
    if f.pt_outcome == PT_CONFIRMED and likelihood < 4:
        likelihood = 4
        why.append("Likelihood raised to 4: confirmed by penetration test")
    elif f.pt_outcome == PT_NOT_CONFIRMED:
        likelihood -= 1
        why.append("Likelihood -1: not confirmed by penetration test")
    f.impact, f.likelihood = clamp(impact), clamp(likelihood)
    f.risk = f.impact * f.likelihood
    f.band = band(f.risk, low_max, medium_max)
    why.append(f"Risk {f.risk} = {f.impact} x {f.likelihood} ({f.band})")
    f.rationale = why
    return f
