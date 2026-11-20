"""Helpers shared by the parsers."""
from __future__ import annotations

from urllib.parse import urlsplit

from ..finding import Finding, normalize_element
from ..scoring import IMPACT_MATRIX

# severity label of a third-party tool -> impact used only when the CWE is not in the impact matrix
SEVERITY_IMPACT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def web_origin(host: str, port: int | str, scheme: str | None = None) -> str:
    port = int(port)
    scheme = scheme or ("https" if port in (443, 8443) else "http")
    return normalize_element(f"{scheme}://{host}:{port}")


def ssh_element(host: str, port: int | str = 22) -> str:
    return f"ssh://{host}:{int(port)}"


def url_origin(url: str) -> str:
    p = urlsplit(url)
    return normalize_element(f"{p.scheme}://{p.netloc}")


def cwe(value) -> str:
    """'cwe-200' / 200 / '200' -> 'CWE-200'; empty or invalid -> 'CWE-16' (configuration)."""
    s = str(value or "").strip().upper().replace("CWE-", "")
    return f"CWE-{int(s)}" if s.isdigit() and int(s) > 0 else "CWE-16"


def finding(source: str, *, severity: str | None = None, external: bool = True, chain: bool = True,
            **kw) -> Finding:
    """Build an external-phase finding. A tool severity is used as impact only for unknown CWEs."""
    factors = {"external": external, "requires_chain": chain}
    factors.update(kw.pop("factors", {}))
    if severity and kw.get("category") not in IMPACT_MATRIX and "cvss" not in factors:
        factors["impact"] = SEVERITY_IMPACT.get(severity.lower(), 3)
    kw.setdefault("phase", "external")
    return Finding(sources=[source], factors=factors, **kw)
