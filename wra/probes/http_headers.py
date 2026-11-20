"""Native external probe: HTTP security headers, cookies, TLS certificate, cleartext HTTP.

Passive: one GET on the base URL, one GET on http://<host>/, one TLS handshake.
check_id values match the ZAP parser so that the two sources merge into one row.
"""
from __future__ import annotations

import re
import ssl

from ..finding import Finding, origin
from ..http import fetch, verify_tls
from .base import Probe

SECURITY_HEADERS = [
    # header, check_id, category, owasp, title, remediation, https_only
    ("Strict-Transport-Security", "missing-hsts", "CWE-319", "A05", "Strict-Transport-Security header not set",
     "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS responses.", True),
    ("Content-Security-Policy", "missing-csp", "CWE-693", "A05", "Content-Security-Policy header not set",
     "Define a restrictive Content-Security-Policy (default-src 'self').", False),
    ("X-Content-Type-Options", "missing-xcto", "CWE-693", "A05", "X-Content-Type-Options header missing",
     "Add 'X-Content-Type-Options: nosniff'.", False),
    ("Referrer-Policy", "missing-referrer-policy", "CWE-200", "A05", "Referrer-Policy header not set",
     "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.", False),
]
VERSION_RE = re.compile(r"\d+\.\d+")


class HttpHeadersProbe(Probe):
    name = "http-headers"
    phase = "external"
    source = "wra-http"
    requires_access = "none"
    order = 10

    def _f(self, ctx, chain: bool = True, **kw) -> Finding:
        kw.setdefault("phase", self.phase)
        kw.setdefault("factors", {"external": True, "requires_chain": chain})
        kw.setdefault("sources", [self.source])
        return Finding(**kw)

    def run(self, ctx) -> list[Finding]:
        cfg = ctx.config.target
        url = cfg.url
        site = origin(url)
        out: list[Finding] = []

        r = fetch(url, timeout=cfg.timeout, insecure=cfg.insecure_tls)
        ctx.store.write_raw(self.phase, "http-headers-base.txt", r.dump())
        if r.error:
            raise RuntimeError(f"target not reachable: {r.error}")
        ev = ctx.store.write_evidence("http-headers-base.txt", r.dump())

        # --- security headers -------------------------------------------------------------------
        csp = (r.header("Content-Security-Policy") or "").lower()
        for header, check_id, cwe, owasp, title, fix, https_only in SECURITY_HEADERS:
            if https_only and cfg.scheme != "https":
                continue
            if r.header(header) is None:
                out.append(self._f(ctx, chain=(check_id != "missing-hsts"), title=title, element=site, category=cwe, owasp=owasp, check_id=check_id,
                                   evidence=[ev], remediation=fix,
                                   description=f"Response to {url} has no {header} header."))
        if r.header("X-Frame-Options") is None and "frame-ancestors" not in csp:
            out.append(self._f(ctx, title="Missing anti-clickjacking protection", element=site, category="CWE-1021",
                               owasp="A05", check_id="missing-anti-clickjacking", evidence=[ev],
                               remediation="Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors 'none''.",
                               description="Neither X-Frame-Options nor CSP frame-ancestors is set."))

        # --- version disclosure -----------------------------------------------------------------
        for h in ("Server", "X-Powered-By"):
            v = r.header(h)
            if v and VERSION_RE.search(v):
                out.append(self._f(ctx, title=f"{h} header discloses version", element=site, category="CWE-497",
                                   owasp="A05", check_id="server-version-disclosure", evidence=[ev],
                                   remediation="Hide version banners (e.g. nginx 'server_tokens off;').",
                                   description=f"{h}: {v}"))

        # --- cookies ----------------------------------------------------------------------------
        for c in r.header_all("Set-Cookie"):
            cname = c.split("=", 1)[0].strip()
            attrs = c.lower()
            for flag, check_id, cwe, fix in (
                ("secure", "cookie-no-secure", "CWE-614", "Set the Secure attribute."),
                ("httponly", "cookie-no-httponly", "CWE-1004", "Set the HttpOnly attribute."),
                ("samesite", "cookie-no-samesite", "CWE-1275", "Set SameSite=Lax or Strict."),
            ):
                if flag == "secure" and cfg.scheme != "https":
                    continue
                if not re.search(rf";\s*{flag}\b", attrs):
                    out.append(self._f(ctx, title=f"Cookie '{cname}' without {flag} attribute", element=site,
                                       category=cwe, owasp="A05", check_id=f"{check_id}:{cname}", evidence=[ev],
                                       remediation=fix, description=f"Set-Cookie: {c}"))

        # --- TLS certificate --------------------------------------------------------------------
        if cfg.scheme == "https":
            valid, detail, der = verify_tls(cfg.host, cfg.port, timeout=cfg.timeout)
            text = f"{cfg.host}:{cfg.port}\n{detail}\n"
            if der:
                text += ssl.DER_cert_to_PEM_cert(der)
            ctx.store.write_raw(self.phase, "tls-certificate.txt", text)
            if not valid and "verification failed" in detail:
                tev = ctx.store.write_evidence("tls-certificate.txt", text)
                out.append(self._f(ctx, chain=False, title="TLS certificate not trusted", element=site, category="CWE-295",
                                   owasp="A02", check_id="tls-untrusted-certificate", evidence=[tev],
                                   description=detail,
                                   remediation="Use a certificate issued by a trusted CA (or an internal CA "
                                               "distributed to clients); self-signed certificates train users "
                                               "to accept MitM warnings."))

            # --- cleartext HTTP -----------------------------------------------------------------
            http_url = f"http://{cfg.host}/"
            h = fetch(http_url, timeout=cfg.timeout)
            ctx.store.write_raw(self.phase, "http-cleartext.txt", h.dump())
            if not h.error:
                loc = h.header("Location") or ""
                if not (300 <= h.status < 400 and loc.lower().startswith("https://")):
                    hev = ctx.store.write_evidence("http-cleartext.txt", h.dump())
                    out.append(self._f(ctx, chain=False, title="Application served over cleartext HTTP", element=origin(http_url),
                                       category="CWE-319", owasp="A02", check_id="cleartext-http", evidence=[hev],
                                       remediation="Redirect all HTTP requests to HTTPS (301) and enable HSTS.",
                                       description=f"http://{cfg.host}/ answered {h.status} without redirecting to HTTPS."))
        return out
