"""PT verifier: security headers re-checked on a fresh response (one request per origin)."""
from __future__ import annotations

from ..http import fetch
from ..pentest import PT_CONFIRMED, PT_NOT_CONFIRMED, Verifier

HEADERS = {
    "missing-csp": "Content-Security-Policy",
    "missing-hsts": "Strict-Transport-Security",
    "missing-xcto": "X-Content-Type-Options",
    "missing-referrer-policy": "Referrer-Policy",
    "missing-coep": "Cross-Origin-Embedder-Policy",
    "missing-coop": "Cross-Origin-Opener-Policy",
    "missing-corp": "Cross-Origin-Resource-Policy",
    "missing-permissions-policy": "Permissions-Policy",
}


class SecurityHeadersVerifier(Verifier):
    name = "pt-security-headers"
    check_ids = (*HEADERS, "missing-anti-clickjacking")
    order = 50

    def __init__(self):
        self._cache = {}

    def _get(self, ctx, origin):
        if origin not in self._cache:
            self._cache[origin] = fetch(origin.rstrip("/") + "/", timeout=ctx.config.target.timeout,
                                        insecure=ctx.config.target.insecure_tls)
        return self._cache[origin]

    def verify(self, ctx, f):
        r = self._get(ctx, f.element)
        if r.error:
            raise RuntimeError(r.error)
        ev = f"GET {f.element}/\n\n{r.dump()}"
        if f.check_id == "missing-anti-clickjacking":
            csp = (r.header("Content-Security-Policy") or "").lower()
            if r.header("X-Frame-Options") is None and "frame-ancestors" not in csp:
                return PT_CONFIRMED, "page can be framed by any site (no X-Frame-Options, no frame-ancestors)", ev
            return PT_NOT_CONFIRMED, "framing restricted", ev
        name = HEADERS[f.check_id]
        value = r.header(name)
        if value is None:
            return PT_CONFIRMED, f"{name} absent on a fresh response (HTTP {r.status})", ev
        return PT_NOT_CONFIRMED, f"{name} present: {value[:80]}", ev
