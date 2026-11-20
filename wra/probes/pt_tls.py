"""PT verifier: TLS certificate trust, by a strict handshake (CA chain + hostname verification)."""
from __future__ import annotations

from urllib.parse import urlsplit

from ..http import verify_tls
from ..pentest import PT_CONFIRMED, PT_NOT_CONFIRMED, Verifier


class TlsTrustVerifier(Verifier):
    name = "pt-tls-trust"
    check_ids = ("tls-untrusted-certificate", "tls-hostname-mismatch")
    order = 10

    def verify(self, ctx, f):
        p = urlsplit(f.element)
        host, port = p.hostname, p.port or 443
        valid, detail, _ = verify_tls(host, port, timeout=ctx.config.target.timeout)
        ev = f"strict TLS handshake to {host}:{port} with system CA store and hostname check\nresult: {detail}\n"
        if not valid:
            return PT_CONFIRMED, f"a client validating certificates refuses the connection: {detail}", ev
        return PT_NOT_CONFIRMED, "certificate validates against the system trust store", ev
