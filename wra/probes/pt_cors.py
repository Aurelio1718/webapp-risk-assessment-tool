"""PT verifier: CORS policy, with a request carrying a foreign (fictitious) Origin."""
from __future__ import annotations

from ..http import fetch
from ..pentest import PT_CONFIRMED, PT_NOT_CONFIRMED, Verifier, matched_url

FOREIGN_ORIGIN = "https://wra-pt.invalid"


class CorsVerifier(Verifier):
    name = "pt-cors"
    check_ids = ("cors-wildcard", "cors-*")
    order = 30

    def verify(self, ctx, f):
        url = matched_url(f) or f.element.rstrip("/") + "/"
        r = fetch(url, timeout=ctx.config.target.timeout, insecure=ctx.config.target.insecure_tls,
                  headers={"Origin": FOREIGN_ORIGIN})
        ev = f"GET {url} with Origin: {FOREIGN_ORIGIN}\n\n{r.dump()}"
        if r.error:
            raise RuntimeError(r.error)
        acao = (r.header("Access-Control-Allow-Origin") or "").strip()
        creds = (r.header("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
        if acao == FOREIGN_ORIGIN:
            return PT_CONFIRMED, ("arbitrary Origin reflected" + (" with credentials allowed: authenticated "
                                  "responses readable cross-origin" if creds else " (no credentials)")), ev
        if acao == "*":
            return PT_CONFIRMED, ("wildcard ACAO: any site can read unauthenticated responses; browsers "
                                  "do not send cookies with '*', which limits impact"), ev
        return PT_NOT_CONFIRMED, f"foreign Origin not allowed (ACAO: {acao or 'absent'})", ev
