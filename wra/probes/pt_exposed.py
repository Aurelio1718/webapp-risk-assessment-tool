"""PT verifier: sensitive endpoints reachable without authentication (API specs, metrics)."""
from __future__ import annotations

from ..http import fetch
from ..pentest import PT_CONFIRMED, PT_NOT_CONFIRMED, PT_NOT_TESTED, Verifier, matched_url

# check_id -> markers proving the content is what the scanner claimed (case-insensitive)
MARKERS = {
    "metrics-exposed": ("# help", "# type"),
    "api-docs-exposed": ('"openapi"', '"swagger"', "swagger-ui"),
}


class ExposedEndpointVerifier(Verifier):
    name = "pt-exposed-endpoint"
    check_ids = tuple(MARKERS)
    order = 40

    def verify(self, ctx, f):
        url = matched_url(f)
        if not url:
            return PT_NOT_TESTED, "no endpoint URL recorded by the scanner", "no 'Matched at' URL in finding\n"
        r = fetch(url, timeout=ctx.config.target.timeout, insecure=ctx.config.target.insecure_tls,
                  max_body=4096)
        ev = f"GET {url} (no credentials, no cookies)\n\n{r.dump()}"
        if r.error:
            raise RuntimeError(r.error)
        text = r.body.decode("utf-8", "replace")
        ev += "\n--- body (first 1500 chars) ---\n" + text[:1500] + "\n"
        body = text.lower()
        hit = [m for m in MARKERS[f.check_id] if m in body]
        if r.status == 200 and hit:
            return PT_CONFIRMED, f"HTTP 200 without authentication, content markers: {', '.join(hit)}", ev
        return PT_NOT_CONFIRMED, f"HTTP {r.status}, expected content not found", ev
