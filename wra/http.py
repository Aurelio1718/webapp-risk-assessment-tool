"""Minimal HTTP(S) client on the standard library. Never follows redirects automatically."""
from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit

USER_AGENT = "wra/0.1 (authorized security assessment)"


@dataclass
class Response:
    url: str
    status: int = 0
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    error: str = ""
    peer_cert_der: bytes | None = None

    def header(self, name: str) -> str | None:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def dump(self) -> str:
        lines = [f"GET {self.url}"]
        if self.error:
            lines.append(f"ERROR: {self.error}")
        else:
            lines.append(f"HTTP {self.status} {self.reason}")
            lines += [f"{k}: {v}" for k, v in self.headers]
        return "\n".join(lines) + "\n"


def insecure_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url: str, timeout: int = 15, insecure: bool = True, method: str = "GET",
          max_body: int = 65536, headers: dict | None = None) -> Response:
    p = urlsplit(url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    resp = Response(url=url)
    try:
        if p.scheme == "https":
            ctx = insecure_context() if insecure else ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        hdrs.update(headers or {})
        conn.request(method, path, headers=hdrs)
        r = conn.getresponse()
        resp.status, resp.reason = r.status, r.reason
        resp.headers = list(r.getheaders())
        resp.body = r.read(max_body)
        if p.scheme == "https" and conn.sock is not None:
            try:
                resp.peer_cert_der = conn.sock.getpeercert(binary_form=True)
            except (ssl.SSLError, ValueError):
                pass
        conn.close()
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        resp.error = f"{type(exc).__name__}: {exc}"
    return resp


def verify_tls(host: str, port: int, timeout: int = 15) -> tuple[bool, str, bytes | None]:
    """Try a fully verified TLS handshake. Return (valid, detail, peer_cert_der)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                return True, f"valid certificate, {tls.version()}", tls.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        der = None
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with insecure_context().wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
        except OSError:
            pass
        return False, f"certificate verification failed: {exc.verify_message or exc}", der
    except (OSError, ssl.SSLError) as exc:
        return False, f"TLS handshake failed: {type(exc).__name__}: {exc}", None
