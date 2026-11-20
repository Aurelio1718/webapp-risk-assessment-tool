"""nmap XML (-oX) parser: service inventory + TLS findings (ssl-cert, ssl-enum-ciphers)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .common import finding, ssh_element, web_origin

SOURCE = "nmap"
WEB_SERVICES = ("http", "https", "http-proxy", "http-alt", "ssl/http")
STRENGTH_ORDER = "ABCDEF"
DEPRECATED_TLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")


@dataclass
class Service:
    host: str
    port: int
    proto: str
    name: str
    product: str
    version: str
    tunnel: str

    @property
    def is_web(self) -> bool:
        return self.name in WEB_SERVICES or self.name.startswith("http") or self.tunnel == "ssl" and "http" in self.name

    @property
    def scheme(self) -> str:
        return "https" if self.tunnel == "ssl" or self.name == "https" else "http"

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version) if x)

    def label(self) -> str:
        return f"{self.port}/{self.proto} {self.name} {self.banner}".strip()


def _scripts(port_el) -> dict[str, ET.Element]:
    return {s.get("id"): s for s in port_el.findall("script")}


def _table(el, key):
    for t in el.findall("table"):
        if t.get("key") == key:
            return t
    return None


def _elem(el, key) -> str:
    for e in el.findall("elem"):
        if e.get("key") == key:
            return (e.text or "").strip()
    return ""


def _service(addr: str, p) -> Service:
    s = p.find("service")
    g = (lambda k: (s.get(k) if s is not None else "") or "")
    return Service(addr, int(p.get("portid")), p.get("protocol"), g("name"), g("product"), g("version"), g("tunnel"))


def _open_ports(root):
    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        for p in host.findall("ports/port"):
            if p.find("state").get("state") == "open":
                yield addr, p


def services(xml_text: str) -> list[Service]:
    return [_service(a, p) for a, p in _open_ports(ET.fromstring(xml_text))]


def _dn(table) -> dict:
    return {e.get("key"): (e.text or "").strip() for e in table.findall("elem")} if table is not None else {}


def _san(cert) -> set[str]:
    out = cert.get("output") or ""
    if "Subject Alternative Name:" not in out:
        return set()
    line = out.split("Subject Alternative Name:", 1)[1].split("\n", 1)[0]
    return {x.strip().split(":", 1)[-1].strip() for x in line.split(",") if x.strip()}


def parse(xml_text: str, evidence: list[str], target_ports: set[int] | None = None) -> list:
    """target_ports: ports the assessment is about (web app); other open ports are reported as exposed."""
    target_ports = target_ports or set()
    out = []
    for addr, p in _open_ports(ET.fromstring(xml_text)):
        svc = _service(addr, p)
        scripts = _scripts(p)
        if svc.is_web:
            el = web_origin(addr, svc.port, svc.scheme)
        elif svc.name == "ssh":
            el = ssh_element(addr, svc.port)
        else:
            el = f"{addr}:{svc.port}/{svc.proto}"

        # --- exposed non-web services -------------------------------------------------------------
        if not svc.is_web and svc.port not in target_ports:
            out.append(finding(
                SOURCE, title=f"Network service exposed: {svc.label()}", element=el, category="CWE-668",
                owasp="A05", check_id="exposed-service", evidence=evidence,
                description=f"nmap found {svc.label()} reachable from the auditor's network.",
                remediation="Expose only the web ports; restrict management services (SSH, DB) to an "
                            "admin network/VPN or by host firewall (e.g. ufw allow from <admin-net>)."))

        # --- version disclosure on web services ----------------------------------------------------
        if svc.is_web and svc.version:
            out.append(finding(
                SOURCE, title="Web server banner discloses version", element=el, category="CWE-497",
                owasp="A05", check_id="server-version-disclosure", evidence=evidence,
                description=f"nmap -sV: {svc.label()}",
                remediation="Hide version banners (e.g. nginx 'server_tokens off;')."))

        # --- certificate ---------------------------------------------------------------------------
        cert = scripts.get("ssl-cert")
        if cert is not None:
            subj, iss = _dn(_table(cert, "subject")), _dn(_table(cert, "issuer"))
            cn = subj.get("commonName", "")
            if subj and subj == iss:
                out.append(finding(
                    SOURCE, chain=False, title="Self-signed TLS certificate", element=el, category="CWE-295",
                    owasp="A02", check_id="tls-untrusted-certificate", evidence=evidence,
                    description=f"Certificate subject equals issuer (CN={cn}).",
                    remediation="Use a certificate issued by a trusted (or internal, distributed) CA."))
            names = {cn} | _san(cert)
            if cn and addr not in names:
                out.append(finding(
                    SOURCE, title="TLS certificate name does not match the host", element=el,
                    category="CWE-297", owasp="A02", check_id="tls-hostname-mismatch", evidence=evidence,
                    description=f"Certificate names {sorted(n for n in names if n)}; host {addr} not included.",
                    remediation="Issue the certificate for the name/IP clients use to reach the service."))

        # --- protocols / ciphers -------------------------------------------------------------------
        enum = scripts.get("ssl-enum-ciphers")
        if enum is not None:
            protos = [t.get("key") for t in enum.findall("table")]
            old = [x for x in protos if x in DEPRECATED_TLS]
            if old:
                out.append(finding(
                    SOURCE, title="Deprecated TLS/SSL protocol enabled", element=el, category="CWE-327",
                    owasp="A02", check_id="tls-deprecated-protocol", evidence=evidence,
                    description=f"Enabled protocols: {', '.join(protos)}",
                    remediation="Allow only TLS 1.2 and TLS 1.3."))
            least = _elem(enum, "least strength")
            if least in STRENGTH_ORDER and STRENGTH_ORDER.index(least) >= 2:
                out.append(finding(
                    SOURCE, title=f"Weak TLS cipher suites (least strength {least})", element=el,
                    category="CWE-327", owasp="A02", check_id="tls-weak-cipher", evidence=evidence,
                    description=f"nmap ssl-enum-ciphers least strength: {least}",
                    remediation="Use a modern cipher configuration (e.g. Mozilla 'intermediate')."))
    return out


def inventory(xml_text: str) -> str:
    """Human-readable service list for the report/raw output."""
    return "\n".join(s.label() for s in services(xml_text)) or "(no open ports)"
