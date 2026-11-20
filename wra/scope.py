"""Scope guardrail: wra only touches hosts explicitly authorized in config.ini."""
from __future__ import annotations

import ipaddress
import socket


class ScopeError(Exception):
    """Raised when a target is not authorized."""


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


def _networks(entries: list[str]):
    nets = []
    for e in entries:
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            continue
    return nets


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in infos})


def host_in_scope(host: str, entries: list[str], resolver=_resolve) -> tuple[bool, str]:
    """Return (allowed, reason).

    A host is in scope when it is listed literally (hostname, case-insensitive) or when it is an IP
    inside a listed IP/CIDR. A hostname not listed literally is allowed only if ALL its resolved
    addresses fall inside listed networks.
    """
    if not host:
        return False, "empty host"
    if any("*" in e for e in entries):
        return False, "wildcards are not allowed in scope.hosts"
    h = host.strip().lower().rstrip(".")
    names = {e.lower().rstrip(".") for e in entries if _as_ip(e) is None and not _networks([e])}
    nets = _networks(entries)
    ip = _as_ip(h)
    if ip is not None:
        for n in nets:
            if ip.version == n.version and ip in n:
                return True, f"{h} is inside {n}"
        return False, f"{h} is not inside any authorized network"
    if h in names:
        return True, f"{h} is listed"
    addrs = resolver(h)
    if not addrs:
        return False, f"{h} is not listed and does not resolve"
    for a in addrs:
        aip = ipaddress.ip_address(a)
        if not any(aip.version == n.version and aip in n for n in nets):
            return False, f"{h} resolves to {a}, which is not authorized"
    return True, f"{h} resolves only to authorized addresses ({', '.join(addrs)})"


def enforce_scope(config) -> list[str]:
    """Validate the whole configuration against the scope. Raise ScopeError, return notes."""
    if not config.scope.authorized:
        raise ScopeError("scope.authorized is not 'yes': confirm written authorization in config.ini")
    if not config.scope.hosts:
        raise ScopeError("scope.hosts is empty")
    notes = []
    targets = [("target.url", config.target.host)]
    if config.ssh.enabled:
        targets.append(("ssh.host", config.ssh.host))
    for label, host in targets:
        ok, reason = host_in_scope(host, config.scope.hosts)
        if not ok:
            raise ScopeError(f"{label} out of scope: {reason}")
        notes.append(f"{label}: {reason}")
    return notes


def url_in_scope(url: str, config) -> bool:
    """Used by probes before following any URL (e.g. redirects)."""
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname or ""
    return host_in_scope(host, config.scope.hosts)[0]
