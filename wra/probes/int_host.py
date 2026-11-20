"""Internal probe: processes, listening sockets, running services, sshd settings, firewall, updates."""
from __future__ import annotations

from ..internal import host_el, ifinding, remote, sections
from .base import Probe

# Ubuntu's sshd_config includes sshd_config.d/*.conf first: print in the same order (first value wins)
SCRIPT = r"""
echo '##os'; . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME"; uname -r
echo '##ps'; ps -eo user:20,pid,comm --no-headers 2>/dev/null | head -400
echo '##listen'; ss -H -tuln 2>/dev/null
echo '##services'; systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}'
echo '##sshd'; cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | grep -Ev '^\s*(#|$)'
echo '##firewall'; for s in ufw firewalld nftables; do echo "$s $(systemctl is-active $s 2>/dev/null)"; done
echo '##ufwconf'; grep -E '^ENABLED=' /etc/ufw/ufw.conf 2>/dev/null
echo '##updates'; apt list --upgradable 2>/dev/null | grep -c upgradable
""".strip()

SSHD_DEFAULTS = {"passwordauthentication": "yes", "permitrootlogin": "prohibit-password",
                 "kbdinteractiveauthentication": "no", "x11forwarding": "no"}


def sshd_effective(lines: list[str]) -> dict[str, str]:
    eff: dict[str, str] = {}
    for line in lines:
        parts = line.strip().split(None, 1)
        if not parts:
            continue
        k = parts[0].lower()
        if k == "match":
            break                       # Match blocks are conditional: ignore what follows
        if k == "include":
            continue
        eff.setdefault(k, parts[1].strip() if len(parts) > 1 else "")
    for k, v in SSHD_DEFAULTS.items():
        eff.setdefault(k, v)
    return eff


def parse(stdout: str, host: str, ssh_port: int, el_host: str, evidence: list[str]) -> tuple[list, str]:
    sec = sections(stdout)
    out = []
    ssh_el = f"ssh://{host}:{ssh_port}"
    eff = sshd_effective(sec.get("sshd", []))
    if sec.get("sshd") and eff["passwordauthentication"].lower() == "yes":
        out.append(ifinding("wra-internal", title="SSH password authentication enabled", element=ssh_el,
                            category="CWE-307", owasp="A07", check_id="ssh-password-auth", evidence=evidence,
                            description="sshd_config (effective, first value wins): PasswordAuthentication yes",
                            remediation="Set 'PasswordAuthentication no' (keys only); consider fail2ban."))
    if eff["permitrootlogin"].lower() == "yes":
        out.append(ifinding("wra-internal", title="SSH root login allowed", element=ssh_el, category="CWE-250",
                            owasp="A07", check_id="ssh-root-login", evidence=evidence,
                            description="sshd_config: PermitRootLogin yes",
                            remediation="Set 'PermitRootLogin no'."))
    fw = {k: v.strip() for k, v in (l.split(" ", 1) for l in sec.get("firewall", []) if " " in l)}
    ufw_conf = " ".join(sec.get("ufwconf", []))
    if ufw_conf:
        # ufw.service is a oneshot that reports 'active' even when ufw is disabled: trust ufw.conf
        fw["ufw"] = "active" if "ENABLED=yes" in ufw_conf else "disabled (ufw.conf ENABLED=no)"
    if sec.get("firewall") and not any(v == "active" for v in fw.values()):
        out.append(ifinding("wra-internal", title="No host firewall active", element=el_host, category="CWE-284",
                            owasp="A05", check_id="host-firewall-inactive", evidence=evidence, chain=True,
                            description="ufw/firewalld/nftables not active: " +
                                        ", ".join(f"{k}={v or 'n/a'}" for k, v in fw.items()),
                            remediation="Enable a default-deny host firewall allowing only 80/443 and SSH from "
                                        "the admin network (note: Docker-published ports bypass ufw rules)."))
    upd = (sec.get("updates") or ["0"])[0].strip()
    if upd.isdigit() and int(upd) > 0:
        out.append(ifinding("wra-internal", title=f"{upd} package update(s) pending", element=el_host,
                            category="CWE-1104", owasp="A06", check_id="host-pending-updates", evidence=evidence,
                            chain=True, description=f"apt list --upgradable: {upd} package(s)",
                            remediation="Apply updates (unattended-upgrades for security updates)."))
    listen = [l.split() for l in sec.get("listen", []) if l.strip()]
    inventory = (
        f"OS: {' / '.join(sec.get('os', []))}\n\nListening sockets (proto local-address):\n"
        + "\n".join(f"  {p[0]} {p[4] if len(p) > 4 else '?'}" for p in listen)
        + "\n\nRunning services:\n" + "\n".join(f"  {s}" for s in sec.get("services", []) if s)
        + f"\n\nProcesses: {len(sec.get('ps', []))} (full list in raw output)\n"
        + "\nsshd effective (selected): " + ", ".join(f"{k}={eff[k]}" for k in SSHD_DEFAULTS) + "\n")
    return out, inventory


class HostInventoryProbe(Probe):
    name = "int-host"
    phase = "internal"
    source = "wra-internal"
    requires_access = "user"
    order = 10

    def element(self, ctx):
        return host_el(ctx) if ctx.config.ssh.host else super().element(ctx)

    def run(self, ctx):
        stdout = remote(ctx, self, SCRIPT)
        ev = ctx.store.write_evidence("int-host.txt", stdout)
        findings, inventory = parse(stdout, ctx.config.ssh.host, _ssh_port(ctx), host_el(ctx), [ev])
        ctx.store.write_raw(self.phase, "host-inventory.txt", inventory)
        return findings


def _ssh_port(ctx) -> int:
    return int(ctx.config.ssh.port or 22)
