"""Internal probe: running containers (docker inspect) - user, privileges, rootfs, capabilities,
docker.sock mounts, published ports. Also reports that docker-group membership is root-equivalent."""
from __future__ import annotations

import json

from ..internal import host_el, ifinding, remote
from .base import Probe

SCRIPT = "ids=$(docker ps -q); [ -n \"$ids\" ] && docker inspect $ids || echo '[]'"
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "ALL"}


def parse(json_text: str, host: str, web_ports: set[int], evidence: list[str]) -> tuple[list, str]:
    data = json.loads(json_text or "[]")
    out, inv = [], []
    for c in data:
        name = c.get("Name", "").lstrip("/")
        cfg, hc = c.get("Config", {}), c.get("HostConfig", {})
        el = f"container://{host}/{name}"
        user = (cfg.get("User") or "").strip()
        image = cfg.get("Image", "")
        binds = [m.get("Source", "") for m in c.get("Mounts", [])]
        ports = []
        for cport, binds_ in (hc.get("PortBindings") or {}).items():
            for b in binds_ or []:
                ports.append((b.get("HostIp") or "0.0.0.0", int(b.get("HostPort") or 0), cport))
        inv.append(f"{name}: image={image} user={user or 'root(default)'} privileged={hc.get('Privileged')} "
                   f"readonly_rootfs={hc.get('ReadonlyRootfs')} cap_add={hc.get('CapAdd')} "
                   f"cap_drop={hc.get('CapDrop')} ports={ports}")

        def add(check, title, cwe, desc, fix, chain=False):
            out.append(ifinding("wra-docker", title=title, element=el, category=cwe, owasp="A05", check_id=check,
                                evidence=evidence, description=f"{name} ({image}): {desc}", remediation=fix,
                                chain=chain))

        if user in ("", "root", "0", "0:0"):
            add("container-runs-as-root", "Container runs as root", "CWE-250", "no USER set (uid 0)",
                "Set a non-root USER in the image or 'user:' in compose.", chain=True)
        if hc.get("Privileged"):
            add("container-privileged", "Privileged container", "CWE-250", "--privileged: full host device access",
                "Remove 'privileged: true'; grant only the specific capabilities needed.")
        caps = set(hc.get("CapAdd") or []) & DANGEROUS_CAPS
        if caps:
            add("container-dangerous-caps", "Container with dangerous capabilities", "CWE-250",
                f"cap_add {sorted(caps)}", "Drop the capabilities (cap_drop: [ALL] and add back only what is needed).")
        if any(b.endswith("docker.sock") for b in binds):
            add("container-docker-socket", "Docker socket mounted in container", "CWE-250",
                "/var/run/docker.sock mounted: container can control the host",
                "Do not mount the Docker socket; use a restricted API proxy if unavoidable.")
        if not hc.get("ReadonlyRootfs"):
            add("container-writable-rootfs", "Container root filesystem writable", "CWE-16",
                "read_only not set", "Set 'read_only: true' with tmpfs for writable paths.", chain=True)
        for ip, hport, cport in ports:
            if ip in ("0.0.0.0", "::", "") and hport not in web_ports:
                add("container-port-exposed", f"Container port {hport} published on all interfaces", "CWE-668",
                    f"{ip}:{hport} -> {cport}", "Publish only the web ports; bind others to 127.0.0.1 or drop them.")
    return out, "\n".join(inv) + "\n"


class ContainersProbe(Probe):
    name = "int-containers"
    phase = "internal"
    source = "wra-docker"
    requires_access = "privileged"
    order = 30

    def element(self, ctx):
        return host_el(ctx) if ctx.config.ssh.host else super().element(ctx)

    def applicable(self, ctx):
        if not ctx.access()["facts"].get("docker"):
            return False, "Docker API not available to the audit user"
        return True, "applicable"

    def run(self, ctx):
        stdout = remote(ctx, self, SCRIPT)
        ev = ctx.store.write_evidence("int-containers.json", stdout)
        web = {ctx.config.target.port, 80, 443}
        findings, inv = parse(stdout, ctx.config.ssh.host, web, [ev])
        ctx.store.write_raw(self.phase, "containers-inventory.txt", inv)
        f = ctx.access()["facts"]
        findings.append(ifinding(
            "wra-docker", title="Docker group membership is root-equivalent", element=f"host://{ctx.config.ssh.host}",
            category="CWE-250", owasp="A01", check_id="docker-group-root-equivalent", evidence=[ev], chain=True,
            description=f"User '{f.get('user')}' can use the Docker API (groups: {' '.join(f.get('groups', []))}); "
                        "any docker-group member can start a privileged container and become root on the host.",
            remediation="Limit the docker group to administrators; consider rootless Docker; remove the audit "
                        "user after the assessment."))
        return findings
