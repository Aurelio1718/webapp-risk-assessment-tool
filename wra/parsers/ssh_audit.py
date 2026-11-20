"""ssh-audit JSON (-j) parser: algorithms marked 'fail' and CVEs. 'warn'-only items are listed, not scored."""
from __future__ import annotations

import json

from .common import finding, ssh_element

SOURCE = "ssh-audit"
GROUPS = {
    "kex": ("ssh-weak-kex", "key exchange", "KexAlgorithms"),
    "key": ("ssh-weak-hostkey", "host key", "HostKeyAlgorithms (and remove the matching HostKey)"),
    "enc": ("ssh-weak-cipher", "cipher", "Ciphers"),
    "mac": ("ssh-weak-mac", "MAC", "MACs"),
}


def parse(json_text: str, evidence: list[str], host: str, port: int = 22) -> list:
    d = json.loads(json_text)
    el = ssh_element(host, port)
    banner = (d.get("banner") or {}).get("raw", "")
    out = []
    for key, (cid, label, directive) in GROUPS.items():
        fails = [(a["algorithm"], "; ".join(a.get("notes", {}).get("fail", [])))
                 for a in d.get(key, []) if a.get("notes", {}).get("fail")]
        warns = [a["algorithm"] for a in d.get(key, [])
                 if a.get("notes", {}).get("warn") and not a.get("notes", {}).get("fail")]
        if not fails:
            continue
        desc = f"{banner}\nFailing {label} algorithms:\n" + "\n".join(f"- {n}: {why}" for n, why in fails)
        if warns:
            desc += f"\nWarnings (not scored): {', '.join(warns)}"
        out.append(finding(
            SOURCE, title=f"SSH server offers weak {label} algorithms", element=el, category="CWE-327",
            owasp="A02", check_id=cid, evidence=evidence, description=desc,
            remediation=f"Remove {', '.join(n for n, _ in fails)} from the sshd '{directive}' directive "
                        "(see ssh-audit hardening guides)."))
    for c in d.get("cves", []):
        cvss = c.get("cvssv2")
        out.append(finding(
            SOURCE, chain=False, title=f"SSH server vulnerable to {c.get('name')}", element=el, category="CWE-1104",
            owasp="A06", check_id=f"ssh-cve:{c.get('name')}", evidence=evidence,
            description=f"{banner}: {c.get('description', '')}", remediation="Update the SSH server package.",
            factors={"cvss": cvss} if isinstance(cvss, (int, float)) else {}))
    return out
