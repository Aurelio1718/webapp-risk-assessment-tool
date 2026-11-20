"""Detect the access level available on the target host. wra never tries to escalate privileges."""
from __future__ import annotations

LEVELS = ["none", "user", "privileged"]

# Constant, read-only remote commands.
CMD_ID = "id -un; id -Gn"
CMD_DOCKER = "docker info --format '{{.ServerVersion}}'"
CMD_SUDO_LIST = "sudo -n -l"


def rank(level: str) -> int:
    return LEVELS.index(level)


def lower(a: str, b: str) -> str:
    return a if rank(a) <= rank(b) else b


def detect(ssh) -> tuple[str, list[str], dict]:
    """Return (level, details, facts). facts: user, groups, docker (bool), sudo (str)."""
    facts = {"user": "", "groups": [], "docker": False, "sudo": ""}
    if ssh is None:
        return "none", ["SSH not configured: external-only assessment"], facts
    r = ssh.run(CMD_ID, timeout=60)
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip().splitlines()
        return "none", [f"SSH login failed ({r.summary()}): {err[-1] if err else 'no output'}"], facts
    lines = r.stdout.strip().splitlines()
    facts["user"] = lines[0] if lines else ""
    facts["groups"] = lines[1].split() if len(lines) > 1 else []
    details = [f"SSH login as {facts['user']} (groups: {' '.join(facts['groups']) or '-'})"]
    level = "user"

    d = ssh.run(CMD_DOCKER, timeout=60)
    if d.returncode == 0 and d.stdout.strip():
        facts["docker"] = True
        level = "privileged"
        details.append(f"Docker API usable without sudo (engine {d.stdout.strip()}): docker group is root-equivalent")
    s = ssh.run(CMD_SUDO_LIST, timeout=60)
    if s.returncode == 0 and "may run" in s.stdout:
        facts["sudo"] = s.stdout.strip()
        level = "privileged"
        rules = [l.strip() for l in s.stdout.splitlines() if l.strip().startswith("(")]
        details.append("Passwordless sudo rules: " + ("; ".join(rules) if rules else "present"))
    if level == "user":
        details.append("No docker group and no passwordless sudo: unprivileged user")
    return level, details, facts


def effective(detected: str, ceiling: str) -> str:
    return detected if ceiling == "auto" else lower(detected, ceiling)
