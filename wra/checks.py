"""`wra check`: verify prerequisites before an assessment (read-only, no scanning)."""
from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

from .config import ConfigError
from .http import fetch
from .scope import host_in_scope

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"


def _file_private(path: str) -> tuple[bool, str]:
    p = Path(path)
    if not p.exists():
        return False, f"{p} does not exist"
    mode = p.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return False, f"{p} is {stat.filemode(mode)}, expected 600"
    return True, f"{p} ({stat.filemode(mode)})"


def run_checks(ctx) -> list[tuple[str, str, str]]:
    cfg = ctx.config
    res: list[tuple[str, str, str]] = []
    add = lambda name, status, detail: res.append((name, status, detail))  # noqa: E731

    # --- local environment -------------------------------------------------------------------
    v = sys.version_info
    add("python", PASS if v >= (3, 10) else FAIL, f"{v.major}.{v.minor}.{v.micro} (>= 3.10 required)")
    cfg_mode = Path(cfg.path).stat().st_mode
    add("config file", WARN if cfg_mode & stat.S_IRWXO else PASS,
        f"{cfg.path} ({stat.filemode(cfg_mode)})" + (" - world-readable, run chmod 600" if cfg_mode & stat.S_IRWXO else ""))

    ok, detail = ctx.runner.engine_version()
    if cfg.runtime.mode == "local":
        add("runtime", PASS if ok else WARN, f"mode local; engine: {detail}")
    else:
        add("runtime", PASS if ok else FAIL, detail)
    for tool in sorted(cfg.images):
        status, detail = ctx.runner.image_status(tool)
        add(f"image {tool}", status, detail)

    # --- scope & target ----------------------------------------------------------------------
    ok, reason = host_in_scope(cfg.target.host, cfg.scope.hosts)
    add("scope authorized", PASS if cfg.scope.authorized else FAIL,
        "scope.authorized = yes" if cfg.scope.authorized else "set scope.authorized = yes after obtaining authorization")
    add("scope target", PASS if ok else FAIL, reason)
    authorized = cfg.scope.authorized
    r = None
    if not (authorized and ok):
        add("target reachable", SKIP, "not contacted: target not authorized/in scope")
    else:
        r = fetch(cfg.target.url, timeout=cfg.target.timeout, insecure=cfg.target.insecure_tls, method="HEAD")
    if r is None:
        pass
    elif r.error:
        add("target reachable", FAIL, f"{cfg.target.url}: {r.error}")
    else:
        add("target reachable", PASS, f"{cfg.target.url}: HTTP {r.status} {r.reason}")

    # --- SSH & access level ------------------------------------------------------------------
    if ctx.ceiling == "none":
        add("ssh", SKIP, "--access-level none")
    elif not cfg.ssh.enabled:
        add("ssh", SKIP, "ssh.host empty: access level none (external + pentest only)")
    else:
        ok, reason = host_in_scope(cfg.ssh.host, cfg.scope.hosts)
        add("scope ssh host", PASS if ok else FAIL, reason)
        if shutil.which("ssh") is None:
            add("ssh client", FAIL, "ssh not found in PATH")
        key_ok = Path(cfg.ssh.key_path).is_file()
        add("ssh key", PASS if key_ok else FAIL, cfg.ssh.key_path + ("" if key_ok else " not found"))
        kh_ok = Path(cfg.ssh.known_hosts).is_file()
        add("ssh known_hosts", PASS if kh_ok else FAIL,
            cfg.ssh.known_hosts + ("" if kh_ok else " not found: do the first manual connection (README)"))
        if not authorized:
            add("ssh login", SKIP, "not attempted: scope.authorized is not yes")
        elif ok and key_ok and kh_ok:
            acc = ctx.access(refresh=True)
            status = PASS if acc["detected"] != "none" else FAIL
            add("ssh login", status, "; ".join(acc["details"]))
    acc = ctx.access() if (authorized or ctx.ceiling == "none" or not cfg.ssh.enabled) else {
        "effective": "none", "detected": "not attempted", "ceiling": ctx.ceiling}
    add("access level", PASS, f"effective {acc['effective']} (detected {acc['detected']}, ceiling {acc['ceiling']})")

    # --- database ----------------------------------------------------------------------------
    db = cfg.db
    if db.access == "none":
        add("database", SKIP, "db.access = none")
    else:
        if os.environ.get("WRA_DB_PASSWORD"):
            add("db password", PASS, "from env WRA_DB_PASSWORD")
        elif db.password_file:
            okf, d = _file_private(db.password_file)
            add("db password", PASS if okf else FAIL, d)
        else:
            add("db password", WARN, "not provided: DB checks limited to what docker exec allows without password")
        add("database", PASS, f"engine {db.engine}, access {db.access}, user {db.user or '(autodetect)'}")

    # --- source code -------------------------------------------------------------------------
    if ctx.source_path:
        add("source (--source)", PASS if Path(ctx.source_path).is_dir() else FAIL, ctx.source_path)

    ctx.store.update_meta(check=[{"check": n, "status": s, "detail": d} for n, s, d in res])
    return res


def print_checks(results) -> int:
    width = max(len(n) for n, _, _ in results)
    for name, status, detail in results:
        print(f"[{status:4}] {name:<{width}}  {detail}")
    fails = sum(1 for _, s, _ in results if s == FAIL)
    warns = sum(1 for _, s, _ in results if s == WARN)
    print(f"\n{len(results)} checks: {fails} FAIL, {warns} WARN")
    return 1 if fails else 0


__all__ = ["run_checks", "print_checks", "ConfigError"]
