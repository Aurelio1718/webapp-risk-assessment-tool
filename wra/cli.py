"""Command line interface: wra check | external | pentest | internal | report | all."""
from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .checks import print_checks, run_checks
from .config import ConfigError, load_config
from .context import Context
from .phases import run_phase
from .report import build_report
from .scope import ScopeError, enforce_scope
from .ssh import SSHError
from .store import now_iso

EXIT_OK, EXIT_CHECK_FAIL, EXIT_CONFIG, EXIT_SCOPE = 0, 1, 2, 3

COMMANDS = {
    "check": "verify prerequisites, scope, SSH and access level (no scanning)",
    "external": "external analysis and vulnerability scanning of the URL",
    "pentest": "targeted non-destructive verification of findings (active checks need --active)",
    "internal": "white-box analysis of the host over SSH (read-only)",
    "report": "rebuild report.md and findings.csv from saved results",
    "all": "check + external + pentest + internal + report",
}


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default="config.ini", help="configuration file (default: config.ini)")
    common.add_argument("--out", help="run directory (default: reports/<target-host>)")
    common.add_argument("--active", action="store_true", help="enable active scans and active pentest checks")
    common.add_argument("--access-level", choices=["auto", "none", "user", "privileged"], default="auto",
                        help="maximum access level to use on the target host (default: auto-detect)")
    common.add_argument("--source", help="local copy of the application source code (SAST without host access)")
    common.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")

    p = argparse.ArgumentParser(prog="wra", description="WebApp Risk Assessment: VS + PT + internal analysis, "
                                                        "risk = impact x likelihood. Authorized targets only.")
    p.add_argument("--version", action="version", version=f"wra {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")
    for name, help_text in COMMANDS.items():
        sub.add_parser(name, parents=[common], help=help_text, description=help_text)
    return p


def setup_logging(verbosity: int) -> None:
    level = logging.WARNING if verbosity == 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    if verbosity == 0:
        logging.getLogger("wra.phase").setLevel(logging.INFO)


def _phase(ctx, phase: str) -> None:
    findings = run_phase(ctx, phase)
    na = sum(1 for f in findings if f.not_assessed)
    print(f"[{phase}] {len(findings) - na} finding(s), {na} check(s) not assessed -> {ctx.store.root}/{phase}/")


def _report(ctx) -> None:
    md, csv_path, n = build_report(ctx.store, ctx.config.scoring.low_max, ctx.config.scoring.medium_max)
    print(f"[report] {n} row(s): {ctx.store.root / md} and {ctx.store.root / csv_path}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    if args.command != "check":
        try:
            notes = enforce_scope(config)
        except ScopeError as exc:
            print(f"SCOPE VIOLATION - refusing to run: {exc}", file=sys.stderr)
            return EXIT_SCOPE
    else:
        notes = []

    try:
        ctx = Context(config, args)
    except SSHError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    ssh_label = f"{config.ssh.user}@{config.ssh.host}:{config.ssh.port}" if config.ssh.enabled else ""
    scope_meta = {"url": config.target.url, "hosts": config.scope.hosts, "ssh": ssh_label}
    if notes:
        scope_meta["notes"] = notes
    meta = ctx.store.meta()
    active = bool(meta.get("active", False)) if args.command == "report" else bool(args.active)
    ctx.store.update_meta(scope={**meta.get("scope", {}), **scope_meta}, active=active,
                          started=meta.get("started", now_iso()))

    try:
        if args.command == "check":
            return print_checks(run_checks(ctx))
        if args.command in ("external", "pentest", "internal"):
            _phase(ctx, args.command)
            return EXIT_OK
        if args.command == "report":
            _report(ctx)
            return EXIT_OK
        if args.command == "all":
            rc = print_checks(run_checks(ctx))
            if rc != EXIT_OK:
                print("check reported failures: continuing, affected modules will be marked 'Not assessed'",
                      file=sys.stderr)
            for phase in ("external", "pentest", "internal"):
                _phase(ctx, phase)
            _report(ctx)
            return EXIT_OK
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return EXIT_OK
