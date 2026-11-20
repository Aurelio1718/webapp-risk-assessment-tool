#!/usr/bin/env python3
"""Acceptance checks on one or more wra run directories (reports/<host>/).

Usage: scripts/acceptance-check.py reports/192.168.122.93 [reports/127.0.0.1 ...]
Checks the delivery requirements on the generated report: single table with every required column,
risk = impact x likelihood, a rationale and evidence for every scored row, coverage/access level,
PT outcomes, external<->internal correlation. Exit code 1 if a check fails.
"""
from __future__ import annotations

import csv
import re
import sys
from collections import Counter
from pathlib import Path

REQUIRED = ["element", "sources", "evidence", "pt_outcome", "impact", "likelihood", "risk", "rationale"]


def check_run(run: Path) -> tuple[list[str], dict]:
    fails, info = [], {}
    csv_path, md_path = run / "findings.csv", run / "report.md"
    if not csv_path.is_file() or not md_path.is_file():
        return [f"{run}: findings.csv or report.md missing (run 'wra report')"], info
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    missing_cols = [c for c in REQUIRED if c not in (rows[0].keys() if rows else REQUIRED)]
    if missing_cols:
        fails.append(f"missing columns: {missing_cols}")
    scored = [r for r in rows if r["pt_outcome"] != "Not assessed" or r["category"] != "N/A"]
    for r in scored:
        rid = r["id"] or r["title"]
        try:
            if int(r["risk"]) != int(r["impact"]) * int(r["likelihood"]):
                fails.append(f"{rid}: risk != impact x likelihood")
        except ValueError:
            fails.append(f"{rid}: impact/likelihood/risk not numeric")
        if not r["rationale"].strip():
            fails.append(f"{rid}: empty rationale")
        ev = [e.strip() for e in r["evidence"].split(";") if e.strip()]
        if not ev:
            fails.append(f"{rid}: no evidence")
        for e in ev:
            if not (run / e).is_file():
                fails.append(f"{rid}: evidence file missing: {e}")
    md = md_path.read_text(encoding="utf-8")
    m = re.search(r"\*\*Access level used:\*\* `([^`]+)`", md)
    if not m:
        fails.append("report.md: access level not stated")
    info["access"] = m.group(1) if m else "?"
    info["rows"] = len(rows)
    info["scored"] = len(scored)
    info["not_assessed"] = len(rows) - len(scored)
    info["pt"] = dict(Counter(r["pt_outcome"] for r in scored))
    info["bands"] = dict(Counter(r["band"] for r in scored))
    info["sources"] = sorted({s.strip() for r in rows for s in r["sources"].split(";") if s.strip()})
    info["correlated"] = [f"{r['id']} {r['title']} [{r['sources']}]" for r in scored
                          if "external" in r["phase"] and "internal" in r["phase"]]
    info["multi_source"] = sum(1 for r in scored if ";" in r["sources"])
    return fails, info


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    all_fails, totals = [], Counter()
    for arg in argv:
        run = Path(arg)
        fails, info = check_run(run)
        print(f"== {run}")
        for k, v in info.items():
            if k == "correlated":
                print(f"  correlated external<->internal: {len(v)}")
                for line in v:
                    print(f"    - {line}")
            else:
                print(f"  {k}: {v}")
        for f in fails:
            print(f"  FAIL {f}")
        all_fails += fails
        for k, v in info.get("pt", {}).items():
            totals[k] += v
        totals["correlated"] += len(info.get("correlated", []))
    print("== checklist")
    checks = [
        ("every scored row: evidence file, rationale, risk = impact x likelihood", not all_fails),
        (">= 1 PT Confirmed", totals["Confirmed"] >= 1),
        (">= 1 PT Not confirmed", totals["Not confirmed"] >= 1),
        (">= 1 issue correlated between external and internal", totals["correlated"] >= 1),
    ]
    for label, ok in checks:
        print(f"  [{'x' if ok else ' '}] {label}")
    return 0 if all(ok for _, ok in checks) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
