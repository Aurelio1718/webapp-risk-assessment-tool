"""On-disk layout of a run:

<out>/meta.json                 scope, access level, coverage, check results
<out>/<phase>/raw/...           raw tool output
<out>/<phase>/findings.json     normalized findings of the phase
<out>/pentest/pt_log.json       pentest log (checks, outcomes, evidence)
<out>/evidence/...              evidence files referenced by findings
<out>/report.md, findings.csv   final report
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .finding import Finding

PHASES = ("external", "pentest", "internal")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(name: str) -> str:
    n = _SAFE.sub("_", name).strip("._") or "file"
    return n[:120]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class RunStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _mkdir(self, p: Path) -> Path:
        p.mkdir(parents=True, exist_ok=True)
        os.chmod(p, 0o700)  # evidence may contain sensitive target data
        return p

    def ensure(self) -> "RunStore":
        self._mkdir(self.root)
        self._mkdir(self.root / "evidence")
        return self

    def rel(self, p: Path) -> str:
        return str(p.relative_to(self.root))

    def _write(self, p: Path, data: str | bytes) -> Path:
        self._mkdir(p.parent)
        if isinstance(data, bytes):
            p.write_bytes(data)
        else:
            p.write_text(data, encoding="utf-8")
        os.chmod(p, 0o600)
        return p

    # ----- raw & evidence ---------------------------------------------------------------------
    def raw_dir(self, phase: str) -> Path:
        return self._mkdir(self.root / phase / "raw")

    def write_raw(self, phase: str, name: str, data: str | bytes) -> str:
        return self.rel(self._write(self.raw_dir(phase) / safe_name(name), data))

    def write_evidence(self, name: str, data: str | bytes) -> str:
        return self.rel(self._write(self.root / "evidence" / safe_name(name), data))

    def list_raw(self) -> list[str]:
        out = []
        for phase in PHASES:
            d = self.root / phase / "raw"
            if d.is_dir():
                out += sorted(self.rel(p) for p in d.rglob("*") if p.is_file())
        return out

    # ----- findings ---------------------------------------------------------------------------
    def save_findings(self, phase: str, findings: list[Finding]) -> str:
        p = self.root / phase / "findings.json"
        self._write(p, json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False))
        return self.rel(p)

    def load_findings(self, phase: str) -> list[Finding]:
        p = self.root / phase / "findings.json"
        if not p.is_file():
            return []
        return [Finding.from_dict(d) for d in json.loads(p.read_text(encoding="utf-8"))]

    def load_all(self) -> list[Finding]:
        out = []
        for phase in PHASES:
            out += self.load_findings(phase)
        return out

    # ----- pentest log ------------------------------------------------------------------------
    def save_pt_log(self, entries: list[dict]) -> None:
        self._write(self.root / "pentest" / "pt_log.json", json.dumps(entries, indent=2, ensure_ascii=False))

    def load_pt_log(self) -> list[dict]:
        p = self.root / "pentest" / "pt_log.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else []

    # ----- meta -------------------------------------------------------------------------------
    def meta(self) -> dict:
        p = self.root / "meta.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}

    def update_meta(self, **kwargs) -> dict:
        m = self.meta()
        m.update(kwargs)
        m["updated"] = now_iso()
        self._write(self.root / "meta.json", json.dumps(m, indent=2, ensure_ascii=False))
        return m

    def set_coverage(self, phase: str, entries: list[dict]) -> None:
        cov = self.meta().get("coverage", {})
        cov[phase] = entries
        self.update_meta(coverage=cov)
