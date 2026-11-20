"""Internal probe: SAST of the application source with Semgrep (runs on the auditor's machine).

Rulesets are chosen from the detected stack (generic: no target-specific rules). Registry rulesets
(p/...) are downloaded from semgrep.dev at run time; --metrics=off disables telemetry.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..parsers import semgrep
from ..source import SourceProbe, acquire
from ._tools import save_run, tail

STACK_RULES = [  # (glob, rulesets)
    ("*.py", ["p/python"]),
    ("*.js", ["p/javascript"]),
    ("*.ts", ["p/typescript"]),
    ("*.php", ["p/php"]),
    ("*.go", ["p/golang"]),
    ("*.java", ["p/java"]),
    ("*.rb", ["p/ruby"]),
    ("Dockerfile*", ["p/dockerfile"]),
]
FRAMEWORK_HINTS = {"flask": "p/flask", "django": "p/django"}


def rulesets(root: Path) -> list[str]:
    out: list[str] = []
    files = [p for p in root.rglob("*") if p.is_file() and "node_modules" not in p.parts]
    for pattern, rules in STACK_RULES:
        if any(p.match(pattern) for p in files):
            out += [r for r in rules if r not in out]
    manifests = " ".join(p.read_text(errors="replace").lower()[:200_000] for p in files
                         if p.name in ("requirements.txt", "pyproject.toml", "package.json", "Pipfile"))
    out += [r for k, r in FRAMEWORK_HINTS.items() if k in manifests and r not in out]
    return out or ["p/default"]


class SemgrepProbe(SourceProbe):
    name = "src-semgrep"
    source = "semgrep"
    tool = "semgrep"
    order = 60

    def run(self, ctx):
        info = acquire(ctx, self)
        rules = rulesets(Path(info["path"]))
        args = ["scan"]
        for r in rules:
            args += ["--config", r]
        args += ["--json", "--metrics=off", "--disable-version-check", "/src"]
        res = ctx.runner.run("semgrep", args, mounts=self.mounts(info), entrypoint="semgrep", timeout=1800)
        ctx.store.write_raw(self.phase, "semgrep.json", res.stdout)
        save_run(ctx, self.phase, "semgrep", res)
        if res.returncode not in (0, 1):        # 1 = findings present
            raise RuntimeError(f"semgrep failed ({res.summary()}): {tail(res.stderr, 5)}")
        data = semgrep.load(res.stdout)
        ctx.store.write_raw(self.phase, "semgrep-summary.txt",
                            f"source: {info['origin']}\nrulesets: {', '.join(rules)}\n"
                            f"files scanned: {len((data.get('paths') or {}).get('scanned', []))}\n"
                            f"results: {len(data.get('results', []))}\nerrors: {len(data.get('errors', []))}\n")

        def evidence_for(r: dict, i: int) -> list[str]:
            body = {k: r.get(k) for k in ("check_id", "path", "start", "end")}
            body["message"] = (r.get("extra") or {}).get("message")
            body["metadata"] = (r.get("extra") or {}).get("metadata")
            body["source"] = info["origin"]
            return [ctx.store.write_evidence(f"semgrep-{i:03d}.json", json.dumps(body, indent=2))]

        return semgrep.parse(res.stdout, evidence_for)
