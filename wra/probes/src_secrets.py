"""Internal probe: hard-coded secrets in the application source with trufflehog.

--no-verification: candidate secrets are never sent to provider APIs. stdout (which contains the raw
secret values) is sanitized in memory and never written to disk as is.
"""
from __future__ import annotations

import json

from ..parsers import trufflehog
from ..source import SourceProbe, acquire
from ._tools import tail

OK_CODES = (0, 183)     # 183 = results found (--fail)


class TrufflehogProbe(SourceProbe):
    name = "src-secrets"
    source = "trufflehog"
    tool = "trufflehog"
    order = 62

    def run(self, ctx):
        info = acquire(ctx, self)
        args = ["filesystem", "/src", "--json", "--no-update", "--no-verification"]
        res = ctx.runner.run("trufflehog", args, mounts=self.mounts(info), timeout=1800)
        records = trufflehog.sanitize(res.stdout)
        res.stdout = ""                                   # drop raw secret material
        ctx.store.write_raw(self.phase, "trufflehog.jsonl", "\n".join(json.dumps(r) for r in records))
        ctx.store.write_raw(self.phase, "trufflehog.log",
                            f"$ {' '.join(res.cmd)}\n# {res.summary()}\nsource: {info['origin']}\n"
                            f"results: {len(records)} (values removed)\n\n--- stderr ---\n{res.stderr}")
        if res.returncode not in OK_CODES:
            raise RuntimeError(f"trufflehog failed ({res.summary()}): {tail(res.stderr, 5)}")

        def evidence_for(d: dict, i: int) -> list[str]:
            return [ctx.store.write_evidence(f"trufflehog-{i:03d}.json", json.dumps(d, indent=2))]

        return trufflehog.parse(records, evidence_for)
