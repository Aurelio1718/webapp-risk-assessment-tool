"""Merge findings from different sources/phases into one row per (element, issue)."""
from __future__ import annotations

from .finding import PT_ORDER, Finding, normalize_element


def merge_key(f: Finding) -> tuple[str, str]:
    return normalize_element(f.element), (f.check_id or f.category).lower()


def _uniq(items):
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def merge(findings: list[Finding]) -> list[Finding]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault(merge_key(f), []).append(f)
    merged = []
    for (element, _), group in groups.items():
        base = Finding.from_dict(group[0].to_dict())
        base.element = element
        if len(group) > 1:
            base.sources = _uniq(s for g in group for s in g.sources)
            base.evidence = _uniq(e for g in group for e in g.evidence)
            base.phase = "+".join(_uniq(g.phase for g in group))
            base.pt_outcome = min((g.pt_outcome for g in group), key=PT_ORDER.index)
            base.description = "\n".join(_uniq(g.description for g in group if g.description))
            base.remediation = next((g.remediation for g in group if g.remediation), "")
            base.owasp = next((g.owasp for g in group if g.owasp), "")
            factors: dict = {}
            for g in group:
                for k, v in g.factors.items():
                    if isinstance(v, bool):
                        factors[k] = factors.get(k, False) or v
                    elif isinstance(v, (int, float)) and k in factors:
                        factors[k] = max(factors[k], v)
                    else:
                        factors.setdefault(k, v)
            base.factors = factors
            base.rationale = _uniq(r for g in group for r in g.rationale)
        base.confidence = len(set(base.sources))
        merged.append(base)
    return merged
