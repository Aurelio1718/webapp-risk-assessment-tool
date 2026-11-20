"""Finding model shared by every probe, plus normalization helpers."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from urllib.parse import urlsplit

PT_CONFIRMED = "Confirmed"
PT_NOT_CONFIRMED = "Not confirmed"
PT_NOT_TESTED = "Not tested"
PT_NOT_ASSESSED = "Not assessed"
PT_ORDER = [PT_CONFIRMED, PT_NOT_CONFIRMED, PT_NOT_TESTED, PT_NOT_ASSESSED]

NOT_ASSESSED_CATEGORY = "N/A"


@dataclass
class Finding:
    title: str
    element: str
    category: str                      # CWE id, e.g. "CWE-693"
    check_id: str                      # canonical issue key used to correlate sources
    phase: str                         # external | pentest | internal
    sources: list[str]
    evidence: list[str] = field(default_factory=list)   # paths relative to the run directory
    description: str = ""
    owasp: str = ""                    # OWASP Top 10 2021 id, e.g. "A05"
    pt_outcome: str = PT_NOT_TESTED
    impact: int | None = None
    likelihood: int | None = None
    risk: int | None = None
    band: str = ""
    rationale: list[str] = field(default_factory=list)
    remediation: str = ""
    # scoring inputs (outputs impact/likelihood/risk are always recomputed from these):
    # external, auth_required, requires_chain, public_exploit, localhost_only, excessive_privilege, cvss,
    # impact / likelihood (explicit override by a source, must come with a rationale line)
    factors: dict = field(default_factory=dict)
    confidence: int = 1
    id: str = ""

    @property
    def not_assessed(self) -> bool:
        return self.pt_outcome == PT_NOT_ASSESSED and self.category == NOT_ASSESSED_CATEGORY

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


def not_assessed(element: str, check_id: str, phase: str, source: str, reason: str) -> Finding:
    """A check that could not run: keeps the report honest about coverage."""
    return Finding(
        title=f"Not assessed - {reason}",
        element=element,
        category=NOT_ASSESSED_CATEGORY,
        check_id=f"not-assessed:{check_id}",
        phase=phase,
        sources=[source],
        pt_outcome=PT_NOT_ASSESSED,
        rationale=[f"Not assessed: {reason}"],
    )


def normalize_element(element: str) -> str:
    """Canonical form so the same element from different tools merges into one row."""
    e = (element or "").strip()
    if "://" in e:
        p = urlsplit(e)
        host = (p.hostname or "").lower()
        default = {"http": 80, "https": 443}.get(p.scheme.lower())
        port = f":{p.port}" if p.port and p.port != default else ""
        path = p.path.rstrip("/")
        q = f"?{p.query}" if p.query else ""
        return f"{p.scheme.lower()}://{host}{port}{path}{q}"
    return e.rstrip("/") if e not in ("/",) else e


def origin(url: str) -> str:
    p = urlsplit(url)
    return normalize_element(f"{p.scheme}://{p.netloc}")
