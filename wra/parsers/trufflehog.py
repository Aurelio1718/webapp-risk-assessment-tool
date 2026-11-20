"""trufflehog JSON-lines (filesystem --json) parser.

The secret value never leaves this module: Raw/RawV2/Redacted/ExtraData are dropped by sanitize()
before anything is stored, and findings only carry detector, file, line and verification state.
"""
from __future__ import annotations

import json

from ..finding import PT_CONFIRMED, PT_NOT_TESTED
from ..internal import ifinding
from ..source import src_el

SOURCE = "trufflehog"
SECRET_KEYS = ("Raw", "RawV2", "Redacted", "ExtraData", "StructuredData")


def sanitize(text: str) -> list[dict]:
    """Keep only result records (log lines and non-JSON are skipped), without secret material."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if "DetectorName" not in d:
            continue
        for k in SECRET_KEYS:
            d.pop(k, None)
        out.append(d)
    return out


def location(d: dict) -> tuple[str, int | None]:
    data = (d.get("SourceMetadata") or {}).get("Data") or {}
    fs = data.get("Filesystem") or data.get("Git") or {}
    return fs.get("file", "?"), fs.get("line")


def parse(records: list[dict], evidence_for) -> list:
    out = []
    for i, d in enumerate(records):
        path, line = location(d)
        verified = bool(d.get("Verified"))
        det = d.get("DetectorName", "?")
        out.append(ifinding(
            SOURCE, title=f"Hard-coded secret ({det})", element=src_el(path, line), category="CWE-798",
            owasp="A07", check_id="hardcoded-secret", evidence=evidence_for(d, i),
            pt_outcome=PT_CONFIRMED if verified else PT_NOT_TESTED,
            factors={"likelihood": 3},
            rationale=["Secret in tracked source: readable by anyone with access to the repository or the image",
                       "Verified by trufflehog (credential is live)" if verified else
                       "Not verified (wra runs trufflehog with --no-verification: candidates are not sent to provider APIs)"],
            description=f"Detector: {det} ({d.get('DetectorDescription', '').strip()})\nFile: {path}"
                        + (f" line {line}" if line else "") + "\nThe secret value is intentionally not reported.",
            remediation="Remove the secret from the code and from git history, rotate it, and load it from a "
                        "secret file or environment variable at runtime."))
    return out
