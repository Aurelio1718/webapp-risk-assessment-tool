# Methodology

`wra` follows the structure of a classic web application assessment (OWASP WSTG): information
gathering and automated vulnerability scanning from outside, manual-style verification of what was
found, and a white-box review with authorized access. The OWASP WSTG warns that black-box automated
testing alone is often not effective: the pentest and internal phases exist to compensate for that.

## 1. Rules of engagement

- The target URL host and the SSH host must be listed in `[scope] hosts` and `authorized = yes` must
  be set: otherwise `wra` refuses to start.
- Default mode is passive. `--active` enables scans that send crafted requests (ZAP spider, Nuclei
  templates) and the pentest verifiers. Nothing is destructive: no brute force, no DoS templates,
  no exploitation, no writes on the target.
- The access level actually used (`none`, `user`, `privileged`) is detected, can be capped with
  `--access-level`, and is stated in the report.

## 2. Phases

| # | Phase | Approach | Output |
|---|---|---|---|
| 1 | Internal (white-box) | Agentless SSH with constant, read-only remote scripts. The source code is exported with `git archive HEAD` (tracked files only) and scanned on the auditor's machine | host, file-permission, container, database and source-code findings |
| 2 | External (black-box) | nmap, ZAP baseline, Nuclei, ssh-audit and native HTTP/TLS checks against the URL | findings with the raw tool output as evidence |
| 3 | Pentest | One verifier per class of external finding, each with a single, minimal, non-destructive test | outcome *Confirmed* / *Not confirmed* per finding, PT log with request/response evidence |
| 4 | Correlation and scoring | merge, score, sort | single table (Markdown + CSV) |

The internal phase runs first because the external SSH checks trigger OpenSSH's
`PerSourcePenalties`, which would temporarily block the internal SSH session.

## 3. Pentest catalog

| Verifier | Verifies | Test performed | Confirmed when |
|---|---|---|---|
| `pt-tls-trust` | untrusted / mismatched certificate | strict TLS handshake (CA chain + hostname) | the handshake fails |
| `pt-ssh-auth-methods` | SSH password authentication | SSH connection with `PreferredAuthentications=none`: the server lists its methods; no password is sent | `password` or `keyboard-interactive` is offered |
| `pt-cors` | permissive CORS | request with a fictitious foreign `Origin` | the origin (or `*`) is allowed in the response |
| `pt-exposed-endpoint` | API specs, metrics reachable | unauthenticated GET of the reported endpoint | HTTP 200 with the expected content |
| `pt-security-headers` | missing security headers | fresh GET, headers re-checked | the header is still missing |

Internal file-permission findings carry their own access test: the audit user (not the owner) opens
the file and reads 0 bytes, so the content is never transferred. A readable file is *Confirmed*; a
permissive mode protected by a non-traversable parent directory is *Not confirmed*.

## 4. Correlation

Each source normalizes its results into a `Finding` with an element (URL origin, `ssh://host:port`,
`file://host/path`, `src://path:line`, `pkg:type/name@version`, container) and a canonical
`check_id`. Findings with the same normalized element and `check_id` are merged into one row: sources
and evidence are united and `confidence` is the number of agreeing sources. Example: *SSH password
authentication* is reported by Nuclei (external), confirmed by `pt-ssh-auth-methods` (pentest) and
read in `sshd_config` (internal) - one row, three sources.

## 5. Scoring

Risk = impact x likelihood, both 1-5 (risk 1-25), the same scheme used for the Linux host risk
assessment tool of the course.

- Impact: category -> effect on confidentiality/integrity/availability (matrix in `wra/scoring.py`),
  or `ceil(CVSS/2)` when the source provides CVSS, or the tool's severity for categories not in the
  matrix (the rationale says which).
- Likelihood: base 4 when reachable from the auditor's network, 2 when host access is required;
  -1 authentication required, -1 needs chaining with another weakness, +1 public exploit/template.
  Static findings (SAST, dependencies) use the tool's likelihood/severity because reachability is
  not verified.
- Deterministic modifiers: pentest *Confirmed* -> likelihood >= 4; *Not confirmed* -> -1; reachable
  only from localhost -> -1; excessive privileges/exposure -> impact +1.
- Bands: low <= 6, medium <= 12, high > 12 (configurable in `[scoring]`).

Every value and every modifier is written into the row's rationale; checks that could not run are
listed as *Not assessed* with the reason, so coverage is explicit and never silently reduced.

## 6. Evidence handling

- Raw tool outputs and the exact commands are kept in `<phase>/raw/`; per-finding evidence in
  `evidence/`. All files are created 600/700.
- Secret values are never stored: trufflehog output is sanitized in memory; the database password is
  only sent on the remote stdin; file-permission tests read 0 bytes.
- The report directory contains a copy of the client's source code (`internal/source/`) and must be
  handed over securely and deleted at the end of the engagement.
