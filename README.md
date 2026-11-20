# webapp-risk-assessment-tool (`wra`)

Command-line tool for vulnerability scanning and penetration testing (VSPT) of web applications, with
an optional authorized white-box analysis of the host. It produces a risk assessment report with a
single findings table where **risk = impact x likelihood** (1-5 each).

| Phase | What it does | Needs |
|---|---|---|
| `external` | Vulnerability scanning of the URL: nmap, OWASP ZAP baseline, Nuclei, ssh-audit, native HTTP/TLS checks | URL |
| `pentest` | Non-destructive verification of external findings (TLS trust, SSH auth methods, CORS, exposed endpoints, headers), with outcome and evidence | URL, `--active` |
| `internal` | Read-only analysis over SSH: SAST (Semgrep), secrets (trufflehog), dependencies and Dockerfiles (Trivy), PostgreSQL roles and settings, processes, services, sshd, firewall, updates, containers, file permissions | SSH account, or `--source` |

Nothing about the target is hard-coded. Checks that cannot run are reported as **Not assessed**, so
the report shows the real coverage. Example: [docs/sample-report.md](docs/sample-report.md) ·
methodology: [docs/methodology.md](docs/methodology.md).

> **Authorized use only.** `wra` refuses to run against hosts not listed in `[scope]`.

## Requirements

- **Auditor machine:** Python >= 3.10 (standard library only), Podman or Docker, OpenSSH client, git.
  Internet access on first runs (Nuclei templates, Trivy DB, Semgrep rules).
- **Target:** the web application running; for internal analysis `sshd`, an audit account and `git`
  (the source is exported with `git archive`). Nothing is installed on the target.

## Installation

```bash
git clone https://github.com/Aurelio1718/webapp-risk-assessment-tool.git
cd webapp-risk-assessment-tool
cp config.example.ini config.ini && chmod 600 config.ini
for img in $(sed -n 's/^[a-z-]* *= *\(docker\.io[^ ]*@sha256:[0-9a-f]*\)$/\1/p' config.ini); do podman pull "$img"; done
./wra.py check                      # prerequisites, scope, images, SSH, access level, DB - no scanning
```

Scanner images are pinned by digest; unpinned images are refused. To update them:
`scripts/pull-images.sh podman`, review the vendor advisories, paste the printed `[images]` block.

## Configuration

| Section | Settings |
|---|---|
| `[scope]` | `authorized = yes` (only with written authorization), `hosts` allowed for URL and SSH host |
| `[target]` | `url`; `insecure_tls = yes` for self-signed HTTPS (still reported) |
| `[ssh]` | `host`, `port`, `user`, `key_path`, `known_hosts`; empty `host` = external-only |
| `[app]` | application directory on the target (git work tree); autodetected from compose files when empty |
| `[db]` | `engine`, `access` (`docker_exec`, `tcp`, `none`), `user`, `database`, `container` |
| `[runtime]` | `engine` (podman/docker), `mode` (`container`/`local`), `extra_args`, `volume_opts` |

The **database password** is never stored in the config: `export WRA_DB_PASSWORD=...` (sent to the
remote `psql` on stdin) or `[db] password_file` with mode 600. Use the application's own role.

Rootless Podman with a libvirt VM: `extra_args = --network host`; `volume_opts = auto` adds `:Z` on
SELinux; `[tool_args] zap = --userns=keep-id`.

## Access levels and permissions

The level is detected by `wra check`, stated in the report and can be capped with `--access-level`.
`wra` never escalates privileges.

| Level | Requirement on the target | Adds |
|---|---|---|
| `none` | - | external + pentest (`--source PATH` still allows code scanning) |
| `user` | SSH key login; read access to the application directory and its `.git` | host inventory, file permission tests, SAST / secrets / dependencies |
| `privileged` | `docker` group (**root-equivalent**) or passwordless `sudo` rules | container inspection, database checks via `docker exec` |

```bash
sudo useradd -m -s /bin/bash wra-user                 # user
sudo useradd -m -s /bin/bash -G docker wra-priv       # privileged
# install ~/.ssh/wra_audit.pub in ~/.ssh/authorized_keys of each account (700/600), then record the
# host key once, checking the fingerprint against the target console:
ssh -i ~/.ssh/wra_audit -o UserKnownHostsFile=~/.ssh/wra_known_hosts -o StrictHostKeyChecking=ask wra-user@<host> id
```

`wra` uses `StrictHostKeyChecking=yes` and `BatchMode=yes` (load passphrase keys with `ssh-add`).
With `--source PATH` and a git work tree only tracked files are scanned, so untracked `.env` files
and secrets are excluded.

## Usage

```bash
./wra.py check -c config.ini
export WRA_DB_PASSWORD='...'                 # only if [db] is configured
./wra.py all -c config.ini --active          # full report: internal + external + pentest + report
unset WRA_DB_PASSWORD

./wra.py all -c config.ini --active --access-level none           # URL only
./wra.py internal -c config.ini --access-level none --source DIR  # code supplied by the client
./wra.py external | pentest | internal | report                   # single phases; report = no rescan
```

Options: `--out DIR` (default `reports/<host>`), `--active`, `--access-level`, `--source`, `-v`.
Without `--active` only passive checks run. `scripts/acceptance-check.py reports/<host>` verifies the
consistency of a generated report.

`wra all` runs the internal phase first: ssh-audit and Nuclei trigger OpenSSH's `PerSourcePenalties`,
which then refuses the auditor's IP for a short time (the SSH pentest check retries).

**Output** (`reports/<host>/`, mode 600/700, git-ignored): `report.md` (scope, access level and
coverage, methodology, findings table, details, PT log), `findings.csv`, `evidence/`, and per phase
`raw/` (tool outputs and exact commands) and `findings.json`. `internal/source/` holds a copy of the
target's source code.

## Scoring

- **Impact:** category -> C/I/A matrix (`wra/scoring.py`), `ceil(CVSS/2)` when available, or the
  tool's severity.
- **Likelihood:** 4 if reachable from the network, 2 if host access is needed; -1 authentication
  required, -1 needs chaining, +1 public exploit. Static findings use the tool's likelihood.
- **Modifiers:** PT *Confirmed* -> likelihood >= 4; *Not confirmed* -> -1; localhost only -> -1;
  excessive privileges -> impact +1. Bands: low <= 6, medium <= 12, high > 12.

Every value and modifier is written in the row's rationale. Findings from different sources on the
same element and issue are merged into one row (`confidence` = number of sources).

## Security of the tool

- Scope guardrail; passive by default; nothing destructive (no brute force, DoS or exploitation).
- No shell: argument lists only; remote scripts are constants, config values validated and quoted.
- The source archive from the target is size-limited and extracted with tarfile's `data` filter;
  code is mounted read-only into the scanners.
- trufflehog runs with `--no-verification` and secret values are dropped before anything is written.
- No secrets in the repository (`config.ini`, `*.local.ini`, `reports/`, keys are git-ignored).

**Limitations:** only the Trivy image signature was verified (cosign); Semgrep downloads its rules
from semgrep.dev; SAST/dependency findings do not verify reachability; Nuclei runs without
Interactsh (no blind/OOB detection); database checks support PostgreSQL only; unauthenticated scans.

## After the assessment

```bash
sudo userdel -r wra-user; sudo userdel -r wra-priv     # target
rm -rf reports/<host>                                  # auditor, after secure hand-over
```

## Tests and lab

`python3 -m unittest discover -s tests` - parsers are tested on real outputs (`tests/fixtures/`).
`lab/` contains OWASP Juice Shop (127.0.0.1 only) to see *Confirmed* pentest results.

## Future work

Lynis host audit and log analysis · authenticated DAST and sqlmap/ffuf verifiers · MySQL/MariaDB ·
HTML report and run diff · cosign verification for every image.

## References

[OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) ·
[OWASP Top 10](https://owasp.org/Top10/) · [CWE](https://cwe.mitre.org/) ·
[Juice Shop](https://owasp.org/www-project-juice-shop/) · [Nmap](https://nmap.org/) ·
[ZAP](https://www.zaproxy.org/) · [Nuclei](https://github.com/projectdiscovery/nuclei) ·
[ssh-audit](https://github.com/jtesta/ssh-audit) · [Trivy](https://trivy.dev/) ·
[Semgrep](https://semgrep.dev/) · [trufflehog](https://github.com/trufflesecurity/trufflehog) ·
[Lynis](https://cisofy.com/lynis/) ·
[sshd PerSourcePenalties](https://man.openbsd.org/sshd_config#PerSourcePenalties)

## License

MIT - see [LICENSE](LICENSE).
