# webapp-risk-assessment-tool (`wra`) - Risk Assessment & VSPT for web applications

`wra` (WebApp Risk Assessment) is a command-line tool for **Vulnerability Scanning and Penetration
Testing (VSPT)** of a web application, extended with an authorized white-box analysis of the host,
that produces a risk assessment report where **risk = impact x likelihood** (1-5 each, risk 1-25).

**Only a URL is needed** for the VSPT part (vulnerability scanning + penetration testing):

```bash
./wra.py all -c config.ini --active --access-level none     # [target] url set, [ssh] host may be empty
```

When authorized access to the machine that hosts the application is available, `wra` adds the
internal analysis and merges everything into **one table**:

| Phase | What it does | Access needed |
|---|---|---|
| `external` | Black-box reconnaissance and vulnerability scanning of the URL (nmap, OWASP ZAP baseline, Nuclei, ssh-audit, native HTTP/TLS checks) | URL only |
| `pentest` | Targeted, non-destructive verification of the external findings, with outcome (*Confirmed* / *Not confirmed*) and evidence | URL only, `--active` |
| `internal` | White-box, read-only analysis over SSH: source code SAST (Semgrep), hard-coded secrets (trufflehog), vulnerable dependencies and Dockerfile misconfigurations (Trivy), database configuration and permissions, processes, listening services, sshd, firewall, pending updates, containers, file permissions | SSH account, or `--source` for the code only |

### Assignment requirements -> implementation

| Requirement | Where |
|---|---|
| Given the URL, analyse the application from outside and run Vulnerability Scanning | `external` phase ([sources](#6-sources-and-checks)) |
| Penetration Testing phase, with checks, outcomes and evidence documented in the report | `pentest` phase; *Penetration test log* section of the report; [pentest catalog](docs/methodology.md#3-pentest-catalog) |
| Access the host with authorized credentials: static analysis of the source code, database configuration and permissions, processes and services, plus extra information (web server, dependencies, containers) | `internal` phase ([access levels](#4-access-levels-and-required-permissions)) |
| Integrate two or more sources and report external and internal results in a single table | 11 sources, merged and correlated into one table (`report.md`, `findings.csv`) |
| For each issue: element, evidence, PT outcome, impact, likelihood, risk = impact x likelihood | table columns; every value justified in the rationale ([scoring](#7-scoring)) |
| Works with `git clone` + README | standard library only; scanners in containers pinned by digest |

An example of the full report is in [docs/sample-report.md](docs/sample-report.md).

The tool is **generic**: nothing about the target is hard-coded. Every check detects whether it
applies; checks that cannot run (missing access, missing tool, active scans disabled) are listed as
**Not assessed**, so the report always shows the real coverage of the analysis.

> **Authorized use only.** Run `wra` only against systems you own or have written permission to
> test. The tool refuses to run against hosts that are not listed in `[scope]`.

---

## 1. Requirements

On the **auditor machine** (where you run `wra`):

| Requirement | Why |
|---|---|
| Python >= 3.10 (standard library only, no `pip install`) | runs `wra` |
| Podman (rootless) **or** Docker | runs the third-party scanners in containers pinned by digest |
| OpenSSH client | internal analysis and SSH pentest check |
| git | exporting a local source copy with `--source` (tracked files only) |
| Network access to the target URL (and SSH port, for internal analysis) | |
| Internet access on first runs | Nuclei templates, Trivy vulnerability DB, Semgrep registry rules |

On the **target host** nothing is installed. Internal analysis needs an SSH account
(see [access levels](#4-access-levels-and-required-permissions)); the source code is exported with
`git archive`, so `git` must be present on the target if the source is collected over SSH.

**Services that must be running:** the web application under test; the container engine CLI on the
auditor machine (`wra` calls `podman`/`docker` directly, no daemon socket needed with Podman);
`sshd` on the target host for internal analysis; for the database checks, the database container
(PostgreSQL via `docker exec`) or a reachable TCP port.

## 2. Installation

```bash
git clone https://github.com/Aurelio1718/webapp-risk-assessment-tool.git
cd webapp-risk-assessment-tool
cp config.example.ini config.ini
chmod 600 config.ini
```

`config.example.ini` already pins every scanner image **by digest** (resolved on 2026-11-20).
Pull them once:

```bash
for img in $(sed -n 's/^[a-z-]* *= *\(docker\.io[^ ]*@sha256:[0-9a-f]*\)$/\1/p' config.ini); do podman pull "$img"; done
```

To move to newer versions, run `scripts/pull-images.sh podman`, review the vendor advisories for
each version, then paste the printed `[images]` block into `config.ini`. Unpinned images are refused
(supply-chain protection; override only for testing with `runtime.allow_unpinned = yes`).
Trivy is pinned to 0.69.3, whose image signature was verified with cosign: 0.69.4-0.69.6 were
compromised in March 2026.

Then run the prerequisite check (no scanning is performed):

```bash
./wra.py check
```

## 3. Configuration (`config.ini`)

| Section | Key settings |
|---|---|
| `[scope]` | `authorized = yes` only with written authorization; `hosts` = hostnames, IPs or CIDRs allowed for the URL **and** the SSH host |
| `[target]` | `url` of the web application; `insecure_tls = yes` to scan self-signed HTTPS (the certificate is still reported) |
| `[ssh]` | `host`, `port`, `user`, `key_path`, `known_hosts`; leave `host` empty for an external-only assessment |
| `[app]` | optional application directory on the target (`source_path`, must be a git work tree) or compose file path; autodetected from compose files under `/opt`, `/srv`, `/var/www`, `/home` when empty |
| `[db]` | `engine` (`auto` or `postgresql`), `access` (`docker_exec`, `tcp`, `none`), `host`, `port`, `user`, `database`, `container`, optional `password_file` |
| `[runtime]` | `engine` (podman/docker), `mode` (`container`, or `local` to use tools already in `PATH`), `extra_args`, `volume_opts` |
| `[tool_args]` | extra `run` arguments per tool (e.g. `zap = --userns=keep-id`) |
| `[images]` | scanner images pinned by digest |
| `[scoring]` | risk band thresholds |

**Specifying the URL:** set `[target] url = https://host[:port]/` and add the host to `[scope] hosts`.

**Database password:** never in `config.ini` and never on a command line. Provide it via the
environment (it is passed to the remote `psql` on stdin) or via a private file:

```bash
read -rs WRA_DB_PASSWORD && export WRA_DB_PASSWORD      # ... run wra ... then: unset WRA_DB_PASSWORD
install -m 600 /dev/null ~/.wra_db_pw && $EDITOR ~/.wra_db_pw   # or set [db] password_file
```

Use the least-privileged account that the application itself uses: `wra` checks what *that* role can
do (superuser, CREATEROLE, table ownership, TLS, authentication rules).

**Rootless Podman notes:** `extra_args = --network host` lets scanner containers reach a VM on the
libvirt network; `volume_opts = auto` adds `:Z` to bind mounts when SELinux is enabled;
`[tool_args] zap = --userns=keep-id` lets ZAP write its report into the output directory.

## 4. Access levels and required permissions

`wra check` detects the access level and records it in the report. `wra` never tries to escalate
privileges. Use `--access-level none|user|privileged` to cap it (e.g. to respect the agreement with
the client).

| Level | How it is detected | Enables |
|---|---|---|
| `none` | no SSH configured (or `--access-level none`) | external + pentest; source scans only with `--source` |
| `user` | SSH login as an unprivileged user | + host inventory (processes, listening sockets, services, sshd settings, firewall, updates), file permission tests, source export (`git archive`) for SAST / secrets / dependencies |
| `privileged` | the user can use the Docker API (member of the `docker` group) **or** has passwordless `sudo` rules (`sudo -n -l`) | + container inspection, database configuration and permissions via `docker exec` |

Permissions in detail:

- **user**: read access to the application directory and its `.git` (for `git archive`); nothing else.
- **privileged**: membership of the `docker` group. **This is root-equivalent** on the host: grant it
  only for the duration of the assessment (it is itself reported as a finding).
- **database**: the application's own role and its password (see above).

`--source PATH` runs SAST, secret and dependency scanning on a local copy of the code when the
client provides the code but no host access. If `PATH` is a git work tree only **tracked** files are
scanned (`git archive HEAD`), so untracked `.env` files and secrets never reach the scanners.

### Creating the audit accounts on the target (example, Ubuntu)

```bash
sudo useradd -m -s /bin/bash wra-user                 # level "user"
sudo useradd -m -s /bin/bash -G docker wra-priv       # level "privileged" (docker group = root-equivalent!)
```

Install the auditor's public key (`ssh-keygen -t ed25519 -f ~/.ssh/wra_audit`) in each account's
`~/.ssh/authorized_keys` (directory 700, file 600).

### First SSH connection (host key verification)

`wra` always uses `StrictHostKeyChecking=yes` with a dedicated `known_hosts` file. Record the host
key once, manually, comparing the fingerprint with the one printed on the target console
(`sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`):

```bash
ssh -i ~/.ssh/wra_audit -o UserKnownHostsFile=~/.ssh/wra_known_hosts -o StrictHostKeyChecking=ask wra-user@<host> id
```

If the key has a passphrase, load it in the agent first (`ssh-add ~/.ssh/wra_audit`): `wra` uses
`BatchMode=yes`.

## 5. Usage

```bash
./wra.py check                   # prerequisites, scope, images, SSH, access level, DB (no scanning)
./wra.py all                     # check + internal + external + pentest + report (passive)
./wra.py all --active            # full report: also active scans and the pentest verifiers
./wra.py external | pentest | internal
./wra.py report                  # rebuild the report from saved results, without rescanning
```

Common options: `-c config.ini`, `--out DIR` (default `reports/<host>`), `--active`,
`--access-level auto|none|user|privileged`, `--source PATH`, `-v`/`-vv`.

**Complete report, step by step:**

```bash
./wra.py check -c config.ini                       # every line must be PASS (or an accepted WARN)
export WRA_DB_PASSWORD='...'                       # only if [db] is configured
./wra.py all -c config.ini --active
unset WRA_DB_PASSWORD
less reports/<host>/report.md                      # or open findings.csv in a spreadsheet
scripts/acceptance-check.py reports/<host>         # optional: consistency checks on the report
```

External-only assessment (no host access), or code supplied by the client:

```bash
./wra.py all -c config.ini --active --access-level none
./wra.py internal -c config.ini --access-level none --source /path/to/source/repo
```

The internal phase runs **first** in `wra all`: ssh-audit, Nuclei and the SSH pentest check open
unauthenticated SSH connections, and OpenSSH >= 9.8 (`PerSourcePenalties`) then temporarily refuses
the auditor's IP. When running phases separately, run `internal` before `external`, or wait a few
minutes.

Exit codes: `0` ok, `1` `check` found failures, `2` configuration error, `3` scope violation.

### Output

```
reports/<host>/
├── report.md          # scope, access level & coverage, methodology, single findings table, details, PT log, raw outputs
├── findings.csv       # same table, for spreadsheets
├── meta.json          # scope, access level, coverage, check results
├── evidence/          # evidence referenced by each finding
└── external|pentest|internal/
    ├── raw/           # raw tool outputs and the exact commands executed
    ├── source/        # (internal) exported copy of the application source code
    └── findings.json  # normalized findings of the phase
```

Each table row has: element, category (CWE / OWASP Top 10), sources (and how many agree), evidence,
pentest outcome, impact, likelihood, risk and a rationale explaining every value. Findings from
different sources about the same element and issue are merged into one row (e.g. *SSH password
authentication*: Nuclei + pentest + sshd configuration read over SSH).

Files are created with mode 600/700: they contain sensitive data about the target, including a copy
of its source code. `reports/` is git-ignored. See [docs/sample-report.md](docs/sample-report.md)
for an example and [docs/methodology.md](docs/methodology.md) for the methodology.

## 6. Sources and checks

| Phase | Source | What is checked |
|---|---|---|
| external | `wra-http` (native) | security headers, cookies, TLS certificate, HTTP->HTTPS redirect, server banner |
| external | nmap | open ports, service versions, TLS scripts (non-intrusive scripts only) |
| external | OWASP ZAP baseline | spider + passive scan (no attacks) |
| external | Nuclei | CVE / misconfiguration / exposure templates; `dos`, `intrusive`, `fuzz`, `brute-force` excluded; Interactsh disabled (`-ni`) |
| external | ssh-audit | SSH banner and algorithms, when SSH is exposed |
| pentest | `wra-pt` | TLS trust (strict handshake), SSH authentication methods (no password sent), CORS with a foreign Origin, unauthenticated sensitive endpoints, security headers on a fresh response |
| internal | `wra-internal` | processes, listening sockets, services, sshd settings, firewall, pending updates, sensitive file permissions with a real access test (opens the file, reads 0 bytes) |
| internal | `wra-docker` | container user, privileged mode, capabilities, writable root fs, docker.sock mounts, published ports |
| internal | `wra-db` | PostgreSQL role attributes, table ownership, TLS, authentication rules |
| internal | Semgrep | SAST with rulesets chosen from the detected stack (Python, JavaScript, Dockerfile, Flask, ...) |
| internal | Trivy fs | vulnerable dependencies (CVE, CVSS) and Dockerfile misconfigurations |
| internal | trufflehog | hard-coded secrets (the value is never stored or reported) |

## 7. Scoring

- **Impact (1-5)** from a category -> C/I/A effect matrix (`wra/scoring.py`), or from CVSS when a
  source provides it (`ceil(CVSS/2)`), or from the tool's own severity for unknown categories.
- **Likelihood (1-5)**: base 4 if reachable from the auditor's network, 2 if it requires host access;
  -1 if authentication is required; -1 if the issue must be chained with another weakness;
  +1 if a public exploit/template exists. SAST and dependency findings use the tool's likelihood or
  severity, because reachability of the vulnerable code is not verified.
- **Modifiers**: pentest *Confirmed* -> likelihood >= 4; *Not confirmed* -> -1; reachable only from
  localhost -> -1; excessive privileges/exposure -> impact +1.
- **Bands** (configurable): low <= 6, medium <= 12, high > 12.

Every value and every modifier applied is written in the row's rationale.

## 8. Security of the tool itself

- Scope guardrail: targets outside `[scope]` or without `authorized = yes` are refused.
- Passive by default; active scans and pentest verifiers only with `--active`; all checks are non-destructive.
- External commands are argument lists (never a shell); remote scripts are constants in the code;
  values from the configuration are validated and quoted; target output is never put into a command.
- The source archive received from the target is treated as untrusted: size-limited and extracted
  with Python's tarfile `data` filter (no absolute paths, `..` or links outside the destination).
- Scanner images pinned by digest; the source code is mounted read-only into the scanners.
- No secrets in the repository (`config.ini`, `*.local.ini`, `reports/`, keys are git-ignored);
  the DB password only from env or a mode-600 file and only on the remote stdin.
- trufflehog runs with `--no-verification` (candidate secrets are not sent to provider APIs) and its
  output is sanitized in memory before anything is written.

## 9. Known limitations

- Only the Trivy image signature was verified (cosign); the other images are pinned by digest only.
- Semgrep downloads its registry rules from semgrep.dev at every run (`--metrics=off`).
- SAST and dependency findings are static: reachability is not verified and false positives are
  possible (e.g. log messages that merely contain the word "password").
- Nuclei runs without Interactsh: out-of-band (blind) issues are not detected.
- ZAP runs in container mode only; the SSH pentest check does not verify the host key (it only asks
  which authentication methods are offered and never authenticates).
- Database checks support PostgreSQL only.
- The scan is unauthenticated (application credentials are not used).

## 10. After the assessment

```bash
sudo userdel -r wra-user; sudo userdel -r wra-priv     # on the target: remove the audit accounts
rm -rf reports/<host>/internal/source                  # on the auditor machine: copy of the client's code
```

Hand over `reports/<host>/` through a secure channel and delete it when the engagement ends.

## 11. Tests and lab

```bash
python3 -m unittest discover -s tests -v
```

Parsers are tested on real tool outputs captured in the author's lab (`tests/fixtures/`, see its
README). `lab/` contains a compose file for OWASP Juice Shop, a deliberately vulnerable application
useful to see *Confirmed* pentest results.

## 12. Future work

- Lynis host audit (`privileged` level) and log analysis.
- Authenticated DAST (application credentials, ZAP authenticated scan) and sqlmap/ffuf verifiers.
- MySQL/MariaDB database checks.
- HTML report and diff between two runs.
- Signature verification (cosign) for every scanner image.

## 13. References

- OWASP Web Security Testing Guide - https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10 - https://owasp.org/Top10/ · CWE - https://cwe.mitre.org/
- OWASP Juice Shop - https://owasp.org/www-project-juice-shop/
- Nmap - https://nmap.org/ · OWASP ZAP - https://www.zaproxy.org/ · Nuclei - https://github.com/projectdiscovery/nuclei
- ssh-audit - https://github.com/jtesta/ssh-audit · OpenSSH PerSourcePenalties - https://man.openbsd.org/sshd_config#PerSourcePenalties
- Trivy - https://trivy.dev/ · Semgrep - https://semgrep.dev/ · trufflehog - https://github.com/trufflesecurity/trufflehog
- Lynis - https://cisofy.com/lynis/

## License

MIT - see [LICENSE](LICENSE).
