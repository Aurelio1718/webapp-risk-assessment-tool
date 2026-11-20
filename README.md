# webapp-risk-assessment-tool (`wra`)

`wra` (WebApp Risk Assessment) is a command-line tool that assesses the security of a web application
and produces a risk assessment report where **risk = impact x likelihood** (1-5 each, risk 1-25).

It combines three analyses and merges their results into **one table**:

| Phase | What it does | Access needed |
|---|---|---|
| `external` | Black-box reconnaissance and vulnerability scanning of the URL | URL only |
| `pentest` | Targeted, non-destructive verification of the external findings, with outcome and evidence | URL only |
| `internal` | White-box, read-only analysis of the host over SSH: source code (SAST), secrets, dependencies, database permissions, processes, services, containers, web server configuration | SSH account |

The tool is generic: nothing about the target is hard-coded. Every check detects whether it applies,
and checks that cannot run (missing access, missing tool, disabled active scans) are listed as
**Not assessed** so the report always shows the real coverage of the analysis.

> **Authorized use only.** Run `wra` only against systems you own or have written permission to
> test. The tool refuses to run against hosts that are not listed in `[scope]`.

> **Status (work in progress):** core, configuration, scope guardrail, container runner, scoring,
> correlation, report and `wra check` are implemented; the native `http-headers` probe is the first
> source. Third-party tool probes (nmap, ZAP, Nuclei, ssh-audit, Trivy, Semgrep, trufflehog, Lynis)
> and pentest/internal checks are being added.

---

## 1. Requirements

On the **auditor machine** (where you run `wra`):

| Requirement | Why |
|---|---|
| Python >= 3.10 (standard library only, no `pip install`) | runs `wra` |
| Podman (rootless) **or** Docker | runs the third-party scanners in pinned containers |
| OpenSSH client | internal analysis over SSH |
| Network access to the target URL (and SSH port, for internal analysis) | |

On the **target host**: nothing is installed. Internal analysis needs only an SSH account
(see [access levels](#4-access-levels-and-required-permissions)).

Services that must be running: the web application under test; the container engine CLI on the
auditor machine (`wra` calls `podman`/`docker` directly, no socket needed); `sshd` on the target host
for internal analysis.

## 2. Installation

```bash
git clone https://github.com/Aurelio1718/webapp-risk-assessment-tool.git
cd webapp-risk-assessment-tool
cp config.example.ini config.ini
chmod 600 config.ini
```

Pull the scanner images once and pin them **by digest** in `config.ini` (`[images]`):

```bash
for img in docker.io/instrumentisto/nmap docker.io/zaproxy/zap-stable docker.io/projectdiscovery/nuclei \
           docker.io/positronsecurity/ssh-audit docker.io/aquasec/trivy docker.io/semgrep/semgrep \
           docker.io/trufflesecurity/trufflehog; do
  podman pull "$img" && podman image inspect --format '{{index .RepoDigests 0}}' "$img"
done
```

Copy each `repository@sha256:...` line into `[images]`. Unpinned images are refused
(supply-chain protection; override only for testing with `runtime.allow_unpinned = yes`).
Before pinning, check the vendor's security advisories for the version you pulled.

## 3. Configuration (`config.ini`)

| Section | Key settings |
|---|---|
| `[scope]` | `authorized = yes` only with written authorization; `hosts` = hostnames, IPs or CIDRs allowed |
| `[target]` | `url` of the web application; `insecure_tls = yes` to scan self-signed HTTPS (still reported) |
| `[ssh]` | `host`, `port`, `user`, `key_path`, `known_hosts`; leave `host` empty for external-only |
| `[app]` | optional source/compose paths on the target (autodetected when empty) |
| `[db]` | `engine`, `access` (`docker_exec`, `tcp`, `none`), `user`, `database`, `container` |
| `[runtime]` | `engine` (podman/docker), `mode` (container/local), `extra_args`, `volume_opts` |
| `[images]` | scanner images pinned by digest |
| `[scoring]` | risk band thresholds |

**Specifying the URL:** set `[target] url = https://host[:port]/` and add the host to `[scope] hosts`.

**Database password:** never in `config.ini`. Provide it via the environment or a private file:

```bash
read -rs WRA_DB_PASSWORD && export WRA_DB_PASSWORD     # or:
install -m 600 /dev/null ~/.wra_db_pw && $EDITOR ~/.wra_db_pw   # then set [db] password_file
```

**Rootless Podman notes:** `extra_args = --network host` lets scanner containers reach a VM on the
libvirt network; `volume_opts = auto` adds `:Z` to bind mounts when SELinux is enabled;
`[tool_args] zap = --userns=keep-id` lets ZAP write its report into the output directory.

## 4. Access levels and required permissions

`wra check` detects the access level and records it in the report. `wra` never tries to escalate
privileges. Use `--access-level none|user|privileged` to cap it (e.g. to respect the agreement with
the client).

| Level | How | Enables |
|---|---|---|
| `none` | URL only, no SSH | external + pentest |
| `user` | SSH as an unprivileged user | + SAST on readable code, dependency manifests, user processes/ports, readable configs, installed versions |
| `privileged` | SSH user in the `docker` group **or** with targeted passwordless `sudo` rules | + container inspection, DB roles/permissions, protected web server configs, secrets files permissions, full Lynis |

`--source PATH` runs SAST on a local copy of the source code when the client provides the code but
no host access.

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

### Cleanup after the assessment

```bash
sudo userdel -r wra-user; sudo userdel -r wra-priv
```

## 5. Usage

```bash
./wra.py check                   # prerequisites, scope, images, SSH, access level, DB (no scanning)
./wra.py all                     # check + external + pentest + internal + report (passive)
./wra.py all --active            # also active scans and active pentest checks
./wra.py external | pentest | internal
./wra.py report                  # rebuild the report from saved results, without rescanning
```

Common options: `-c config.ini`, `--out DIR` (default `reports/<host>`), `--active`,
`--access-level auto|none|user|privileged`, `--source PATH`, `-v`/`-vv`.

Exit codes: `0` ok, `1` `check` found failures, `2` configuration error, `3` scope violation.

### Output

```
reports/<host>/
├── report.md          # scope, access level & coverage, methodology, single findings table, PT log, raw outputs
├── findings.csv       # same table, for spreadsheets
├── meta.json          # scope, access level, coverage, check results
├── evidence/          # evidence referenced by each finding
└── external|pentest|internal/
    ├── raw/           # raw tool outputs
    └── findings.json  # normalized findings of the phase
```

Each table row has: element, category (CWE / OWASP Top 10), sources (and how many agree), evidence,
pentest outcome, impact, likelihood, risk and a rationale explaining every value.
Files are created with mode 600/700: they contain sensitive data about the target.

## 6. Scoring

- **Impact (1-5)** from a category -> C/I/A effect matrix (`wra/scoring.py`), or from CVSS when a
  source provides it (`ceil(CVSS/2)`).
- **Likelihood (1-5)**: base 4 if reachable from the auditor's network, 2 if it requires host access;
  -1 if authentication is required; -1 if the issue must be chained with another weakness;
  +1 if a public exploit/template exists.
- **Modifiers**: pentest *Confirmed* -> likelihood >= 4; *Not confirmed* -> -1; reachable only from
  localhost -> -1; excessive privileges/exposure -> impact +1.
- **Bands** (configurable): low <= 6, medium <= 12, high > 12.

## 7. Security of the tool itself

- Scope guardrail: targets outside `[scope]` or without `authorized = yes` are refused.
- Passive by default; active scans only with `--active`.
- External commands are argument lists (never a shell); target output is never put into a command.
- Scanner images pinned by digest; no secrets in the repository (`config.ini`, `reports/`, keys are
  git-ignored); DB password only from env or a mode-600 file.

## 8. Tests

```bash
python3 -m unittest discover -s tests -v
```

## 9. Future work

- HTML report.
- Authenticated DAST (application credentials).

## 10. References

- OWASP Web Security Testing Guide - https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10 - https://owasp.org/Top10/
- CWE - https://cwe.mitre.org/
- OWASP Juice Shop - https://juice-shop.github.io/
- Nmap - https://nmap.org/ · ZAP - https://www.zaproxy.org/ · Nuclei - https://github.com/projectdiscovery/nuclei
- Lynis - https://cisofy.com/lynis/ · Trivy - https://trivy.dev/ · Semgrep - https://semgrep.dev/
- sqlmap - https://sqlmap.org/ · ffuf - https://github.com/ffuf/ffuf

## License

MIT - see [LICENSE](LICENSE).
