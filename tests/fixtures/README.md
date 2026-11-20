# Parser fixtures

Real outputs captured on 2026-11-20 with `scripts/capture-fixtures.sh` against the author's lab:

| File | Tool | Target |
|---|---|---|
| `nmap-vm.xml`, `zap-vm.json`, `nuclei-vm.jsonl`, `ssh-audit-vm.json` | nmap 7.98, ZAP stable, Nuclei 3.11.1, ssh-audit | lab VM (Chess Coach, 192.168.122.93, private libvirt network) |
| `nmap-juiceshop.xml`, `zap-juiceshop.json`, `nuclei-juiceshop.jsonl` | same | OWASP Juice Shop on 127.0.0.1:3000 |
| `semgrep-chesscoach.json`, `trivy-fs-chesscoach.json`, `trufflehog-chesscoach.jsonl` | Semgrep 1.185.0 (p/python, p/flask, p/dockerfile), Trivy 0.69.3 (fs vuln,misconfig), trufflehog 3.100.0 (--no-verification) | Chess Coach source, `git archive HEAD` export (tracked files only) |

Synthetic fixtures (real tool schema, invented data) cover paths the real targets do not exercise:

| File | Why |
|---|---|
| `trivy-fs-synthetic-vuln.json` | the real source has 0 vulnerable dependencies; exercises CVE/CVSS/fix-version parsing and a root-user Dockerfile |
| `trufflehog-synthetic.jsonl` | the real source has 0 secrets; contains a fake value (`FAKE-SECRET-VALUE-DO-NOT-REPORT`) that the tests assert is never stored or reported |

Nuclei request/response bodies are truncated to 2000 characters. No credentials or session values are
contained (checked: ZAP evidence holds cookie names only).
