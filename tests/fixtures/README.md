# Parser fixtures

Real outputs captured on 2026-11-20 with `scripts/capture-fixtures.sh` against the author's lab:

| File | Tool | Target |
|---|---|---|
| `nmap-vm.xml`, `zap-vm.json`, `nuclei-vm.jsonl`, `ssh-audit-vm.json` | nmap 7.98, ZAP stable, Nuclei 3.11.1, ssh-audit | lab VM (Chess Coach, 192.168.122.93, private libvirt network) |
| `nmap-juiceshop.xml`, `zap-juiceshop.json`, `nuclei-juiceshop.jsonl` | same | OWASP Juice Shop on 127.0.0.1:3000 |

Nuclei request/response bodies are truncated to 2000 characters. No credentials or session values are
contained (checked: ZAP evidence holds cookie names only).
