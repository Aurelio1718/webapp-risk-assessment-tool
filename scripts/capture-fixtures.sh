#!/usr/bin/env bash
# Developer helper: run every external tool once against the lab targets and pack the raw
# outputs, to (re)build the parser fixtures in tests/fixtures/.
# AUTHORIZED LAB TARGETS ONLY. Passive/non-intrusive settings.
#
# Usage: scripts/capture-fixtures.sh <images-file> <vm-url> [juice-shop-url]
#   images-file: output of scripts/pull-images.sh
#   e.g. scripts/capture-fixtures.sh images.txt https://192.168.122.93/ http://127.0.0.1:3000/
set -uo pipefail

IMAGES_FILE="${1:?images file}"
VM_URL="${2:?vm url}"
JS_URL="${3:-}"
ENGINE="${ENGINE:-podman}"
OUT="output/fixtures"
CACHE="${HOME}/.cache/wra"
VOL=""; [[ -e /sys/fs/selinux/enforce ]] && VOL=":Z"

img() { grep -E "^$1 = " "$IMAGES_FILE" | head -1 | sed -E 's/^[^=]+= //'; }
host_of() { python3 -c 'import sys,urllib.parse as u; print(u.urlsplit(sys.argv[1]).hostname)' "$1"; }
port_of() { python3 -c 'import sys,urllib.parse as u; p=u.urlsplit(sys.argv[1]); print(p.port or {"http":80,"https":443}[p.scheme])' "$1"; }
log() { printf '\n=== %s\n' "$*"; }
rc() { echo "$1 rc=$2" >> "$OUT/RETURN_CODES.txt"; }

mkdir -p "$OUT" "$CACHE/nuclei"
chmod 777 "$OUT"   # ZAP writes as its own user inside the container
: > "$OUT/RETURN_CODES.txt"
RUN=("$ENGINE" run --rm --network host)

capture() {  # $1 = label, $2 = url
  local label="$1" url="$2" host port
  host="$(host_of "$url")"; port="$(port_of "$url")"

  log "nmap $label ($host)"
  local ports="$port"; [[ "$label" == vm ]] && ports="$(printf "22\n80\n443\n%s\n" "$port" | sort -un | paste -sd,)"
  "${RUN[@]}" -v "$PWD/$OUT:/out$VOL" "$(img nmap)" \
    -sT -sV -Pn -T4 -p "$ports" --script ssl-cert,ssl-enum-ciphers,http-title,http-server-header \
    -oX "/out/nmap-$label.xml" "$host" > "$OUT/nmap-$label.stdout.txt" 2>&1
  rc "nmap-$label" $?

  log "zap baseline $label"
  "${RUN[@]}" --userns=keep-id -v "$PWD/$OUT:/zap/wrk$VOL" "$(img zap)" \
    zap-baseline.py -t "$url" -m 1 -I -J "zap-$label.json" > "$OUT/zap-$label.stdout.txt" 2>&1
  rc "zap-$label" $?

  log "nuclei $label"
  [[ -d "$CACHE/nuclei/nuclei-templates" ]] || \
    "${RUN[@]}" -v "$CACHE/nuclei:/root$VOL" "$(img nuclei)" -ut -nc > "$OUT/nuclei-update.txt" 2>&1  # -duc would block it
  timeout 1500 "${RUN[@]}" -v "$CACHE/nuclei:/root$VOL" -v "$PWD/$OUT:/out$VOL" "$(img nuclei)" \
    -u "$url" -jsonl -o "/out/nuclei-$label.jsonl" -duc -ni -nc \
    -exclude-tags dos,intrusive,fuzz,brute-force,bruteforce -rl 50 -timeout 10 \
    > "$OUT/nuclei-$label.stdout.txt" 2>&1
  rc "nuclei-$label" $?
}

capture vm "$VM_URL"

log "ssh-audit vm"
"${RUN[@]}" "$(img ssh-audit)" -j "$(host_of "$VM_URL")" > "$OUT/ssh-audit-vm.json" 2> "$OUT/ssh-audit-vm.stderr.txt"
rc ssh-audit-vm $?

[[ -n "$JS_URL" ]] && capture juiceshop "$JS_URL"

log "versions"
{
  for t in nmap zap nuclei ssh-audit; do echo "$t: $(img "$t")"; done
  "${RUN[@]}" "$(img nmap)" --version 2>&1 | head -1
  "${RUN[@]}" "$(img nuclei)" -version 2>&1 | tail -1
  echo "nuclei templates: $(cat "$CACHE/nuclei/.config/nuclei/.templates-config.json" 2>/dev/null | head -c 300)"
} > "$OUT/VERSIONS.txt"

tar -czf output/fixtures.tar.gz -C output fixtures
log "done"
cat "$OUT/RETURN_CODES.txt"
ls -la "$OUT"
echo "Attach output/fixtures.tar.gz in chat."
