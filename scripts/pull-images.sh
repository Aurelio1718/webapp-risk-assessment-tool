#!/usr/bin/env bash
# Pull the scanner images and print an [images] block pinned by digest.
# Usage: scripts/pull-images.sh [podman|docker] > images.txt
# Uses skopeo (preinstalled on Fedora Atomic/Bazzite) when available.
# Review the vendor advisories for each pulled version BEFORE pasting the block into config.ini.
set -euo pipefail

ENGINE="${1:-podman}"
command -v "$ENGINE" >/dev/null || { echo "error: $ENGINE not found" >&2; exit 1; }

# key in [images] -> image reference to pull (tags are resolved to digests below)
IMAGES=(
  "nmap=docker.io/instrumentisto/nmap:latest"
  "zap=docker.io/zaproxy/zap-stable:latest"
  "nuclei=docker.io/projectdiscovery/nuclei:latest"
  "ssh-audit=docker.io/positronsecurity/ssh-audit:latest"
  # Trivy pinned to 0.69.3: 0.69.4-0.69.6 were compromised (March 2026).
  "trivy=docker.io/aquasec/trivy:0.69.3"
  "semgrep=docker.io/semgrep/semgrep:latest"
  "trufflehog=docker.io/trufflesecurity/trufflehog:latest"
)

echo "[images]"
for entry in "${IMAGES[@]}"; do
  key="${entry%%=*}"
  ref="${entry#*=}"
  "$ENGINE" pull -q "$ref" >/dev/null
  repo="${ref%:*}"
  # Prefer the multi-arch index digest (the object vendors sign, portable across architectures).
  # Fallback: the platform manifest digest recorded by the engine.
  if command -v skopeo >/dev/null; then
    digest="${repo}@$(skopeo inspect --format '{{.Digest}}' "docker://${ref}")"
  else
    digest="$("$ENGINE" image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" \
              | grep -m1 "^${repo}@sha256:" || true)"
  fi
  if [[ ! "$digest" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "error: no digest found for $ref" >&2
    exit 1
  fi
  # Pull by digest too: guarantees the pinned reference resolves locally (wra check inspects it).
  "$ENGINE" pull -q "$digest" >/dev/null
  printf '%s = %s\n' "$key" "$digest"
  printf '#   %s -> %s\n' "$ref" "$("$ENGINE" image inspect --format '{{.Created}}' "$digest")" >&2
done
