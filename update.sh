#!/usr/bin/env bash
# HostPanel update from the command line — the same path as the panel's
# "Güncelle" button (hp-update.sh: download, SHA-256 check, DB copy, install,
# health check, automatic rollback), with the output on the terminal.
#
#   sudo /opt/hostpanel/update.sh            latest release
#   sudo /opt/hostpanel/update.sh v1.2.3     a specific release (also to go back)
set -euo pipefail

fail() {
  echo "HATA: $*" >&2
  exit 1
}

[[ $EUID -eq 0 ]] || fail "root olarak çalıştırın (sudo)"
[[ -x /opt/hostpanel/scripts/hp-update.sh ]] || fail "HostPanel kurulu değil (/opt/hostpanel)"
want=${1:-latest}
[[ $# -le 1 ]] || fail "kullanım: $0 [latest|vX.Y.Z]"

repo=$(sed -nE 's/^update_repo:[[:space:]]*"?([^"#[:space:]]*)"?.*$/\1/p' /etc/hostpanel/config.yaml 2>/dev/null | head -n1)
repo=${repo:-zahit5834/hostpanel}
[[ $repo =~ ^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$ ]] || fail "config.yaml: geçersiz update_repo"

if [[ $want == latest ]]; then
  want=$(curl -fsSL --proto '=https' --max-time 30 -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${repo}/releases/latest" | jq -r .tag_name) || fail "son sürüm bulunamadı (${repo})"
fi
[[ $want =~ ^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || fail "geçersiz sürüm: ${want}"

current=$(/opt/hostpanel/bin/hostpanel version 2>/dev/null || echo unknown)
if [[ $current == "$want" ]]; then
  echo "Zaten ${want} kurulu."
  exit 0
fi
echo "HostPanel ${current} → ${want}"
exec /opt/hostpanel/scripts/hp-update.sh run "$want"
