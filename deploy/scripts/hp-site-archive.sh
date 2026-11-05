#!/usr/bin/env bash
# hp-site-archive.sh — take a final archive of a site before deletion.
# Usage: hp-site-archive.sh <domain>
# Writes /var/backups/hostpanel/<domain>/pre-delete-<ts>.tar.zst (site files,
# nginx config, env file). Runs with low CPU/IO priority. Independent of the
# Faz 4 backup system (kept outside plan retention).
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -eq 1 ]] || die "kullanım: $(basename "$0") <domain>"
domain=$1
dir=$(site_dir "$domain")
if [[ ! -d $dir ]]; then
  log "site dizini yok, arşivlenecek bir şey yok"
  exit 0
fi
out_dir=/var/backups/hostpanel/$domain
install -d -o root -g root -m 0700 /var/backups/hostpanel "$out_dir"
ts=$(date +%Y%m%d-%H%M%S)

paths=("var/www/sites/$domain")
[[ -f /etc/nginx/sites-available/hp-$domain.conf ]] && paths+=("etc/nginx/sites-available/hp-$domain.conf")
[[ -f $ENV_DIR/$domain.env ]] && paths+=("${ENV_DIR#/}/$domain.env")

if command -v zstd >/dev/null; then
  out="$out_dir/pre-delete-$ts.tar.zst"
  nice -n 10 ionice -c3 tar --zstd -cf "$out" -C / "${paths[@]}"
else
  out="$out_dir/pre-delete-$ts.tar.gz"
  nice -n 10 ionice -c3 tar -czf "$out" -C / "${paths[@]}"
fi
chmod 0600 "$out"
log "arşiv: ${out} ($(du -h "$out" | cut -f1))"
