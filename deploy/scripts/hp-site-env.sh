#!/usr/bin/env bash
# hp-site-env.sh — write/delete a site's systemd EnvironmentFile.
# Usage: hp-site-env.sh write <domain>   (stdin: KEY=VALUE lines, raw values)
#        hp-site-env.sh delete <domain>
# The file is root:root 0600 (systemd reads it before dropping privileges).
# Values are single-quoted (or double-quoted with \ " $ escaped when they contain
# a single quote) so systemd keeps them literal.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -eq 2 ]] || die "kullanım: $(basename "$0") write|delete <domain>"
action=$1
validate_oneof "$action" write delete
validate_domain "$2"
file="$ENV_DIR/$2.env"
ensure_etc_dir
install -d -o root -g root -m 0700 "$ENV_DIR"

case $action in
  write)
    tmpin=$(mktemp)
    trap 'rm -f "$tmpin"' EXIT
    read_stdin_limited "$tmpin" 262144
    out=""
    n=0
    while IFS= read -r line || [[ -n $line ]]; do
      [[ -z $line ]] && continue
      key=${line%%=*}
      val=${line#*=}
      [[ $line == *=* && $key =~ ^[A-Za-z_][A-Za-z0-9_]{0,127}$ ]] || die "geçersiz satır (KEY=VALUE bekleniyor)"
      [[ $val != *$'\r'* ]] || die "${key}: değer satır sonu içeremez"
      out+="$(env_line "$key" "$val")"$'\n'
      n=$((n + 1))
      ((n <= 500)) || die "en fazla 500 değişken"
    done <"$tmpin"
    printf '%s' "$out" | atomic_write "$file" 0600 root:root
    log "ortam dosyası yazıldı: ${file} (${n} değişken)"
    ;;
  delete)
    rm -f "$file"
    log "ortam dosyası silindi: ${file}"
    ;;
esac
