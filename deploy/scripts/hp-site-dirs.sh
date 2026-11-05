#!/usr/bin/env bash
# hp-site-dirs.sh — create/delete a site's directory tree.
# Usage: hp-site-dirs.sh create <domain> <site_user>
#        hp-site-dirs.sh delete <domain>
# Layout: /var/www/sites/<domain>/{releases,shared,logs,current->releases/<x>}
# Mode 2750 <site_user>:www-data — setgid so new files keep group www-data (nginx can read static files).
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
action=${1:-}
validate_oneof "$action" create delete

case $action in
  create)
    [[ $# -eq 3 ]] || die "kullanım: $(basename "$0") create <domain> <site_user>"
    dir=$(site_dir "$2") user=$3
    validate_site_user "$user"
    id -u "$user" >/dev/null 2>&1 || die "kullanıcı yok: ${user}"
    install -d -o root -g root -m 0755 "$SITES_ROOT"
    if [[ -e $dir ]]; then
      [[ $(stat -c %U "$dir") == "$user" ]] || die "dizin zaten var ve başka kullanıcıya ait: ${dir}"
    fi
    for d in "$dir" "$dir/releases" "$dir/shared" "$dir/logs"; do
      install -d -o "$user" -g www-data -m 2750 "$d"
    done
    ph="$dir/releases/00000000-000000"
    install -d -o "$user" -g www-data -m 2750 "$ph"
    install -o "$user" -g www-data -m 0640 "$HP_TEMPLATES/pages/coming-soon.html" "$ph/index.html"
    if [[ ! -e $dir/current ]]; then
      ln -s "releases/00000000-000000" "$dir/current"
      chown -h "$user:www-data" "$dir/current"
    fi
    log "dizinler hazır: ${dir}"
    ;;
  delete)
    [[ $# -eq 2 ]] || die "kullanım: $(basename "$0") delete <domain>"
    dir=$(site_dir "$2")
    if [[ -d $dir ]]; then
      rm -rf --one-file-system -- "$dir"
      log "silindi: ${dir}"
    else
      log "dizin yok: ${dir}"
    fi
    ;;
esac
