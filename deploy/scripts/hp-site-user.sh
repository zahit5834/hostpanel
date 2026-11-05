#!/usr/bin/env bash
# hp-site-user.sh — create/delete a site's Linux account (no login shell, no home files).
# Usage: hp-site-user.sh create|delete <site_user> <domain>
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -eq 3 ]] || die "kullanım: $(basename "$0") create|delete <site_user> <domain>"
action=$1 user=$2 domain=$3
validate_oneof "$action" create delete
validate_site_user "$user"
validate_domain "$domain"

case $action in
  create)
    if id -u "$user" >/dev/null 2>&1; then
      log "kullanıcı zaten var: ${user}"
      exit 0
    fi
    useradd --system --user-group --no-create-home \
      --home-dir "${SITES_ROOT}/${domain}" --shell /usr/sbin/nologin "$user"
    log "kullanıcı oluşturuldu: ${user}"
    ;;
  delete)
    if ! id -u "$user" >/dev/null 2>&1; then
      log "kullanıcı yok: ${user}"
      exit 0
    fi
    pkill -KILL -u "$user" 2>/dev/null || true
    userdel "$user"
    log "kullanıcı silindi: ${user}"
    ;;
esac
