#!/usr/bin/env bash
# hp-nginx-site.sh — install/remove a site's nginx server config.
# Usage: hp-nginx-site.sh install <domain>   (stdin: full config, max 256 KB)
#        hp-nginx-site.sh remove <domain>
# install: validate content → write → nginx -t → reload. If nginx -t fails the
# previous file is restored (or the new one removed) so a broken config never goes live.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -eq 2 ]] || die "kullanım: $(basename "$0") install|remove <domain>"
action=$1 domain=$2
validate_oneof "$action" install remove
validate_domain "$domain"
command -v nginx >/dev/null || die "nginx kurulu değil"

avail=/etc/nginx/sites-available/hp-${domain}.conf
enabled=/etc/nginx/sites-enabled/hp-${domain}.conf

reload_nginx() {
  if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl start nginx; fi
}

case $action in
  install)
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' EXIT
    read_stdin_limited "$tmp" 262144
    validate_nginx_conf "$tmp" "$domain"

    # Shared http-level helpers (websocket upgrade map) and ACME webroot.
    maps_src="$HP_TEMPLATES/nginx/hostpanel-maps.conf"
    if ! cmp -s "$maps_src" /etc/nginx/conf.d/hostpanel-maps.conf; then
      install -o root -g root -m 0644 "$maps_src" /etc/nginx/conf.d/hostpanel-maps.conf
    fi
    install -d -o root -g root -m 0755 /var/www/letsencrypt

    backup=""
    if [[ -f $avail ]]; then
      backup=$(mktemp)
      cp -p "$avail" "$backup"
    fi
    atomic_write "$avail" 0644 root:root <"$tmp"
    ln -sfn "$avail" "$enabled"

    if ! test_out=$(nginx -t 2>&1); then
      if [[ -n $backup ]]; then
        mv -f "$backup" "$avail"
        log "nginx -t başarısız; önceki yapılandırma geri yüklendi"
      else
        rm -f "$avail" "$enabled"
        log "nginx -t başarısız; yeni yapılandırma kaldırıldı"
      fi
      echo "$test_out" >&2
      die "nginx yapılandırması geçersiz, canlıya alınmadı"
    fi
    [[ -n $backup ]] && rm -f "$backup"
    reload_nginx
    log "nginx yapılandırması yüklendi: ${avail}"
    ;;
  remove)
    rm -f "$enabled" "$avail"
    if nginx -t >/dev/null 2>&1; then reload_nginx; fi
    log "nginx yapılandırması kaldırıldı: ${domain}"
    ;;
esac
