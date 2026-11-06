#!/usr/bin/env bash
# runtimes/php.sh — install/remove PHP 8.3 from the Ubuntu archive.
# Called only by hp-runtime.sh (already validated): php.sh install|remove 8.3
# Sites do not use the distribution's php8.3-fpm service: every PHP site runs
# its own php-fpm master in its own unit (hp-php-pool.sh + hp-site-unit.sh),
# so the stock service (www pool, 2+ idle workers) is disabled — its config is
# left untouched and "systemctl enable --now php8.3-fpm" brings it back.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
require_root
action=$1 version=$2
[[ $version == 8.3 ]] || die "yalnızca PHP 8.3 (Ubuntu deposu) destekleniyor"
pkgs=(php8.3-fpm php8.3-cli php8.3-opcache php8.3-mysql php8.3-pgsql php8.3-sqlite3 php8.3-curl
  php8.3-mbstring php8.3-xml php8.3-zip php8.3-gd php8.3-intl php8.3-bcmath php8.3-sybase composer)
export DEBIAN_FRONTEND=noninteractive

case $action in
  install)
    log "apt-get update"
    apt-get update -q
    log "kuruluyor: ${pkgs[*]}"
    apt-get install -y -q --no-install-recommends "${pkgs[@]}"
    systemctl disable --now php8.3-fpm.service >/dev/null 2>&1 || true
    log "dağıtımın php8.3-fpm servisi devre dışı (siteler kendi php-fpm süreçlerini çalıştırır)"
    /usr/sbin/php-fpm8.3 -v | head -n1
    php -m | tr '\n' ' '
    echo
    ;;
  remove)
    log "kaldırılıyor: ${pkgs[*]}"
    apt-get remove -y -q "${pkgs[@]}"
    log "kaldırıldı (yapılandırma dosyaları /etc/php altında kalır)"
    ;;
  *) die "geçersiz işlem: ${action}" ;;
esac
