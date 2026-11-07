#!/usr/bin/env bash
# hp-php-pool.sh — render/remove the php-fpm config of a PHP site.
# Each PHP site runs its own php-fpm master as the site user in its own
# systemd unit (hp-site-<short>.service, rendered by hp-site-unit.sh); this
# script writes the config that master reads. Content comes from validated
# arguments only, never from the panel.
# Usage: hp-php-pool.sh install <domain> <short> <memory_limit_MB> <max_children> <upload_MB>
#        hp-php-pool.sh remove <domain>
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
action=${1:-}
validate_oneof "$action" install remove

case $action in
  install)
    [[ $# -eq 6 ]] || die "kullanım: $(basename "$0") install <domain> <short> <memMB> <max_children> <uploadMB>"
    domain=$2 short=$3 mem=$4 children=$5 upload=$6
    dir=$(site_dir "$domain")
    validate_short "$short"
    user="site_${short}"
    id -u "$user" >/dev/null 2>&1 || die "kullanıcı yok: ${user}"
    [[ -d $dir && $(stat -c %U "$dir") == "$user" ]] || die "site dizini sahibi beklenen kullanıcı değil"
    [[ $mem =~ ^[0-9]{2,4}$ ]] && ((mem >= 16 && mem <= 4096)) || die "geçersiz memory_limit: ${mem}"
    [[ $children =~ ^[0-9]{1,2}$ ]] && ((children >= 1 && children <= 50)) || die "geçersiz max_children: ${children}"
    [[ $upload =~ ^[0-9]{1,5}$ ]] && ((upload >= 1 && upload <= 10240)) || die "geçersiz upload limiti: ${upload}"

    # The socket lives in the setgid (www-data) site tree: it gets group
    # www-data, so nginx can connect and other sites cannot.
    [[ ! -L $dir/run ]] || die "${dir}/run symlink olamaz"
    install -d -o "$user" -g www-data -m 2750 "$dir/run"
    [[ ! -L $dir/.sessions ]] || die "${dir}/.sessions symlink olamaz"
    install -d -o "$user" -g "$user" -m 0700 "$dir/.sessions"
    ensure_etc_dir
    install -d -o root -g root -m 0755 "$PHP_CONF_DIR"

    cat <<CONF | atomic_write "$PHP_CONF_DIR/$domain.conf" 0644 root:root
; Managed by HostPanel — rendered by hp-php-pool.sh; do not edit.
[global]
error_log = syslog
syslog.ident = hp-site-${short}
log_level = notice
daemonize = no
process_control_timeout = 10s

[${short}]
listen = ${dir}/run/php.sock
listen.mode = 0660
pm = ondemand
pm.max_children = ${children}
pm.process_idle_timeout = 60s
pm.max_requests = 500
clear_env = no
catch_workers_output = yes
decorate_workers_output = no
security.limit_extensions = .php
php_admin_value[open_basedir] = ${dir}/:/tmp/:/usr/share/php/
php_admin_value[memory_limit] = ${mem}M
php_admin_value[upload_max_filesize] = ${upload}M
php_admin_value[post_max_size] = ${upload}M
php_admin_value[upload_tmp_dir] = /tmp
php_admin_value[sys_temp_dir] = /tmp
php_admin_value[session.save_path] = ${dir}/.sessions
php_admin_value[session.gc_probability] = 1
CONF
    log "php-fpm yapılandırması yazıldı: ${PHP_CONF_DIR}/${domain}.conf (max_children=${children}, memory_limit=${mem}M)"
    ;;
  remove)
    [[ $# -eq 2 ]] || die "kullanım: $(basename "$0") remove <domain>"
    validate_domain "$2"
    rm -f -- "$PHP_CONF_DIR/$2.conf"
    log "php-fpm yapılandırması silindi: $2"
    ;;
esac
