#!/usr/bin/env bash
# hp-site-unit.sh — render/remove the systemd unit of a proxy site.
# The unit is rendered HERE from validated arguments (never from panel-supplied
# file content), so a compromised panel cannot create e.g. a User=root unit.
# Usage: hp-site-unit.sh install <domain> <short> <template> <memoryMB> <cpuPct> -- <exec> [args...]
#        hp-site-unit.sh remove <short>
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
action=${1:-}
validate_oneof "$action" install remove

case $action in
  install)
    [[ $# -ge 8 && ${7:-} == "--" ]] || die "kullanım: $(basename "$0") install <domain> <short> <template> <memMB> <cpu%> -- <exec> [args...]"
    domain=$2 short=$3 tpl=$4 mem=$5 cpu=$6
    shift 7
    dir=$(site_dir "$domain")
    validate_short "$short"
    user="site_${short}"
    id -u "$user" >/dev/null 2>&1 || die "kullanıcı yok: ${user}"
    [[ $tpl =~ ^[a-z0-9-]+\.service\.tpl$ ]] || die "geçersiz şablon adı: ${tpl}"
    tplfile="$HP_TEMPLATES/systemd/$tpl"
    [[ -f $tplfile ]] || die "şablon bulunamadı: ${tplfile}"
    [[ $mem =~ ^[0-9]{2,5}$ ]] && ((mem >= 64 && mem <= 65536)) || die "geçersiz bellek limiti: ${mem}"
    [[ $cpu =~ ^[0-9]{1,4}$ ]] && ((cpu >= 5 && cpu <= 1600)) || die "geçersiz CPU kotası: ${cpu}"

    bin=$1
    shift
    [[ $bin == /usr/share/dotnet/dotnet || $bin =~ ^/opt/node/v[0-9]+\.[0-9]+\.[0-9]+/bin/node$ || $bin == /usr/sbin/php-fpm8.3 ]] \
      || die "izin verilmeyen çalıştırılabilir: ${bin}"
    [[ -x $bin ]] || die "çalıştırılabilir bulunamadı (altyapı kurulu mu?): ${bin}"
    if [[ $bin == /usr/sbin/php-fpm8.3 ]]; then
      # php-fpm only ever reads the config hp-php-pool.sh wrote for this domain.
      [[ $# -eq 2 && $1 == --nodaemonize && $2 == "--fpm-config=$PHP_CONF_DIR/$domain.conf" ]] \
        || die "php-fpm argümanları: --nodaemonize --fpm-config=${PHP_CONF_DIR}/${domain}.conf"
      [[ -f $PHP_CONF_DIR/$domain.conf ]] || die "php-fpm yapılandırması yok (hp-php-pool.sh install)"
    fi
    execline=$bin
    for a in "$@"; do
      # No spaces, quotes, $ or % (systemd would expand them), no traversal, no absolute paths.
      [[ $a =~ ^[A-Za-z0-9._@:=,+-][A-Za-z0-9._/@:=,+-]*$ && $a != *..* ]] || die "geçersiz argüman: ${a}"
      execline+=" $a"
    done

    unit="hp-site-${short}"
    out=$(<"$tplfile")
    out=${out//\{\{domain\}\}/$domain}
    out=${out//\{\{user\}\}/$user}
    out=${out//\{\{unit\}\}/$unit}
    out=${out//\{\{workdir\}\}/$dir/current}
    out=${out//\{\{exec\}\}/$execline}
    out=${out//\{\{envfile\}\}/$ENV_DIR/$domain.env}
    out=${out//\{\{memory\}\}/$mem}
    out=${out//\{\{cpu\}\}/$cpu}
    out=${out//\{\{rwpath\}\}/$dir}
    [[ $out != *'{{'* ]] || die "şablonda bilinmeyen yer tutucu kaldı"

    printf '%s\n' "$out" | atomic_write "/etc/systemd/system/${unit}.service" 0644 root:root
    systemctl daemon-reload
    systemctl enable "${unit}.service" >/dev/null 2>&1
    log "unit yazıldı: ${unit}.service (${execline})"
    ;;
  remove)
    [[ $# -eq 2 ]] || die "kullanım: $(basename "$0") remove <short>"
    validate_short "$2"
    unit="hp-site-$2"
    systemctl disable --now "${unit}.service" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${unit}.service"
    systemctl daemon-reload
    systemctl reset-failed "${unit}.service" >/dev/null 2>&1 || true
    log "unit kaldırıldı: ${unit}.service"
    ;;
esac
