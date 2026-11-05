#!/usr/bin/env bash
# hp-site-service.sh — control a site's systemd unit.
# Usage: hp-site-service.sh start|stop|restart|enable|disable <short>
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -eq 2 ]] || die "kullanım: $(basename "$0") start|stop|restart|enable|disable <short>"
action=$1
validate_oneof "$action" start stop restart enable disable
validate_short "$2"
unit="hp-site-$2.service"
[[ -f /etc/systemd/system/$unit ]] || die "unit bulunamadı: ${unit}"

case $action in
  start | restart)
    # Clear a previous crash-loop start limit so a manual (re)start always works.
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    systemctl "$action" "$unit"
    sleep 1
    if ! systemctl is-active --quiet "$unit"; then
      journalctl -u "$unit" -n 20 --no-pager -o cat >&2 || true
      die "servis çalışmıyor: ${unit}"
    fi
    ;;
  *)
    systemctl "$action" "$unit"
    ;;
esac
log "${action}: ${unit}"
