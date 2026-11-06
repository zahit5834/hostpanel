#!/usr/bin/env bash
# hp-site-cron.sh — run a site cron job as the site user.
# Usage:
#   hp-site-cron.sh run <domain> <site_user> <cron_id> <runtime> <version> <timeout_s> <memMB> <cpu%>   (command on stdin)
#   hp-site-cron.sh stop-all <short>
# The command runs with bash INSIDE a sandboxed transient unit as the site user
# (run_as_site); root never interprets it.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
action=${1:-}
validate_oneof "$action" run stop-all

case $action in
  run)
    [[ $# -eq 9 ]] || die "kullanım: $(basename "$0") run <domain> <site_user> <cron_id> <runtime> <version> <timeout> <memMB> <cpu%>"
    dir=$(site_dir "$2")
    user=$3 id=$4 rt=$5 ver=$6
    validate_site_user "$user"
    validate_id "$id"
    validate_limits "$7" "$8" "$9"
    [[ -d $dir && $(stat -c %U "$dir") == "$user" ]] || die "site dizini sahibi beklenen kullanıcı değil"
    [[ -d $dir/current ]] || die "aktif sürüm yok"
    pathpre=$(runtime_path "$rt" "$ver")
    cmd=$(read_user_command)
    run_as_site "$dir" "$user" "hp-cron-${user#site_}-${id}" "$7" "$8" "$9" "$dir/current" "$pathpre" "$cmd"
    ;;
  stop-all)
    [[ $# -eq 2 ]] || die "kullanım: $(basename "$0") stop-all <short>"
    validate_short "$2"
    mapfile -t units < <(systemctl list-units --plain --no-legend --all "hp-cron-$2-*.service" "hp-build-$2.service" | awk '{print $1}')
    for u in "${units[@]}"; do
      [[ $u =~ ^hp-(cron-$2-[0-9]+|build-$2)\.service$ ]] || continue
      systemctl stop "$u" >/dev/null 2>&1 || true
      log "durduruldu: ${u}"
    done
    ;;
esac
