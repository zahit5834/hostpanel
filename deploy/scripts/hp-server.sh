#!/usr/bin/env bash
# hp-server.sh — server page helpers.
#
#   hp-server.sh ufw-status
#       active=yes|no, protected=<ports>, then the "ufw status numbered" rules.
#   hp-server.sh ufw-add <allow|deny> <port|a:b> <tcp|udp|any> <any|IP|CIDR>
#   hp-server.sh ufw-delete <rule-number> <hash>
#       hash = first 16 hex of sha256 of the rule's "ufw status numbered" line
#       as the panel saw it: if the list changed meanwhile, nothing is deleted.
#   hp-server.sh disk-usage           key=bytes lines (sites, backups, mssql, postgres, mail, docker, panel, logs)
#
# The panel never enables or disables UFW (SSH lock-out risk); rules are only
# added/removed while UFW is already active. Rules for SSH (22 and sshd's real
# port), HTTP/HTTPS, the panel port, app profiles (OpenSSH, Nginx …) and the
# MSSQL rules managed by hp-mssql.sh can't be deleted, and no deny rule may
# cover a protected port.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") ufw-status|ufw-add|ufw-delete|disk-usage …"
action=$1
shift

protected_ports() {
  local ports=(22 80 443) p
  if command -v sshd >/dev/null; then
    while read -r p; do [[ $p =~ ^[0-9]+$ ]] && ports+=("$p"); done < <(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}')
  fi
  p=$(config_value listen)
  p=${p##*:}
  [[ $p =~ ^[0-9]{1,5}$ ]] && ports+=("$p")
  p=$(config_value panel_port)
  [[ $p =~ ^[0-9]{1,5}$ ]] && ports+=("$p")
  p=$(config_value panel_ip_port)
  [[ $p =~ ^[0-9]{1,5}$ && $p != 0 ]] && ports+=("$p")
  printf '%s\n' "${ports[@]}" | sort -un | paste -sd, -
}

need_ufw() { command -v ufw >/dev/null || die "UFW kurulu değil"; }
ufw_active() { [[ $(ufw status 2>/dev/null | head -n1) == "Status: active" ]]; }

case $action in
  ufw-status)
    [[ $# -eq 0 ]] || die "kullanım: ufw-status"
    if ! command -v ufw >/dev/null; then
      echo "installed=no"
      exit 0
    fi
    echo "installed=yes"
    if ufw_active; then echo "active=yes"; else echo "active=no"; fi
    echo "protected=$(protected_ports)"
    echo "---"
    ufw status numbered | grep -E '^\[ *[0-9]+\]' | sed -E 's/[[:space:]]+$//' || true
    ;;

  ufw-add)
    [[ $# -eq 4 ]] || die "kullanım: ufw-add <allow|deny> <port|a:b> <tcp|udp|any> <any|IP|CIDR>"
    rule=$1 port=$2 proto=$3 from=$4
    validate_oneof "$rule" allow deny
    validate_ufw_port "$port"
    validate_oneof "$proto" tcp udp any
    [[ $from == any ]] || validate_ip_or_cidr "$from"
    [[ $port != *:* || $proto != any ]] || die "port aralığında protokol (tcp/udp) seçilmeli"
    need_ufw
    ufw_active || die "UFW etkin değil; panel UFW'yi açmaz (önce SSH ile: ufw allow OpenSSH && ufw enable)"
    if [[ $rule == deny ]]; then
      IFS=, read -ra prot <<<"$(protected_ports)"
      for p in "${prot[@]}"; do
        if ports_overlap "$port" "$p"; then die "korumalı port (${p}) için deny kuralı eklenemez"; fi
      done
    fi
    args=("$rule")
    [[ $proto != any ]] && args+=(proto "$proto")
    args+=(from "$from" to any port "$port" comment hostpanel)
    ufw "${args[@]}"
    log "kural eklendi: ${args[*]}"
    ;;

  ufw-delete)
    [[ $# -eq 2 ]] || die "kullanım: ufw-delete <rule-number> <hash>"
    n=$1 want=$2
    validate_ufw_rule_no "$n"
    [[ $want =~ ^[0-9a-f]{16}$ ]] || die "geçersiz kural özeti"
    need_ufw
    ufw_active || die "UFW etkin değil"
    line=$(ufw status numbered | grep -E "^\[ *${n}\]" | head -n1) || true
    [[ -n $line ]] || die "kural bulunamadı: ${n}"
    line=$(sed -E 's/[[:space:]]+$//' <<<"$line")
    got=$(printf '%s' "$line" | sha256sum | cut -c1-16)
    [[ $got == "$want" ]] || die "kural listesi değişti; sayfayı yenileyip tekrar deneyin"
    [[ $line != *hostpanel-mssql* ]] || die "MSSQL kuralları Veritabanları sayfasından yönetilir"
    [[ $line != *hostpanel-pg* ]] || die "PostgreSQL kuralları Veritabanları → PostgreSQL sayfasından yönetilir"
    [[ $line != *hostpanel-dns* ]] || die "DNS sunucusunun 53 kuralları panelden silinemez"
    to=$(sed -E 's/^\[ *[0-9]+\] +//' <<<"$line" | awk '{print $1}')
    spec=${to%%/*}
    [[ $spec =~ ^[0-9,:]+$ ]] || die "profil / tüm portlar kuralı (${to}) panelden silinemez"
    IFS=, read -ra prot <<<"$(protected_ports)"
    for p in "${prot[@]}"; do
      if ports_overlap "$spec" "$p"; then die "korumalı port (${p}) kuralı silinemez"; fi
    done
    ufw --force delete "$n"
    log "kural silindi: ${line}"
    ;;

  disk-usage)
    [[ $# -eq 0 ]] || die "kullanım: disk-usage"
    du_b() { if [[ -d $1 ]]; then nice -n 10 ionice -c3 timeout 120 du -sb "${@:2}" "$1" 2>/dev/null | cut -f1; else echo 0; fi; }
    echo "sites=$(du_b /var/www/sites)"
    echo "backups=$(du_b /var/backups/hostpanel)"
    echo "mssql=$(du_b "$(db_path mssql)")"
    pg=$(($(du_b "$(db_path postgres)") + $(du_b "$(db_path postgres-backup)")))
    echo "postgres=$pg"
    echo "mail=$(du_b /var/lib/hostpanel-mail)"
    echo "docker=$(du_b /var/lib/docker)"
    echo "panel=$(du_b /var/lib/hostpanel --exclude=/var/lib/hostpanel/mssql --exclude=/var/lib/hostpanel/postgres --exclude=/var/lib/hostpanel/postgres-backup)"
    echo "logs=$(du_b /var/log)"
    ;;

  *)
    die "bilinmeyen işlem: ${action}"
    ;;
esac
