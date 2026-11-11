#!/usr/bin/env bash
# hp-mail.sh — mail server (docker-mailserver) for HostPanel.
#
#   precheck <hostname>              Docker, nginx, certbot, ports 25/465/587/993 free
#   prepare <first_domain>           directories, fail2ban ignore list, first account
#                                    postmaster@<first_domain> (random password nobody knows)
#   vhost <hostname>                 port 80 nginx vhost (ACME only)
#   cert <hostname> <email>          Let's Encrypt (lineage hostpanel-mail) → tls/, renewal hook
#   create <image> <hostname> <memory_mb> <clamav 0|1> <msg_limit_mb> <postmaster_domain>
#   wait                             until the container reports healthy (≤180 s)
#   remove                           container only; data, accounts, keys kept
#   purge                            failed installs: container, vhost, certificate; data moved aside
#   start|stop|restart
#   status                           key=value lines
#   logs <n>
#   list                             "account <addr> <quota_mb>" / "alias <addr> <targets>"
#   usage                            "<addr> <used_kib> <limit_kib|->" (container running)
#   account-set <addr> create|reset  stdin: password (one line)
#   account-del <addr>               maildir archived to _mail/pre-delete-*.tar.zst, then removed
#   quota-set <addr> <mb>            0 = unlimited
#   alias-add <alias> <target>
#   alias-del <alias> <target>
#   dkim <domain>                    key created if missing; prints txt=<record>
#   domain-del <domain>              refuses while accounts/aliases exist; keys archived
#   queue | flush
#   bans | unban <ip>
#   backup <name>                    /var/backups/hostpanel/_mail/<name>/; prints size=<bytes>
#   restore <name>                   previous config+data kept in pre-restore/ (put back on failure)
#
# The panel sends validated names and numbers only: the container's arguments,
# the vhost and the account files are written here. Passwords arrive on stdin
# and only their SHA512-CRYPT hash is stored.
#
# Ports are published on IPv4 by Docker (bridge network): they bypass UFW, as
# documented in the panel. Host networking is avoided on purpose: the
# container's Fail2ban would write rules into the host firewall (SSH risk) and
# its internal services (Rspamd, Redis) would listen on the host.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") precheck|prepare|vhost|cert|create|wait|remove|purge|start|stop|restart|status|logs|list|usage|account-*|quota-set|alias-*|dkim|domain-del|queue|flush|bans|unban|backup|restore …"
action=$1
shift

NAME=hostpanel-mail
ROOT=$MAIL_ROOT
CONF=$ROOT/config # /tmp/docker-mailserver
DATA=$ROOT/data   # /var/mail
STATE=$ROOT/state # /var/mail-state (queue, spam statistics; not backed up)
TLS=$ROOT/tls     # /etc/hostpanel-tls (read-only)
ACC=$CONF/postfix-accounts.cf
VIRT=$CONF/postfix-virtual.cf
QUOTA=$CONF/dovecot-quotas.cf
DKIM_DIR=$CONF/rspamd/dkim
DKIM_MAP=$CONF/rspamd/dkim_selectors.map
SELECTOR=mail
MAIL_BACKUP=$BACKUP_ROOT/_mail
WEBROOT=/var/www/letsencrypt
HOOK=/etc/letsencrypt/renewal-hooks/deploy/hostpanel-mail.sh
PORTS=(25 465 587 993)
LOW=(nice -n 10 ionice -c3)

need_docker() { command -v docker >/dev/null || die "Docker kurulu değil"; }
exists() { docker inspect --type container "$NAME" >/dev/null 2>&1; }
running() { [[ $(docker inspect --type container -f '{{.State.Running}}' "$NAME" 2>/dev/null) == true ]]; }
need_running() {
  need_docker
  exists || die "posta sunucusu container'ı yok"
  running || die "posta sunucusu çalışmıyor"
}
health() { docker inspect --type container -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$NAME" 2>/dev/null || true; }
rand_pw() { head -c 48 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9' | head -c 32; }
stamp() { date +%Y%m%d-%H%M%S; }

# The whole tree is root 0700: host users (whatever uid the container's
# services map to) cannot reach the keys, hashes or mail.
check_dirs() {
  local d
  for d in "$ROOT" "$CONF" "$DATA" "$STATE" "$TLS"; do
    [[ ! -L $d ]] || die "${d} symlink olamaz"
  done
}
check_dirs

# lock — serializes every change to the account/alias/quota/DKIM files.
lock() {
  [[ -d $ROOT ]] || die "posta sunucusu hazırlanmamış (${ROOT} yok)"
  exec 9>"$ROOT/.lock"
  flock -w 120 9 || die "başka bir posta işlemi sürüyor"
}

ensure_dirs() {
  install -d -o root -g root -m 0700 "$ROOT" "$TLS"
  # 0711: Rspamd (its own uid inside the container) must traverse the config
  # mount to read the DKIM keys; with 0700 signing silently stops.
  install -d -o root -g root -m 0711 "$CONF"
  install -d -o root -g root -m 0755 "$DATA" "$STATE"
}

wait_healthy() {
  local i h
  for ((i = 0; i < 90; i++)); do
    if ! running; then
      sleep 2
      running && continue
      docker logs --tail 40 "$NAME" 2>&1 || true
      die "posta sunucusu container'ı durdu"
    fi
    h=$(health)
    [[ $h == healthy ]] && return 0
    sleep 2
  done
  docker logs --tail 40 "$NAME" 2>&1 || true
  die "posta sunucusu zamanında hazır olmadı (sağlık: ${h:-?})"
}

copy_tls() {
  local live=/etc/letsencrypt/live/$MAIL_CERT_NAME f
  [[ -f $live/fullchain.pem && -f $live/privkey.pem ]] || die "sertifika dosyaları yok: ${live}"
  install -d -o root -g root -m 0700 "$TLS"
  for f in fullchain.pem privkey.pem; do
    install -o root -g root -m 0600 /dev/null "$TLS/.$f.tmp"
    cat -- "$live/$f" >"$TLS/.$f.tmp"
    mv -f -- "$TLS/.$f.tmp" "$TLS/$f"
  done
}

install_hook() {
  local tmp
  install -d -o root -g root -m 0755 "$(dirname "$HOOK")"
  tmp=$(mktemp)
  cat >"$tmp" <<'HOOK'
#!/bin/sh
# Installed by HostPanel (hp-mail.sh cert). After a renewal of the mail
# server's certificate, copy it where the container reads it; docker-mailserver
# notices the change and reloads Postfix/Dovecot by itself.
set -e
[ "$(basename "$RENEWED_LINEAGE")" = hostpanel-mail ] || exit 0
d=/var/lib/hostpanel-mail/tls
[ -d "$d" ] && [ ! -L "$d" ] || exit 0
umask 077
for f in fullchain.pem privkey.pem; do
  cat "$RENEWED_LINEAGE/$f" >"$d/.$f.tmp"
  mv -f "$d/.$f.tmp" "$d/$f"
done
HOOK
  if ! cmp -s "$tmp" "$HOOK"; then
    atomic_write "$HOOK" 0755 root:root <"$tmp"
    log "yenileme kancası kuruldu: ${HOOK}"
  fi
  rm -f "$tmp"
}

read_pw() {
  local pw
  IFS= read -r pw || die "stdin: şifre yok"
  [[ $pw =~ ^[!-~]{10,128}$ ]] || die "geçersiz şifre biçimi"
  printf '%s' "$pw"
}

write_manifest() { # DIR NAME
  local size
  size=$(du -sb "$1" | cut -f1)
  printf '{"version":1,"domain":"_mail","name":"%s","components":["mail"],"size":%d,"created":"%s"}\n' \
    "$2" "$size" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$1/manifest.json"
  chmod 0600 "$1/manifest.json"
  echo "size=$size"
}

# tar_ok RC — 1 means "a file changed while it was read" (live maildirs).
tar_ok() { (($1 <= 1)); }

# members_under ARCHIVE TOP — every member is TOP or below it, no "..".
members_under() {
  tar --zstd -tf "$1" | awk -v p="$2" '
    $0 != p && $0 != p "/" && index($0, p "/") != 1 { bad = 1 }
    /(^|\/)\.\.(\/|$)/ { bad = 1 }
    END { exit bad }'
}

case $action in
  precheck)
    [[ $# -eq 1 ]] || die "kullanım: precheck <hostname>"
    validate_domain "$1"
    need_docker
    systemctl is-active --quiet docker || die "Docker servisi çalışmıyor"
    command -v nginx >/dev/null || die "nginx kurulu değil"
    command -v certbot >/dev/null || die "certbot kurulu değil (apt install certbot)"
    if ! exists; then
      for p in "${PORTS[@]}"; do
        if [[ -n $(ss -Hltn "sport = :$p") ]]; then
          die "${p} portu başka bir süreç tarafından kullanılıyor (sunucuda başka bir posta servisi — postfix/exim — olabilir)"
        fi
      done
    fi
    log "ön kontroller tamam"
    ;;

  prepare)
    [[ $# -eq 1 ]] || die "kullanım: prepare <first_domain>"
    validate_domain "$1"
    ensure_dirs
    lock
    # Local senders (sites on this server) reach the container from the
    # bridge gateway: a site with a wrong SMTP password must not get every
    # local sender banned.
    gw=$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' 2>/dev/null || true)
    ignore=("127.0.0.1/8" "::1")
    for ip in $gw $(server_ips); do
      [[ $ip =~ ^[0-9A-Fa-f:.]{2,45}$ ]] && ignore+=("$ip")
    done
    printf '[DEFAULT]\nignoreip = %s\n' "${ignore[*]}" | atomic_write "$CONF/fail2ban-jail.cf" 0644 root:root
    log "Fail2ban muafiyeti: ${ignore[*]}"
    # docker-mailserver stops when it finds no account: create one before
    # the first start. Its password is random and never shown (set it from
    # the panel with "Şifre sıfırla").
    if (($(mail_account_count "$ACC") == 0)); then
      hash=$(rand_pw | openssl passwd -6 -stdin)
      mail_account_set "$ACC" "postmaster@$1" "$hash"
      log "ilk hesap oluşturuldu: postmaster@$1"
    fi
    ;;

  vhost)
    [[ $# -eq 1 ]] || die "kullanım: vhost <hostname>"
    validate_domain "$1"
    command -v nginx >/dev/null || die "nginx kurulu değil"
    install -d -o root -g root -m 0755 "$WEBROOT"
    write_mail_vhost "$1"
    log "nginx: ${MAIL_VHOST} (yalnızca 80. port, ACME)"
    ;;

  cert)
    [[ $# -eq 2 ]] || die "kullanım: cert <hostname> <email>"
    validate_domain "$1"
    validate_email "$2"
    command -v certbot >/dev/null || die "certbot kurulu değil"
    install -d -o root -g root -m 0755 "$WEBROOT"
    certbot certonly --non-interactive --agree-tos --no-eff-email --email "$2" \
      --cert-name "$MAIL_CERT_NAME" --keep-until-expiring --expand \
      --webroot -w "$WEBROOT" -d "$1"
    ensure_dirs
    copy_tls
    install_hook
    log "sertifika hazır: $(openssl x509 -noout -enddate -in "$TLS/fullchain.pem")"
    ;;

  create)
    [[ $# -eq 6 ]] || die "kullanım: create <image> <hostname> <memory_mb> <clamav> <msg_limit_mb> <postmaster_domain>"
    image=$1 host=$2 mem=$3 clam=$4 msg=$5 pmd=$6
    validate_mail_image "$image"
    validate_domain "$host"
    [[ $mem =~ ^[0-9]{3,5}$ ]] && ((mem >= 768 && mem <= 65536)) || die "geçersiz bellek: $mem"
    validate_oneof "$clam" 0 1
    if [[ $clam == 1 ]] && ((mem < 2560)); then die "ClamAV için en az 2560 MB bellek gerekir"; fi
    [[ $msg =~ ^[0-9]{1,3}$ ]] && ((msg >= 1 && msg <= 200)) || die "geçersiz ileti boyutu: $msg"
    validate_domain "$pmd"
    need_docker
    ! exists || die "container zaten var: $NAME"
    for p in "${PORTS[@]}"; do
      if [[ -n $(ss -Hltn "sport = :$p") ]]; then die "${p} portu başka bir süreç tarafından kullanılıyor"; fi
    done
    [[ -s $TLS/fullchain.pem && -s $TLS/privkey.pem ]] || die "sertifika yok (önce cert)"
    (($(mail_account_count "$ACC") > 0)) || die "hesap yok (önce prepare)"
    ensure_dirs

    log "docker pull $image"
    docker pull -q "$image"
    # Attachments travel base64 encoded (+33 %) plus headers.
    limit=$((msg * 1048576 * 7 / 5))
    log "docker run $NAME (${host}, bellek ${mem}m, ClamAV ${clam}, ileti ${msg} MB)"
    docker run -d --name "$NAME" \
      --hostname "$host" \
      --restart unless-stopped \
      --stop-timeout 60 \
      --cap-add NET_ADMIN \
      --memory "${mem}m" --memory-swap "${mem}m" \
      -p 0.0.0.0:25:25 -p 0.0.0.0:465:465 -p 0.0.0.0:587:587 -p 0.0.0.0:993:993 \
      -v "$DATA:/var/mail" \
      -v "$STATE:/var/mail-state" \
      -v "$CONF:/tmp/docker-mailserver" \
      -v "$TLS:/etc/hostpanel-tls:ro" \
      --log-driver json-file --log-opt max-size=20m --log-opt max-file=5 \
      -e ENABLE_RSPAMD=1 -e ENABLE_OPENDKIM=0 -e ENABLE_OPENDMARC=0 -e ENABLE_POLICYD_SPF=0 \
      -e ENABLE_AMAVIS=0 -e ENABLE_SPAMASSASSIN=0 -e ENABLE_POSTGREY=0 \
      -e ENABLE_CLAMAV="$clam" -e ENABLE_FAIL2BAN=1 \
      -e SSL_TYPE=manual -e SSL_CERT_PATH=/etc/hostpanel-tls/fullchain.pem -e SSL_KEY_PATH=/etc/hostpanel-tls/privkey.pem \
      -e SPOOF_PROTECTION=1 -e PERMIT_DOCKER=none -e ENABLE_QUOTAS=1 -e ENABLE_POP3=0 -e ENABLE_UPDATE_CHECK=0 \
      -e POSTFIX_MESSAGE_SIZE_LIMIT="$limit" -e POSTMASTER_ADDRESS="postmaster@$pmd" \
      "$image" >/dev/null
    log "container başlatıldı"
    ;;

  wait)
    [[ $# -eq 0 ]] || die "kullanım: wait"
    need_docker
    exists || die "container yok"
    wait_healthy
    log "posta sunucusu hazır (healthy)"
    ;;

  remove)
    [[ $# -eq 0 ]] || die "kullanım: remove"
    need_docker
    if exists; then
      docker stop -t 60 "$NAME" >/dev/null 2>&1 || true
      docker rm -f "$NAME" >/dev/null
      log "container kaldırıldı (veri korunuyor: $ROOT)"
    fi
    ;;

  purge)
    [[ $# -eq 0 ]] || die "kullanım: purge"
    if command -v docker >/dev/null && exists; then docker rm -f "$NAME" >/dev/null; fi
    if [[ -f $MAIL_VHOST || -L $MAIL_VHOST_LINK ]]; then
      rm -f -- "$MAIL_VHOST_LINK" "$MAIL_VHOST"
      if nginx -t -q 2>/dev/null; then systemctl reload nginx || true; fi
      log "nginx vhost'u kaldırıldı"
    fi
    if command -v certbot >/dev/null && [[ -d /etc/letsencrypt/live/$MAIL_CERT_NAME ]]; then
      certbot delete --non-interactive --cert-name "$MAIL_CERT_NAME" >/dev/null 2>&1 || true
      log "sertifika silindi"
    fi
    rm -f -- "$HOOK"
    if [[ -d $ROOT ]]; then
      dest="$ROOT.removed-$(stamp)"
      mv -T -- "$ROOT" "$dest"
      log "veri dizini kenara alındı: $dest"
    fi
    ;;

  start | restart)
    [[ $# -eq 0 ]] || die "kullanım: $action"
    need_docker
    exists || die "container yok"
    if [[ $action == start ]]; then docker start "$NAME" >/dev/null; else docker restart -t 60 "$NAME" >/dev/null; fi
    wait_healthy
    log "$action tamam"
    ;;

  stop)
    [[ $# -eq 0 ]] || die "kullanım: stop"
    need_docker
    exists || die "container yok"
    docker stop -t 60 "$NAME" >/dev/null
    log "durduruldu"
    ;;

  status)
    [[ $# -eq 0 ]] || die "kullanım: status"
    if ! command -v docker >/dev/null; then
      echo "docker=absent"
      exit 0
    fi
    if ! systemctl is-active --quiet docker; then
      echo "docker=inactive"
      exit 0
    fi
    echo "docker=active"
    if [[ -f $TLS/fullchain.pem ]]; then
      end=$(openssl x509 -noout -enddate -in "$TLS/fullchain.pem" 2>/dev/null | cut -d= -f2)
      [[ -n $end ]] && echo "cert_until=$(date -d "$end" +%s)"
    fi
    if ! exists; then
      echo "container=absent"
      exit 0
    fi
    docker inspect --type container -f 'container={{.State.Status}}
started_at={{.State.StartedAt}}
restarts={{.RestartCount}}
oom={{.State.OOMKilled}}
image={{.Config.Image}}
health={{if .State.Health}}{{.State.Health.Status}}{{end}}' "$NAME"
    if running; then
      docker stats --no-stream --format 'cpu={{.CPUPerc}}
mem={{.MemUsage}}
mem_pct={{.MemPerc}}' "$NAME"
    fi
    ;;

  logs)
    [[ $# -eq 1 && $1 =~ ^[0-9]{1,4}$ ]] && (($1 >= 1)) || die "kullanım: logs <1-9999>"
    need_docker
    exists || die "container yok"
    docker logs --tail "$1" --timestamps "$NAME" 2>&1
    ;;

  list)
    [[ $# -eq 0 ]] || die "kullanım: list"
    mail_list "$ACC" "$VIRT" "$QUOTA"
    ;;

  usage)
    [[ $# -eq 0 ]] || die "kullanım: usage"
    need_running
    # doveadm also reports the dummy accounts DMS creates for aliases (with
    # an error on stderr): keep real accounts only.
    { docker exec "$NAME" doveadm -f tab quota get -A 2>/dev/null || true; } |
      awk -F'\t' -v A="$ACC" '
        FILENAME == A { split($0, p, "|"); acc[p[1]] = 1; next }
        $3 == "STORAGE" && ($1 in acc) && $4 ~ /^[0-9]+$/ { print $1 " " $4 " " ($5 ~ /^[0-9]+$/ ? $5 : "-") }' "$(_mail_src "$ACC")" -
    ;;

  account-set)
    [[ $# -eq 2 ]] || die "kullanım: account-set <addr> create|reset"
    validate_mail_addr "$1"
    validate_oneof "$2" create reset
    pw=$(read_pw)
    hash=$(printf '%s' "$pw" | openssl passwd -6 -stdin)
    unset pw
    lock
    if [[ $2 == create ]]; then
      ! mail_has_account "$ACC" "$1" || die "hesap zaten var: $1"
      ! mail_has_alias "$VIRT" "$1" || die "bu adres bir yönlendirme: $1"
    else
      mail_has_account "$ACC" "$1" || die "hesap yok: $1"
    fi
    mail_account_set "$ACC" "$1" "$hash"
    log "hesap $([[ $2 == create ]] && echo oluşturuldu || echo şifresi değişti): $1"
    ;;

  account-del)
    [[ $# -eq 1 ]] || die "kullanım: account-del <addr>"
    validate_mail_addr "$1"
    addr=$1 local=${1%%@*} domain=${1#*@}
    lock
    mail_has_account "$ACC" "$addr" || die "hesap yok: $addr"
    (($(mail_account_count "$ACC") > 1)) || die "son hesap silinemez (posta sunucusu en az bir hesap ister)"
    mail_account_del "$ACC" "$VIRT" "$QUOTA" "$addr"
    flock -u 9
    log "hesap silindi: $addr (yeni posta kabul edilmiyor)"
    md=$DATA/$domain/$local
    if [[ -e $md || -L $md ]]; then
      [[ -d $md && ! -L $md && ! -L $DATA/$domain ]] || die "beklenmeyen posta dizini: $md"
      install -d -o root -g root -m 0700 "$BACKUP_ROOT" "$MAIL_BACKUP"
      arc=$MAIL_BACKUP/pre-delete-$addr-$(stamp).tar.zst
      log "postalar arşivleniyor ($(du -sh "$md" | cut -f1))…"
      rc=0
      "${LOW[@]}" tar --zstd -cf "$arc" --numeric-owner -C "$DATA/$domain" "$local" || rc=$?
      tar_ok "$rc" || die "arşiv alınamadı; posta dizini silinmedi: $md"
      chmod 0600 "$arc"
      rm -rf --one-file-system -- "$md"
      log "arşiv: $arc"
    fi
    ;;

  quota-set)
    [[ $# -eq 2 ]] || die "kullanım: quota-set <addr> <mb>"
    validate_mail_addr "$1"
    [[ $2 =~ ^[0-9]{1,7}$ ]] && (($2 <= 1048576)) || die "geçersiz kota: $2"
    lock
    mail_has_account "$ACC" "$1" || die "hesap yok: $1"
    mail_quota_set "$QUOTA" "$1" "$2"
    log "kota: $1 = $([[ $2 == 0 ]] && echo sınırsız || echo "$2 MB")"
    ;;

  alias-add)
    [[ $# -eq 2 ]] || die "kullanım: alias-add <alias> <target>"
    validate_mail_addr "$1"
    validate_mail_target "$2"
    [[ $1 != "$2" ]] || die "bir adres kendisine yönlendirilemez"
    lock
    ! mail_has_account "$ACC" "$1" || die "bu adres bir posta kutusu: $1"
    mail_alias_add "$VIRT" "$1" "$2"
    log "yönlendirme: $1 → $2"
    ;;

  alias-del)
    [[ $# -eq 2 ]] || die "kullanım: alias-del <alias> <target>"
    validate_mail_addr "$1"
    validate_mail_target "$2"
    lock
    mail_alias_del "$VIRT" "$1" "$2"
    log "yönlendirme silindi: $1 → $2"
    ;;

  dkim)
    [[ $# -eq 1 ]] || die "kullanım: dkim <domain>"
    validate_domain "$1"
    need_running
    lock
    priv=$DKIM_DIR/$1-$SELECTOR.private pub=$DKIM_DIR/$1-$SELECTOR.public.dns.txt
    [[ ! -L $DKIM_DIR && ! -L $priv && ! -L $pub ]] || die "DKIM dosyaları symlink olamaz"
    if [[ ! -f $priv ]]; then
      # Exits 0 even when it refuses to overwrite: the files are checked below.
      docker exec "$NAME" setup config dkim domain "$1" >/dev/null
      log "DKIM anahtarı üretildi: $1 (seçici ${SELECTOR}, RSA 2048)"
    fi
    [[ -f $priv && -f $pub ]] || die "DKIM anahtarı oluşturulamadı: $1"
    [[ -f $DKIM_MAP && ! -L $DKIM_MAP ]] || die "dkim_selectors.map yok"
    if ! awk -v d="$1" -v s="$SELECTOR" '$1 == d && $2 == s { f = 1 } END { exit !f }' "$DKIM_MAP"; then
      owner=$(stat -c %u:%g "$DKIM_MAP")
      { awk -v d="$1" '$1 != d' "$DKIM_MAP"; echo "$1 $SELECTOR"; } | atomic_write "$DKIM_MAP" 0644 "$owner"
      log "DKIM seçici eşlemesi eklendi: $1"
    fi
    echo "txt=$(tr -d '\n' <"$pub")"
    ;;

  domain-del)
    [[ $# -eq 1 ]] || die "kullanım: domain-del <domain>"
    validate_domain "$1"
    lock
    ! mail_domain_used "$ACC" "$VIRT" "$1" || die "alan adında posta kutusu ya da yönlendirme var: $1"
    keys=()
    for f in "$DKIM_DIR/$1-$SELECTOR".private "$DKIM_DIR/$1-$SELECTOR".public.dns.txt "$DKIM_DIR/$1-$SELECTOR".public.txt; do
      if [[ -f $f && ! -L $f ]]; then keys+=("${f#"$CONF"/}"); fi
    done
    if ((${#keys[@]})); then
      install -d -o root -g root -m 0700 "$BACKUP_ROOT" "$MAIL_BACKUP"
      arc=$MAIL_BACKUP/dkim-$1-$(stamp).tar.zst
      tar --zstd -cf "$arc" --numeric-owner -C "$CONF" "${keys[@]}"
      chmod 0600 "$arc"
      for f in "${keys[@]}"; do rm -f -- "${CONF:?}/$f"; done
      log "DKIM anahtarı arşivlendi: $arc"
    fi
    if [[ -f $DKIM_MAP && ! -L $DKIM_MAP ]]; then
      owner=$(stat -c %u:%g "$DKIM_MAP")
      awk -v d="$1" '$1 != d' "$DKIM_MAP" | atomic_write "$DKIM_MAP" 0644 "$owner"
    fi
    log "alan adı kaldırıldı: $1"
    ;;

  queue)
    [[ $# -eq 0 ]] || die "kullanım: queue"
    n=0
    if command -v docker >/dev/null && exists && running; then
      n=$({ docker exec "$NAME" postqueue -j 2>/dev/null || true; } | grep -c '^{' || true)
    fi
    echo "count=${n:-0}"
    ;;

  flush)
    [[ $# -eq 0 ]] || die "kullanım: flush"
    need_running
    docker exec "$NAME" postqueue -f
    log "kuyruktaki iletiler yeniden deneniyor"
    ;;

  bans)
    [[ $# -eq 0 ]] || die "kullanım: bans"
    need_running
    { docker exec "$NAME" setup fail2ban 2>&1 || true; } | sed -E 's/\x1b\[[0-9;]*m//g' |
      sed -nE 's/.*Banned in ([a-z][a-z0-9-]*):[[:space:]]*(.*)$/\1 \2/p' |
      awk '{ for (i = 2; i <= NF; i++) if ($i ~ /^[0-9A-Fa-f:.]+$/) print $1 " " $i }'
    ;;

  unban)
    [[ $# -eq 1 && $1 =~ ^[0-9A-Fa-f:.]{2,45}$ && $1 == *[.:]* ]] || die "kullanım: unban <ip>"
    need_running
    docker exec "$NAME" setup fail2ban unban "$1"
    log "engel kaldırıldı: $1"
    ;;

  backup)
    [[ $# -eq 1 ]] || die "kullanım: backup <name>"
    out=$(backup_dir _mail "$1")
    [[ -d $CONF && -d $DATA ]] || die "posta sunucusu verisi yok"
    [[ ! -e $out ]] || die "yedek zaten var: ${out}"
    command -v zstd >/dev/null || die "zstd kurulu değil"
    install -d -o root -g root -m 0700 "$BACKUP_ROOT" "$MAIL_BACKUP" "$out"
    done_ok=0
    trap '((done_ok)) || rm -rf --one-file-system -- "$out"' EXIT
    # The container keeps running: maildirs hold one file per message, a
    # message arriving meanwhile is either in the archive or not.
    log "yapılandırma paketleniyor (hesaplar, yönlendirmeler, kotalar, DKIM anahtarları)…"
    rc=0
    "${LOW[@]}" tar --zstd -cf "$out/mail-config.tar.zst" --numeric-owner -C "$ROOT" config || rc=$?
    tar_ok "$rc" || die "yapılandırma paketlenemedi"
    log "postalar paketleniyor ($(du -sh "$DATA" | cut -f1))…"
    rc=0
    "${LOW[@]}" tar --zstd -cf "$out/mail-data.tar.zst" --numeric-owner -C "$ROOT" data || rc=$?
    tar_ok "$rc" || die "postalar paketlenemedi"
    chmod 0600 "$out"/*
    (cd "$out" && sha256sum mail-config.tar.zst mail-data.tar.zst >SHA256SUMS)
    chmod 0600 "$out/SHA256SUMS"
    write_manifest "$out" "$1"
    # shellcheck disable=SC2034 # read by the EXIT trap
    done_ok=1
    log "yedek hazır: ${out} ($(du -sh "$out" | cut -f1))"
    ;;

  restore)
    [[ $# -eq 1 ]] || die "kullanım: restore <name>"
    src=$(backup_dir _mail "$1")
    [[ -d $src && ! -L $src ]] || die "yedek bulunamadı: ${src}"
    check_sums "$src"
    for f in mail-config mail-data; do
      [[ -f $src/$f.tar.zst ]] || die "yedekte $f.tar.zst yok"
    done
    members_under "$src/mail-config.tar.zst" config || die "yapılandırma arşivinde beklenmeyen yol"
    members_under "$src/mail-data.tar.zst" data || die "posta arşivinde beklenmeyen yol"
    need_docker
    exists || die "posta sunucusu container'ı yok"
    lock
    prev=$ROOT/pre-restore
    log "posta sunucusu durduruluyor…"
    docker stop -t 60 "$NAME" >/dev/null
    rm -rf --one-file-system -- "$prev"
    install -d -o root -g root -m 0700 "$prev"
    mv -T -- "$CONF" "$prev/config"
    mv -T -- "$DATA" "$prev/data"
    rollback() {
      log "geri yükleme başarısız; önceki veriler geri alınıyor"
      docker stop -t 60 "$NAME" >/dev/null 2>&1 || true
      rm -rf --one-file-system -- "$CONF" "$DATA"
      mv -T -- "$prev/config" "$CONF"
      mv -T -- "$prev/data" "$DATA"
      docker start "$NAME" >/dev/null 2>&1 || true
    }
    trap 'rc=$?; if ((rc != 0)); then rollback; fi' EXIT
    log "yapılandırma açılıyor…"
    tar --zstd -xpf "$src/mail-config.tar.zst" --numeric-owner -C "$ROOT"
    log "postalar açılıyor…"
    "${LOW[@]}" tar --zstd -xpf "$src/mail-data.tar.zst" --numeric-owner -C "$ROOT"
    [[ -d $CONF && ! -L $CONF && -d $DATA && ! -L $DATA ]] || die "arşivden config/ ve data/ çıkmadı"
    chown root:root "$CONF" "$DATA"
    chmod 0711 "$CONF"
    chmod 0755 "$DATA"
    (($(mail_account_count "$ACC") > 0)) || die "yedekte hesap yok"
    log "posta sunucusu başlatılıyor…"
    docker start "$NAME" >/dev/null
    wait_healthy
    trap - EXIT
    log "geri yüklendi. Önceki yapılandırma ve postalar ${prev} altında duruyor (bir sonraki geri yüklemede silinir)."
    ;;

  *)
    die "bilinmeyen işlem: ${action}"
    ;;
esac
