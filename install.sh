#!/usr/bin/env bash
# HostPanel installer — Ubuntu 24.04, amd64/arm64. Safe to run again (idempotent):
# existing keys, passwords, config values and data are kept.
#
#   curl -fsSL https://raw.githubusercontent.com/zahit5834/hostpanel/main/install.sh | sudo bash -s -- [options]
#
# Options:
#   --domain NAME      serve the panel on NAME with a Let's Encrypt certificate
#   --email ADDR       Let's Encrypt account e-mail (recommended with --domain)
#   --port N           public HTTPS port of the panel (default 8443; 443 allowed with --domain)
#   --version vX.Y.Z   release to install (default: latest)
#   --tarball FILE     install from a local release tarball (needs --sums)
#   --sums FILE        SHA256SUMS for --tarball
#   --import FILE      import an exported panel configuration (.hpcfg); passphrase from
#                      HP_IMPORT_PASS or asked on the terminal
#   --no-firewall      do not touch UFW
#   --yes              do not ask before enabling UFW
#
# Not installed here (the panel installs them when needed): Docker, MSSQL,
# .NET, Node.js, PHP, rclone.
set -euo pipefail

REPO=${HP_REPO:-zahit5834/hostpanel}
PACKAGES=(nginx certbot python3-certbot-nginx ufw fail2ban zstd curl jq unzip openssl git ca-certificates)

DOMAIN="" EMAIL="" PORT=8443 VERSION=latest TARBALL="" SUMS="" IMPORT="" NO_FW=0 YES=0

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mUYARI:\033[0m %s\n' "$*" >&2; }
fail() {
  printf '\033[1;31mHATA:\033[0m %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" 2>/dev/null | sed 's/^# \{0,1\}//' || true
}

# parse_args "$@" — sets the globals above; validates every value.
parse_args() {
  while (($#)); do
    case $1 in
      --domain | --email | --port | --version | --tarball | --sums | --import)
        [[ $# -ge 2 ]] || fail "$1 bir değer ister"
        ;;
    esac
    case $1 in
      --domain) DOMAIN=$2 && shift ;;
      --email) EMAIL=$2 && shift ;;
      --port) PORT=$2 && shift ;;
      --version) VERSION=$2 && shift ;;
      --tarball) TARBALL=$2 && shift ;;
      --sums) SUMS=$2 && shift ;;
      --import) IMPORT=$2 && shift ;;
      --no-firewall) NO_FW=1 ;;
      --yes | -y) YES=1 ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) fail "bilinmeyen seçenek: $1 (--help)" ;;
    esac
    shift
  done
  DOMAIN=${DOMAIN,,}
  if [[ -n $DOMAIN ]]; then
    [[ $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || fail "geçersiz domain: ${DOMAIN}"
  fi
  if [[ -n $EMAIL ]]; then
    [[ $EMAIL =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || fail "geçersiz e-posta: ${EMAIL}"
  fi
  [[ $PORT =~ ^[0-9]{1,5}$ ]] || fail "geçersiz port: ${PORT}"
  ((PORT == 443 || (PORT >= 1024 && PORT <= 65535))) || fail "port 443 ya da 1024-65535 olmalı"
  ((PORT != 8090)) || fail "8090 panelin iç portu; başka bir port seçin"
  [[ $PORT != 443 || -n $DOMAIN ]] || fail "443 yalnızca --domain ile (sitelerle aynı portu paylaşır)"
  [[ $VERSION == latest || $VERSION =~ ^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || fail "geçersiz sürüm: ${VERSION}"
  if [[ -n $TARBALL ]]; then
    [[ -f $TARBALL ]] || fail "dosya yok: ${TARBALL}"
    [[ -n $SUMS && -f $SUMS ]] || fail "--tarball için --sums (SHA256SUMS) gerekli"
  fi
  if [[ -n $IMPORT ]]; then
    [[ -f $IMPORT ]] || fail "dosya yok: ${IMPORT}"
  fi
  return 0
}

# archive_ok TARBALL TOPDIR — only regular files and directories, all under
# TOPDIR/, no "..". (No "cmd | grep -q" here: with pipefail an early grep exit
# turns into a SIGPIPE failure and the check would silently pass.)
archive_ok() {
  local list
  list=$(tar -tzvf "$1") || return 1
  [[ -z $(awk 'substr($1,1,1) != "-" && substr($1,1,1) != "d"' <<<"$list") ]] || return 1
  list=$(tar -tzf "$1") || return 1
  [[ -z $(grep -vE "^${2//./\\.}(/|$)" <<<"$list") ]] || return 1
  [[ -z $(grep -E '(^|/)\.\.(/|$)' <<<"$list") ]]
}

# ssh_ports_from — sshd -T output on stdin → listening ports, one per line.
ssh_ports_from() {
  awk '$1 == "port" && $2 ~ /^[0-9]+$/ {print $2}' | sort -un
}

# ssh_ports — every port sshd listens on, plus the one this session came in on.
ssh_ports() {
  {
    sshd -T 2>/dev/null | ssh_ports_from || true
    if [[ -n ${SSH_CONNECTION:-} ]]; then
      local p
      p=$(awk '{print $4}' <<<"$SSH_CONNECTION")
      [[ $p =~ ^[0-9]+$ ]] && echo "$p"
    fi
  } | sort -un
}

# ufw_plan SSHPORT... — the allow rules install.sh adds (SSH first).
ufw_plan() {
  local p
  for p in "$@"; do echo "${p}/tcp"; done
  echo 80/tcp
  echo 443/tcp
  [[ $PORT == 443 ]] || echo "${PORT}/tcp"
}

# client_ip — address of the admin running this over SSH (kept out of fail2ban bans).
client_ip() {
  local ip
  ip=$(awk '{print $1}' <<<"${SSH_CONNECTION:-}")
  [[ $ip =~ ^[0-9a-fA-F.:]+$ ]] && echo "$ip"
  return 0
}

confirm() {
  ((YES)) && return 0
  [[ -r /dev/tty ]] || return 1
  local a
  read -r -p "$1 [E/h] " a </dev/tty || return 1
  [[ -z $a || $a == [EeYy]* ]]
}

# os_release FILE — prints "<ID> <VERSION_ID>". Sourced in a subshell:
# os-release defines VERSION, NAME, ID… which would overwrite our own
# variables (VERSION is the release tag to download).
os_release() {
  (
    # shellcheck disable=SC1090
    . "$1"
    printf '%s %s\n' "${ID:-}" "${VERSION_ID:-}"
  )
}

check_system() {
  [[ $EUID -eq 0 ]] || fail "root olarak çalıştırın (sudo)"
  local os
  os=$(os_release /etc/os-release)
  [[ $os == "ubuntu 24.04" ]] || fail "yalnızca Ubuntu 24.04 desteklenir (bulunan: ${os:-?})"
  case $(dpkg --print-architecture) in
    amd64) ARCH=amd64 ;;
    arm64) ARCH=arm64 ;;
    *) fail "desteklenmeyen mimari: $(dpkg --print-architecture)" ;;
  esac
  command -v systemctl >/dev/null || fail "systemd gerekli"
}

install_packages() {
  local missing=() p
  for p in "${PACKAGES[@]}"; do
    [[ $(dpkg-query -W -f='${Status}' "$p" 2>/dev/null) == *"install ok installed"* ]] || missing+=("$p")
  done
  if ((${#missing[@]} == 0)); then
    say "Paketler kurulu"
    return
  fi
  say "Paketler kuruluyor: ${missing[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q --no-install-recommends "${missing[@]}"
}

create_user() {
  if ! id hostpanel >/dev/null 2>&1; then
    say "hostpanel kullanıcısı oluşturuluyor"
    useradd --system --user-group --home-dir /var/lib/hostpanel --no-create-home --shell /usr/sbin/nologin hostpanel
  fi
  # adm: /var/log/{nginx,auth.log,fail2ban.log}; systemd-journal: site journals (read-only).
  usermod -a -G adm,systemd-journal hostpanel
}

# fetch_release DIR — unpack the release into DIR, verified against SHA256SUMS.
# Prints the unpacked package directory.
fetch_release() {
  local dir=$1 name tarball sums
  if [[ -n $TARBALL ]]; then
    tarball=$(readlink -f "$TARBALL") sums=$(readlink -f "$SUMS")
  else
    if [[ $VERSION == latest ]]; then
      VERSION=$(curl -fsSL --proto '=https' --max-time 30 -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/${REPO}/releases/latest" | jq -r .tag_name) || fail "son sürüm bulunamadı"
      [[ $VERSION =~ ^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || fail "son sürüm etiketi beklenmeyen: ${VERSION}"
    fi
    name=hostpanel-${VERSION}-linux-${ARCH}
    say "İndiriliyor: ${REPO} ${VERSION} (${ARCH})" >&2
    curl -fsSL --proto '=https' --tlsv1.2 --max-time 900 -o "$dir/${name}.tar.gz" \
      "https://github.com/${REPO}/releases/download/${VERSION}/${name}.tar.gz" || fail "indirme başarısız"
    curl -fsSL --proto '=https' --tlsv1.2 --max-time 60 -o "$dir/SHA256SUMS" \
      "https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS" || fail "SHA256SUMS indirilemedi"
    tarball=$dir/${name}.tar.gz sums=$dir/SHA256SUMS
  fi
  local base want got
  base=$(basename "$tarball")
  [[ $base =~ ^hostpanel-v[0-9]+\.[0-9]+\.[0-9]+-linux-(amd64|arm64)\.tar\.gz$ ]] || fail "beklenmeyen dosya adı: ${base}"
  [[ $base == *-linux-${ARCH}.tar.gz ]] || fail "${base} bu sunucunun mimarisi (${ARCH}) için değil"
  want=$(awk -v f="$base" '$2 == f {print $1}' "$sums")
  [[ $want =~ ^[0-9a-f]{64}$ ]] || fail "SHA256SUMS içinde ${base} yok"
  got=$(sha256sum "$tarball" | awk '{print $1}')
  [[ $got == "$want" ]] || fail "SHA-256 uyuşmuyor: ${base}"
  say "SHA-256 doğrulandı: ${base}" >&2
  name=${base%.tar.gz}
  archive_ok "$tarball" "$name" || fail "arşivde beklenmeyen giriş (link, mutlak yol, ..)"
  tar -xzf "$tarball" -C "$dir" --no-same-owner --no-same-permissions
  echo "$dir/$name"
}

create_dirs() {
  # /etc/hostpanel: panel reads config/key/runtimes, others may only traverse
  # (php-fpm as the site user reads php/<domain>.conf). See lib.sh ensure_etc_dir.
  install -d -o root -g hostpanel -m 0751 /etc/hostpanel
  chown root:hostpanel /etc/hostpanel
  chmod 0751 /etc/hostpanel
  install -d -o root -g root -m 0700 /etc/hostpanel/env /etc/hostpanel/ssl /etc/hostpanel/git
  install -d -o root -g root -m 0755 /etc/hostpanel/php /etc/hostpanel/runtimes
  install -d -o hostpanel -g hostpanel -m 0750 /var/lib/hostpanel /var/log/hostpanel
  install -d -o root -g hostpanel -m 0750 /var/log/hostpanel-root
  install -d -o root -g root -m 0755 /var/www/sites
  install -d -o root -g root -m 0700 /var/backups/hostpanel
}

master_key() {
  local k=/etc/hostpanel/master.key
  if [[ -s $k ]]; then
    chown hostpanel:hostpanel "$k"
    chmod 0600 "$k"
    return
  fi
  say "master.key üretiliyor"
  local tmp
  tmp=$(mktemp /etc/hostpanel/.key.XXXXXX)
  head -c 32 /dev/urandom >"$tmp"
  chown hostpanel:hostpanel "$tmp"
  chmod 0600 "$tmp"
  mv "$tmp" "$k"
}

# set_config KEY VALUE — replace (or append) a top-level scalar in config.yaml.
set_config() {
  local f=/etc/hostpanel/config.yaml k=$1 v=$2
  if grep -qE "^${k}:" "$f"; then
    sed -i -E "s|^${k}:.*$|${k}: ${v}|" "$f"
  else
    printf '%s: %s\n' "$k" "$v" >>"$f"
  fi
}

write_config() {
  local f=/etc/hostpanel/config.yaml
  if [[ ! -f $f ]]; then
    say "config.yaml yazılıyor"
    install -o root -g hostpanel -m 0640 "$PKG/deploy/config.example.yaml" "$f"
  fi
  chown root:hostpanel "$f"
  chmod 0640 "$f"
  set_config panel_domain "\"${DOMAIN}\""
  set_config panel_port "$PORT"
  set_config update_repo "$REPO"
}

setup_firewall() {
  if ((NO_FW)); then
    say "UFW atlandı (--no-firewall)"
    return
  fi
  local ports rule active=0 enable=0
  mapfile -t ports < <(ssh_ports)
  if ((${#ports[@]} == 0)); then
    warn "SSH portu tespit edilemedi; SSH erişimini kesmemek için UFW'ye dokunulmadı"
    return
  fi
  [[ $(ufw status 2>/dev/null | head -n1) == "Status: active" ]] && active=1
  say "UFW izin kuralları: $(ufw_plan "${ports[@]}" | paste -sd' ' -)"
  if ((!active)); then
    if confirm "UFW kapalı. Bu kurallarla etkinleştirilsin mi? (SSH portları ${ports[*]} açık kalır)"; then
      enable=1
    else
      warn "UFW açılmadı; kurallar eklendi, hazır olduğunuzda 'sudo ufw enable'"
    fi
  fi
  # Rules first (also while UFW is off), SSH before anything else.
  while read -r rule; do
    ufw allow "$rule" >/dev/null
  done < <(ufw_plan "${ports[@]}")
  if ((enable)); then
    ufw --force enable >/dev/null
    say "UFW etkinleştirildi"
  fi
}

setup_fail2ban() {
  local ign="127.0.0.1/8 ::1" ip
  ip=$(client_ip)
  [[ -n $ip ]] && ign+=" $ip"
  install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d
  cat >/etc/fail2ban/filter.d/hostpanel.conf <<'FILTER'
# HostPanel panel logins (written by install.sh). Line format of
# /var/log/hostpanel/auth.log: "<RFC3339> hostpanel: login failed ip=<IP> reason=<r>"
[Definition]
failregex = hostpanel: login failed ip=<HOST>(?:\s|$)
ignoreregex =
FILTER
  # The filter must match a real line before the jail is trusted.
  local sample on=true
  sample="$(date -u +%Y-%m-%dT%H:%M:%SZ) hostpanel: login failed ip=192.0.2.10 reason=password"
  if [[ $(fail2ban-regex "$sample" /etc/fail2ban/filter.d/hostpanel.conf 2>/dev/null) != *"Lines: 1 lines, 0 ignored, 1 matched"* ]]; then
    warn "fail2ban filtresi örnek satırı eşleştirmedi; hostpanel jail'i kapalı yazıldı"
    on=false
  fi
  local f2b_ports="443"
  [[ $PORT == 443 ]] || f2b_ports="${PORT},443"
  cat >/etc/fail2ban/jail.d/hostpanel.conf <<JAIL
# HostPanel (written by install.sh). ignoreip keeps the installing admin's
# address from being locked out; edit if that address changes.
[hostpanel]
enabled  = ${on}
filter   = hostpanel
logpath  = /var/log/hostpanel/auth.log
backend  = auto
port     = ${f2b_ports}
maxretry = 5
findtime = 15m
bantime  = 1h
ignoreip = ${ign}

[sshd]
enabled  = true
ignoreip = ${ign}
JAIL
  [[ -f /var/log/hostpanel/auth.log ]] || install -o hostpanel -g hostpanel -m 0640 /dev/null /var/log/hostpanel/auth.log
  if fail2ban-client -t >/dev/null 2>&1; then
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban
    say "fail2ban: sshd + hostpanel jail'leri (muaf: ${ign})"
  else
    warn "fail2ban yapılandırma testi başarısız; servis yeniden başlatılmadı (fail2ban-client -t)"
  fi
}

setup_logrotate() {
  cat >/etc/logrotate.d/hostpanel <<'ROTATE'
# HostPanel (written by install.sh). The panel keeps panel.log/auth.log open → copytruncate.
/var/log/hostpanel/panel.log /var/log/hostpanel/auth.log {
    su hostpanel hostpanel
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
# Root helper logs are opened on every write.
/var/log/hostpanel-root/*.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root hostpanel
}
ROTATE
}

# setup_vhost — panel behind nginx: Let's Encrypt for --domain, else self-signed on the IP.
setup_vhost() {
  if [[ -n $DOMAIN ]]; then
    if [[ ! -s /etc/letsencrypt/live/$PANEL_CERT_NAME/fullchain.pem ]] ||
      [[ $(openssl x509 -in "/etc/letsencrypt/live/$PANEL_CERT_NAME/fullchain.pem" -noout -checkhost "$DOMAIN" 2>/dev/null) != *"does match"* ]]; then
      say "Let's Encrypt sertifikası alınıyor: ${DOMAIN}"
      write_panel_vhost acme "$DOMAIN" "$PORT"
      local args=(certonly --non-interactive --agree-tos --no-eff-email --webroot -w /var/www/letsencrypt
        --cert-name "$PANEL_CERT_NAME" -d "$DOMAIN" --keep-until-expiring)
      if [[ -n $EMAIL ]]; then args+=(--email "$EMAIL"); else args+=(--register-unsafely-without-email); fi
      if ! certbot "${args[@]}"; then
        warn "sertifika alınamadı (DNS ${DOMAIN} → bu sunucu mu, 80 açık mı?). Panel şimdilik IP üzerinden self-signed ile açılıyor; düzeltip install.sh'yi aynı --domain ile tekrar çalıştırın."
        panel_self_signed
        write_panel_vhost ip "" "$PORT"
        ensure_default_vhost
        return
      fi
    fi
    write_panel_vhost domain "$DOMAIN" "$PORT"
  else
    panel_self_signed
    write_panel_vhost ip "" "$PORT"
  fi
  ensure_default_vhost
}

import_config() {
  [[ -n $IMPORT ]] || return 0
  local pass=${HP_IMPORT_PASS:-}
  if [[ -z $pass ]]; then
    [[ -r /dev/tty ]] || fail "parola için HP_IMPORT_PASS verin (terminal yok)"
    read -r -s -p "Yapılandırma dosyasının parolası: " pass </dev/tty
    echo
  fi
  say "Yapılandırma içe aktarılıyor: ${IMPORT}"
  systemctl stop hostpanel 2>/dev/null || true
  HP_IMPORT_PASS=$pass "$HP_OPT/bin/hostpanel" admin import-config --file "$IMPORT" --config /etc/hostpanel/config.yaml
}

start_panel() {
  systemctl enable hostpanel >/dev/null 2>&1
  systemctl restart hostpanel
  local i
  for ((i = 0; i < 30; i++)); do
    [[ $(curl -fsS --max-time 2 "http://${PANEL_UPSTREAM}/healthz" 2>/dev/null) == "ok "* ]] && return 0
    sleep 1
  done
  journalctl -u hostpanel -n 30 --no-pager >&2 || true
  fail "panel başlamadı (journalctl -u hostpanel)"
}

summary() {
  local url ip creds=$1
  if [[ -n $DOMAIN && -s /etc/letsencrypt/live/$PANEL_CERT_NAME/fullchain.pem ]]; then
    url="https://${DOMAIN}"
    [[ $PORT == 443 ]] || url+=":${PORT}"
  else
    ip=$(server_ips | grep -v ':' | head -n1)
    [[ -n $ip ]] || ip=$(server_ips | head -n1)
    url="https://${ip:-<sunucu-ip>}:${PORT}"
  fi
  echo
  echo "────────────────────────────────────────────────────────────"
  echo " HostPanel ${VERSION} kuruldu"
  echo
  echo " Adres:     ${url}"
  if [[ $creds == *Şifre:* ]]; then
    sed 's/^/ /' <<<"$creds"
    echo
    echo " Şifreyi saklayın; ilk girişten sonra Ayarlar → Güvenlik'ten 2FA'yı açın."
  else
    echo " Giriş:     mevcut admin hesabı (unutulduysa: sudo -u hostpanel ${HP_OPT}/bin/hostpanel admin reset-password)"
  fi
  if [[ $url != https://${DOMAIN}* || -z $DOMAIN ]]; then
    echo
    echo " Sertifika self-signed; tarayıcı bir kez uyarır. Parmak izi (SHA-256):"
    echo "   $(openssl x509 -in "$PANEL_TLS_DIR/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
  fi
  echo "────────────────────────────────────────────────────────────"
}

WORK=""
main() {
  parse_args "$@"
  check_system
  install_packages
  create_user
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  PKG=$(fetch_release "$WORK")
  VERSION=$(basename "$PKG")
  VERSION=${VERSION#hostpanel-}
  VERSION=${VERSION%-linux-*}
  # From here on the release's own helper library does the work.
  # shellcheck source=deploy/scripts/lib.sh disable=SC1091
  source "$PKG/deploy/scripts/lib.sh"
  create_dirs
  say "Dosyalar kuruluyor (/opt/hostpanel)"
  install_release "$PKG"
  master_key
  write_config
  "$HP_OPT/scripts/hp-ssl.sh" setup >/dev/null
  setup_logrotate
  setup_firewall
  setup_fail2ban
  setup_vhost
  import_config
  local creds
  creds=$(runuser -u hostpanel -- "$HP_OPT/bin/hostpanel" admin init --config /etc/hostpanel/config.yaml)
  start_panel
  summary "$creds"
}

[[ ${HP_INSTALL_LIB:-} == 1 ]] || main "$@"
