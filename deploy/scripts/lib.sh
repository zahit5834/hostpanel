#!/usr/bin/env bash
# Shared helpers for HostPanel root helper scripts.
#
# Every hp-*.sh script runs as root via sudo and MUST re-validate all of its
# arguments with these functions: the panel validates too, but these scripts
# are the security boundary between the unprivileged panel and root.
#
# Usage (first lines of each helper):
#   #!/usr/bin/env bash
#   source "$(dirname "$(readlink -f "$0")")/lib.sh"

set -euo pipefail
umask 027
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

die() {
  echo "HATA: $*" >&2
  exit 1
}

log() {
  echo "[$(basename "$0")] $*"
}

require_root() {
  [[ ${EUID} -eq 0 ]] || die "root olarak çalıştırılmalı (sudo)"
}

# validate_domain NAME — lowercase FQDN, labels 1-63 chars, total <= 253, at least one dot.
validate_domain() {
  local d=${1:-}
  [[ ${#d} -ge 3 && ${#d} -le 253 ]] || die "geçersiz domain uzunluğu: '${d}'"
  [[ $d =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || die "geçersiz domain: '${d}'"
}

# validate_name NAME [MAXLEN] — short identifiers: site users, db names, logins.
validate_name() {
  local n=${1:-} max=${2:-32}
  [[ ${#n} -ge 1 && ${#n} -le ${max} ]] || die "geçersiz ad uzunluğu: '${n}'"
  [[ $n =~ ^[a-z][a-z0-9_]*$ ]] || die "geçersiz ad: '${n}' (küçük harf, rakam, _)"
}

# validate_port N — panel-assigned app ports only.
validate_port() {
  local p=${1:-}
  [[ $p =~ ^[0-9]{1,5}$ ]] || die "geçersiz port: '${p}'"
  ((p >= 1024 && p <= 65535)) || die "port aralık dışı: ${p}"
}

# validate_oneof VALUE ALLOWED... — whitelist check.
validate_oneof() {
  local v=${1:-}
  shift
  local a
  for a in "$@"; do
    [[ $v == "$a" ]] && return 0
  done
  die "izin verilmeyen değer: '${v}' (izinli: $*)"
}

# validate_path_under PATH BASE — PATH must resolve (symlinks included) inside BASE.
# Prevents ../ traversal and symlink tricks pointing outside the allowed tree.
validate_path_under() {
  local p=${1:-} base=${2:-}
  [[ -n $p && -n $base ]] || die "path doğrulama: eksik argüman"
  [[ $p != *$'\n'* ]] || die "geçersiz path"
  local rp rb
  rp=$(realpath -m -- "$p") || die "path çözülemedi: ${p}"
  rb=$(realpath -m -- "$base") || die "base çözülemedi: ${base}"
  [[ $rp == "$rb" || $rp == "$rb"/* ]] || die "path izin verilen dizin dışında: ${p}"
  printf '%s\n' "$rp"
}

# atomic_write DEST MODE OWNER — write stdin to DEST via a temp file + rename.
atomic_write() {
  local dest=$1 mode=$2 owner=$3 tmp
  tmp=$(mktemp "$(dirname "$dest")/.hp-tmp.XXXXXX")
  cat >"$tmp"
  chmod "$mode" "$tmp"
  chown "$owner" "$tmp"
  mv -f "$tmp" "$dest"
}

# ---------------------------------------------------------------------------
# Site helpers (Faz 1)
# ---------------------------------------------------------------------------

# bash 5.2 expands '&' in ${var//pat/rep} replacements; we never want that.
shopt -u patsub_replacement 2>/dev/null || true

HP_ROOT=$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")
HP_TEMPLATES=${HP_TEMPLATES:-${HP_ROOT}/templates}
SITES_ROOT=/var/www/sites
ENV_DIR=/etc/hostpanel/env
UPLOAD_DIR=/var/lib/hostpanel/uploads

# validate_short NAME — site short name (site user is site_<short>).
validate_short() {
  [[ ${1:-} =~ ^[a-z][a-z0-9_]{0,23}$ ]] || die "geçersiz kısa ad: '${1:-}'"
}

# validate_site_user NAME — only panel-created site accounts.
validate_site_user() {
  [[ ${1:-} =~ ^site_[a-z][a-z0-9_]{0,23}$ ]] || die "geçersiz site kullanıcısı: '${1:-}'"
}

# validate_release NAME — YYYYMMDD-HHMMSS (00000000-000000 = placeholder).
validate_release() {
  [[ ${1:-} =~ ^[0-9]{8}-[0-9]{6}$ ]] || die "geçersiz sürüm adı: '${1:-}'"
}

# validate_reldir PATH — relative dir like "wwwroot/uploads"; no "..", no dot-start segments.
validate_reldir() {
  local d=${1:-}
  [[ $d =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$ && $d != *..* ]] || die "geçersiz dizin: '${d}'"
}

# site_dir DOMAIN — validated site root that must not be a symlink.
site_dir() {
  validate_domain "$1"
  local d=${SITES_ROOT}/$1
  [[ ! -L $d ]] || die "site dizini symlink olamaz: ${d}"
  printf '%s\n' "$d"
}

# conf_directives FILE — prints "name<TAB>firstarg" per nginx statement.
# Statements are split at every ; { } (even inside quotes/comments): this can
# only create extra statements, never hide one. Quotes and backslashes are
# stripped from tokens. Mirrors confDirectives() in internal/sites/validate.go.
conf_directives() {
  awk 'BEGIN { RS = "[;{}]"; q = "[\"\047\\\\]" }
  {
    rec = $0
    while (1) {
      sub(/^[ \t\r\n]+/, "", rec)
      if (rec == "") break
      tok = rec; sub(/[ \t\r\n].*$/, "", tok); gsub(q, "", tok)
      if (substr(tok, 1, 1) != "#") break
      i = index(rec, "\n"); if (i == 0) rec = ""; else rec = substr(rec, i + 1)
    }
    if (rec == "") next
    n = split(rec, f, /[ \t\r\n]+/)
    name = f[1]; arg = (n > 1) ? f[2] : ""
    gsub(q, "", name); gsub(q, "", arg)
    print name "\t" arg
  }' "$1"
}

# validate_nginx_conf FILE DOMAIN — reject directives that would make the root
# nginx master load code or open arbitrary files (logs, temp/cache paths, includes).
validate_nginx_conf() {
  local file=$1 domain=$2 name arg
  local forbidden='^(load_module|include|user|env|pid|daemon|master_process|lock_file|ssl_engine|ssl_conf_command|[a-z]+_ssl_conf_command|working_directory|thread_pool|worker_[a-z_]+|[a-z_]*_temp_path|[a-z_]*_cache_path|perl[a-z_]*|lua[a-z_]*|js_[a-z_]+)$'
  local sslfile='^([a-z]+_)?ssl_(certificate|certificate_key|trusted_certificate|client_certificate|crl|dhparam|password_file|stapling_file|session_ticket_key)$'
  while IFS=$'\t' read -r name arg; do
    [[ $name =~ $forbidden ]] && die "nginx: izin verilmeyen direktif: ${name}"
    if [[ $name =~ $sslfile ]]; then
      [[ $arg != *..* && $arg != *'$'* ]] &&
        [[ $arg == "/etc/letsencrypt/live/${domain}/"* || $arg == "/etc/hostpanel/ssl/${domain}/"* ]] ||
        die "nginx: ${name} yalnızca sitenin kendi sertifika dosyalarını gösterebilir"
    fi
    case $name in
      access_log)
        [[ $arg == off || $arg == "/var/log/nginx/hp-${domain}.access.log" ]] || die "nginx: access_log yalnızca site log dosyasına yazabilir" ;;
      error_log)
        [[ $arg == "/var/log/nginx/hp-${domain}.error.log" ]] || die "nginx: error_log yalnızca site log dosyasına yazabilir" ;;
      fastcgi_pass)
        [[ $arg == "unix:${SITES_ROOT}/${domain}/run/php.sock" ]] || die "nginx: fastcgi_pass yalnızca sitenin kendi PHP soketini gösterebilir" ;;
    esac
  done < <(conf_directives "$file")
  return 0
}

# read_stdin_limited DEST MAXBYTES — copy stdin to DEST, failing if larger than MAXBYTES.
read_stdin_limited() {
  local dest=$1 max=$2
  head -c "$((max + 1))" >"$dest"
  (( $(stat -c %s "$dest") <= max )) || die "girdi çok büyük (en fazla ${max} bayt)"
}

# env_line KEY VALUE — one systemd EnvironmentFile line that keeps VALUE literal:
# single-quoted (no processing at all), or double-quoted with \ " $ escaped
# when the value itself contains a single quote.
env_line() {
  local key=$1 val=$2
  if [[ $val != *"'"* ]]; then
    printf "%s='%s'" "$key" "$val"
  else
    val=${val//\\/\\\\}
    val=${val//\"/\\\"}
    val=${val//\$/\\\$}
    printf '%s="%s"' "$key" "$val"
  fi
}

# validate_email ADDR — mirrors ssl.ValidEmail.
validate_email() {
  [[ $1 =~ ^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$ ]] || die "geçersiz e-posta: $1"
}

# validate_id N — positive integer (database ids).
validate_id() {
  [[ $1 =~ ^[1-9][0-9]{0,17}$ ]] || die "geçersiz id: $1"
}

# split_pem_bundle IN KEYOUT CERTOUT — split a PEM stream into the private key
# (exactly one) and certificates (at least one). Any other block type is rejected.
split_pem_bundle() {
  local in=$1 keyout=$2 certout=$3 counts
  counts=$(awk -v k="$keyout" -v c="$certout" '
    /^-----BEGIN [A-Z ]+-----$/ {
      t = $0; sub(/^-----BEGIN /, "", t); sub(/-----$/, "", t)
      if (t == "PRIVATE KEY" || t == "RSA PRIVATE KEY" || t == "EC PRIVATE KEY") { out = k; nk++ }
      else if (t == "CERTIFICATE") { out = c; nc++ }
      else { bad++; out = "" }
    }
    out != "" { print > out }
    /^-----END [A-Z ]+-----$/ { out = "" }
    END { printf "%d %d %d", nk, nc, bad }' "$in")
  [[ $counts =~ ^1\ [1-9][0-9]*\ 0$ ]] || die "PEM paketi geçersiz (key/sertifika/diğer: ${counts})"
}

# cert_key_match CERT KEY — the first certificate's public key equals the key's.
cert_key_match() {
  local a b
  a=$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum) || return 1
  b=$(openssl pkey -in "$2" -pubout -outform DER 2>/dev/null | sha256sum) || return 1
  [[ -n $a && $a == "$b" && $a != "$(printf '' | sha256sum)" ]]
}

# validate_mssql_image REF — only Microsoft's SQL Server 2022/2025 images, pinned tag.
validate_mssql_image() {
  [[ $1 =~ ^mcr\.microsoft\.com/mssql/server:20(22|25)-[A-Za-z0-9.-]{1,64}$ ]] || die "izin verilmeyen imaj: $1"
}

# validate_mssql_pid PID — edition name or product key.
validate_mssql_pid() {
  [[ $1 =~ ^(Express|Developer|[A-Z0-9]{5}(-[A-Z0-9]{5}){4})$ ]] || die "geçersiz MSSQL_PID"
}

# validate_ip_or_cidr V — charset/length check; ufw parses the value itself
# (passed as one argv element, never through a shell).
validate_ip_or_cidr() {
  [[ ${#1} -le 50 && $1 =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ && $1 == *[.:]* ]] || die "geçersiz IP/CIDR: $1"
  [[ $1 != */0 ]] || die "/0 kabul edilmez: $1"
}

# ---------------------------------------------------------------------------
# Backups (Faz 4)
# ---------------------------------------------------------------------------

BACKUP_ROOT=/var/backups/hostpanel
MSSQL_HOST_BACKUP=/var/lib/hostpanel/mssql/backup
# ROOT_LOG_DIR holds logs root writes and the panel reads. It must not live in
# /var/log/hostpanel: that directory belongs to the panel user, who could plant
# a symlink and make root append to (or chgrp) an arbitrary file.
ROOT_LOG_DIR=/var/log/hostpanel-root

# root_log_file PATH — make sure PATH (inside ROOT_LOG_DIR) exists as a regular
# root:hostpanel 0640 file in a root-owned 0750 directory.
root_log_file() {
  local f=$1 grp=root
  getent group hostpanel >/dev/null && grp=hostpanel
  [[ ! -L $ROOT_LOG_DIR ]] || die "${ROOT_LOG_DIR} symlink olamaz"
  install -d -o root -g "$grp" -m 0750 "$ROOT_LOG_DIR"
  [[ ! -L $f ]] || die "${f} symlink olamaz"
  [[ -f $f ]] || install -o root -g "$grp" -m 0640 /dev/null "$f"
}

RCLONE_CONF=/etc/hostpanel/rclone.conf
RCLONE_SA=/etc/hostpanel/rclone-sa.json
RCLONE_BIN=/usr/local/bin/rclone
RCLONE_LOG=${ROOT_LOG_DIR}/rclone.log

# validate_backup_name NAME — YYYYMMDD-HHMMSS-<4 hex> (mirrors backups.ValidName).
validate_backup_name() {
  [[ ${1:-} =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$ ]] || die "geçersiz yedek adı: '${1:-}'"
}

# validate_components LIST — comma separated subset of files,db,config,ssl.
validate_components() {
  [[ ${1:-} =~ ^(files|db|config|ssl)(,(files|db|config|ssl)){0,3}$ ]] || die "geçersiz bileşen listesi: '${1:-}'"
}

# validate_bwlimit V — "0" (none) or rclone size like 512K, 2M.
validate_bwlimit() {
  [[ ${1:-} == 0 || ${1:-} =~ ^[1-9][0-9]{0,5}[KMG]?$ ]] || die "geçersiz bant genişliği: '${1:-}'"
}

# validate_server_name V — remote folder of this server.
validate_server_name() {
  [[ ${1:-} =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]] || die "geçersiz sunucu adı: '${1:-}'"
}

# validate_folder V — Drive root folder: up to 5 segments, no "." / "..".
validate_folder() {
  local f=${1:-} seg
  [[ ${#f} -le 200 && $f =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){0,4}$ ]] || die "geçersiz klasör: '${f}'"
  IFS=/ read -ra segs <<<"$f"
  for seg in "${segs[@]}"; do
    [[ $seg != . && $seg != .. ]] || die "geçersiz klasör: '${f}'"
  done
}

# validate_shared_id V — Shared Drive id or "-".
validate_shared_id() {
  [[ ${1:-} == - || ${1:-} =~ ^[A-Za-z0-9_-]{10,100}$ ]] || die "geçersiz Shared Drive ID"
}

# validate_staged_bak NAME — file name in the MSSQL backup volume.
validate_staged_bak() {
  [[ ${1:-} =~ ^hp(rs|im)-[A-Za-z0-9._-]{1,200}\.bak$ && ${1:-} != *..* ]] || die "geçersiz dosya adı: '${1:-}'"
}

# validate_backup_file NAME — files allowed inside a backup directory.
validate_backup_file() {
  [[ ${1:-} =~ ^(files\.tar\.zst|ssl\.tar\.zst|config\.json|nginx\.conf|manifest\.json|SHA256SUMS|db-[a-z][a-z0-9_]{1,62}\.bak)$ ]] || die "yedekte beklenmeyen dosya: '${1:-}'"
}

# ---------------------------------------------------------------------------
# Server page (Faz 5)
# ---------------------------------------------------------------------------

# validate_ufw_port V — single port or range a:b (1-65535). Mirrors system.ValidUFWPort.
validate_ufw_port() {
  local v=${1:-} a b
  if [[ $v =~ ^([0-9]{1,5}):([0-9]{1,5})$ ]]; then
    a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]}
    ((a >= 1 && b <= 65535 && a < b)) || die "geçersiz port aralığı: ${v}"
  elif [[ $v =~ ^[0-9]{1,5}$ ]]; then
    ((v >= 1 && v <= 65535)) || die "geçersiz port: ${v}"
  else
    die "geçersiz port: '${v}'"
  fi
}

# validate_ufw_rule_no N — rule number from "ufw status numbered".
validate_ufw_rule_no() {
  [[ ${1:-} =~ ^[1-9][0-9]{0,3}$ ]] || die "geçersiz kural numarası: '${1:-}'"
}

# ports_overlap SPEC PORT — SPEC is "22", "8000:9000" or "80,443"; true if PORT is covered.
ports_overlap() {
  local spec=$1 p=$2 part
  IFS=, read -ra parts <<<"$spec"
  for part in "${parts[@]}"; do
    if [[ $part =~ ^([0-9]+):([0-9]+)$ ]]; then
      ((p >= BASH_REMATCH[1] && p <= BASH_REMATCH[2])) && return 0
    elif [[ $part =~ ^[0-9]+$ ]]; then
      ((part == p)) && return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# Site crons, git deploy, PHP (Faz 5b)
# ---------------------------------------------------------------------------

GIT_KEY_ROOT=/etc/hostpanel/git
PHP_CONF_DIR=/etc/hostpanel/php

# validate_user_command CMD — one line, no control characters, 1–1000 bytes.
# The command only ever runs as the site user inside run_as_site (bash -c
# there, never here). Mirrors crons.ValidCommand.
validate_user_command() {
  local c=${1:-}
  [[ -n ${c//[[:space:]]/} ]] || die "komut boş"
  ((${#c} <= 1000)) || die "komut çok uzun (en fazla 1000 bayt)"
  [[ $c != *[[:cntrl:]]* ]] || die "komut kontrol karakteri içeremez (tek satır olmalı)"
}

# read_user_command — read the command from stdin (at most 1000 bytes) and validate it.
read_user_command() {
  local c
  c=$(head -c 1001)
  validate_user_command "$c"
  printf '%s' "$c"
}

# validate_git_url URL — git@host:path, ssh://[user@]host[:port]/path or
# https://host[:port]/path (no credentials). Mirrors sites.ValidGitURL.
validate_git_url() {
  local u=${1:-}
  local host='[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*'
  local path='[A-Za-z0-9_~][A-Za-z0-9._~/-]*'
  ((${#u} <= 300)) || die "repo adresi çok uzun"
  [[ $u != *..* ]] || die "geçersiz repo adresi: ${u}"
  [[ $u =~ ^[A-Za-z0-9][A-Za-z0-9._-]*@${host}:${path}$ ||
    $u =~ ^ssh://([A-Za-z0-9][A-Za-z0-9._-]*@)?${host}(:[0-9]{1,5})?/${path}$ ||
    $u =~ ^https://${host}(:[0-9]{1,5})?/${path}$ ]] || die "geçersiz repo adresi: ${u}"
}

# validate_git_branch NAME — conservative subset of git's ref rules.
validate_git_branch() {
  local b=${1:-}
  [[ $b =~ ^[A-Za-z0-9_][A-Za-z0-9._/-]{0,99}$ ]] || die "geçersiz branch: '${b}'"
  [[ $b != *..* && $b != *//* && $b != */ && $b != *. && $b != *.lock && $b != */.* ]] || die "geçersiz branch: '${b}'"
}

# validate_outdir D — "." or a relative directory (build output).
validate_outdir() {
  [[ ${1:-} == . ]] || validate_reldir "${1:-}"
}

# validate_limits TIMEOUT MEM CPU — seconds / MB / percent for run_as_site.
validate_limits() {
  [[ $1 =~ ^[0-9]{1,5}$ ]] && (($1 >= 10 && $1 <= 7200)) || die "geçersiz zaman aşımı: $1"
  [[ $2 =~ ^[0-9]{2,5}$ ]] && (($2 >= 64 && $2 <= 65536)) || die "geçersiz bellek limiti: $2"
  [[ $3 =~ ^[0-9]{1,4}$ ]] && (($3 >= 5 && $3 <= 1600)) || die "geçersiz CPU kotası: $3"
}

# runtime_path ID VERSION — PATH prefix for a runtime's binaries (may be empty).
runtime_path() {
  case $1 in
    dotnet) printf '%s' /usr/share/dotnet ;;
    node)
      [[ $2 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}$ ]] || die "geçersiz Node sürümü: $2"
      printf '%s' "/opt/node/v$2/bin" ;;
    php | static) ;;
    *) die "geçersiz altyapı: $1" ;;
  esac
}

# run_as_site DIR USER UNIT TIMEOUT MEM CPU WORKDIR PATHPREFIX CMD — run CMD
# with bash as the site user in a transient, sandboxed unit (same isolation as
# the site's own service). Arguments must already be validated. Variable
# expansion by systemd is off: "$" in CMD is the shell's business. The fixed
# unit name means a second run of the same job cannot start while one runs.
# Exit status is the command's.
run_as_site() {
  local dir=$1 user=$2 unit=$3 timeout=$4 mem=$5 cpu=$6 workdir=$7 pathpre=$8 cmd=$9
  local domain path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  domain=$(basename "$dir")
  [[ -n $pathpre ]] && path=$pathpre:$path
  local home=$dir/.home
  [[ ! -L $home ]] || die "${home} symlink olamaz"
  [[ -d $home ]] || install -d -o "$user" -g "$user" -m 0700 "$home"
  local args=(--wait --pipe --collect --expand-environment=no --unit="$unit"
    --uid="$user" --gid="$user" --working-directory="$workdir"
    --setenv=HOME="$home" --setenv=PATH="$path"
    -p RuntimeMaxSec="$timeout" -p MemoryMax="${mem}M" -p CPUQuota="${cpu}%" -p TasksMax=256
    -p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes
    -p PrivateDevices=yes -p ProtectKernelTunables=yes -p ProtectKernelModules=yes
    -p ProtectControlGroups=yes -p RestrictSUIDSGID=yes -p LockPersonality=yes
    -p ReadWritePaths="$dir" -p UMask=0027 -p SyslogIdentifier="$unit")
  [[ -f $ENV_DIR/$domain.env ]] && args+=(-p EnvironmentFile="$ENV_DIR/$domain.env")
  systemd-run "${args[@]}" -- /bin/bash -c "$cmd" </dev/null
}

# finalize_release DIR USER REL [persistent_dir...] — link persistent dirs from
# shared/ into a release and fix permissions (nginx's group may read). Runs the
# file operations as the site user.
finalize_release() {
  local dir=$1 user=$2 rel=$3 d
  shift 3
  for d in "$@"; do
    runuser -u "$user" -- mkdir -p -- "$dir/shared/$d"
    if [[ -e $rel/$d || -L $rel/$d ]]; then
      log "kalıcı dizin '${d}' sürümden kaldırılıp shared/'a bağlanıyor"
      runuser -u "$user" -- rm -rf -- "$rel/$d"
    fi
    runuser -u "$user" -- mkdir -p -- "$(dirname "$rel/$d")"
    runuser -u "$user" -- ln -s -- "$dir/shared/$d" "$rel/$d"
  done
  runuser -u "$user" -- chmod -R u+rwX,g+rX,g-w,o-rwx -- "$rel"
  log "sürüm hazır: $(basename "$rel") ($(du -sh "$rel" | cut -f1), $(find "$rel" -type f | wc -l) dosya)"
}
