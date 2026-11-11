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

# ensure_etc_dir — /etc/hostpanel is root:hostpanel 0751: the panel reads
# config.yaml, master.key and runtimes/ there but cannot create files; others
# may only traverse (php-fpm runs as the site user and reads php/<domain>.conf).
# Everything sensitive inside is 0600/0640 or in 0700 subdirectories. Helpers
# must never "install -d" it with other modes: that would lock the panel out.
ensure_etc_dir() {
  local grp=root
  getent group hostpanel >/dev/null && grp=hostpanel
  [[ ! -L /etc/hostpanel ]] || die "/etc/hostpanel symlink olamaz"
  if [[ ! -d /etc/hostpanel ]]; then
    install -d -o root -g "$grp" -m 0751 /etc/hostpanel
  fi
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
# validate_zone_file FILE ZONE — the zone file the panel rendered for ZONE.
# Same rules as Go dns.ValidateZoneFile (tests: testdata_zone_bad.txt):
# first line "$TTL n", then one record per line "owner. ttl IN TYPE rdata"
# with an absolute owner inside ZONE and type-specific rdata. No other $
# directive ($INCLUDE would make named read arbitrary files), no comments,
# no parentheses, printable ASCII only. Exactly one SOA, on line 2.
validate_zone_file() {
  local f=$1 zone=$2
  local size line n=0 soa=0 owner typ data
  [[ -f $f && ! -L $f ]] || die "zone dosyası yok"
  size=$(stat -c %s -- "$f")
  ((size > 0 && size <= 1048576)) || die "zone dosyası boyutu geçersiz"
  [[ $(tail -c1 -- "$f" | od -An -tx1 | tr -d ' ') == 0a ]] || die "zone dosyası satır sonuyla bitmeli"
  local host='[a-z0-9_-]+(\.[a-z0-9_-]+)*\.'
  local txtc='([] !#-[^-~]|\\["\\])*'
  local octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
  local re_rr='^([a-z0-9_*.-]+)\. ([0-9]{1,6}) IN (SOA|NS|A|AAAA|CNAME|MX|TXT|SRV|CAA) (.+)$'
  local re_owner='^(\*\.)?([a-z0-9_-]+\.)*[a-z0-9_-]+$'
  local re_soa="^${host} ${host} [0-9]{1,10}( [0-9]{1,10}){4}\$"
  local re_host="^${host}\$"
  local re_a="^(${octet}\\.){3}${octet}\$"
  local re_aaaa='^[0-9a-f:.]{2,45}$'
  local re_mx="^[0-9]{1,5} ${host}\$"
  local re_srv="^[0-9]{1,5} [0-9]{1,5} [0-9]{1,5} ${host}\$"
  local re_txt="^\"${txtc}\"( \"${txtc}\")*\$"
  local re_caa='^(0|128) (issue|issuewild|iodef) "[] !#-[^-~]{1,255}"$'
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    [[ $line != *[^[:print:]]* ]] || die "zone satır ${n}: geçersiz karakter"
    if ((n == 1)); then
      [[ $line =~ ^\$TTL\ [0-9]{2,6}$ ]] || die "zone: ilk satır \$TTL olmalı"
      continue
    fi
    [[ $line =~ $re_rr ]] || die "zone satır ${n}: geçersiz kayıt"
    owner=${BASH_REMATCH[1]} typ=${BASH_REMATCH[3]} data=${BASH_REMATCH[4]}
    [[ $owner == "$zone" || $owner == *".$zone" ]] || die "zone satır ${n}: ad zone dışında: ${owner}"
    [[ $owner =~ $re_owner ]] || die "zone satır ${n}: geçersiz ad: ${owner}"
    case $typ in
      SOA)
        ((n == 2)) && [[ $owner == "$zone" ]] || die "zone satır ${n}: SOA yalnızca 2. satırda ve kökte"
        [[ $data =~ $re_soa ]] || die "zone satır ${n}: geçersiz SOA"
        soa=$((soa + 1))
        ;;
      NS | CNAME) [[ $data =~ $re_host ]] || die "zone satır ${n}: geçersiz ${typ}" ;;
      A) [[ $data =~ $re_a ]] || die "zone satır ${n}: geçersiz A" ;;
      AAAA) [[ $data =~ $re_aaaa ]] || die "zone satır ${n}: geçersiz AAAA" ;;
      MX) [[ $data =~ $re_mx ]] || die "zone satır ${n}: geçersiz MX" ;;
      SRV) [[ $data =~ $re_srv ]] || die "zone satır ${n}: geçersiz SRV" ;;
      TXT) [[ $data =~ $re_txt ]] || die "zone satır ${n}: geçersiz TXT" ;;
      CAA) [[ $data =~ $re_caa ]] || die "zone satır ${n}: geçersiz CAA" ;;
    esac
  done <"$f"
  ((soa == 1)) || die "zone: tam bir SOA kaydı olmalı"
}

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

# validate_pg_image REF — only the official postgres image, pinned major.minor tag.
validate_pg_image() {
  [[ $1 =~ ^postgres:1[6-9]\.[0-9]{1,2}-(trixie|bookworm)$ ]] || die "izin verilmeyen imaj: $1"
}

# validate_pg_name NAME — PostgreSQL role/database names the panel manages.
# Mirrors pgsql.ValidName: never a system name, a pg_ prefix or the isolation
# test's hpiso_ prefix.
validate_pg_name() {
  [[ ${1:-} =~ ^[a-z][a-z0-9_]{1,62}$ ]] || die "geçersiz ad: '${1:-}'"
  case $1 in
    postgres | template0 | template1 | public | pg_* | hpiso_* | hprs_*) die "sistem adı kullanılamaz: $1" ;;
  esac
}

# validate_ip_or_cidr V — charset/length check; ufw parses the value itself
# (passed as one argv element, never through a shell).
validate_ip_or_cidr() {
  [[ ${#1} -le 50 && $1 =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ && $1 == *[.:]* ]] || die "geçersiz IP/CIDR: $1"
  [[ $1 != */0 ]] || die "/0 kabul edilmez: $1"
  # 0.0.0.0 / :: as a source match nothing (Go ParseAllowIPs gives the message).
  [[ ${1%%/*} != 0.0.0.0 && ${1%%/*} != :: && ${1%%/*} != 127.* ]] || die "geçersiz kaynak adresi: $1"
}

# ---------------------------------------------------------------------------
# Backups (Faz 4)
# ---------------------------------------------------------------------------

BACKUP_ROOT=/var/backups/hostpanel
MSSQL_HOST_BACKUP=/var/lib/hostpanel/mssql/backup
# PostgreSQL dumps written by root on the host (pre-drop + backup staging);
# kept outside the container's volume.
PG_HOST_BACKUP=/var/lib/hostpanel/postgres-backup

# check_db_dirs — the database directories sit in /var/lib/hostpanel, which the
# panel user owns: it could replace one with a symlink (e.g. to /etc) before
# root runs "install -d -m 0700 -o <uid>" on it or bind-mounts it into a
# container. Every helper touching them refuses symlinks first.
check_db_dirs() {
  local d
  for d in /var/lib/hostpanel/mssql /var/lib/hostpanel/postgres "$PG_HOST_BACKUP"; do
    [[ ! -L $d ]] || die "${d} symlink olamaz"
  done
}
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
  [[ ${1:-} =~ ^(files\.tar\.zst|ssl\.tar\.zst|config\.json|nginx\.conf|manifest\.json|SHA256SUMS|db-[a-z][a-z0-9_]{1,62}\.bak|db-pg-[a-z][a-z0-9_]{1,62}\.dump|mail-config\.tar\.zst|mail-data\.tar\.zst)$ ]] || die "yedekte beklenmeyen dosya: '${1:-}'"
}

# backup_dir DOMAIN NAME — the local directory of one backup. DOMAIN is a site
# domain or "_mail" (mail server backups, Faz 9).
backup_dir() {
  [[ ${1:-} == _mail ]] || validate_domain "$1"
  validate_backup_name "$2"
  printf '%s\n' "$BACKUP_ROOT/$1/$2"
}

# check_sums DIR — every file is an expected one and matches SHA256SUMS.
check_sums() {
  local d=$1 f line
  [[ -f $d/SHA256SUMS ]] || die "SHA256SUMS yok: ${d}"
  while IFS= read -r f; do
    validate_backup_file "$f"
  done < <(find "$d" -mindepth 1 -maxdepth 1 -printf '%f\n')
  [[ -z $(find "$d" -mindepth 1 \( -type l -o -type d \)) ]] || die "yedekte dizin/symlink olamaz"
  while IFS= read -r line; do
    [[ $line =~ ^[0-9a-f]{64}\ \ (.+)$ ]] || die "SHA256SUMS biçimi bozuk"
    validate_backup_file "${BASH_REMATCH[1]}"
  done <"$d/SHA256SUMS"
  (cd "$d" && sha256sum --quiet --strict -c SHA256SUMS) || die "sağlama toplamı tutmuyor: ${d}"
  log "sağlama toplamları doğru"
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

# ---------------------------------------------------------------------------
# Install / update (Faz 6) — shared by install.sh and hp-update.sh
# ---------------------------------------------------------------------------

HP_CONFIG=/etc/hostpanel/config.yaml
HP_OPT=/opt/hostpanel
HP_SUDOERS=/etc/sudoers.d/hostpanel
HP_UNIT=/etc/systemd/system/hostpanel.service
HP_VHOST=/etc/nginx/sites-available/hostpanel.conf
HP_VHOST_LINK=/etc/nginx/sites-enabled/hostpanel.conf
PANEL_TLS_DIR=/etc/hostpanel/panel-tls
PANEL_CERT_NAME=hostpanel-panel
PANEL_UPSTREAM=127.0.0.1:8090
UPDATE_DIR=/var/lib/hostpanel-update

# config_value KEY — top-level scalar from config.yaml ("" when missing).
# config.yaml is root:hostpanel 0640, so root may trust what it reads here.
config_value() {
  local k=$1
  [[ $k =~ ^[a-z_]+$ ]] || die "geçersiz config anahtarı"
  [[ -f $HP_CONFIG && ! -L $HP_CONFIG ]] || return 0
  sed -nE "s/^${k}:[[:space:]]*\"?([^\"#[:space:]]*)\"?[[:space:]]*(#.*)?\$/\\1/p" "$HP_CONFIG" | head -n1
}

# validate_version V — release tags look like v1.2.3.
validate_version() {
  [[ ${1:-} =~ ^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || die "geçersiz sürüm: '${1:-}' (vX.Y.Z)"
}

# validate_repo OWNER/NAME — GitHub repository.
validate_repo() {
  [[ ${1:-} =~ ^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$ && ${1:-} != *..* ]] || die "geçersiz repo: '${1:-}'"
}

# validate_panel_port N — 443 or an unprivileged port, never 80.
validate_panel_port() {
  local p=${1:-}
  [[ $p =~ ^[0-9]{1,5}$ ]] || die "geçersiz panel portu: '${p}'"
  ((p == 443 || (p >= 1024 && p <= 65535))) || die "panel portu 443 ya da 1024-65535 olmalı: ${p}"
  [[ $p != "${PANEL_UPSTREAM##*:}" ]] || die "panel portu iç port (${PANEL_UPSTREAM##*:}) ile aynı olamaz"
}

# hp_arch — release architecture name of this machine.
hp_arch() {
  case $(dpkg --print-architecture 2>/dev/null || uname -m) in
    amd64 | x86_64) echo amd64 ;;
    arm64 | aarch64) echo arm64 ;;
    *) die "desteklenmeyen mimari: $(uname -m)" ;;
  esac
}

# replace_tree SRC DEST — swap DEST for a root-owned copy of SRC (dirs 0755,
# files 0644, *.sh 0755). The old tree is renamed first, so a running script
# keeps its open file.
replace_tree() {
  local src=$1 dest=$2
  [[ -d $src && ! -L $dest ]] || die "replace_tree: geçersiz argüman"
  rm -rf -- "${dest}.new" "${dest}.old"
  cp -R -- "$src" "${dest}.new"
  chown -R root:root -- "${dest}.new"
  find "${dest}.new" -type d -exec chmod 0755 {} +
  find "${dest}.new" -type f -exec chmod 0644 {} +
  find "${dest}.new" -type f -name '*.sh' -exec chmod 0755 {} +
  [[ -e $dest ]] && mv -- "$dest" "${dest}.old"
  mv -- "${dest}.new" "$dest"
  rm -rf -- "${dest}.old"
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

# install_release SRC — install an unpacked release (SRC/bin/hostpanel,
# SRC/deploy/...): binary, helper scripts, templates, shipped runtime
# definitions (same-named files are replaced, extra ones kept), sudoers
# (visudo-checked first) and the systemd unit.
install_release() {
  local src=$1 f tmp
  for f in bin/hostpanel deploy/scripts/lib.sh deploy/templates deploy/runtimes deploy/sudoers/hostpanel deploy/systemd/hostpanel.service; do
    [[ -e $src/$f ]] || die "paket eksik: ${f}"
  done
  install -d -o root -g root -m 0755 "$HP_OPT" "$HP_OPT/bin"
  install -o root -g root -m 0755 "$src/bin/hostpanel" "$HP_OPT/bin/.hostpanel.new"
  mv -f -- "$HP_OPT/bin/.hostpanel.new" "$HP_OPT/bin/hostpanel"
  replace_tree "$src/deploy/scripts" "$HP_OPT/scripts"
  replace_tree "$src/deploy/templates" "$HP_OPT/templates"
  ensure_etc_dir
  install -d -o root -g root -m 0755 /etc/hostpanel/runtimes
  for f in "$src"/deploy/runtimes/*.yaml; do
    install -o root -g root -m 0644 "$f" /etc/hostpanel/runtimes/
  done
  # sudo ignores sudoers.d files whose name contains a dot: stage as .hostpanel.new.
  tmp=/etc/sudoers.d/.hostpanel.new
  install -o root -g root -m 0440 "$src/deploy/sudoers/hostpanel" "$tmp"
  if ! visudo -cqf "$tmp"; then
    rm -f -- "$tmp"
    die "sudoers dosyası doğrulanamadı (visudo -c)"
  fi
  mv -f -- "$tmp" "$HP_SUDOERS"
  install -o root -g root -m 0644 "$src/deploy/systemd/hostpanel.service" "$HP_UNIT"
  for f in install.sh update.sh uninstall.sh; do
    [[ -f $src/$f ]] && install -o root -g root -m 0755 "$src/$f" "$HP_OPT/$f"
  done
  systemctl daemon-reload
}

# server_ips — non-loopback addresses of this host, one per line.
server_ips() {
  hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9a-fA-F.:]+$' | grep -vE '^(127\.|::1$|fe80:)' || true
}

# panel_self_signed — create the IP-mode certificate once (ECDSA P-256, 10 years,
# SAN = server IPs). Kept across re-runs so the browser exception stays valid.
panel_self_signed() {
  ensure_etc_dir
  install -d -o root -g root -m 0700 "$PANEL_TLS_DIR"
  [[ -s $PANEL_TLS_DIR/cert.pem && -s $PANEL_TLS_DIR/key.pem ]] && return 0
  local san="DNS:localhost" ip
  while read -r ip; do
    [[ -n $ip ]] && san+=",IP:${ip}"
  done < <(server_ips)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=HostPanel" -addext "subjectAltName=${san}" \
    -keyout "$PANEL_TLS_DIR/key.pem" -out "$PANEL_TLS_DIR/cert.pem" 2>/dev/null || die "self-signed sertifika üretilemedi"
  chmod 0600 "$PANEL_TLS_DIR/key.pem"
  chmod 0644 "$PANEL_TLS_DIR/cert.pem"
}

# render_panel_vhost MODE DOMAIN PORT — print the panel's nginx config.
#   ip:     PORT ssl default_server with the self-signed certificate
#   acme:   port 80 for DOMAIN only (ACME challenge before the certificate exists)
#   domain: port 80 (ACME + redirect) and PORT ssl with the Let's Encrypt certificate
render_panel_vhost() {
  local mode=$1 domain=$2 port=$3 cert key redirect
  validate_oneof "$mode" ip acme domain
  validate_panel_port "$port"
  [[ $mode == ip ]] || validate_domain "$domain"
  echo "# HostPanel panel vhost (${mode}) — written by install.sh / hp-update.sh; do not edit."
  if [[ $mode != ip ]]; then
    redirect="https://\$host:${port}\$request_uri"
    [[ $port == 443 ]] && redirect="https://\$host\$request_uri"
    cat <<CONF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type text/plain;
    }
    location / {
        return 301 ${redirect};
    }
}
CONF
  fi
  [[ $mode == acme ]] && return 0
  if [[ $mode == ip ]]; then
    cert=$PANEL_TLS_DIR/cert.pem key=$PANEL_TLS_DIR/key.pem
  else
    cert=/etc/letsencrypt/live/$PANEL_CERT_NAME/fullchain.pem key=/etc/letsencrypt/live/$PANEL_CERT_NAME/privkey.pem
  fi
  local listen_opts="ssl http2" name=$domain hsts=""
  if [[ $mode == ip ]]; then
    name=_
    [[ $port != 443 ]] && listen_opts="ssl http2 default_server"
  else
    hsts='    add_header Strict-Transport-Security "max-age=31536000" always;'
  fi
  cat <<CONF
server {
    listen ${port} ${listen_opts};
    listen [::]:${port} ${listen_opts};
    server_name ${name};
    ssl_certificate ${cert};
    ssl_certificate_key ${key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:hp_ssl:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
${hsts}
    access_log /var/log/nginx/hostpanel-panel.access.log;
    error_log /var/log/nginx/hostpanel-panel.error.log;
    client_max_body_size 1100m;

    location / {
        proxy_pass http://${PANEL_UPSTREAM};
        proxy_http_version 1.1;
        # \$http_host keeps the port: the panel compares it with the Origin header (CSRF).
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        # SSE (live job and log streams) and large uploads go straight through.
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Database backup uploads (.bak / pg_dump): the panel allows 10 GiB there
    # (MaxBakBytes), everything else stays at 1100m.
    location ~ ^/sites/[0-9]+/import/(db|pg)\$ {
        client_max_body_size 10300m;
        proxy_pass http://${PANEL_UPSTREAM};
        proxy_http_version 1.1;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
CONF
}

# write_panel_vhost MODE DOMAIN PORT — install the panel vhost; nginx -t must
# pass, otherwise the previous file is restored.
write_panel_vhost() {
  local tmp backup=""
  tmp=$(mktemp)
  render_panel_vhost "$@" >"$tmp"
  if [[ -f $HP_VHOST ]]; then
    backup=$(mktemp)
    cp -p -- "$HP_VHOST" "$backup"
  fi
  install -o root -g root -m 0644 "$tmp" "$HP_VHOST"
  rm -f -- "$tmp"
  ln -sfn -- "$HP_VHOST" "$HP_VHOST_LINK"
  if ! nginx -t -q 2>/dev/null; then
    nginx -t 2>&1 | tail -n 5 >&2 || true
    if [[ -n $backup ]]; then
      install -o root -g root -m 0644 "$backup" "$HP_VHOST"
    else
      rm -f -- "$HP_VHOST" "$HP_VHOST_LINK"
    fi
    rm -f -- "$backup"
    die "panel nginx yapılandırması reddedildi; önceki hali geri yüklendi"
  fi
  rm -f -- "$backup"
  systemctl reload nginx
}

# ---------------------------------------------------------------------------
# Mail server (Faz 9, docker-mailserver)
# ---------------------------------------------------------------------------
# The account, alias and quota files are docker-mailserver's documented plain
# formats; root writes them here (never DMS's "setup email add", which puts the
# password on argv inside the container). Addresses are validated before they
# reach these functions, so they never contain "|", ":", "," or whitespace.

MAIL_ROOT=/var/lib/hostpanel-mail
MAIL_VHOST=/etc/nginx/sites-available/hostpanel-mail.conf
MAIL_VHOST_LINK=/etc/nginx/sites-enabled/hostpanel-mail.conf
MAIL_CERT_NAME=hostpanel-mail
MAIL_FILE_OWNER=${MAIL_FILE_OWNER:-root:root} # tests run unprivileged

# validate_mail_image REF — only docker-mailserver 17+, pinned release tag.
validate_mail_image() {
  [[ ${1:-} =~ ^mailserver/docker-mailserver:1[7-9]\.[0-9]{1,2}\.[0-9]{1,2}(-r[0-9]{1,2})?$ ]] || die "izin verilmeyen imaj: '${1:-}'"
}

_mail_local_ok() { [[ $1 =~ $2 && $1 != *..* && $1 != *. ]]; }

# validate_mail_addr A — mailbox/alias address (mirrors mail.ValidAddress).
validate_mail_addr() {
  local a=${1:-}
  [[ ${#a} -le 254 && $a == *@* ]] || die "geçersiz adres: '${a}'"
  _mail_local_ok "${a%%@*}" '^[a-z0-9][a-z0-9._-]{0,63}$' || die "geçersiz adres: '${a}'"
  validate_domain "${a#*@}"
}

# validate_mail_target A — forwarding target, may be external (mail.ValidTarget).
validate_mail_target() {
  local a=${1:-}
  [[ ${#a} -le 254 && $a == *@* ]] || die "geçersiz hedef: '${a}'"
  _mail_local_ok "${a%%@*}" '^[a-z0-9][a-z0-9._+-]{0,63}$' || die "geçersiz hedef: '${a}'"
  validate_domain "${a#*@}"
}

mail_write() { atomic_write "$1" 0600 "$MAIL_FILE_OWNER"; }
_mail_src() { if [[ -f $1 ]]; then printf '%s\n' "$1"; else echo /dev/null; fi; }

# mail_list ACC VIRT QUOTA — "account <addr> <quota_mb>" and
# "alias <addr> <target,target>" lines (no password hashes).
mail_list() {
  local acc virt quota
  acc=$(_mail_src "$1") virt=$(_mail_src "$2") quota=$(_mail_src "$3")
  awk -F'|' -v Q="$quota" '
    FILENAME == Q {
      n = split($0, q, ":")
      if (n == 2 && q[2] ~ /^[0-9]+M$/) { sub(/M$/, "", q[2]); qs[q[1]] = q[2] + 0 }
      next
    }
    NF >= 2 && $1 != "" { print "account " $1 " " (($1 in qs) ? qs[$1] : 0) }' "$quota" "$acc"
  awk '!/^[[:space:]]*#/ && NF == 2 { print "alias " $1 " " $2 }' "$virt"
}

# mail_has_account ACC ADDR / mail_has_alias VIRT ADDR
mail_has_account() { awk -F'|' -v a="$2" '$1 == a { f = 1 } END { exit !f }' "$(_mail_src "$1")"; }
mail_has_alias() { awk -v a="$2" 'NF == 2 && $1 == a { f = 1 } END { exit !f }' "$(_mail_src "$1")"; }
mail_account_count() { awk -F'|' 'NF >= 2 && $1 != "" { n++ } END { print n + 0 }' "$(_mail_src "$1")"; }

# mail_domain_used ACC VIRT DOMAIN — true if DOMAIN has an account or alias.
mail_domain_used() {
  awk -F'|' -v d="$3" '{ n = split($1, p, "@") } n == 2 && p[2] == d { f = 1 } END { exit !f }' "$(_mail_src "$1")" ||
    awk -v d="$3" 'NF == 2 { n = split($1, p, "@") } NF == 2 && n == 2 && p[2] == d { f = 1 } END { exit !f }' "$(_mail_src "$2")"
}

# mail_account_set ACC ADDR HASH — add or replace the account's line.
mail_account_set() {
  local acc=$1 addr=$2 hash=$3 re='^\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}$'
  [[ $hash =~ $re ]] || die "geçersiz şifre özeti"
  {
    awk -F'|' -v a="$addr" '$1 != a' "$(_mail_src "$acc")"
    printf '%s|{SHA512-CRYPT}%s\n' "$addr" "$hash"
  } | mail_write "$acc"
}

# mail_virt_drop VIRT ALIAS TARGET — remove TARGET from ALIAS ("" = from every
# alias); aliases left without targets disappear.
mail_virt_drop() {
  awk -v al="$2" -v t="$3" '
    NF == 2 && (al == "" || $1 == al) {
      n = split($2, ts, ","); out = ""
      for (i = 1; i <= n; i++) if (ts[i] != t && ts[i] != "") out = out (out == "" ? "" : ",") ts[i]
      if (out != "") print $1 " " out
      next
    }
    { print }' "$(_mail_src "$1")"
}

# mail_account_del ACC VIRT QUOTA ADDR — the account, its quota and every
# alias target pointing at it.
mail_account_del() {
  local acc=$1 virt=$2 quota=$3 addr=$4
  awk -F'|' -v a="$addr" '$1 != a' "$(_mail_src "$acc")" | mail_write "$acc"
  if [[ -f $quota ]]; then awk -F: -v a="$addr" '$1 != a' "$quota" | mail_write "$quota"; fi
  if [[ -f $virt ]]; then mail_virt_drop "$virt" "" "$addr" | mail_write "$virt"; fi
}

# mail_quota_set QUOTA ADDR MB — 0 removes the limit.
mail_quota_set() {
  local quota=$1 addr=$2 mb=$3
  {
    awk -F: -v a="$addr" '$1 != a' "$(_mail_src "$quota")"
    if ((mb > 0)); then printf '%s:%dM\n' "$addr" "$mb"; fi
  } | mail_write "$quota"
}

# mail_alias_add VIRT ALIAS TARGET — at most 50 targets per alias.
mail_alias_add() {
  local virt=$1 al=$2 t=$3 n
  n=$(awk -v al="$al" 'NF == 2 && $1 == al { print split($2, x, ",") }' "$(_mail_src "$virt")")
  ((${n:-0} < 50)) || die "bir adres en fazla 50 hedefe yönlendirilebilir"
  awk -v al="$al" -v t="$t" '
    NF == 2 && $1 == al {
      n = split($2, ts, ","); f = 0
      for (i = 1; i <= n; i++) if (ts[i] == t) f = 1
      print $1 " " (f ? $2 : $2 "," t); done = 1; next
    }
    { print }
    END { if (!done) print al " " t }' "$(_mail_src "$virt")" | mail_write "$virt"
}

# mail_alias_del VIRT ALIAS TARGET
mail_alias_del() { mail_virt_drop "$1" "$2" "$3" | mail_write "$1"; }

# render_mail_vhost HOST — port 80 only: the ACME challenge for the mail
# certificate; nothing else is served for the mail host name.
render_mail_vhost() {
  validate_domain "$1"
  cat <<CONF
# HostPanel mail server (hp-mail.sh) — certificate challenges only; do not edit.
server {
    listen 80;
    listen [::]:80;
    server_name $1;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type text/plain;
    }
    location / {
        return 404;
    }
}
CONF
}

# write_mail_vhost HOST — install it; nginx -t must pass, otherwise the
# previous file is restored.
write_mail_vhost() {
  local tmp backup=""
  tmp=$(mktemp)
  render_mail_vhost "$1" >"$tmp"
  if [[ -f $MAIL_VHOST ]]; then
    backup=$(mktemp)
    cp -p -- "$MAIL_VHOST" "$backup"
  fi
  install -o root -g root -m 0644 "$tmp" "$MAIL_VHOST"
  rm -f -- "$tmp"
  ln -sfn -- "$MAIL_VHOST" "$MAIL_VHOST_LINK"
  if ! nginx -t -q 2>/dev/null; then
    nginx -t 2>&1 | tail -n 5 >&2 || true
    if [[ -n $backup ]]; then
      install -o root -g root -m 0644 "$backup" "$MAIL_VHOST"
    else
      rm -f -- "$MAIL_VHOST" "$MAIL_VHOST_LINK"
    fi
    rm -f -- "$backup"
    die "posta sunucusu nginx yapılandırması reddedildi; önceki hali geri yüklendi"
  fi
  rm -f -- "$backup"
  systemctl reload nginx
}
