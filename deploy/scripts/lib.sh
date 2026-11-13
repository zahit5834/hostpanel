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

# zone_serial FILE — SOA serial of a panel zone file (line 2, field 7).
zone_serial() {
  awk 'NR == 2 && $4 == "SOA" { print $7; exit }' "$1"
}

# zone_set_serial FILE SERIAL — rewrite the SOA serial in place.
zone_set_serial() {
  local f=$1 s=$2
  [[ $s =~ ^[0-9]{1,10}$ ]] && ((s <= 4294967295)) || die "SOA serial taşması: ${s}"
  awk -v s="$s" 'NR == 2 && $4 == "SOA" { $7 = s } { print }' "$f" >"$f.serial" && mv -f "$f.serial" "$f"
}

# zone_next_serial INCOMING CURRENT — max(incoming, current+1); current may
# be empty (new zone). A serial that moves backwards would leave secondaries
# and the inline-signed copy of a DNSSEC zone on the old data.
zone_next_serial() {
  local in=$1 cur=${2:-}
  if [[ -n $cur ]] && ((cur + 1 > in)); then echo $((cur + 1)); else echo "$in"; fi
}

# ACME DNS-01 challenge lines (root generated only): one TXT per value, TTL 60.
ACME_TTL=60
acme_line() { printf '_acme-challenge.%s. %s IN TXT "%s"\n' "$1" "$ACME_TTL" "$2"; }

# validate_acme_value V — certbot's CERTBOT_VALIDATION (base64url SHA-256).
validate_acme_value() {
  [[ $1 =~ ^[A-Za-z0-9_-]{43}$ ]] || die "geçersiz ACME doğrulama değeri"
}

# zone_with_acme SRC STATE OUT — SRC without the lines of STATE that it may
# already hold, plus every line of STATE (deduplicated, input order kept).
zone_with_acme() {
  local src=$1 state=$2 out=$3
  if [[ -s $state ]]; then
    grep -vxF -f "$state" "$src" >"$out" || true
    awk '!seen[$0]++' "$state" >>"$out"
  else
    cat "$src" >"$out"
  fi
}

# acme_state_edit STATE add|del LINE — add/remove one challenge line
# (at most 20 per zone: a renewal holds two per wildcard name).
acme_state_edit() {
  local state=$1 op=$2 line=$3 n
  touch "$state"
  grep -vxF -- "$line" "$state" >"$state.new" || true
  if [[ $op == add ]]; then
    n=$(wc -l <"$state.new")
    ((n < 20)) || die "bu zone'da çok fazla bekleyen ACME doğrulaması var"
    printf '%s\n' "$line" >>"$state.new"
  fi
  mv -f "$state.new" "$state"
  chmod 0600 "$state"
}

# acme_zone_for NAME ZONE... — the longest zone that NAME belongs to.
acme_zone_for() {
  local name=$1 z best=""
  shift
  for z in "$@"; do
    if [[ $name == "$z" || $name == *".$z" ]] && ((${#z} > ${#best})); then best=$z; fi
  done
  [[ -n $best ]] || return 1
  printf '%s\n' "$best"
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

# Database directories (Faz 13). They used to sit in /var/lib/hostpanel, which
# the panel user owns: it could swap one for a symlink between root's check
# and use. The new parent DB_ROOT belongs to root, so nothing in the path is
# writable by the panel. Installs from before Faz 13 keep the old location
# until the panel's "move" job (relocate) runs, one engine at a time.
DB_ROOT=/var/lib/hostpanel-db
OLD_DB_ROOT=/var/lib/hostpanel
DB_NAMES=(mssql postgres postgres-backup)
DB_ROOT_UID=0 # owner required for DB_ROOT (test_lib.sh uses its own uid)

# db_path NAME — where NAME (mssql|postgres|postgres-backup) lives: the old
# location only while it exists there and not in the new one.
db_path() {
  if [[ -e $DB_ROOT/$1 || -L $DB_ROOT/$1 || ! (-e $OLD_DB_ROOT/$1 || -L $OLD_DB_ROOT/$1) ]]; then
    printf '%s\n' "$DB_ROOT/$1"
  else
    printf '%s\n' "$OLD_DB_ROOT/$1"
  fi
}

# db_moved NAME — 0 when NAME uses the root-owned location.
db_moved() { [[ $(db_path "$1") == "$DB_ROOT/$1" ]]; }

# ensure_db_root — the root-owned parent (created only when missing; an
# existing one must be a real directory owned by root and not group/world
# writable).
ensure_db_root() {
  [[ ! -L $DB_ROOT ]] || die "${DB_ROOT} symlink olamaz"
  if [[ ! -e $DB_ROOT ]]; then
    install -d -o root -g root -m 0711 "$DB_ROOT"
  fi
  [[ -d $DB_ROOT ]] || die "${DB_ROOT} dizin değil"
  local st
  st=$(stat -c '%u %a' "$DB_ROOT")
  [[ ${st%% *} == "$DB_ROOT_UID" ]] || die "${DB_ROOT} root'a ait değil"
  (((8#${st#* } & 8#022) == 0)) || die "${DB_ROOT} başkalarınca yazılabilir"
}

MSSQL_HOST_BACKUP=$(db_path mssql)/backup
# PostgreSQL dumps written by root on the host (pre-drop + backup staging);
# kept outside the container's volume.
PG_HOST_BACKUP=$(db_path postgres-backup)

# ensure_pg_backup_dir — root 0700 directory for host-side PostgreSQL dumps.
ensure_pg_backup_dir() {
  if [[ $PG_HOST_BACKUP == "$DB_ROOT"/* ]]; then ensure_db_root; fi
  install -d -m 0700 -o root -g root "$PG_HOST_BACKUP"
}

# check_db_dirs — refuse symlinks for every database directory (old and new
# location) and for the new parent; every helper touching them calls it first.
check_db_dirs() {
  local d n
  [[ ! -L $DB_ROOT ]] || die "${DB_ROOT} symlink olamaz"
  for n in "${DB_NAMES[@]}"; do
    for d in "$OLD_DB_ROOT/$n" "$DB_ROOT/$n"; do
      [[ ! -L $d ]] || die "${d} symlink olamaz"
    done
  done
}

# db_relocate to-new|to-old NAME... — move database directories between the
# old and the new parent. A rename on the same filesystem only (instant, no
# copy); the caller removes the container first. Everything is checked
# before the first move.
db_relocate() {
  local dir=$1 n src dst
  shift
  validate_oneof "$dir" to-new to-old
  check_db_dirs
  ensure_db_root
  for n in "$@"; do
    validate_oneof "$n" "${DB_NAMES[@]}"
    if [[ $dir == to-new ]]; then src=$OLD_DB_ROOT/$n dst=$DB_ROOT/$n; else src=$DB_ROOT/$n dst=$OLD_DB_ROOT/$n; fi
    [[ -e $src ]] || continue
    [[ -d $src ]] || die "${src} dizin değil"
    [[ ! -e $dst ]] || die "hedef zaten var: ${dst}"
    [[ $(stat -c %d "$src") == "$(stat -c %d "$(dirname "$dst")")" ]] ||
      die "${src} ile $(dirname "$dst") farklı dosya sistemlerinde (taşıma yalnızca aynı diskte yapılır)"
  done
  for n in "$@"; do
    if [[ $dir == to-new ]]; then src=$OLD_DB_ROOT/$n dst=$DB_ROOT/$n; else src=$DB_ROOT/$n dst=$OLD_DB_ROOT/$n; fi
    [[ -e $src ]] || continue
    mv -T -- "$src" "$dst"
    log "taşındı: ${src} → ${dst}"
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
  [[ ${1:-} =~ ^hp(rs|im|vf)-[A-Za-z0-9._-]{1,200}\.bak$ && ${1:-} != *..* ]] || die "geçersiz dosya adı: '${1:-}'"
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

# render_panel_vhost MODE DOMAIN PORT [IP_PORT] — print the panel's nginx config.
#   ip:     PORT ssl default_server with the self-signed certificate
#   acme:   port 80 for DOMAIN only (ACME challenge before the certificate exists)
#   domain: port 80 (ACME + redirect) and PORT ssl with the Let's Encrypt
#           certificate; with IP_PORT also the self-signed IP entry there
#           (fallback when the name is broken; settings → panel address)
render_panel_vhost() {
  local mode=$1 domain=$2 port=$3 ip_port=${4:-} redirect
  validate_oneof "$mode" ip acme domain
  validate_panel_port "$port"
  [[ $mode == ip ]] || validate_domain "$domain"
  if [[ -n $ip_port ]]; then
    [[ $mode == domain ]] || die "IP girişi yalnızca domain modunda"
    validate_panel_port "$ip_port"
    [[ $ip_port != "$port" ]] || die "IP girişi portu alan adının portundan farklı olmalı"
  fi
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
  case $mode in
    acme) return 0 ;;
    ip) _panel_tls_server "$port" "ssl http2 default_server" _ "$PANEL_TLS_DIR/cert.pem" "$PANEL_TLS_DIR/key.pem" "" ;;
    domain)
      _panel_tls_server "$port" "ssl http2" "$domain" "/etc/letsencrypt/live/$PANEL_CERT_NAME/fullchain.pem" \
        "/etc/letsencrypt/live/$PANEL_CERT_NAME/privkey.pem" '    add_header Strict-Transport-Security "max-age=31536000" always;'
      if [[ -n $ip_port ]]; then
        _panel_tls_server "$ip_port" "ssl http2 default_server" _ "$PANEL_TLS_DIR/cert.pem" "$PANEL_TLS_DIR/key.pem" ""
      fi
      ;;
  esac
}

# _panel_tls_server PORT LISTEN_OPTS NAME CERT KEY HSTS_LINE — one HTTPS block
# proxying to the panel.
_panel_tls_server() {
  local port=$1 opts=$2 name=$3 cert=$4 key=$5 hsts=$6
  cat <<CONF
server {
    listen ${port} ${opts};
    listen [::]:${port} ${opts};
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

# write_panel_vhost MODE DOMAIN PORT [IP_PORT] — install the panel vhost;
# nginx -t must pass, otherwise the previous file is restored.
write_panel_vhost() {
  local tmp default_port=""
  tmp=$(mktemp)
  render_panel_vhost "$@" >"$tmp"
  # a self-signed IP entry on 443 is that port's default server itself: drop
  # the catch-all first (nginx refuses two); ensure_default_vhost re-adds 80.
  [[ $1 == ip ]] && default_port=$3
  [[ $1 == domain && -n ${4:-} ]] && default_port=$4
  if [[ $default_port == 443 && -f $HP_DEFAULT_VHOST ]]; then
    rm -f -- "$HP_DEFAULT_VHOST_LINK" "$HP_DEFAULT_VHOST"
  fi
  install_vhost "$tmp" "$HP_VHOST" "$HP_VHOST_LINK" "panel"
}

# panel_vhost_from_config — write the vhost config.yaml describes: the domain
# (+ IP entry on panel_ip_port) once its certificate exists, else IP mode.
panel_vhost_from_config() {
  local domain port ip_port
  domain=$(config_value panel_domain)
  port=$(config_value panel_port)
  ip_port=$(config_value panel_ip_port)
  [[ -n $port ]] || port=8443
  [[ $ip_port == 0 ]] && ip_port=""
  if [[ -n $domain && -s /etc/letsencrypt/live/$PANEL_CERT_NAME/fullchain.pem ]]; then
    [[ -n $ip_port ]] && panel_self_signed
    write_panel_vhost domain "$domain" "$port" "$ip_port"
  else
    # no certificate (yet): the IP entry keeps its own port if there is one
    [[ -n $ip_port ]] && port=$ip_port
    panel_self_signed
    write_panel_vhost ip "" "$port"
  fi
}

# set_config_values KEY=VALUE... — rewrite top-level scalars of config.yaml
# (others, comments and mode/owner kept; empty VALUE = "", "-" = drop the key).
# Values are domains or numbers here (callers validate them).
set_config_values() {
  local kv k v owner mode tmp
  [[ -f $HP_CONFIG && ! -L $HP_CONFIG ]] || die "${HP_CONFIG} yok"
  owner=$(stat -c %U:%G "$HP_CONFIG") mode=$(stat -c %a "$HP_CONFIG")
  tmp=$(mktemp)
  cp -- "$HP_CONFIG" "$tmp"
  for kv in "$@"; do
    k=${kv%%=*} v=${kv#*=}
    [[ $k =~ ^[a-z_]+$ && $v =~ ^[a-z0-9.-]*$ ]] || die "geçersiz config değeri: ${kv}"
    if [[ $v == - ]]; then
      sed -i -E "/^${k}:/d" "$tmp"
      continue
    fi
    [[ $v =~ ^[0-9]+$ ]] || v="\"${v}\""
    if grep -qE "^${k}:" "$tmp"; then
      sed -i -E "s|^${k}:.*\$|${k}: ${v}|" "$tmp"
    else
      printf '%s: %s\n' "$k" "$v" >>"$tmp"
    fi
  done
  atomic_write "$HP_CONFIG" "$mode" "$owner" <"$tmp"
  rm -f -- "$tmp"
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

# mail_list ACC VIRT QUOTA [SUSPENDED_MAP BLOCKED_MAP] — lines
#   account <addr> <quota_mb> <flags>   flags: suspended,blocked or "-"
#   alias <addr> <target,target>
#   catchall <domain> <target>
# (no password hashes; the identity lines kept for catch-all are not aliases).
mail_list() {
  local acc virt quota susp blk
  acc=$(_mail_src "$1") virt=$(_mail_src "$2") quota=$(_mail_src "$3")
  susp=$(_mail_src "${4:-}") blk=$(_mail_src "${5:-}")
  awk -F'|' -v Q="$quota" -v S="$susp" -v B="$blk" '
    FILENAME == Q {
      n = split($0, q, ":")
      if (n == 2 && q[2] ~ /^[0-9]+M$/) { sub(/M$/, "", q[2]); qs[q[1]] = q[2] + 0 }
      next
    }
    FILENAME == S { if (NF) su[$1] = 1; next }
    FILENAME == B { if (NF) bl[$1] = 1; next }
    NF >= 2 && $1 != "" {
      fl = ""
      if (($1 in su) || $3 ~ /(^|,)nologin=y(,|$)/) fl = "suspended"
      if ($1 in bl) fl = fl (fl == "" ? "" : ",") "blocked"
      print "account " $1 " " (($1 in qs) ? qs[$1] : 0) " " (fl == "" ? "-" : fl)
    }' FS='|' "$quota" FS='[ \t]+' "$susp" "$blk" FS='|' "$acc"
  awk '!/^[[:space:]]*#/ && NF == 2 && $1 != $2 {
    if (substr($1, 1, 1) == "@") print "catchall " substr($1, 2) " " $2
    else print "alias " $1 " " $2
  }' "$virt"
}

# mail_has_account ACC ADDR / mail_has_alias VIRT ADDR
mail_has_account() { awk -F'|' -v a="$2" '$1 == a { f = 1 } END { exit !f }' "$(_mail_src "$1")"; }
mail_has_alias() { awk -v a="$2" 'NF == 2 && $1 == a && $2 != a { f = 1 } END { exit !f }' "$(_mail_src "$1")"; }
mail_account_count() { awk -F'|' 'NF >= 2 && $1 != "" { n++ } END { print n + 0 }' "$(_mail_src "$1")"; }

# mail_domain_used ACC VIRT DOMAIN — true if DOMAIN has an account or alias.
mail_domain_used() {
  awk -F'|' -v d="$3" '{ n = split($1, p, "@") } n == 2 && p[2] == d { f = 1 } END { exit !f }' "$(_mail_src "$1")" ||
    awk -v d="$3" 'NF == 2 { n = split($1, p, "@") } NF == 2 && n == 2 && p[2] == d { f = 1 } END { exit !f }' "$(_mail_src "$2")"
}

# mail_account_set ACC ADDR HASH — add or replace the account's line; extra
# fields of an existing line (nologin=y while suspended) are kept.
mail_account_set() {
  local acc=$1 addr=$2 hash=$3 re='^\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}$' extra
  [[ $hash =~ $re ]] || die "geçersiz şifre özeti"
  extra=$(awk -F'|' -v a="$addr" '$1 == a && NF >= 3 { print $3 }' "$(_mail_src "$acc")" | tail -n 1)
  [[ -z $extra || $extra =~ ^[a-z_]+=[a-z0-9]+(,[a-z_]+=[a-z0-9]+)*$ ]] || extra=""
  {
    awk -F'|' -v a="$addr" '$1 != a' "$(_mail_src "$acc")"
    printf '%s|{SHA512-CRYPT}%s%s\n' "$addr" "$hash" "${extra:+|$extra}"
  } | mail_write "$acc"
}

# mail_account_nologin ACC ADDR on|off — Dovecot extra field nologin=y:
# IMAP refuses the login with "Login disabled"; mail keeps arriving.
mail_account_nologin() {
  local tmp
  tmp=$(awk -F'|' -v OFS='|' -v a="$2" -v on="$3" '
    $1 == a && NF >= 2 { print $1, $2 (on == "on" ? "|nologin=y" : ""); next }
    { print }' "$(_mail_src "$1")")
  printf '%s\n' "$tmp" | mail_write "$1"
}

# mail_map_set MAP ADDR on|off — one address per line (Rspamd multimap).
mail_map_set() {
  local map=$1 addr=$2 on=$3
  {
    awk -v a="$addr" 'NF && $1 != a' "$(_mail_src "$map")"
    if [[ $on == on ]]; then printf '%s\n' "$addr"; fi
  } | atomic_write "$map" 0644 "$MAIL_FILE_OWNER"
}

# mail_catchall_sync ACC VIRT — Postfix matches "@domain" before the real
# accounts' implicit mapping, so a domain with a catch-all needs an identity
# line ("addr addr") for every account; domains without one get none.
mail_catchall_sync() {
  local acc virt
  acc=$(_mail_src "$1") virt=$(_mail_src "$2")
  {
    awk 'NF && !(NF == 2 && $1 == $2)' "$virt"
    awk -v V="$virt" '
      FILENAME == V { if (NF == 2 && substr($1, 1, 1) == "@") ca[substr($1, 2)] = 1; next }
      { split($0, f, "|"); n = split(f[1], p, "@") }
      n == 2 && (p[2] in ca) { print f[1] " " f[1] }' "$virt" "$acc" | sort -u
  } | mail_write "$2"
}

# mail_catchall_set ACC VIRT DOMAIN TARGET|- — TARGET must be an account.
mail_catchall_set() {
  local acc=$1 virt=$2 d=$3 t=$4
  if [[ $t != - ]]; then mail_has_account "$acc" "$t" || die "hedef bir posta kutusu olmalı: $t"; fi
  {
    awk -v k="@$d" '!(NF == 2 && $1 == k)' "$(_mail_src "$virt")"
    if [[ $t != - ]]; then printf '@%s %s\n' "$d" "$t"; fi
  } | mail_write "$virt"
  mail_catchall_sync "$acc" "$virt"
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

# Rspamd overrides written by the panel (config/rspamd/override.d; DMS
# copies them into /etc/rspamd/override.d and reloads Rspamd on change).
MAIL_RS_SETTINGS=settings.conf MAIL_RS_MULTIMAP=multimap.conf MAIL_RS_RATELIMIT=ratelimit.conf
MAIL_SEND_BLOCKED=hostpanel-send-blocked.map MAIL_SUSPENDED=hostpanel-suspended.map

# mail_rspamd_base DIR — settings + multimap + empty maps. DMS disables every
# Rspamd check for authenticated users (only DKIM signing stays); the
# override keeps that and enables the panel's limit and block lists.
mail_rspamd_base() {
  local d=$1 m
  [[ ! -L $d && ! -L ${d%/*} ]] || die "${d} symlink olamaz"
  mkdir -p -m 0755 -- "$d"
  cat <<'CONF' | atomic_write "$d/$MAIL_RS_SETTINGS" 0644 "$MAIL_FILE_OWNER"
# HostPanel (hp-mail.sh) — do not edit.
authenticated {
  priority = high;
  authenticated = yes;
  apply {
    groups_enabled = [dkim];
    symbols_enabled = [RATELIMIT_CHECK, RATELIMIT_UPDATE, HOSTPANEL_SEND_BLOCKED, HOSTPANEL_SUSPENDED];
  }
}
CONF
  cat <<CONF | atomic_write "$d/$MAIL_RS_MULTIMAP" 0644 "$MAIL_FILE_OWNER"
# HostPanel (hp-mail.sh) — do not edit. Authenticated senders on these lists
# are refused at submission; IMAP and incoming mail are not affected.
HOSTPANEL_SEND_BLOCKED {
  type = "user";
  map = "/etc/rspamd/override.d/${MAIL_SEND_BLOCKED}";
  action = "reject";
  message = "Bu hesabin gonderimi durduruldu";
}
HOSTPANEL_SUSPENDED {
  type = "user";
  map = "/etc/rspamd/override.d/${MAIL_SUSPENDED}";
  action = "reject";
  message = "Bu hesap askiya alindi";
}
CONF
  for m in "$MAIL_SEND_BLOCKED" "$MAIL_SUSPENDED"; do
    [[ ! -L $d/$m ]] || die "${d}/${m} symlink olamaz"
    if [[ ! -f $d/$m ]]; then atomic_write "$d/$m" 0644 "$MAIL_FILE_OWNER" </dev/null; fi
  done
}

# mail_ratelimit DIR N — messages per hour per authenticated account
# (Rspamd ratelimit, selector user; 0 = no limit, else 10–10000).
mail_ratelimit() {
  local d=$1 n=$2
  [[ $n =~ ^[0-9]{1,5}$ ]] && ((n == 0 || (n >= 10 && n <= 10000))) || die "geçersiz saatlik sınır: $n"
  mail_rspamd_base "$d"
  if ((n == 0)); then
    printf '# HostPanel (hp-mail.sh): no sending limit.\n'
  else
    printf '# HostPanel (hp-mail.sh) — do not edit.\nrates {\n  hostpanel_user = {\n    selector = "user.lower";\n    bucket = { burst = %d; rate = "%d / 1h"; }\n  }\n}\n' "$n" "$n"
  fi | atomic_write "$d/$MAIL_RS_RATELIMIT" 0644 "$MAIL_FILE_OWNER"
}

# mail_ratelimit_get DIR — the current limit (0 = none or not written yet).
mail_ratelimit_get() {
  sed -n 's/^    bucket = { burst = \([0-9]*\); .*/\1/p' "$(_mail_src "$1/$MAIL_RS_RATELIMIT")" | head -n 1 | grep . || echo 0
}

# DMARC report mails copied for the panel to parse (it never reads a
# maildir itself). Root-owned 0750 directory, files 0640 for the panel group.
MAIL_REPORT_DIR=/var/lib/hostpanel-mail-reports
MAIL_REPORT_LOCAL=dmarc

# mail_report_sync MAILDIR DEST GROUP — copy the report mailbox's messages
# (cur/new and the Junk folder; ≤10 MB, ≤180 days, newest 5000) to DEST as
# "<unique name>" (the maildir flags after ":" change when read); files no
# longer in the mailbox are removed. Prints copied=N kept=N removed=N.
mail_report_sync() {
  local md=$1 dest=$2 grp=$3 list f base n=0 k=0 r=0 sub
  [[ ! -L $md && ! -L $dest ]] || die "rapor dizinleri symlink olamaz"
  install -d -o "$(id -u)" -g "$grp" -m 0750 "$dest"
  list=$(mktemp)
  for sub in cur new .Junk/cur .Junk/new; do
    [[ -d $md/$sub && ! -L $md/$sub && ! -L ${md}/${sub%/*} ]] || continue
    find "$md/$sub" -maxdepth 1 -type f -size -10240k -mtime -180 -printf '%T@ %p\n'
  done | sort -rn | head -n 5000 | cut -d' ' -f2- >"$list"
  declare -A want=()
  while IFS= read -r f; do
    base=${f##*/}
    base=${base%%:*}
    [[ $base =~ ^[A-Za-z0-9._,=-]{1,200}$ && $base != .* ]] || continue
    want[$base]=1
    if [[ -f $dest/$base ]]; then
      k=$((k + 1))
      continue
    fi
    install -o "$(id -u)" -g "$grp" -m 0640 /dev/null "$dest/.$base.tmp"
    cat -- "$f" >"$dest/.$base.tmp"
    mv -f -- "$dest/.$base.tmp" "$dest/$base"
    n=$((n + 1))
  done <"$list"
  rm -f -- "$list"
  for f in "$dest"/*; do
    [[ -e $f ]] || continue
    base=${f##*/}
    if [[ -z ${want[$base]:-} ]]; then
      rm -f -- "$f"
      r=$((r + 1))
    fi
  done
  echo "copied=$n kept=$k removed=$r"
}

# TLS profile shared by the vhosts root renders itself (Mozilla intermediate).
HP_TLS_PROFILE='    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;'

# mail_base HOST — the parent domain of the mail host (mail.ornek.com →
# ornek.com); its autoconfig./autodiscover. names serve client set-up.
mail_base() { printf '%s\n' "${1#*.}"; }

# mail_autoconf_xml HOST — Thunderbird autoconfig (config-v1.1).
mail_autoconf_xml() {
  cat <<XML
<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="$1">
    <domain>$(mail_base "$1")</domain>
    <displayName>$1</displayName>
    <displayShortName>$1</displayShortName>
    <incomingServer type="imap">
      <hostname>$1</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>$1</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <outgoingServer type="smtp">
      <hostname>$1</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
XML
}

# mail_autodiscover_xml HOST — Outlook POX autodiscover (no LoginName: a
# static answer cannot know the address; Outlook then uses the address).
mail_autodiscover_xml() {
  cat <<XML
<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>$1</Server>
        <Port>993</Port>
        <DomainRequired>off</DomainRequired>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>$1</Server>
        <Port>465</Port>
        <DomainRequired>off</DomainRequired>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
        <UsePOPAuth>on</UsePOPAuth>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
XML
}

# _mail_vhost_locations HOST — the set-up documents (fixed content; nginx
# return also answers Outlook's POST) and a short notice for the rest.
_mail_vhost_locations() {
  cat <<CONF
    location = /mail/config-v1.1.xml {
        default_type text/xml;
        charset utf-8;
        return 200 '$(mail_autoconf_xml "$1")';
    }
    location = /.well-known/autoconfig/mail/config-v1.1.xml {
        default_type text/xml;
        charset utf-8;
        return 200 '$(mail_autoconf_xml "$1")';
    }
    location ~* ^/autodiscover/autodiscover\.xml\$ {
        default_type text/xml;
        charset utf-8;
        return 200 '$(mail_autodiscover_xml "$1")';
    }
CONF
}

# render_mail_vhost HOST [TLS_NAMES] — port 80: the ACME challenge for the
# mail host and its autoconfig./autodiscover. names, the client set-up
# documents, 404 for the rest. With TLS_NAMES (the names the certificate
# holds, space separated) also port 443 with the mail certificate, the
# set-up documents and a short notice, so https://HOST never lands on (and
# shows the certificate of) a customer's site.
render_mail_vhost() {
  validate_domain "$1"
  local host=$1 base names tls="" n
  base=$(mail_base "$1")
  validate_domain "$base"
  names="$host autoconfig.$base autodiscover.$base"
  for n in ${2:-}; do
    validate_oneof "$n" $names
    tls+="${tls:+ }$n"
  done
  cat <<CONF
# HostPanel mail server (hp-mail.sh) — certificate challenges and client set-up only; do not edit.
server {
    listen 80;
    listen [::]:80;
    server_name $names;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type text/plain;
    }
$(_mail_vhost_locations "$host")
    location / {
        return 404;
    }
}
CONF
  [[ -n $tls ]] || return 0
  cat <<CONF
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $tls;
    ssl_certificate /etc/letsencrypt/live/${MAIL_CERT_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${MAIL_CERT_NAME}/privkey.pem;
${HP_TLS_PROFILE}
$(_mail_vhost_locations "$host")
    location / {
        default_type text/plain;
        charset utf-8;
        return 200 "$host bir posta sunucusudur (IMAP 993 SSL/TLS, SMTP 465 SSL/TLS veya 587 STARTTLS).\n";
    }
}
CONF
}

# mail_cert_names HOST CERT — the names of HOST's vhost the certificate holds.
mail_cert_names() {
  local base out="" n sans
  base=$(mail_base "$1")
  sans=$(openssl x509 -noout -ext subjectAltName -in "$2" 2>/dev/null | tr ',' '\n' | sed -n 's/^ *DNS:\([a-z0-9.-]*\) *$/\1/p')
  for n in "$1" "autoconfig.$base" "autodiscover.$base"; do
    if grep -qxF -- "$n" <<<"$sans"; then out+="${out:+ }$n"; fi
  done
  printf '%s\n' "$out"
}

# install_vhost TMP FILE LINK WHAT — install a rendered vhost; nginx -t must
# pass, otherwise the previous file is restored (or the new one removed).
install_vhost() {
  local tmp=$1 file=$2 link=$3 what=$4 backup=""
  if [[ -f $file ]]; then
    backup=$(mktemp)
    cp -p -- "$file" "$backup"
  fi
  install -o root -g root -m 0644 "$tmp" "$file"
  rm -f -- "$tmp"
  ln -sfn -- "$file" "$link"
  if ! nginx -t -q 2>/dev/null; then
    nginx -t 2>&1 | tail -n 5 >&2 || true
    if [[ -n $backup ]]; then
      install -o root -g root -m 0644 "$backup" "$file"
    else
      rm -f -- "$file" "$link"
    fi
    rm -f -- "$backup"
    die "${what} nginx yapılandırması reddedildi; önceki hali geri yüklendi"
  fi
  rm -f -- "$backup"
  systemctl reload nginx
}

# write_mail_vhost HOST — install it (with port 443 once the certificate exists).
write_mail_vhost() {
  local tmp names
  tmp=$(mktemp)
  local cert=/etc/letsencrypt/live/$MAIL_CERT_NAME/fullchain.pem
  if [[ -s $cert ]]; then
    names=$(mail_cert_names "$1" "$cert")
    render_mail_vhost "$1" "${names:-$1}" >"$tmp"
  else
    render_mail_vhost "$1" >"$tmp"
  fi
  install_vhost "$tmp" "$MAIL_VHOST" "$MAIL_VHOST_LINK" "posta sunucusu"
}

# refresh_mail_vhost — re-render an existing mail vhost (panel update): the
# host is read back from its server_name and validated again.
refresh_mail_vhost() {
  [[ -f $MAIL_VHOST && ! -L $MAIL_VHOST ]] || return 0
  local host
  host=$(sed -n 's/^    server_name \([^ ;]*\)[ ;].*/\1/p' "$MAIL_VHOST" | head -n 1)
  [[ -n $host ]] || return 0
  write_mail_vhost "$host"
}

# Catch-all vhost: names that point here but have no vhost of their own
# (a mail host, a removed site, a stray DNS record) would otherwise get the
# first site's certificate and its redirect. Port 443 refuses the TLS
# handshake, port 80 closes the connection (444).
HP_DEFAULT_VHOST=/etc/nginx/sites-available/hostpanel-default.conf
HP_DEFAULT_VHOST_LINK=/etc/nginx/sites-enabled/hostpanel-default.conf

# render_default_vhost PORT... — 80 and/or 443.
render_default_vhost() {
  echo "# HostPanel catch-all (lib.sh ensure_default_vhost) — names without a vhost of their own; do not edit."
  local p
  for p in "$@"; do
    case $p in
      80)
        cat <<'CONF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
CONF
        ;;
      443)
        cat <<CONF
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    ssl_reject_handshake on;
${HP_TLS_PROFILE}
}
CONF
        ;;
      *) die "geçersiz port: $p" ;;
    esac
  done
}

# has_default_server PORT [DIR...] — another enabled config already declares
# default_server on PORT (Ubuntu's "default" site on 80, an IP-mode panel on
# 443): nginx refuses two, so that port is left alone.
has_default_server() {
  local port=$1 d f
  shift
  local dirs=("$@")
  ((${#dirs[@]})) || dirs=(/etc/nginx/sites-enabled /etc/nginx/conf.d)
  for d in "${dirs[@]}"; do
    for f in "$d"/*; do
      [[ -f $f && $(basename "$f") != "$(basename "$HP_DEFAULT_VHOST")" ]] || continue
      grep -qE "^[[:space:]]*listen[[:space:]]+([^;[:space:]]*:)?${port}[[:space:]][^;]*default_server" -- "$f" && return 0
    done
  done
  return 1
}

# ensure_default_vhost — install (or drop) the catch-all for the free ports.
ensure_default_vhost() {
  local ports=() p tmp
  command -v nginx >/dev/null || return 0
  for p in 80 443; do
    has_default_server "$p" || ports+=("$p")
  done
  if ((${#ports[@]} == 0)); then
    if [[ -e $HP_DEFAULT_VHOST_LINK || -e $HP_DEFAULT_VHOST ]]; then
      rm -f -- "$HP_DEFAULT_VHOST_LINK" "$HP_DEFAULT_VHOST"
      nginx -t -q && systemctl reload nginx
    fi
    return 0
  fi
  tmp=$(mktemp)
  render_default_vhost "${ports[@]}" >"$tmp"
  if [[ -f $HP_DEFAULT_VHOST ]] && cmp -s "$tmp" "$HP_DEFAULT_VHOST" && [[ -L $HP_DEFAULT_VHOST_LINK ]]; then
    rm -f -- "$tmp"
    return 0
  fi
  install_vhost "$tmp" "$HP_DEFAULT_VHOST" "$HP_DEFAULT_VHOST_LINK" "varsayılan (catch-all)"
}

# ---------------------------------------------------------------------------
# Server security (Faz 11): SSH, host fail2ban
# ---------------------------------------------------------------------------

# sshd uses the FIRST value it reads for most keywords and sshd_config includes
# sshd_config.d/*.conf at its top: "00-" sorts before cloud-init's
# 50-cloud-init.conf (which usually says PasswordAuthentication yes).
SSH_DROPIN=${SSH_DROPIN:-/etc/ssh/sshd_config.d/00-hostpanel.conf}
SSH_STATE_DIR=${SSH_STATE_DIR:-/var/lib/hostpanel-ssh}
SSH_REVERT_UNIT=hostpanel-ssh-revert
SSH_REVERT_SECS=180
F2B_JAIL=${F2B_JAIL:-/etc/fail2ban/jail.d/hostpanel.conf}
F2B_FILTER=${F2B_FILTER:-/etc/fail2ban/filter.d/hostpanel.conf}

# render_sshd_dropin PASSWORD(yes|no) ROOT(no|prohibit-password|yes)
render_sshd_dropin() {
  validate_oneof "${1:-}" yes no
  validate_oneof "${2:-}" no prohibit-password yes
  cat <<CONF
# HostPanel (hp-ssh.sh apply, Sunucu → SSH) — do not edit; the panel rewrites it.
# sshd keeps the first value it reads, so this file sorts before 50-cloud-init.conf.
PasswordAuthentication $1
KbdInteractiveAuthentication no
PermitRootLogin $2
PubkeyAuthentication yes
CONF
}

# validate_sys_user NAME — a login name (checked against the admin list by the caller).
validate_sys_user() {
  [[ ${1:-} =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "geçersiz kullanıcı adı: '${1:-}'"
}

# validate_fingerprint FP — OpenSSH SHA256 fingerprint.
validate_fingerprint() {
  [[ ${1:-} =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || die "geçersiz parmak izi: '${1:-}'"
}

# validate_pubkey LINE — prints the normalized "type base64 [comment]" line.
# Lines with options (command=, from=, …) are refused: the panel adds plain keys only.
validate_pubkey() {
  local line=$1 t b c fp bits tmp
  [[ ${#line} -le 16384 && $line != *$'\n'* && $line != *$'\r'* ]] || die "geçersiz anahtar satırı"
  read -r t b c <<<"$line"
  case $t in
    ssh-ed25519 | ecdsa-sha2-nistp256 | ecdsa-sha2-nistp384 | ecdsa-sha2-nistp521 | ssh-rsa | \
      sk-ssh-ed25519@openssh.com | sk-ecdsa-sha2-nistp256@openssh.com) ;;
    *) die "desteklenmeyen anahtar türü (seçenekli satırlar kabul edilmez): '${t:0:40}'" ;;
  esac
  [[ ${#b} -ge 60 && $b =~ ^[A-Za-z0-9+/]+={0,3}$ ]] || die "geçersiz anahtar verisi"
  [[ -z $c || $c =~ ^[A-Za-z0-9@._\ -]{1,100}$ ]] || die "geçersiz anahtar açıklaması (harf, rakam, @ . _ - ve boşluk)"
  tmp=$(mktemp)
  printf '%s %s\n' "$t" "$b" >"$tmp"
  fp=$(ssh-keygen -lf "$tmp" 2>/dev/null) || {
    rm -f -- "$tmp"
    die "anahtar okunamadı (ssh-keygen)"
  }
  rm -f -- "$tmp"
  bits=${fp%% *}
  [[ $t != ssh-rsa ]] || ((bits >= 2048)) || die "RSA anahtarı en az 2048 bit olmalı"
  printf '%s %s%s\n' "$t" "$b" "${c:+ $c}"
}

# key_fingerprint LINE — SHA256 fingerprint of one authorized_keys line ("" if not a key).
key_fingerprint() {
  local tmp fp
  tmp=$(mktemp)
  printf '%s\n' "$1" >"$tmp"
  fp=$(ssh-keygen -lf "$tmp" 2>/dev/null | awk '{print $2}') || fp=""
  rm -f -- "$tmp"
  printf '%s' "$fp"
}

# render_f2b_jail ON MAXRETRY FINDTIME_MIN BANTIME_MIN RECIDIVE PORTS IGNORE...
# The host jails: panel logins ([hostpanel], ON = its filter matched a sample
# line), [sshd] and optionally [recidive] (repeat offenders, one week, all ports).
render_f2b_jail() {
  local on=$1 retry=$2 find=$3 ban=$4 rec=$5 ports=$6
  shift 6
  validate_oneof "$on" true false
  validate_oneof "$rec" 0 1
  [[ $retry =~ ^[0-9]{1,2}$ ]] && ((retry >= 3 && retry <= 20)) || die "geçersiz deneme sayısı: $retry"
  [[ $find =~ ^[0-9]{1,4}$ ]] && ((find >= 5 && find <= 1440)) || die "geçersiz süre (findtime): $find"
  [[ $ban =~ ^[0-9]{1,5}$ ]] && ((ban >= 10 && ban <= 10080)) || die "geçersiz ban süresi: $ban"
  [[ $ports =~ ^[0-9]{1,5}(,[0-9]{1,5})*$ ]] || die "geçersiz port listesi: $ports"
  local ign="127.0.0.1/8 ::1" ip
  for ip in "$@"; do
    validate_ip_or_cidr "$ip"
    ign+=" $ip"
  done
  cat <<JAIL
# HostPanel (install.sh / hp-ssh.sh f2b-config, Sunucu → fail2ban) — do not edit.
# hp-config: maxretry=${retry} findtime=${find} bantime=${ban} recidive=${rec}
[hostpanel]
enabled  = ${on}
filter   = hostpanel
logpath  = /var/log/hostpanel/auth.log
backend  = auto
port     = ${ports}
maxretry = ${retry}
findtime = ${find}m
bantime  = ${ban}m
ignoreip = ${ign}

[sshd]
enabled  = true
maxretry = ${retry}
findtime = ${find}m
bantime  = ${ban}m
ignoreip = ${ign}
JAIL
  if [[ $rec == 1 ]]; then
    cat <<JAIL

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = %(banaction_allports)s
findtime = 1d
bantime  = 1w
maxretry = 3
ignoreip = ${ign}
JAIL
  fi
}

# write_f2b_filter — the panel-login filter; prints "true" when it matches a
# sample line of /var/log/hostpanel/auth.log (otherwise the jail stays off).
write_f2b_filter() {
  install -d -m 0755 "$(dirname "$F2B_FILTER")" "$(dirname "$F2B_JAIL")"
  cat >"$F2B_FILTER" <<'FILTER'
# HostPanel panel logins (written by install.sh). Line format of
# /var/log/hostpanel/auth.log: "<RFC3339> hostpanel: login failed ip=<IP> reason=<r>"
[Definition]
failregex = hostpanel: login failed ip=<HOST>(?:\s|$)
ignoreregex =
FILTER
  local sample
  sample="$(date -u +%Y-%m-%dT%H:%M:%SZ) hostpanel: login failed ip=192.0.2.10 reason=password"
  if [[ $(fail2ban-regex "$sample" "$F2B_FILTER" 2>/dev/null) == *"Lines: 1 lines, 0 ignored, 1 matched"* ]]; then
    echo true
  else
    echo false
  fi
}

# f2b_ports — ports of the panel jail: 443 plus the configured panel port
# and the IP entry's port (panel on a domain).
f2b_ports() {
  local p q x out=443
  p=$(config_value panel_port)
  q=$(config_value panel_ip_port)
  [[ $p =~ ^[0-9]{1,5}$ ]] || p=8443
  for x in "$p" "$q"; do
    [[ $x =~ ^[0-9]{1,5}$ && $x != 0 && $x != 443 && ,$out, != *,$x,* ]] && out="${x},${out}"
  done
  echo "$out"
}

# f2b_current — "MAXRETRY FINDTIME BANTIME RECIDIVE" of the jail file (the
# install.sh defaults 5 15 60 0 when the file predates the hp-config line).
f2b_current() {
  local line r=5 f=15 b=60 c=0
  if [[ -f $F2B_JAIL ]]; then
    line=$(grep -m1 '^# hp-config:' "$F2B_JAIL" || true)
    [[ $line =~ maxretry=([0-9]+) ]] && r=${BASH_REMATCH[1]}
    [[ $line =~ findtime=([0-9]+) ]] && f=${BASH_REMATCH[1]}
    [[ $line =~ bantime=([0-9]+) ]] && b=${BASH_REMATCH[1]}
    [[ $line =~ recidive=([01]) ]] && c=${BASH_REMATCH[1]}
  fi
  echo "$r $f $b $c"
}

# f2b_ignored — the extra ignoreip entries of the jail file (loopback left out), one per line.
f2b_ignored() {
  [[ -f $F2B_JAIL ]] || return 0
  grep -m1 '^ignoreip' "$F2B_JAIL" | cut -d= -f2- | tr ' ' '\n' |
    grep -vE '^(127\.0\.0\.1/8|::1|)$' || true
}
