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
