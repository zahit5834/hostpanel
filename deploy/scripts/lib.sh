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
