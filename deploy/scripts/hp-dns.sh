#!/usr/bin/env bash
# hp-dns.sh — authoritative DNS (BIND 9) for HostPanel.
#
#   hp-dns.sh install
#       apt-get install bind9 bind9-utils, authoritative-only options
#       (recursion off, RRL, no transfers), include the panel's zone list,
#       open 53/tcp+udp in UFW when UFW is active (comment hostpanel-dns).
#       Refuses when a BIND not installed by the panel already has zones.
#   hp-dns.sh write-zone <zone>      zone file on stdin (validate_zone_file,
#                                    named-checkzone, install, rndc reload)
#   hp-dns.sh sync-config            stdin: "<zone> <dnssec 0|1>" per line; this
#                                    script writes named.conf.hostpanel itself
#   hp-dns.sh delete-zone <zone>     archive zone file + keys, then remove them
#   hp-dns.sh ds <zone>              DS records of the zone's KSK/CSK (stdout)
#   hp-dns.sh status                 key=value lines
#
# The panel never writes BIND configuration text: zone stanzas are generated
# here from validated names, and zone files are checked line by line ($INCLUDE
# and every other directive but $TTL are refused) before named-checkzone.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") install|write-zone|sync-config|delete-zone|ds|status …"
action=$1
shift

BIND_ETC=/etc/bind
MARKER=$BIND_ETC/.hostpanel
CONF=$BIND_ETC/named.conf.hostpanel
ZONE_DIR=/var/lib/bind/hostpanel
KEY_DIR=$ZONE_DIR/keys
ARCHIVE_DIR=/var/backups/hostpanel/dns
UFW_TAG=hostpanel-dns

need_bind() {
  [[ -f $MARKER ]] || die "DNS sunucusu panel tarafından kurulmamış"
  command -v named-checkzone >/dev/null || die "bind9-utils kurulu değil"
}

zone_file() { echo "$ZONE_DIR/$1.db"; }

zone_configured() { [[ -f $CONF ]] && grep -qxF "zone \"$1\" {" "$CONF"; }

ufw_active() { command -v ufw >/dev/null && [[ $(ufw status 2>/dev/null | head -n1) == "Status: active" ]]; }

# named.conf.local without comments/blank lines (pre-existing zones?).
local_conf_used() {
  local f=$BIND_ETC/named.conf.local
  [[ -f $f ]] || return 1
  [[ -n $(grep -vE '^[[:space:]]*(//.*)?$' "$f" | grep -vF 'named.conf.hostpanel') ]]
}

write_options() {
  local f=$BIND_ETC/named.conf.options
  [[ -f $f.orig || ! -f $f ]] || cp -a "$f" "$f.orig"
  cat >"$f.new" <<'CONF'
// Managed by HostPanel (hp-dns.sh install) — authoritative only.
// The distribution's original file is kept as named.conf.options.orig.
options {
    directory "/var/cache/bind";
    recursion no;
    allow-recursion { none; };
    allow-query-cache { none; };
    allow-query { any; };
    allow-transfer { none; };
    notify no;
    dnssec-validation no;
    version "none";
    hostname none;
    server-id none;
    minimal-responses yes;
    listen-on { any; };
    listen-on-v6 { any; };
    rate-limit {
        responses-per-second 10;
        window 5;
    };
};
CONF
  chown root:bind "$f.new"
  chmod 0644 "$f.new"
  mv -f "$f.new" "$f"
}

case $action in
install)
  [[ $# -eq 0 ]] || die "kullanım: install"
  if [[ ! -f $MARKER && $(dpkg-query -W -f='${Status}' bind9 2>/dev/null) == *"install ok installed"* ]] && local_conf_used; then
    die "bu sunucuda panel dışında yapılandırılmış bir BIND var (named.conf.local dolu); mevcut DNS yapılandırmasına dokunulmadı"
  fi
  export DEBIAN_FRONTEND=noninteractive
  log "apt-get update"
  apt-get update -q
  log "apt-get install bind9 bind9-utils"
  apt-get install -y -q --no-install-recommends bind9 bind9-utils
  touch "$MARKER"
  install -d -o bind -g bind -m 0750 "$ZONE_DIR" "$KEY_DIR"
  [[ -f $CONF ]] || install -o root -g bind -m 0644 /dev/null "$CONF"
  write_options
  lc=$BIND_ETC/named.conf.local
  [[ -f $lc ]] || install -o root -g bind -m 0644 /dev/null "$lc"
  grep -qF "include \"$CONF\";" "$lc" || printf 'include "%s";\n' "$CONF" >>"$lc"
  named-checkconf || die "named-checkconf başarısız"
  systemctl enable named >/dev/null 2>&1 || true
  systemctl restart named
  systemctl is-active --quiet named || die "named başlatılamadı (journalctl -u named)"
  log "BIND $(named -v 2>/dev/null | awk '{print $2}') çalışıyor (yalnızca yetkili sunucu, recursion kapalı)"
  if ufw_active; then
    ufw allow proto udp to any port 53 comment "$UFW_TAG" >/dev/null
    ufw allow proto tcp to any port 53 comment "$UFW_TAG" >/dev/null
    log "UFW: 53/udp ve 53/tcp açıldı (${UFW_TAG})"
  else
    log "UYARI: UFW etkin değil; 53/udp ve 53/tcp için kural eklenmedi (panel UFW'yi açmaz)"
  fi
  ;;

write-zone)
  [[ $# -eq 1 ]] || die "kullanım: write-zone <zone>"
  zone=$1
  validate_domain "$zone"
  need_bind
  install -d -o bind -g bind -m 0750 "$ZONE_DIR"
  tmp=$(mktemp "$ZONE_DIR/.${zone}.XXXXXX")
  trap 'rm -f "$tmp"' EXIT
  head -c 1048577 >"$tmp"
  validate_zone_file "$tmp" "$zone"
  named-checkzone -q -k fail -n fail "$zone" "$tmp" || {
    named-checkzone -k fail -n fail "$zone" "$tmp" >&2 || true
    die "named-checkzone zone'u reddetti"
  }
  dst=$(zone_file "$zone")
  [[ ! -L $dst ]] || die "zone dosyası symlink olamaz"
  [[ ! -f $dst ]] || cp -a "$dst" "$dst.prev"
  chown bind:bind "$tmp"
  chmod 0640 "$tmp"
  mv -f "$tmp" "$dst"
  trap - EXIT
  if zone_configured "$zone" && systemctl is-active --quiet named; then
    if ! rndc reload "$zone" >/dev/null; then
      [[ -f $dst.prev ]] && mv -f "$dst.prev" "$dst"
      rndc reload "$zone" >/dev/null 2>&1 || true
      die "rndc reload başarısız; önceki zone dosyası geri yüklendi"
    fi
  fi
  rm -f "$dst.prev"
  log "zone yazıldı: $zone"
  ;;

sync-config)
  [[ $# -eq 0 ]] || die "kullanım: sync-config (stdin: zone dnssec)"
  need_bind
  new=$(mktemp "$BIND_ETC/.named.conf.hostpanel.XXXXXX")
  trap 'rm -f "$new"' EXIT
  {
    echo "// Managed by HostPanel (hp-dns.sh sync-config) — do not edit."
    count=0
    while IFS= read -r line || [[ -n $line ]]; do
      [[ -n $line ]] || continue
      ((++count <= 10000)) || die "çok fazla zone"
      [[ $line =~ ^([a-z0-9.-]+)\ ([01])$ ]] || die "geçersiz satır: ${line}"
      zone=${BASH_REMATCH[1]} sec=${BASH_REMATCH[2]}
      validate_domain "$zone"
      [[ -f $(zone_file "$zone") ]] || die "zone dosyası yok: $zone (önce write-zone)"
      printf 'zone "%s" {\n    type primary;\n    file "%s";\n    allow-transfer { none; };\n' "$zone" "$(zone_file "$zone")"
      if [[ $sec == 1 ]]; then
        printf '    dnssec-policy default;\n    inline-signing yes;\n    key-directory "%s";\n' "$KEY_DIR"
      fi
      printf '};\n'
    done
  } >"$new"
  chown root:bind "$new"
  chmod 0644 "$new"
  [[ ! -f $CONF ]] || cp -a "$CONF" "$CONF.prev"
  mv -f "$new" "$CONF"
  trap - EXIT
  if ! named-checkconf; then
    [[ -f $CONF.prev ]] && mv -f "$CONF.prev" "$CONF"
    die "named-checkconf başarısız; önceki zone listesi geri yüklendi"
  fi
  if systemctl is-active --quiet named; then
    rndc reconfig >/dev/null || {
      [[ -f $CONF.prev ]] && mv -f "$CONF.prev" "$CONF" && rndc reconfig >/dev/null 2>&1
      die "rndc reconfig başarısız; önceki zone listesi geri yüklendi"
    }
  else
    systemctl start named || die "named başlatılamadı (journalctl -u named)"
  fi
  rm -f "$CONF.prev"
  log "BIND zone listesi güncellendi"
  ;;

delete-zone)
  [[ $# -eq 1 ]] || die "kullanım: delete-zone <zone>"
  zone=$1
  validate_domain "$zone"
  need_bind
  ! zone_configured "$zone" || die "zone hâlâ yapılandırmada; önce sync-config"
  shopt -s nullglob
  files=("$ZONE_DIR/$zone".db* "$KEY_DIR/K$zone".+*)
  if ((${#files[@]} > 0)); then
    install -d -m 0700 "$ARCHIVE_DIR"
    arc="$ARCHIVE_DIR/${zone}-$(date +%Y%m%d-%H%M%S).tar.zst"
    tar --zstd -cf "$arc" --absolute-names "${files[@]}"
    chmod 0600 "$arc"
    rm -f -- "${files[@]}"
    log "zone arşivlendi ve silindi: $arc"
  fi
  ;;

ds)
  [[ $# -eq 1 ]] || die "kullanım: ds <zone>"
  zone=$1
  validate_domain "$zone"
  need_bind
  shopt -s nullglob
  for k in "$KEY_DIR/K$zone".+*.key; do
    # 257 = KSK/CSK (SEP bit); the DS for the registrar comes from these.
    if grep -qE "IN[[:space:]]+DNSKEY[[:space:]]+257 " "$k"; then
      dnssec-dsfromkey -2 "$k"
    fi
  done
  ;;

status)
  [[ $# -eq 0 ]] || die "kullanım: status"
  echo "installed=$([[ -f $MARKER ]] && echo 1 || echo 0)"
  echo "active=$(systemctl is-active named 2>/dev/null || true)"
  if command -v named >/dev/null; then echo "version=$(named -v 2>/dev/null | awk '{print $2}')"; fi
  ;;

*)
  die "bilinmeyen işlem: $action"
  ;;
esac
