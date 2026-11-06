#!/usr/bin/env bash
# hp-ssl.sh — TLS certificates for HostPanel sites.
#
#   hp-ssl.sh setup
#       ACME webroot, certbot deploy hook (nginx reload + renewal log line).
#   hp-ssl.sh issue <domain> <email> <method> <staging 0|1> <force 0|1> <name>...
#       Let's Encrypt via certbot certonly; lineage name = <domain>.
#       method: webroot (dns-* methods can be added here later).
#   hp-ssl.sh renew <domain> <force 0|1>
#   hp-ssl.sh show <domain>            prints the LE fullchain (public data)
#   hp-ssl.sh export-key <domain>      prints the LE private key (panel export)
#   hp-ssl.sh install-custom <domain> <id>
#       stdin: private key + certificates (PEM, max 64 KB). Written to
#       /etc/hostpanel/ssl/<domain>/<id>/ after re-checking that the key
#       matches the certificate.
#   hp-ssl.sh delete <domain> le|all|custom <id>
#
# nginx itself is configured by hp-nginx-site.sh; this script never edits nginx files.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") setup|issue|renew|show|export-key|install-custom|delete …"
action=$1
shift

WEBROOT=/var/www/letsencrypt
CUSTOM_ROOT=/etc/hostpanel/ssl
RENEW_LOG=${ROOT_LOG_DIR}/ssl-renewals.log
HOOK=/etc/letsencrypt/renewal-hooks/deploy/hostpanel.sh

need_certbot() { command -v certbot >/dev/null || die "certbot kurulu değil (apt install certbot)"; }

reload_nginx() {
  nginx -t -q && systemctl reload nginx
}

custom_dir() {
  local d=${CUSTOM_ROOT}/$1
  [[ ! -L $CUSTOM_ROOT && ! -L $d ]] || die "sertifika dizini symlink olamaz"
  printf '%s\n' "$d"
}

setup() {
  install -d -o root -g root -m 0755 "$WEBROOT"
  ensure_etc_dir
  install -d -o root -g root -m 0700 "$CUSTOM_ROOT"
  install -d -o root -g root -m 0755 "$(dirname "$HOOK")"
  root_log_file "$RENEW_LOG"
  local tmp
  tmp=$(mktemp)
  cat >"$tmp" <<'HOOK'
#!/bin/sh
# Installed by HostPanel (hp-ssl.sh setup). certbot runs it after every
# successful renewal: reload nginx and leave a line for the panel's log center.
set -e
nginx -t -q && systemctl reload nginx
log=/var/log/hostpanel-root/ssl-renewals.log
[ -L "$log" ] || printf '%s renewed %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(basename "$RENEWED_LINEAGE")" >>"$log"
HOOK
  if ! cmp -s "$tmp" "$HOOK"; then
    atomic_write "$HOOK" 0755 root:root <"$tmp"
    log "yenileme kancası kuruldu: ${HOOK}"
  fi
  rm -f "$tmp"
}

case $action in
  setup)
    [[ $# -eq 0 ]] || die "setup argüman almaz"
    setup
    ;;

  issue)
    [[ $# -ge 6 ]] || die "kullanım: issue <domain> <email> <method> <staging> <force> <name>..."
    domain=$1 email=$2 method=$3 staging=$4 force=$5
    shift 5
    validate_domain "$domain"
    validate_email "$email"
    validate_oneof "$method" webroot
    validate_oneof "$staging" 0 1
    validate_oneof "$force" 0 1
    (( $# <= 100 )) || die "en fazla 100 alan adı"
    args=(certonly --non-interactive --agree-tos --no-eff-email --email "$email"
          --cert-name "$domain" --keep-until-expiring --expand)
    for n in "$@"; do
      validate_domain "$n"
      args+=(-d "$n")
    done
    case $method in
      webroot) args+=(--webroot -w "$WEBROOT") ;;
    esac
    [[ $staging == 1 ]] && args+=(--test-cert)
    if [[ $force == 1 ]]; then
      args+=(--force-renewal)
      [[ $staging == 1 ]] && args+=(--break-my-certs)
    fi
    need_certbot
    setup
    log "certbot ${args[*]}"
    certbot "${args[@]}"
    ;;

  renew)
    [[ $# -eq 2 ]] || die "kullanım: renew <domain> <force 0|1>"
    validate_domain "$1"
    validate_oneof "$2" 0 1
    need_certbot
    args=(renew --non-interactive --cert-name "$1" --no-random-sleep-on-renew --no-directory-hooks)
    [[ $2 == 1 ]] && args+=(--force-renewal)
    certbot "${args[@]}"
    reload_nginx
    ;;

  show | export-key)
    [[ $# -eq 1 ]] || die "kullanım: ${action} <domain>"
    validate_domain "$1"
    live=/etc/letsencrypt/live/$1
    [[ -d $live && ! -L $live ]] || die "Let's Encrypt sertifikası yok: $1"
    if [[ $action == show ]]; then cat "$live/fullchain.pem"; else cat "$live/privkey.pem"; fi
    ;;

  install-custom)
    [[ $# -eq 2 ]] || die "kullanım: install-custom <domain> <id>"
    domain=$1 id=$2
    validate_domain "$domain"
    validate_id "$id"
    command -v openssl >/dev/null || die "openssl kurulu değil"
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    read_stdin_limited "$work/in.pem" 65536
    split_pem_bundle "$work/in.pem" "$work/key.pem" "$work/fullchain.pem"
    cert_key_match "$work/fullchain.pem" "$work/key.pem" || die "private key sertifikayla eşleşmiyor"
    openssl x509 -in "$work/fullchain.pem" -noout -checkend 0 >/dev/null || die "sertifikanın süresi dolmuş"
    setup
    base=$(custom_dir "$domain")
    install -d -o root -g root -m 0700 "$base" "$base/$id"
    atomic_write "$base/$id/privkey.pem" 0600 root:root <"$work/key.pem"
    atomic_write "$base/$id/fullchain.pem" 0644 root:root <"$work/fullchain.pem"
    log "sertifika yazıldı: $base/$id/"
    ;;

  delete)
    [[ $# -ge 2 ]] || die "kullanım: delete <domain> le|all|custom <id>"
    domain=$1 what=$2
    validate_domain "$domain"
    validate_oneof "$what" le all custom
    base=$(custom_dir "$domain")
    if [[ $what == le || $what == all ]]; then
      if [[ -d /etc/letsencrypt/live/$domain ]] && command -v certbot >/dev/null; then
        certbot delete --non-interactive --cert-name "$domain"
      fi
    fi
    if [[ $what == custom ]]; then
      [[ $# -eq 3 ]] || die "custom için id gerekli"
      validate_id "$3"
      rm -rf -- "${base:?}/$3"
    fi
    if [[ $what == all ]]; then
      rm -rf -- "${base:?}"
    fi
    log "sertifika silindi: ${domain} (${what})"
    ;;

  *)
    die "bilinmeyen işlem: ${action}"
    ;;
esac
