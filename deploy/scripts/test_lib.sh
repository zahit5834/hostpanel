#!/usr/bin/env bash
# Unit tests for lib.sh validators. Runs unprivileged: `make test-scripts`.
# Not installed on servers and not listed in sudoers.
set -uo pipefail
cd "$(dirname "$0")"
fail=0

ok()  { if ( source ./lib.sh; set +e; "$@" ) >/dev/null 2>&1; then :; else echo "FAIL (should pass): $*"; fail=1; fi; }
bad() { if ( source ./lib.sh; "$@" ) >/dev/null 2>&1; then echo "FAIL (should fail): $*"; fail=1; fi; }

ok  validate_domain example.com
ok  validate_domain www.sub-1.example.com.tr
bad validate_domain Example.com
bad validate_domain example
bad validate_domain "-bad.com"
bad validate_domain "a.com; rm -rf /"
bad validate_domain "../etc.com"
bad validate_domain ""

ok  validate_name site_ornek
bad validate_name Site
bad validate_name 1abc
bad validate_name "a b"
bad validate_name "$(printf 'a%.0s' {1..40})"

ok  validate_port 5000
bad validate_port 80
bad validate_port 70000
bad validate_port 5x

ok  validate_oneof ping ping pong
bad validate_oneof "ping;id" ping

tmp=$(mktemp -d)
mkdir -p "$tmp/base/sub"
ln -s / "$tmp/base/escape"
ok  validate_path_under "$tmp/base/sub/file" "$tmp/base"
bad validate_path_under "$tmp/base/../outside" "$tmp/base"
bad validate_path_under "$tmp/base/escape/etc/passwd" "$tmp/base"
bad validate_path_under "$tmp/basefoo" "$tmp/base"
rm -rf "$tmp"

ok  validate_release 20261105-140000
bad validate_release 2026-11-05
ok  validate_reldir wwwroot/uploads
ok  validate_reldir App_Data
bad validate_reldir ../x
bad validate_reldir .env
bad validate_reldir a/../b
bad validate_reldir /abs
ok  validate_short ornek_com
bad validate_short Ornek
ok  validate_site_user site_ornek_com
bad validate_site_user root
bad validate_site_user site_

# nginx config validation: every line of testdata_nginx_bad.txt must be rejected on its own.
tmpc=$(mktemp)
while IFS= read -r line; do
  printf '%s\n' "$line" >"$tmpc"
  bad validate_nginx_conf "$tmpc" ornek.com
done <testdata_nginx_bad.txt
cat >"$tmpc" <<'CONF'
# Managed by HostPanel
server {
    listen 80;
    server_name ornek.com www.ornek.com;
    access_log /var/log/nginx/hp-ornek.com.access.log;
    error_log /var/log/nginx/hp-ornek.com.error.log;
    location / { proxy_pass http://127.0.0.1:5000; proxy_set_header Host $host; }
    location ^~ /__hostpanel/ { internal; alias /opt/hostpanel/templates/pages/; }
}
server {
    listen 443 ssl http2;
    server_name ornek.com;
    ssl_certificate /etc/letsencrypt/live/ornek.com/fullchain.pem;
    ssl_certificate_key "/etc/hostpanel/ssl/ornek.com/7/privkey.pem";
    access_log /var/log/nginx/hp-ornek.com.access.log;
    error_log /var/log/nginx/hp-ornek.com.error.log;
}
CONF
ok  validate_nginx_conf "$tmpc" ornek.com
bad validate_nginx_conf "$tmpc" other.com
rm -f "$tmpc"

# env_line keeps values literal.
check_env() {
  local got
  got=$(source ./lib.sh; env_line "$1" "$2")
  [[ $got == "$3" ]] || { echo "FAIL env_line $1: got [$got] want [$3]"; fail=1; }
}
check_env A 'plain value' "A='plain value'"
check_env B 'x$y"z\w' "B='x\$y\"z\\w'"
check_env C "it's \$HOME" 'C="it'"'"'s \$HOME"'

# e-mail / id
ok  validate_email admin@ornek.com.tr
bad validate_email 'a@b'
bad validate_email 'x@y.com;rm'
ok  validate_id 42
bad validate_id 0
bad validate_id '1/../2'

# PEM bundle split + key/cert match (real openssl, no root needed).
if command -v openssl >/dev/null; then
  pd=$(mktemp -d)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$pd/k1.pem" -out "$pd/c1.pem" -subj /CN=ornek.com -days 2 2>/dev/null
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$pd/k2.pem" -out "$pd/c2.pem" -subj /CN=ornek.com -days 2 2>/dev/null
  cat "$pd/k1.pem" "$pd/c1.pem" >"$pd/bundle.pem"
  ok  split_pem_bundle "$pd/bundle.pem" "$pd/ko.pem" "$pd/co.pem"
  ok  cert_key_match "$pd/co.pem" "$pd/ko.pem"
  bad cert_key_match "$pd/c2.pem" "$pd/k1.pem"
  cat "$pd/k1.pem" "$pd/k2.pem" "$pd/c1.pem" >"$pd/two-keys.pem"
  bad split_pem_bundle "$pd/two-keys.pem" "$pd/x.pem" "$pd/y.pem"
  bad split_pem_bundle "$pd/c1.pem" "$pd/x.pem" "$pd/y.pem"
  printf -- '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' | cat "$pd/bundle.pem" - >"$pd/extra.pem"
  bad split_pem_bundle "$pd/extra.pem" "$pd/x.pem" "$pd/y.pem"
  rm -rf "$pd"
fi

# MSSQL helper validators
ok  validate_mssql_image mcr.microsoft.com/mssql/server:2025-CU10-ubuntu-24.04
ok  validate_mssql_image mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04
bad validate_mssql_image mcr.microsoft.com/mssql/server:latest
bad validate_mssql_image docker.io/evil/server:2025-CU10
bad validate_mssql_image "mcr.microsoft.com/mssql/server:2025-x;id"
ok  validate_mssql_pid Express
ok  validate_mssql_pid ABCDE-12345-FGHIJ-67890-KLMNO
bad validate_mssql_pid Enterprise
bad validate_mssql_pid "Express --privileged"
ok  validate_ip_or_cidr 203.0.113.7
ok  validate_ip_or_cidr 198.51.100.0/24
ok  validate_ip_or_cidr 2001:db8::1
bad validate_ip_or_cidr 0.0.0.0/0
bad validate_ip_or_cidr ::/0
bad validate_ip_or_cidr "1.2.3.4 port 22"
bad validate_ip_or_cidr any
bad validate_ip_or_cidr 1234

ok  validate_backup_name 20261105-120000-a1b2
bad validate_backup_name 20261105-120000
bad validate_backup_name "20261105-120000-a1b2/../x"
bad validate_backup_name 20261105-120000-A1B2
ok  validate_components files,db,config,ssl
ok  validate_components config
bad validate_components files,,db
bad validate_components "files;id"
ok  validate_bwlimit 0
ok  validate_bwlimit 512K
ok  validate_bwlimit 10M
bad validate_bwlimit 0M
bad validate_bwlimit "1M --dry-run"
ok  validate_server_name web-01.example
bad validate_server_name "-x"
bad validate_server_name "a/b"
ok  validate_folder HostPanel-Backups
ok  validate_folder a/b/c
bad validate_folder a/../b
bad validate_folder ../a
bad validate_folder "/abs"
bad validate_folder "a b"
ok  validate_shared_id -
ok  validate_shared_id 0ABCdef123_-xyz
bad validate_shared_id short
ok  validate_staged_bak hprs-20261105-120000-a1b2-shop.bak
ok  validate_staged_bak hpim-42.bak
bad validate_staged_bak hpbk-x.bak
bad validate_staged_bak "hprs-../../etc.bak"
ok  validate_backup_file files.tar.zst
ok  validate_backup_file db-shop_db.bak
bad validate_backup_file ../config.json
bad validate_backup_file db-Shop.bak

ok  validate_ufw_port 8080
ok  validate_ufw_port 6000:6100
bad validate_ufw_port 0
bad validate_ufw_port 70000
bad validate_ufw_port 6100:6000
bad validate_ufw_port "22 --dry-run"
ok  validate_ufw_rule_no 3
bad validate_ufw_rule_no 0
bad validate_ufw_rule_no "1;id"
ok  ports_overlap 22 22
ok  ports_overlap 20:30 22
ok  ports_overlap 80,443 443
bad ports_overlap 8080 80
bad ports_overlap 1:21 22

if [[ $fail -eq 0 ]]; then echo "lib.sh: tüm testler geçti"; fi
exit $fail
