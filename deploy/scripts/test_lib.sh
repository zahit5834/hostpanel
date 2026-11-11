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

# Faz 5b: user commands, git, limits, runtime PATH.
ok  validate_user_command "cd current && php artisan schedule:run >/dev/null 2>&1"
ok  validate_user_command 'echo "$HOME" | tee -a log.txt'
bad validate_user_command ""
bad validate_user_command "   "
bad validate_user_command "$(printf 'echo a\necho b')"
bad validate_user_command "$(printf 'echo\ta')"
bad validate_user_command "$(printf 'x%.0s' {1..1001})"
ok  validate_git_url git@github.com:acme/app.git
ok  validate_git_url ssh://git@gitlab.example.com:2222/acme/app.git
ok  validate_git_url https://github.com/acme/app
bad validate_git_url file:///etc/passwd
bad validate_git_url "ext::sh -c id"
bad validate_git_url -oProxyCommand=x
bad validate_git_url git@-host:x
bad validate_git_url https://user:pw@github.com/a/b
bad validate_git_url https://github.com/../x
bad validate_git_url git@github.com:-x
bad validate_git_url 'ssh://h/$(id)'
bad validate_git_url http://github.com/a/b
ok  validate_git_branch main
ok  validate_git_branch release/1.2
bad validate_git_branch -f
bad validate_git_branch a..b
bad validate_git_branch a.lock
bad validate_git_branch a/.b
bad validate_git_branch "x y"
ok  validate_outdir .
ok  validate_outdir hp-publish
bad validate_outdir .hp-out
bad validate_outdir ../x
ok  validate_limits 600 512 100
bad validate_limits 5 512 100
bad validate_limits 600 32 100
bad validate_limits 600 512 2000
ok  runtime_path node 24.11.1
ok  runtime_path php 8.3
bad runtime_path node "24;id"
bad runtime_path java 1.2.3

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

# zone file validation: each line of testdata_zone_bad.txt after a valid head must be rejected.
tmpz=$(mktemp)
while IFS= read -r line; do
  printf '%s\n%s\n%s\n' '$TTL 3600' 'ornek.com. 3600 IN SOA ns1.ornek.com. hostmaster.ornek.com. 1 2 3 4 5' "$line" >"$tmpz"
  bad validate_zone_file "$tmpz" ornek.com
done <testdata_zone_bad.txt
ok validate_zone_file testdata_zone_good.txt ornek.com
bad validate_zone_file testdata_zone_good.txt baska.com
printf '%s\n%s' '$TTL 3600' 'ornek.com. 3600 IN SOA ns1.ornek.com. h.ornek.com. 1 2 3 4 5' >"$tmpz" # no final newline
bad validate_zone_file "$tmpz" ornek.com
printf '%s\r\n%s\n' '$TTL 3600' 'ornek.com. 3600 IN SOA ns1.ornek.com. h.ornek.com. 1 2 3 4 5' >"$tmpz"
bad validate_zone_file "$tmpz" ornek.com
rm -f "$tmpz"

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
bad validate_ip_or_cidr 0.0.0.0
bad validate_ip_or_cidr 0.0.0.0/8
bad validate_ip_or_cidr ::
bad validate_ip_or_cidr 127.0.0.1
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
ok  validate_backup_file db-pg-otopanom.dump
bad validate_backup_file db-pg-../x.dump
bad validate_backup_file db-shop.dump

ok  validate_pg_image postgres:18.6-trixie
ok  validate_pg_image postgres:16.10-bookworm
bad validate_pg_image postgres:latest
bad validate_pg_image postgres:15.4-bookworm
bad validate_pg_image evil/postgres:18.6-trixie
bad validate_pg_image "postgres:18.6-trixie --privileged"
ok  validate_pg_name otopanom
ok  validate_pg_name c_acme
bad validate_pg_name postgres
bad validate_pg_name template1
bad validate_pg_name pg_shadow
bad validate_pg_name hpiso_a
bad validate_pg_name hprs_1
bad validate_pg_name Otopanom
bad validate_pg_name 'a";drop'

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

# --- install / update (Faz 6) ---
ok  validate_version v0.1.0
ok  validate_version v12.34.567
bad validate_version 0.1.0
bad validate_version v0.1
bad validate_version "v0.1.0;id"
bad validate_version latest
ok  validate_repo zahit5834/hostpanel
ok  validate_repo my-org/host.panel_2
bad validate_repo zahit5834
bad validate_repo "a/b/c"
bad validate_repo "a/.."
bad validate_repo "a/b c"
ok  validate_panel_port 8443
ok  validate_panel_port 443
bad validate_panel_port 80
bad validate_panel_port 8090
bad validate_panel_port 1023
bad validate_panel_port 70000

tmp6=$(mktemp -d)
trap 'rm -rf "$tmp6"' EXIT
cat >"$tmp6/config.yaml" <<'CFG'
listen: 127.0.0.1:8090
panel_domain: "panel.ornek.com"   # comment
panel_port: 8443
update_repo: zahit5834/hostpanel
empty: ""
CFG
cfgval() { ( source ./lib.sh; HP_CONFIG=$tmp6/config.yaml; config_value "$1" ); }
for kv in "listen=127.0.0.1:8090" "panel_domain=panel.ornek.com" "panel_port=8443" "update_repo=zahit5834/hostpanel" "empty=" "missing="; do
  k=${kv%%=*} want=${kv#*=}
  got=$(cfgval "$k")
  [[ $got == "$want" ]] || { echo "FAIL config_value $k: got '$got' want '$want'"; fail=1; }
done
bad config_value "a;b"

vhost() { ( source ./lib.sh; render_panel_vhost "$@" ); }
v=$(vhost ip "" 8443)
for want in "listen 8443 ssl http2 default_server;" "ssl_certificate /etc/hostpanel/panel-tls/cert.pem;" \
  "proxy_pass http://127.0.0.1:8090;" 'proxy_set_header Host $http_host;' "proxy_buffering off;" "client_max_body_size 1100m;"; do
  [[ $v == *"$want"* ]] || { echo "FAIL ip vhost misses: $want"; fail=1; }
done
[[ $v != *"listen 80;"* && $v != *Strict-Transport* ]] || { echo "FAIL ip vhost has port 80/HSTS"; fail=1; }
v=$(vhost domain panel.ornek.com 443)
for want in "server_name panel.ornek.com;" "listen 443 ssl http2;" "return 301 https://\$host\$request_uri;" \
  "/etc/letsencrypt/live/hostpanel-panel/fullchain.pem" "Strict-Transport-Security" "/.well-known/acme-challenge/"; do
  [[ $v == *"$want"* ]] || { echo "FAIL domain vhost misses: $want"; fail=1; }
done
[[ $v != *default_server* ]] || { echo "FAIL domain vhost on 443 must not be default_server"; fail=1; }
v=$(vhost domain panel.ornek.com 8443)
[[ $v == *'return 301 https://$host:8443$request_uri;'* ]] || { echo "FAIL redirect keeps the port"; fail=1; }
v=$(vhost acme panel.ornek.com 8443)
[[ $v == *"listen 80;"* && $v != *ssl_certificate* ]] || { echo "FAIL acme vhost"; fail=1; }
bad render_panel_vhost domain "x.com; include /etc/passwd" 8443
bad render_panel_vhost ip "" 80
bad render_panel_vhost other "" 8443

# archive_ok: plain files/dirs under the top directory only.
mkdir -p "$tmp6/a/pkg-v1/bin" "$tmp6/b/pkg-v1" "$tmp6/c/other"
echo x >"$tmp6/a/pkg-v1/bin/f"
ln -s /etc/passwd "$tmp6/b/pkg-v1/passwd"
echo x >"$tmp6/c/other/f"
tar -czf "$tmp6/good.tgz" -C "$tmp6/a" pkg-v1
tar -czf "$tmp6/link.tgz" -C "$tmp6/b" pkg-v1
tar -czf "$tmp6/outside.tgz" -C "$tmp6/c" other
ok  archive_ok "$tmp6/good.tgz" pkg-v1
bad archive_ok "$tmp6/link.tgz" pkg-v1
bad archive_ok "$tmp6/outside.tgz" pkg-v1
bad archive_ok "$tmp6/good.tgz" pkg-v2

# Panel vhost: database dump uploads get their own body limit.
v=$(vhost domain panel.ornek.com 8443)
[[ $v == *'location ~ ^/sites/[0-9]+/import/(db|pg)$ {'* && $v == *"client_max_body_size 10300m;"* && $v == *"client_max_body_size 1100m;"* ]] ||
  { echo "FAIL panel vhost upload limits"; fail=1; }

# Faz 9: mail server.
ok  validate_mail_image mailserver/docker-mailserver:17.0.0-r1
ok  validate_mail_image mailserver/docker-mailserver:18.1.2
bad validate_mail_image mailserver/docker-mailserver:latest
bad validate_mail_image mailserver/docker-mailserver:16.0.0
bad validate_mail_image evil/docker-mailserver:17.0.0
ok  validate_mail_addr info@ornek.com
ok  validate_mail_addr ali.veli_1@sub.ornek.com.tr
bad validate_mail_addr Info@ornek.com
bad validate_mail_addr "a|b@ornek.com"
bad validate_mail_addr "a b@ornek.com"
bad validate_mail_addr a+b@ornek.com
bad validate_mail_addr a..b@ornek.com
bad validate_mail_addr a.@ornek.com
bad validate_mail_addr .a@ornek.com
bad validate_mail_addr a@b@ornek.com
bad validate_mail_addr "a:1@ornek.com"
bad validate_mail_addr "a,b@ornek.com"
bad validate_mail_addr ornek.com
ok  validate_mail_target a+tag@gmail.com
bad validate_mail_target "a,b@gmail.com"
ok  validate_backup_file mail-config.tar.zst
ok  validate_backup_file mail-data.tar.zst
ok  backup_dir _mail 20261111-120000-abcd
bad backup_dir _other 20261111-120000-abcd
bad backup_dir ../x 20261111-120000-abcd

tm=$(mktemp -d)
mailtest() { (
  source ./lib.sh
  MAIL_FILE_OWNER="$(id -u):$(id -g)"
  set -e
  A=$tm/postfix-accounts.cf V=$tm/postfix-virtual.cf Q=$tm/dovecot-quotas.cf
  h=$(printf 'parola12345' | openssl passwd -6 -stdin)
  [[ $(mail_account_count "$A") == 0 ]]
  mail_account_set "$A" postmaster@ornek.com "$h"
  mail_account_set "$A" ali@ornek.com "$h"
  mail_account_set "$A" ali@ornek.com "$h" # replace, not duplicate
  [[ $(mail_account_count "$A") == 2 ]]
  [[ $(stat -c %a "$A") == 600 ]]
  mail_has_account "$A" ali@ornek.com
  if mail_has_account "$A" ali@ornek.co; then exit 1; fi
  if mail_has_account "$A" li@ornek.com; then exit 1; fi
  mail_quota_set "$Q" ali@ornek.com 500
  mail_quota_set "$Q" ali@ornek.com 250
  [[ $(cat "$Q") == "ali@ornek.com:250M" ]]
  mail_alias_add "$V" info@ornek.com ali@ornek.com
  mail_alias_add "$V" info@ornek.com dis@gmail.com
  mail_alias_add "$V" info@ornek.com dis@gmail.com
  mail_alias_add "$V" satis@ornek.com ali@ornek.com
  [[ $(grep -c . "$V") == 2 ]]
  mail_has_alias "$V" info@ornek.com
  out=$(mail_list "$A" "$V" "$Q")
  [[ $out == *"account ali@ornek.com 250"* && $out == *"account postmaster@ornek.com 0"* ]]
  [[ $out == *"alias info@ornek.com ali@ornek.com,dis@gmail.com"* ]]
  [[ $out != *SHA512* ]]
  mail_domain_used "$A" "$V" ornek.com
  if mail_domain_used "$A" "$V" diger.com; then exit 1; fi
  mail_alias_del "$V" info@ornek.com dis@gmail.com
  [[ $(mail_list "$A" "$V" "$Q") == *"alias info@ornek.com ali@ornek.com"* ]]
  mail_account_del "$A" "$V" "$Q" ali@ornek.com
  [[ $(mail_account_count "$A") == 1 ]]
  [[ ! -s $Q && ! -s $V ]] # quota line and the aliases pointing only at ali are gone
  mail_quota_set "$Q" postmaster@ornek.com 0
  [[ ! -s $Q ]]
  [[ $(mail_list "$tm/none" "$tm/none" "$tm/none") == "" ]]
) >/dev/null 2>&1; }
# Not "mailtest || …": set -e is ignored inside a tested command.
mailtest
[[ $? -eq 0 ]] || { echo "FAIL mail account/alias/quota file functions"; fail=1; }
bad mail_account_set "$tm/x" a@ornek.com 'plain'
( source ./lib.sh; MAIL_FILE_OWNER="$(id -u):$(id -g)"; for i in $(seq 1 50); do mail_alias_add "$tm/v50" x@ornek.com "t$i@gmail.com"; done ) >/dev/null 2>&1
bad mail_alias_add "$tm/v50" x@ornek.com t51@gmail.com
rm -rf "$tm"
v=$( (source ./lib.sh; render_mail_vhost mail.ornek.com) )
[[ $v == *"server_name mail.ornek.com;"* && $v == *"/.well-known/acme-challenge/"* && $v == *"return 404;"* && $v != *ssl* ]] ||
  { echo "FAIL mail vhost"; fail=1; }
bad render_mail_vhost "mail.ornek.com; include /etc/passwd"

if [[ $fail -eq 0 ]]; then echo "lib.sh: tüm testler geçti"; fi
exit $fail
