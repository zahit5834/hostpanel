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
tm2=$(mktemp -d)
mailops() { (
  source ./lib.sh
  MAIL_FILE_OWNER="$(id -u):$(id -g)"
  set -e
  A=$tm2/acc V=$tm2/virt Q=$tm2/q R=$tm2/rspamd/override.d
  h=$(printf 'parola12345' | openssl passwd -6 -stdin)
  mail_account_set "$A" ali@ornek.com "$h"
  mail_account_set "$A" veli@ornek.com "$h"
  mail_account_set "$A" can@diger.com "$h"
  mail_alias_add "$V" info@ornek.com ali@ornek.com
  # Suspension: nologin=y survives a password reset, list shows it.
  mail_rspamd_base "$R"
  mail_account_nologin "$A" ali@ornek.com on
  mail_map_set "$R/$MAIL_SUSPENDED" ali@ornek.com on
  mail_map_set "$R/$MAIL_SUSPENDED" ali@ornek.com on
  [[ $(grep -c . "$R/$MAIL_SUSPENDED") == 1 ]]
  mail_account_set "$A" ali@ornek.com "$h"
  grep -q '^ali@ornek.com|{SHA512-CRYPT}[^|]*|nologin=y$' "$A"
  mail_map_set "$R/$MAIL_SEND_BLOCKED" veli@ornek.com on
  out=$(mail_list "$A" "$V" "$Q" "$R/$MAIL_SUSPENDED" "$R/$MAIL_SEND_BLOCKED")
  [[ $out == *"account ali@ornek.com 0 suspended"* && $out == *"account veli@ornek.com 0 blocked"* && $out == *"account can@diger.com 0 -"* ]]
  mail_account_nologin "$A" ali@ornek.com off
  if grep -q nologin "$A"; then exit 1; fi
  # Catch-all: identity lines for every account of that domain only, hidden from list.
  mail_catchall_set "$A" "$V" ornek.com veli@ornek.com
  grep -qx '@ornek.com veli@ornek.com' "$V"
  grep -qx 'ali@ornek.com ali@ornek.com' "$V"
  grep -qx 'veli@ornek.com veli@ornek.com' "$V"
  if grep -q 'can@diger.com can@diger.com' "$V"; then exit 1; fi
  grep -qx 'info@ornek.com ali@ornek.com' "$V"
  out=$(mail_list "$A" "$V" "$Q")
  [[ $out == *"catchall ornek.com veli@ornek.com"* && $out != *"alias ali@ornek.com"* && $out != *"alias @"* ]]
  if mail_has_alias "$V" ali@ornek.com; then exit 1; fi
  mail_account_set "$A" yeni@ornek.com "$h"
  mail_catchall_sync "$A" "$V"
  grep -qx 'yeni@ornek.com yeni@ornek.com' "$V"
  mail_account_del "$A" "$V" "$Q" yeni@ornek.com
  mail_catchall_sync "$A" "$V"
  if grep -q yeni "$V"; then exit 1; fi
  # Deleting the target drops the catch-all and with it the identity lines.
  mail_account_del "$A" "$V" "$Q" veli@ornek.com
  mail_catchall_sync "$A" "$V"
  [[ $(cat "$V") == "info@ornek.com ali@ornek.com" ]]
  if (mail_catchall_set "$A" "$V" ornek.com dis@gmail.com); then exit 1; fi
  mail_catchall_set "$A" "$V" ornek.com ali@ornek.com
  mail_catchall_set "$A" "$V" ornek.com -
  [[ $(cat "$V") == "info@ornek.com ali@ornek.com" ]]
  # Rspamd overrides.
  mail_ratelimit "$R" 200
  grep -q 'burst = 200; rate = "200 / 1h"' "$R/ratelimit.conf"
  [[ $(mail_ratelimit_get "$R") == 200 ]]
  grep -q 'symbols_enabled = \[RATELIMIT_CHECK, RATELIMIT_UPDATE, HOSTPANEL_SEND_BLOCKED, HOSTPANEL_SUSPENDED\]' "$R/settings.conf"
  grep -q 'groups_enabled = \[dkim\]' "$R/settings.conf"
  grep -q 'map = "/etc/rspamd/override.d/hostpanel-suspended.map"' "$R/multimap.conf"
  [[ $(grep -c . "$R/$MAIL_SEND_BLOCKED") == 1 ]] # base rewrite keeps the lists
  mail_ratelimit "$R" 0
  if grep -q rates "$R/ratelimit.conf"; then exit 1; fi
  [[ $(mail_ratelimit_get "$R") == 0 ]]
  if (mail_ratelimit "$R" 5); then exit 1; fi
  if (mail_ratelimit "$R" 10001); then exit 1; fi
  if (mail_ratelimit "$R" "1;x"); then exit 1; fi
  [[ $(mail_ratelimit_get "$tm2/none") == 0 ]]
) >/dev/null 2>&1; }
mailops
[[ $? -eq 0 ]] || { echo "FAIL mail suspend/catch-all/ratelimit functions"; fail=1; }
rm -rf "$tm2"
tr_=$(mktemp -d)
mkdir -p "$tr_/md/cur" "$tr_/md/new" "$tr_/md/.Junk/cur" "$tr_/md/.Spam/cur"
echo a >"$tr_/md/cur/1700.M1P1.host,S=1:2,S"
echo b >"$tr_/md/new/1701.M2P2.host,S=1"
echo c >"$tr_/md/.Junk/cur/1702.M3P3.host:2,"
echo d >"$tr_/md/.Spam/cur/1703.M4P4.host:2,"  # other folders are not read
head -c 11000000 /dev/zero >"$tr_/md/cur/big.M5:2,"
echo old >"$tr_/md/cur/1600.old:2,"; touch -d '200 days ago' "$tr_/md/cur/1600.old:2,"
out=$( (source ./lib.sh; mail_report_sync "$tr_/md" "$tr_/out" "$(id -g)") 2>&1 )
[[ $out == "copied=3 kept=0 removed=0" && -f "$tr_/out/1700.M1P1.host,S=1" && -f "$tr_/out/1702.M3P3.host" && ! -e "$tr_/out/big.M5" ]] ||
  { echo "FAIL mail_report_sync copy: $out $(ls "$tr_/out")"; fail=1; }
[[ $(stat -c %a "$tr_/out") == 750 && $(stat -c %a "$tr_/out/1701.M2P2.host,S=1") == 640 ]] || { echo "FAIL mail_report_sync modes"; fail=1; }
mv "$tr_/md/cur/1700.M1P1.host,S=1:2,S" "$tr_/md/cur/1700.M1P1.host,S=1:2,RS" # flags change: same copy
rm "$tr_/md/new/1701.M2P2.host,S=1"
out=$( (source ./lib.sh; mail_report_sync "$tr_/md" "$tr_/out" "$(id -g)") 2>&1 )
[[ $out == "copied=0 kept=2 removed=1" ]] || { echo "FAIL mail_report_sync resync: $out"; fail=1; }
ln -s /etc "$tr_/evil"
bad mail_report_sync "$tr_/evil" "$tr_/out2" "$(id -g)"
rm -rf "$tr_"
bad mail_account_set "$tm/x" a@ornek.com 'plain'
( source ./lib.sh; MAIL_FILE_OWNER="$(id -u):$(id -g)"; for i in $(seq 1 50); do mail_alias_add "$tm/v50" x@ornek.com "t$i@gmail.com"; done ) >/dev/null 2>&1
bad mail_alias_add "$tm/v50" x@ornek.com t51@gmail.com
rm -rf "$tm"
v=$( (source ./lib.sh; render_mail_vhost mail.ornek.com) )
[[ $v == *"server_name mail.ornek.com autoconfig.ornek.com autodiscover.ornek.com;"* && $v == *"/.well-known/acme-challenge/"* && $v == *"return 404;"* && $v != *ssl* ]] ||
  { echo "FAIL mail vhost"; fail=1; }
[[ $v == *"location = /mail/config-v1.1.xml"* && $v == *"<username>%EMAILADDRESS%</username>"* && $v == *"<socketType>STARTTLS</socketType>"* ]] ||
  { echo "FAIL mail vhost autoconfig"; fail=1; }
[[ $v == *'location ~* ^/autodiscover/autodiscover\.xml$'* && $v == *"<Server>mail.ornek.com</Server>"* ]] || { echo "FAIL mail vhost autodiscover"; fail=1; }
[[ $v != *'$('* && $(grep -c "'" <<<"$v") == 6 ]] || { echo "FAIL mail vhost quoting"; fail=1; }
bad render_mail_vhost "mail.ornek.com; include /etc/passwd"
bad render_mail_vhost mail.ornek.com "mail.ornek.com evil.com"
bad render_mail_vhost mail.ornek.com tls
v=$( (source ./lib.sh; render_mail_vhost mail.ornek.com "mail.ornek.com autoconfig.ornek.com") )
for want in "listen 443 ssl http2;" "server_name mail.ornek.com autoconfig.ornek.com;" "/etc/letsencrypt/live/hostpanel-mail/fullchain.pem" \
  "/etc/letsencrypt/live/hostpanel-mail/privkey.pem" "ssl_protocols TLSv1.2 TLSv1.3;" 'return 200 "mail.ornek.com bir posta sunucusudur'; do
  [[ $v == *"$want"* ]] || { echo "FAIL mail tls vhost misses: $want"; fail=1; }
done
tc=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tc/k" -out "$tc/c" -days 1 -subj /CN=mail.ornek.com \
  -addext "subjectAltName=DNS:mail.ornek.com,DNS:autodiscover.ornek.com,DNS:other.com" 2>/dev/null
[[ $( (source ./lib.sh; mail_cert_names mail.ornek.com "$tc/c") ) == "mail.ornek.com autodiscover.ornek.com" ]] || { echo "FAIL mail_cert_names"; fail=1; }
rm -rf "$tc"
[[ $v != *default_server* ]] || { echo "FAIL mail vhost must not be default_server"; fail=1; }
bad render_mail_vhost mail.ornek.com other

# catch-all: 443 refuses the handshake, 80 closes; only free ports.
v=$( (source ./lib.sh; render_default_vhost 80 443) )
for want in "listen 80 default_server;" "listen [::]:80 default_server;" "return 444;" "listen 443 ssl http2 default_server;" \
  "listen [::]:443 ssl http2 default_server;" "ssl_reject_handshake on;" "ssl_protocols TLSv1.2 TLSv1.3;"; do
  [[ $v == *"$want"* ]] || { echo "FAIL default vhost misses: $want"; fail=1; }
done
v=$( (source ./lib.sh; render_default_vhost 443) )
[[ $v != *"listen 80"* && $v == *ssl_reject_handshake* ]] || { echo "FAIL default vhost 443 only"; fail=1; }
bad render_default_vhost 8080
td=$(mktemp -d)
mkdir -p "$td/en" "$td/cd"
printf 'server {\n    listen 80 default_server;\n    listen [::]:80 default_server;\n    # listen 443 ssl default_server;\n}\n' >"$td/en/default"
printf 'server {\n    listen 8443 ssl http2 default_server;\n}\n' >"$td/en/hostpanel.conf"
printf 'server {\n    listen 443 ssl http2 default_server;\n}\n' >"$td/en/hostpanel-default.conf"
dflt() { ( source ./lib.sh; has_default_server "$@" ); }
dflt 80 "$td/en" "$td/cd" || { echo "FAIL default_server on 80 not found (Ubuntu default site)"; fail=1; }
! dflt 443 "$td/en" "$td/cd" || { echo "FAIL 443: comment, 8443 or own catch-all counted"; fail=1; }
printf 'server {\n  listen [::]:443 ssl default_server;\n}\n' >"$td/cd/x.conf"
dflt 443 "$td/en" "$td/cd" || { echo "FAIL [::]:443 default_server not found"; fail=1; }
rm -rf "$td"
v=$(vhost ip "" 443)
[[ $v == *"listen 443 ssl http2 default_server;"* ]] || { echo "FAIL ip panel on 443 must be the default server"; fail=1; }

# --- Faz 11: SSH drop-in, keys, fail2ban jail
v=$( (source ./lib.sh; render_sshd_dropin no prohibit-password) )
for want in "PasswordAuthentication no" "KbdInteractiveAuthentication no" "PermitRootLogin prohibit-password" "PubkeyAuthentication yes"; do
  [[ $v == *"$want"* ]] || { echo "FAIL sshd dropin misses: $want"; fail=1; }
done
bad render_sshd_dropin maybe no
bad render_sshd_dropin no without-password
ok  validate_sys_user ubuntu
bad validate_sys_user "Ubuntu"
bad validate_sys_user "a;b"
ok  validate_fingerprint "SHA256:$(printf 'A%.0s' {1..43})"
bad validate_fingerprint "SHA256:short"
bad validate_fingerprint "MD5:aa:bb"
kd=$(mktemp -d)
ssh-keygen -q -t ed25519 -N '' -C 'admin@laptop' -f "$kd/k" >/dev/null
ssh-keygen -q -t rsa -b 1024 -N '' -f "$kd/r" >/dev/null 2>&1 || true
key=$(cat "$kd/k.pub")
ok  validate_pubkey "$key"
got=$( (source ./lib.sh; validate_pubkey "$key  ") )
[[ $got == "$key" ]] || { echo "FAIL pubkey normalize: $got"; fail=1; }
bad validate_pubkey "command=\"/bin/sh\" $key"
bad validate_pubkey "from=\"1.2.3.4\" $key"
bad validate_pubkey "ssh-dss AAAAB3NzaC1kc3MAAACBAP$(printf 'A%.0s' {1..80})"
bad validate_pubkey "${key% *} bad\$comment"
bad validate_pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI$(printf 'B%.0s' {1..60})"
bad validate_pubkey "$key"$'\n'"$key"
[[ -f $kd/r.pub ]] && bad validate_pubkey "$(cat "$kd/r.pub")"
fp=$( (source ./lib.sh; key_fingerprint "$key") )
[[ $fp == "$(ssh-keygen -lf "$kd/k.pub" | awk '{print $2}')" && $fp == SHA256:* ]] || { echo "FAIL key_fingerprint: $fp"; fail=1; }
fp=$( (source ./lib.sh; key_fingerprint "# not a key") )
[[ -z $fp ]] || { echo "FAIL key_fingerprint comment: $fp"; fail=1; }
rm -rf "$kd"

v=$( (source ./lib.sh; render_f2b_jail true 5 15 60 1 8443,443 203.0.113.5 10.0.0.0/8) )
for want in "# hp-config: maxretry=5 findtime=15 bantime=60 recidive=1" "[hostpanel]" "enabled  = true" "port     = 8443,443" \
  "[sshd]" "findtime = 15m" "bantime  = 60m" "ignoreip = 127.0.0.1/8 ::1 203.0.113.5 10.0.0.0/8" "[recidive]" "bantime  = 1w"; do
  [[ $v == *"$want"* ]] || { echo "FAIL f2b jail misses: $want"; fail=1; }
done
v=$( (source ./lib.sh; render_f2b_jail false 3 5 10 0 443) )
[[ $v != *recidive]* && $v == *"ignoreip = 127.0.0.1/8 ::1"$'\n'* ]] || { echo "FAIL f2b jail without recidive/ignore"; fail=1; }
bad render_f2b_jail true 2 15 60 0 443
bad render_f2b_jail true 5 4 60 0 443
bad render_f2b_jail true 5 15 20000 0 443
bad render_f2b_jail true 5 15 60 2 443
bad render_f2b_jail true 5 15 60 0 "443;x"
bad render_f2b_jail true 5 15 60 0 443 0.0.0.0/0
bad render_f2b_jail true 5 15 60 0 443 "1.2.3.4 5.6.7.8"
jd=$(mktemp -d)
(source ./lib.sh; render_f2b_jail true 7 30 120 1 443 198.51.100.9) >"$jd/j.conf"
cur=$( (F2B_JAIL=$jd/j.conf; source ./lib.sh; F2B_JAIL=$jd/j.conf; f2b_current) )
[[ $cur == "7 30 120 1" ]] || { echo "FAIL f2b_current: $cur"; fail=1; }
ign=$( (source ./lib.sh; F2B_JAIL=$jd/j.conf; f2b_ignored) )
[[ $ign == 198.51.100.9 ]] || { echo "FAIL f2b_ignored: $ign"; fail=1; }
cur=$( (source ./lib.sh; F2B_JAIL=$jd/none; f2b_current) )
[[ $cur == "5 15 60 0" ]] || { echo "FAIL f2b_current default: $cur"; fail=1; }
rm -rf "$jd"

# --- database directory location (Faz 13, T2) ---
dd=$(mktemp -d)
dbt() { (source ./lib.sh; DB_ROOT=$dd/new OLD_DB_ROOT=$dd/old DB_ROOT_UID=$(id -u); "$@"); }
mkdir -p "$dd/old/mssql/backup" "$dd/old/postgres"
[[ $(dbt db_path mssql) == "$dd/old/mssql" ]] || { echo "FAIL db_path old"; fail=1; }
[[ $(dbt db_path postgres-backup) == "$dd/new/postgres-backup" ]] || { echo "FAIL db_path absent → new"; fail=1; }
mkdir -p "$dd/new"
chmod 0711 "$dd/new"
dbt db_relocate to-new mssql >/dev/null 2>&1 || { echo "FAIL db_relocate to-new"; fail=1; }
[[ -d $dd/new/mssql/backup && ! -e $dd/old/mssql ]] || { echo "FAIL relocate result"; fail=1; }
[[ $(dbt db_path mssql) == "$dd/new/mssql" ]] || { echo "FAIL db_path after move"; fail=1; }
# A retried job moves again: already moved = no-op, data stays.
dbt db_relocate to-new mssql >/dev/null 2>&1 || { echo "FAIL repeated to-new"; fail=1; }
[[ -d $dd/new/mssql/backup && ! -e $dd/old/mssql ]] || { echo "FAIL repeated to-new moved data"; fail=1; }
mkdir "$dd/old/mssql"
if dbt db_relocate to-old mssql >/dev/null 2>&1; then echo "FAIL relocate over existing target"; fail=1; fi
rmdir "$dd/old/mssql"
dbt db_relocate to-old mssql >/dev/null 2>&1 || { echo "FAIL db_relocate to-old"; fail=1; }
[[ -d $dd/old/mssql/backup ]] || { echo "FAIL relocate back"; fail=1; }
dbt db_relocate to-new postgres postgres-backup >/dev/null 2>&1 || { echo "FAIL relocate pg (no backup dir)"; fail=1; }
[[ -d $dd/new/postgres ]] || { echo "FAIL pg moved"; fail=1; }
if dbt db_relocate to-new etc >/dev/null 2>&1; then echo "FAIL relocate unknown name"; fail=1; fi
ln -s /etc "$dd/old/postgres-backup"
if dbt check_db_dirs >/dev/null 2>&1; then echo "FAIL check_db_dirs symlink"; fail=1; fi
rm "$dd/old/postgres-backup"
chmod 0777 "$dd/new"
if dbt ensure_db_root >/dev/null 2>&1; then echo "FAIL ensure_db_root writable"; fail=1; fi
rm -rf "$dd"

# --- Faz 13: ACME DNS-01 lines, serial never moves backwards
za=$(mktemp -d)
cp testdata_zone_good.txt "$za/z"
[[ $( (source ./lib.sh; zone_serial "$za/z") ) == 2026110701 ]] || { echo "FAIL zone_serial"; fail=1; }
[[ $( (source ./lib.sh; zone_next_serial 2026110701 2026110705) ) == 2026110706 ]] || { echo "FAIL next serial behind"; fail=1; }
[[ $( (source ./lib.sh; zone_next_serial 2026111201 2026110705) ) == 2026111201 ]] || { echo "FAIL next serial ahead"; fail=1; }
[[ $( (source ./lib.sh; zone_next_serial 2026111201 "") ) == 2026111201 ]] || { echo "FAIL next serial new zone"; fail=1; }
(source ./lib.sh; zone_set_serial "$za/z" 2026111299) || { echo "FAIL zone_set_serial"; fail=1; }
[[ $( (source ./lib.sh; zone_serial "$za/z") ) == 2026111299 && $(wc -l <"$za/z") == $(wc -l <testdata_zone_good.txt) ]] || { echo "FAIL serial rewrite"; fail=1; }
if (source ./lib.sh; zone_set_serial "$za/z" 4294967296) 2>/dev/null; then echo "FAIL serial overflow"; fail=1; fi
v1=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ v2=0123456789_-abcdefghijklmnopqrstuvwxyzABCDE
(source ./lib.sh; validate_acme_value "$v1") || { echo "FAIL acme value"; fail=1; }
for b in short "${v1}x" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO\"Q" 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN P'; do
  if (source ./lib.sh; validate_acme_value "$b") 2>/dev/null; then echo "FAIL acme value accepted: $b"; fail=1; fi
done
(
  source ./lib.sh
  st=$za/state
  acme_state_edit "$st" add "$(acme_line ornek.com "$v1")"
  acme_state_edit "$st" add "$(acme_line ornek.com "$v2")"
  acme_state_edit "$st" add "$(acme_line ornek.com "$v1")" # duplicate
  [[ $(wc -l <"$st") == 2 ]] || { echo "FAIL acme state dedupe"; exit 1; }
  zone_with_acme "$za/z" "$st" "$za/out"
  [[ $(grep -c '^_acme-challenge.ornek.com. 60 IN TXT "' "$za/out") == 3 ]] || { echo "FAIL acme lines (2 root + 1 manual)"; exit 1; }
  validate_zone_file "$za/out" ornek.com || exit 1
  # rewrite with the lines already in the source: still once each
  zone_with_acme "$za/out" "$st" "$za/out2"
  cmp -s "$za/out" "$za/out2" || { echo "FAIL acme merge not idempotent"; exit 1; }
  acme_state_edit "$st" del "$(acme_line ornek.com "$v1")"
  [[ $(cat "$st") == "$(acme_line ornek.com "$v2")" ]] || { echo "FAIL acme state del"; exit 1; }
  [[ $(stat -c %a "$st") == 600 ]] || { echo "FAIL acme state mode"; exit 1; }
  [[ $(acme_zone_for www.app.ornek.com ornek.com app.ornek.com baska.com) == app.ornek.com ]] || { echo "FAIL acme zone longest"; exit 1; }
  [[ $(acme_zone_for ornek.com ornek.com) == ornek.com ]] || { echo "FAIL acme zone apex"; exit 1; }
  if acme_zone_for xornek.com ornek.com; then echo "FAIL acme zone suffix without dot"; exit 1; fi
  for i in $(seq 1 19); do acme_state_edit "$st" add "$(acme_line ornek.com "$(printf 'a%042d' "$i")")"; done
  if (acme_state_edit "$st" add "$(acme_line ornek.com "$v1")") 2>/dev/null; then echo "FAIL acme state cap"; exit 1; fi
) || fail=1
rm -rf "$za"

if [[ $fail -eq 0 ]]; then echo "lib.sh: tüm testler geçti"; fi
exit $fail
