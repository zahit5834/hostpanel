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

if [[ $fail -eq 0 ]]; then echo "lib.sh: tüm testler geçti"; fi
exit $fail
