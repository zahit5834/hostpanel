#!/usr/bin/env bash
# Unit tests for install.sh's pure functions (argument parsing, SSH port
# detection, UFW rule plan). Runs unprivileged: `make test-scripts`.
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0

load() { HP_INSTALL_LIB=1 source ./install.sh; }

args_ok() { if ( load; parse_args "$@" ) >/dev/null 2>&1; then :; else echo "FAIL (should pass): parse_args $*"; fail=1; fi; }
args_bad() { if ( load; parse_args "$@" ) >/dev/null 2>&1; then echo "FAIL (should fail): parse_args $*"; fail=1; fi; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
touch "$tmp/hostpanel-v0.1.0-linux-amd64.tar.gz" "$tmp/SHA256SUMS" "$tmp/cfg.hpcfg"

args_ok
args_ok --domain panel.ornek.com --email admin@ornek.com
args_ok --domain Panel.Ornek.COM
args_ok --domain panel.ornek.com --port 443
args_ok --port 9443 --version v1.2.3 --no-firewall --yes
args_ok --tarball "$tmp/hostpanel-v0.1.0-linux-amd64.tar.gz" --sums "$tmp/SHA256SUMS"
args_ok --import "$tmp/cfg.hpcfg"
args_bad --domain "x.com;id"
args_bad --domain
args_bad --email not-an-email
args_bad --port 80
args_bad --port 8090
args_bad --port 443 # IP mode would take 443 from the sites
args_bad --port abc
args_bad --version 1.2.3
args_bad --version "v1.2.3;id"
args_bad --tarball "$tmp/hostpanel-v0.1.0-linux-amd64.tar.gz" # no --sums
args_bad --tarball /nonexistent --sums "$tmp/SHA256SUMS"
args_bad --import /nonexistent
args_bad --unknown

# Parsed values.
got=$( load; parse_args --domain Panel.Ornek.com --port 9443 --no-firewall; echo "$DOMAIN $PORT $NO_FW $VERSION" )
[[ $got == "panel.ornek.com 9443 1 latest" ]] || { echo "FAIL parsed values: $got"; fail=1; }

# sshd -T → ports.
got=$( load; printf 'port 22\nport 2222\nlistenaddress 0.0.0.0:22\npermitrootlogin no\nport 22\n' | ssh_ports_from | paste -sd, - )
[[ $got == "22,2222" ]] || { echo "FAIL ssh_ports_from: $got"; fail=1; }
got=$( load; printf 'ports 22\n' | ssh_ports_from )
[[ -z $got ]] || { echo "FAIL ssh_ports_from accepted '$got'"; fail=1; }

# UFW plan: SSH first, then web and panel port; no duplicate 443.
got=$( load; PORT=8443; ufw_plan 22 2222 | paste -sd' ' - )
[[ $got == "22/tcp 2222/tcp 80/tcp 443/tcp 8443/tcp" ]] || { echo "FAIL ufw_plan: $got"; fail=1; }
got=$( load; PORT=443; ufw_plan 22 | paste -sd' ' - )
[[ $got == "22/tcp 80/tcp 443/tcp" ]] || { echo "FAIL ufw_plan 443: $got"; fail=1; }

# os-release must not clobber the installer's VERSION (release tag).
cat >"$tmp/os-release" <<'OS'
PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
ID=ubuntu
OS
got=$( load; VERSION=latest; o=$(os_release "$tmp/os-release"); echo "$o|$VERSION" )
[[ $got == "ubuntu 24.04|latest" ]] || { echo "FAIL os_release: $got"; fail=1; }

# Installer's own SSH client address (kept out of fail2ban bans).
got=$( load; SSH_CONNECTION="203.0.113.7 51234 10.0.0.5 22" client_ip )
[[ $got == 203.0.113.7 ]] || { echo "FAIL client_ip: $got"; fail=1; }
got=$( load; SSH_CONNECTION="" client_ip )
[[ -z $got ]] || { echo "FAIL client_ip without SSH: $got"; fail=1; }
got=$( load; SSH_CONNECTION="203.0.113.7 51234 10.0.0.5 2222" ssh_ports | tail -n1 )
[[ $got == 2222 ]] || { echo "FAIL ssh_ports from SSH_CONNECTION: $got"; fail=1; }

if [[ $fail -eq 0 ]]; then echo "install.sh: tüm testler geçti"; fi
exit $fail
