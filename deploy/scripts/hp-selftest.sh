#!/usr/bin/env bash
# hp-selftest.sh — verifies the sudo + helper script chain works.
# Usage: hp-selftest.sh ping
# Changes nothing on the system.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root

[[ $# -eq 1 ]] || die "kullanım: $(basename "$0") ping"
validate_oneof "$1" ping

log "root yetkisi doğrulandı (uid=${EUID})"
log "çekirdek: $(uname -r)"
log "ok"
