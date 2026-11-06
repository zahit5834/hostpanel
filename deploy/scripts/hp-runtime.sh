#!/usr/bin/env bash
# hp-runtime.sh — install/remove a runtime version via scripts/runtimes/<id>.sh.
# Usage: hp-runtime.sh install|remove <runtime-id> <X.Y[.Z]>
#        hp-runtime.sh install-sdk dotnet <X.Y>        (latest SDK of the channel)
#        hp-runtime.sh remove-sdk dotnet <X.Y.Z>
# Only scripts shipped in /opt/hostpanel/scripts/runtimes (root-owned) can run.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -eq 3 ]] || die "kullanım: $(basename "$0") install|remove|install-sdk|remove-sdk <runtime> <sürüm>"
action=$1 id=$2 version=$3
validate_oneof "$action" install remove install-sdk remove-sdk
[[ $id =~ ^[a-z][a-z0-9-]{1,20}$ ]] || die "geçersiz altyapı: ${id}"
[[ $version =~ ^[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,4})?$ ]] || die "geçersiz sürüm: ${version}"
case $action in
  install-sdk)
    [[ $id == dotnet && $version =~ ^[0-9]{1,3}\.[0-9]{1,3}$ ]] || die "SDK yalnızca .NET için, kanal X.Y biçiminde" ;;
  remove-sdk)
    [[ $id == dotnet && $version =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}$ ]] || die "SDK sürümü X.Y.Z biçiminde olmalı" ;;
esac
script="$(dirname "$(readlink -f "$0")")/runtimes/${id}.sh"
[[ -f $script ]] || die "kurulum betiği yok: ${id}"
exec bash "$script" "$action" "$version"
