#!/usr/bin/env bash
# runtimes/dotnet.sh — install/remove an ASP.NET Core runtime side by side in /usr/share/dotnet.
# Called only by hp-runtime.sh (already validated): dotnet.sh install|remove <X.Y.Z>
#   dotnet.sh install-sdk <X.Y>   — latest SDK of the channel (needed for git deploy builds)
#   dotnet.sh remove-sdk <X.Y.Z>
# Downloads from Microsoft's release metadata and verifies the published SHA-512.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
require_root
action=$1 version=$2
DOTNET_ROOT=/usr/share/dotnet

case $(dpkg --print-architecture) in
  amd64) rid=x64 ;;
  arm64) rid=arm64 ;;
  *) die "desteklenmeyen mimari" ;;
esac

case $action in
  install | remove)
    [[ $version =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}$ ]] || die ".NET sürümü X.Y.Z olmalı" ;;
esac

case $action in
  install)
    command -v jq >/dev/null || die "jq kurulu değil"
    channel=${version%.*}
    meta="https://builds.dotnet.microsoft.com/dotnet/release-metadata/${channel}/releases.json"
    log "sürüm bilgisi: ${meta}"
    read -r url hash < <(curl -fsSL --retry 3 "$meta" | jq -r --arg v "$version" --arg n "aspnetcore-runtime-linux-${rid}.tar.gz" \
      '.releases[] | select(.runtime.version == $v) | .["aspnetcore-runtime"].files[] | select(.name == $n) | "\(.url) \(.hash)"' | head -n1) || true
    [[ -n ${url:-} && ${hash:-} =~ ^[0-9a-f]{128}$ ]] || die "${version} için aspnetcore-runtime-linux-${rid} bulunamadı"
    [[ $url == https://builds.dotnet.microsoft.com/* || $url == https://download.visualstudio.microsoft.com/* ]] || die "beklenmeyen indirme adresi: ${url}"

    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    log "indiriliyor: ${url}"
    curl -fsSL --retry 3 -o "$work/rt.tar.gz" "$url"
    echo "${hash}  $work/rt.tar.gz" | sha512sum -c --quiet - || die "SHA-512 doğrulaması başarısız"
    log "SHA-512 doğrulandı"
    mkdir -p "$work/x"
    tar -xzf "$work/rt.tar.gz" -C "$work/x"

    install -d -m 0755 "$DOTNET_ROOT/shared" "$DOTNET_ROOT/host/fxr"
    for fw in Microsoft.NETCore.App Microsoft.AspNetCore.App; do
      [[ -d $work/x/shared/$fw/$version ]] || die "arşivde ${fw}/${version} yok"
      install -d -m 0755 "$DOTNET_ROOT/shared/$fw"
      rm -rf "${DOTNET_ROOT:?}/shared/$fw/$version"
      cp -a "$work/x/shared/$fw/$version" "$DOTNET_ROOT/shared/$fw/"
    done
    for fxr in "$work"/x/host/fxr/*; do
      [[ -d $fxr && ! -e $DOTNET_ROOT/host/fxr/$(basename "$fxr") ]] && cp -a "$fxr" "$DOTNET_ROOT/host/fxr/"
    done
    # The muxer (dotnet) is backward compatible: only replace it with a newer one.
    newest=$(printf '%s\n' "$DOTNET_ROOT"/host/fxr/* | xargs -n1 basename | sort -V | tail -n1)
    if [[ ! -x $DOTNET_ROOT/dotnet || $newest == "$version" ]]; then
      install -m 0755 "$work/x/dotnet" "$DOTNET_ROOT/dotnet"
      cp -f "$work/x/LICENSE.txt" "$work/x/ThirdPartyNotices.txt" "$DOTNET_ROOT/" 2>/dev/null || true
    fi
    chown -R root:root "$DOTNET_ROOT"
    chmod -R a+rX,go-w "$DOTNET_ROOT"
    log "kuruldu: ASP.NET Core ${version}"
    "$DOTNET_ROOT/dotnet" --list-runtimes
    ;;
  install-sdk)
    command -v jq >/dev/null || die "jq kurulu değil"
    meta="https://builds.dotnet.microsoft.com/dotnet/release-metadata/${version}/releases.json"
    log "sürüm bilgisi: ${meta}"
    json=$(curl -fsSL --retry 3 "$meta") || die "sürüm bilgisi alınamadı"
    sdk=$(jq -r '."latest-sdk" // empty' <<<"$json")
    [[ $sdk =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}$ ]] || die "${version} kanalında SDK bulunamadı"
    read -r url hash < <(jq -r --arg v "$sdk" --arg n "dotnet-sdk-linux-${rid}.tar.gz" \
      '[.releases[] | (.sdks // [.sdk])[] | select(.version == $v) | .files[] | select(.name == $n)][0] | "\(.url) \(.hash)"' <<<"$json") || true
    [[ -n ${url:-} && ${hash:-} =~ ^[0-9a-f]{128}$ ]] || die "SDK ${sdk} için dotnet-sdk-linux-${rid} bulunamadı"
    [[ $url == https://builds.dotnet.microsoft.com/* || $url == https://download.visualstudio.microsoft.com/* ]] || die "beklenmeyen indirme adresi: ${url}"
    [[ ! -d $DOTNET_ROOT/sdk/$sdk ]] || { log "SDK ${sdk} zaten kurulu"; "$DOTNET_ROOT/dotnet" --list-sdks; exit 0; }

    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    log "indiriliyor: ${url}"
    curl -fsSL --retry 3 -o "$work/sdk.tar.gz" "$url"
    echo "${hash}  $work/sdk.tar.gz" | sha512sum -c --quiet - || die "SHA-512 doğrulaması başarısız"
    log "SHA-512 doğrulandı"
    mkdir -p "$work/x"
    tar -xzf "$work/sdk.tar.gz" -C "$work/x"
    [[ -d $work/x/sdk/$sdk ]] || die "arşivde sdk/${sdk} yok"
    install -d -m 0755 "$DOTNET_ROOT"
    # Merge without overwriting what is installed (runtimes, packs, fxr).
    for part in sdk sdk-manifests packs templates shared host; do
      [[ -d $work/x/$part ]] && cp -a -n "$work/x/$part" "$DOTNET_ROOT/"
    done
    newest=$(printf '%s\n' "$DOTNET_ROOT"/host/fxr/* | xargs -n1 basename | sort -V | tail -n1)
    if [[ ! -x $DOTNET_ROOT/dotnet || -d $work/x/host/fxr/$newest ]]; then
      install -m 0755 "$work/x/dotnet" "$DOTNET_ROOT/dotnet"
    fi
    chown -R root:root "$DOTNET_ROOT"
    chmod -R a+rX,go-w "$DOTNET_ROOT"
    log "kuruldu: .NET SDK ${sdk}"
    "$DOTNET_ROOT/dotnet" --list-sdks
    ;;
  remove-sdk)
    rm -rf "${DOTNET_ROOT:?}/sdk/$version"
    log "SDK kaldırıldı: ${version}"
    [[ -x $DOTNET_ROOT/dotnet ]] && "$DOTNET_ROOT/dotnet" --list-sdks || true
    ;;
  remove)
    for fw in Microsoft.NETCore.App Microsoft.AspNetCore.App; do
      rm -rf "${DOTNET_ROOT:?}/shared/$fw/$version"
    done
    # Keep host/fxr: it's shared and tiny; the newest one serves all versions.
    log "kaldırıldı: ${version}"
    [[ -x $DOTNET_ROOT/dotnet ]] && "$DOTNET_ROOT/dotnet" --list-runtimes || true
    ;;
esac
