#!/usr/bin/env bash
# runtimes/node.sh — install/remove a Node.js version under /opt/node/v<X.Y.Z>.
# Called only by hp-runtime.sh (already validated): node.sh install|remove <X.Y.Z>
# Verifies the tarball against nodejs.org's SHASUMS256.txt.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
require_root
action=$1 version=$2
[[ $action == install || $action == remove ]] || die "geçersiz işlem: ${action}"
[[ $version =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}$ ]] || die "Node sürümü X.Y.Z olmalı"
NODE_ROOT=/opt/node

case $(dpkg --print-architecture) in
  amd64) arch=x64 ;;
  arm64) arch=arm64 ;;
  *) die "desteklenmeyen mimari" ;;
esac
target="$NODE_ROOT/v$version"

case $action in
  install)
    [[ ! -e $target ]] || die "zaten kurulu: ${target}"
    base="https://nodejs.org/dist/v${version}"
    file="node-v${version}-linux-${arch}.tar.xz"
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    log "indiriliyor: ${base}/${file}"
    curl -fsSL --retry 3 -o "$work/SHASUMS256.txt" "$base/SHASUMS256.txt"
    expected=$(awk -v f="$file" '$2 == f { print $1 }' "$work/SHASUMS256.txt")
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "SHASUMS256.txt içinde ${file} yok"
    curl -fsSL --retry 3 -o "$work/$file" "$base/$file"
    echo "${expected}  $work/$file" | sha256sum -c --quiet - || die "SHA-256 doğrulaması başarısız"
    log "SHA-256 doğrulandı"
    install -d -o root -g root -m 0755 "$NODE_ROOT"
    mkdir "$work/x"
    tar -xJf "$work/$file" -C "$work/x" --strip-components=1 --no-same-owner
    chown -R root:root "$work/x"
    chmod -R a+rX,go-w "$work/x"
    mv "$work/x" "$target"
    log "kuruldu: $("$target/bin/node" --version) → ${target}"
    ;;
  remove)
    [[ -d $target ]] || die "kurulu değil: ${target}"
    rm -rf --one-file-system -- "$target"
    log "kaldırıldı: ${target}"
    ;;
esac
