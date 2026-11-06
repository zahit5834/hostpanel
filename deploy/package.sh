#!/usr/bin/env bash
# package.sh VERSION ARCH BINARY OUTDIR — build the release tarball
#   OUTDIR/hostpanel-VERSION-linux-ARCH.tar.gz
# containing hostpanel-VERSION-linux-ARCH/{bin/hostpanel, deploy/…, install.sh,
# update.sh, uninstall.sh, VERSION}. Run from the repository root (make dist).
set -euo pipefail

[[ $# -eq 4 ]] || {
  echo "kullanım: $0 VERSION ARCH BINARY OUTDIR" >&2
  exit 2
}
v=$1 arch=$2 bin=$3 out=$4
[[ $v =~ ^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || {
  echo "sürüm vX.Y.Z olmalı: $v" >&2
  exit 2
}
[[ $arch == amd64 || $arch == arm64 ]] || {
  echo "mimari amd64|arm64: $arch" >&2
  exit 2
}

name=hostpanel-${v}-linux-${arch}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
d=$tmp/$name
mkdir -p "$d/bin" "$d/deploy"
install -m 0755 "$bin" "$d/bin/hostpanel"
cp -R deploy/scripts deploy/templates deploy/runtimes deploy/sudoers deploy/systemd "$d/deploy/"
cp deploy/config.example.yaml "$d/deploy/"
# Tests stay in the repository.
rm -f "$d"/deploy/scripts/test_*.sh "$d"/deploy/scripts/testdata_*
install -m 0755 install.sh update.sh uninstall.sh "$d/"
echo "$v" >"$d/VERSION"
find "$d" -type d -exec chmod 0755 {} +
find "$d" -type f ! -name '*.sh' ! -path '*/bin/*' -exec chmod 0644 {} +
find "$d" -type f \( -name '*.sh' -o -path '*/bin/*' \) -exec chmod 0755 {} +
mtime=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}
tar --owner=0 --group=0 --numeric-owner --sort=name --mtime="@${mtime}" -czf "$out/${name}.tar.gz" -C "$tmp" "$name"
echo "$out/${name}.tar.gz"
