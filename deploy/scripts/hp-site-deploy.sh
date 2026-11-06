#!/usr/bin/env bash
# hp-site-deploy.sh — release management for a site.
# Usage:
#   hp-site-deploy.sh extract  <domain> <site_user> <upload.zip> <release> [persistent_dir...]
#   hp-site-deploy.sh activate <domain> <release>
#   hp-site-deploy.sh prune    <domain> <keep>
# The zip is extracted AS THE SITE USER (runuser), so zip-slip or symlink
# tricks inside an archive can never write outside what that user may write.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
action=${1:-}
validate_oneof "$action" extract activate prune
PLACEHOLDER=00000000-000000

as_user() { runuser -u "$user" -- "$@"; }

site_owner_check() {
  [[ -d $dir ]] || die "site dizini yok: ${dir}"
  user=$(stat -c %U "$dir")
  validate_site_user "$user"
}

case $action in
  extract)
    [[ $# -ge 5 ]] || die "kullanım: $(basename "$0") extract <domain> <site_user> <upload.zip> <release> [dir...]"
    dir=$(site_dir "$2")
    expected_user=$3 upload=$4 release=$5
    shift 5
    validate_site_user "$expected_user"
    site_owner_check
    [[ $user == "$expected_user" ]] || die "site dizini sahibi beklenen kullanıcı değil"
    validate_release "$release"
    [[ $release != "$PLACEHOLDER" ]] || die "ayrılmış sürüm adı"
    upload=$(validate_path_under "$upload" "$UPLOAD_DIR")
    [[ -f $upload && ! -L $upload ]] || die "yükleme dosyası bulunamadı: ${upload}"
    for d in "$@"; do validate_reldir "$d"; done
    command -v unzip >/dev/null || die "unzip kurulu değil"

    rel="$dir/releases/$release"
    [[ ! -e $rel ]] || die "sürüm zaten var: ${release}"
    install -d -o "$user" -g www-data -m 2750 "$rel"
    incoming="$dir/releases/.incoming-$release.zip"
    install -o "$user" -g "$user" -m 0600 "$upload" "$incoming"
    trap 'rm -f "$incoming"' EXIT

    log "zip açılıyor ($(du -h "$upload" | cut -f1))…"
    if ! as_user unzip -q -o "$incoming" -d "$rel"; then
      rm -rf --one-file-system -- "$rel"
      die "zip açılamadı"
    fi

    # A zip with a single top-level folder (e.g. "publish/") is flattened.
    mapfile -t entries < <(find "$rel" -mindepth 1 -maxdepth 1)
    if [[ ${#entries[@]} -eq 1 && -d ${entries[0]} && ! -L ${entries[0]} ]]; then
      only=${entries[0]}
      log "tek klasör algılandı ($(basename "$only")/), içerik köke taşınıyor"
      as_user find "$only" -mindepth 1 -maxdepth 1 -exec mv -t "$rel" -- {} +
      as_user rmdir "$only"
    fi

    finalize_release "$dir" "$user" "$rel" "$@"
    ;;

  activate)
    [[ $# -eq 3 ]] || die "kullanım: $(basename "$0") activate <domain> <release>"
    dir=$(site_dir "$2")
    release=$3
    validate_release "$release"
    site_owner_check
    rel="$dir/releases/$release"
    [[ -d $rel && ! -L $rel ]] || die "sürüm bulunamadı: ${release}"
    # Atomic switch: build the new symlink beside, then rename over "current".
    as_user ln -sfn "releases/$release" "$dir/.current.tmp"
    as_user mv -fT "$dir/.current.tmp" "$dir/current"
    log "aktif sürüm: ${release}"
    ;;

  prune)
    [[ $# -eq 3 ]] || die "kullanım: $(basename "$0") prune <domain> <keep>"
    dir=$(site_dir "$2")
    keep=$3
    [[ $keep =~ ^[0-9]{1,2}$ ]] && ((keep >= 1)) || die "geçersiz keep: ${keep}"
    site_owner_check
    current=$(basename "$(readlink "$dir/current")")
    n=0
    while IFS= read -r r; do
      [[ $r == "$current" || $r == "$PLACEHOLDER" ]] && continue
      n=$((n + 1))
      if ((n > keep)); then
        rm -rf --one-file-system -- "${dir:?}/releases/$r"
        log "eski sürüm silindi: ${r}"
      fi
    done < <(find "$dir/releases" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | grep -E '^[0-9]{8}-[0-9]{6}$' | sort -r)
    ;;
esac
