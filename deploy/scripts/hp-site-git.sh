#!/usr/bin/env bash
# hp-site-git.sh — git deploy steps for a site.
# Usage:
#   hp-site-git.sh keygen <domain>                     new ed25519 deploy key, prints the public key
#   hp-site-git.sh info <domain>                       public key + key/host fingerprints
#   hp-site-git.sh reset-hostkey <domain>
#   hp-site-git.sh remove <domain>
#   hp-site-git.sh fetch <domain> <site_user> <branch> <release>     (repo URL on stdin)
#   hp-site-git.sh build <domain> <site_user> <release> <runtime> <version> <timeout> <memMB> <cpu%>  (command on stdin)
#   hp-site-git.sh release <domain> <site_user> <release> <outdir> [persistent_dir...]
#   hp-site-git.sh clean <domain> <release>
# The private key stays in /etc/hostpanel/git/<domain>/ (root 0600); during a
# fetch it is copied into a root-owned directory the site user can only read.
# git, tar and the build run as the site user.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
action=${1:-}
validate_oneof "$action" keygen info reset-hostkey remove fetch build release clean
GIT_RUN=/run/hostpanel-git

as_user() { runuser -u "$user" -- env HOME="$dir/.home" "$@"; }

owner_check() {
  [[ -d $dir ]] || die "site dizini yok: ${dir}"
  [[ $(stat -c %U "$dir") == "$user" ]] || die "site dizini sahibi beklenen kullanıcı değil"
  [[ ! -L $dir/.home ]] || die "${dir}/.home symlink olamaz"
  [[ -d $dir/.home ]] || install -d -o "$user" -g "$user" -m 0700 "$dir/.home"
}

keydir() {
  validate_domain "$1"
  ensure_etc_dir
  install -d -o root -g root -m 0700 "$GIT_KEY_ROOT"
  kd="$GIT_KEY_ROOT/$1"
  [[ ! -L $kd ]] || die "${kd} symlink olamaz"
  install -d -o root -g root -m 0700 "$kd"
}

case $action in
  keygen)
    [[ $# -eq 2 ]] || die "kullanım: $(basename "$0") keygen <domain>"
    keydir "$2"
    rm -f "$kd/id_ed25519" "$kd/id_ed25519.pub"
    ssh-keygen -q -t ed25519 -N '' -C "hostpanel-deploy@$2" -f "$kd/id_ed25519" </dev/null
    chmod 0600 "$kd/id_ed25519"
    cat "$kd/id_ed25519.pub"
    ;;
  info)
    [[ $# -eq 2 ]] || die "kullanım: $(basename "$0") info <domain>"
    keydir "$2"
    [[ -f $kd/id_ed25519.pub ]] && echo "pub=$(cat "$kd/id_ed25519.pub")"
    [[ -f $kd/id_ed25519.pub ]] && echo "fp=$(ssh-keygen -lf "$kd/id_ed25519.pub" | awk '{print $2}')"
    if [[ -f $kd/known_hosts ]]; then
      ssh-keygen -lf "$kd/known_hosts" 2>/dev/null | awk '{print "host=" $3 " " $2 " " $4}'
    fi
    ;;
  reset-hostkey)
    [[ $# -eq 2 ]] || die "kullanım: $(basename "$0") reset-hostkey <domain>"
    keydir "$2"
    rm -f "$kd/known_hosts"
    log "host anahtarı kaydı silindi"
    ;;
  remove)
    [[ $# -eq 2 ]] || die "kullanım: $(basename "$0") remove <domain>"
    validate_domain "$2"
    kd="$GIT_KEY_ROOT/$2"
    [[ ! -L $kd ]] || die "${kd} symlink olamaz"
    rm -rf -- "$kd"
    log "deploy anahtarı silindi"
    ;;

  fetch)
    [[ $# -eq 5 ]] || die "kullanım: $(basename "$0") fetch <domain> <site_user> <branch> <release>"
    dir=$(site_dir "$2")
    user=$3 branch=$4 release=$5
    validate_site_user "$user"
    validate_git_branch "$branch"
    validate_release "$release"
    url=$(head -c 301)
    validate_git_url "$url"
    owner_check
    keydir "$2"
    command -v git >/dev/null || die "git kurulu değil"

    # Root-owned scratch dir: the site user can read the key but cannot plant
    # symlinks or swap files (the directory is not writable for it).
    short=${user#site_}
    install -d -o root -g root -m 0711 "$GIT_RUN"
    tmp="$GIT_RUN/$short"
    rm -rf --one-file-system -- "$tmp"
    install -d -o root -g "$user" -m 0750 "$tmp"
    trap 'rm -rf --one-file-system -- "$tmp"' EXIT
    if [[ -f $kd/id_ed25519 ]]; then
      install -o "$user" -g "$user" -m 0400 "$kd/id_ed25519" "$tmp/key"
    else
      install -o "$user" -g "$user" -m 0400 /dev/null "$tmp/key"
    fi
    if [[ -f $kd/known_hosts && ! -L $kd/known_hosts ]]; then
      install -o "$user" -g "$user" -m 0600 "$kd/known_hosts" "$tmp/known_hosts"
    else
      install -o "$user" -g "$user" -m 0600 /dev/null "$tmp/known_hosts"
    fi
    sshcmd="ssh -i $tmp/key -o IdentitiesOnly=yes -o UserKnownHostsFile=$tmp/known_hosts -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=20"
    gitc=(git -c protocol.allow=never -c protocol.https.allow=always -c protocol.ssh.allow=always -c core.hooksPath=/dev/null)

    cache="$dir/.git-cache"
    [[ ! -L $cache ]] || die "${cache} symlink olamaz"
    if [[ ! -d $cache ]]; then
      as_user "${gitc[@]}" init -q --bare "$cache"
    fi
    as_user "${gitc[@]}" -C "$cache" config remote.origin.url "$url"
    log "fetch: ${url} (${branch})"
    if ! as_user GIT_SSH_COMMAND="$sshcmd" GIT_TERMINAL_PROMPT=0 timeout 600 \
      "${gitc[@]}" -C "$cache" fetch --prune --no-tags --depth 50 origin "+refs/heads/${branch}:refs/remotes/origin/${branch}"; then
      die "fetch başarısız (deploy key repo'ya eklendi mi? host anahtarı değişti mi?)"
    fi
    # Persist a newly accepted host key (only well-formed lines).
    if [[ -f $tmp/known_hosts && ! -L $tmp/known_hosts ]]; then
      head -c 65536 "$tmp/known_hosts" | grep -E '^[^ ]+ (ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-[a-z0-9@.-]+) [A-Za-z0-9+/=]+$' \
        | atomic_write "$kd/known_hosts" 0600 root:root || true
    fi
    commit=$(as_user "${gitc[@]}" -C "$cache" rev-parse --verify "refs/remotes/origin/${branch}^{commit}")
    [[ $commit =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "commit bulunamadı"
    subject=$(as_user "${gitc[@]}" -C "$cache" log -1 --format=%s "$commit" | head -c 200 | tr -d '\000-\037')
    echo "commit=${commit}"
    echo "subject=${subject}"

    build="$dir/build"
    [[ ! -L $build ]] || die "${build} symlink olamaz"
    [[ -d $build ]] || install -d -o "$user" -g www-data -m 2750 "$build"
    out="$build/$release"
    [[ ! -e $out ]] || die "derleme dizini zaten var: ${release}"
    as_user mkdir "$out"
    as_user "${gitc[@]}" -C "$cache" archive --format=tar "$commit" | as_user tar -x -C "$out"
    log "kaynak hazır: build/${release} ($(du -sh "$out" | cut -f1))"
    ;;

  build)
    [[ $# -eq 9 ]] || die "kullanım: $(basename "$0") build <domain> <site_user> <release> <runtime> <version> <timeout> <memMB> <cpu%>"
    dir=$(site_dir "$2")
    user=$3 release=$4 rt=$5 ver=$6
    validate_site_user "$user"
    validate_release "$release"
    validate_limits "$7" "$8" "$9"
    owner_check
    work="$dir/build/$release"
    [[ -d $work && ! -L $work && ! -L $dir/build ]] || die "derleme dizini yok: ${release}"
    pathpre=$(runtime_path "$rt" "$ver")
    cmd=$(read_user_command)
    log "build: ${cmd}"
    run_as_site "$dir" "$user" "hp-build-${user#site_}" "$7" "$8" "$9" "$work" "$pathpre" "$cmd"
    ;;

  release)
    [[ $# -ge 5 ]] || die "kullanım: $(basename "$0") release <domain> <site_user> <release> <outdir> [dir...]"
    dir=$(site_dir "$2")
    user=$3 release=$4 outdir=$5
    shift 5
    validate_site_user "$user"
    validate_release "$release"
    validate_outdir "$outdir"
    for d in "$@"; do validate_reldir "$d"; done
    owner_check
    work="$dir/build/$release"
    [[ -d $work && ! -L $work && ! -L $dir/build ]] || die "derleme dizini yok: ${release}"
    src=$(validate_path_under "$work/$outdir" "$work")
    [[ -d $src && ! -L $work/$outdir ]] || die "çıktı dizini bulunamadı: ${outdir}"
    rel="$dir/releases/$release"
    [[ ! -e $rel ]] || die "sürüm zaten var: ${release}"
    runuser -u "$user" -- mv -T -- "$src" "$rel"
    [[ $src == "$work" ]] || rm -rf --one-file-system -- "$work"
    [[ -d $rel && ! -L $rel ]] || die "sürüm dizini oluşturulamadı"
    finalize_release "$dir" "$user" "$rel" "$@"
    ;;

  clean)
    [[ $# -eq 3 ]] || die "kullanım: $(basename "$0") clean <domain> <release>"
    dir=$(site_dir "$2")
    validate_release "$3"
    [[ ! -L $dir/build ]] || die "${dir}/build symlink olamaz"
    rm -rf --one-file-system -- "$dir/build/$3"
    ;;
esac
