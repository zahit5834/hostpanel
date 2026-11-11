#!/usr/bin/env bash
# hp-backup.sh — site backups (local + Google Drive via rclone).
#
#   create <domain> <name> <components> <release|-> [db...]
#       stdin: config.json (written by the panel). Packs into
#       /var/backups/hostpanel/<domain>/<name>/ (root 0700): files.tar.zst
#       (active release + shared/), db-<db>.bak (moved from the MSSQL volume,
#       written there by the panel's BACKUP DATABASE), db-pg-<db>.dump (db
#       argument pg:<db>; written by hp-pg.sh dump), config.json, nginx.conf,
#       ssl.tar.zst, SHA256SUMS, manifest.json. Prints size=<bytes>.
#   delete <domain> <name>               local copy (+ leftover DB staging files)
#   verify <domain> <name>               SHA256SUMS check
#   read-config <domain> <name>          config.json to stdout
#   rclone-install                       pinned official zip, SHA-256 checked
#   remote-config <drive-oauth|drive-sa> <root_folder> <crypt 0|1> <shared_drive_id|->
#       stdin (5 lines): crypt password|-, crypt salt|-, client_id|-, client_secret|-, token/SA JSON
#   remote-test <server>
#   upload <server> <domain> <name> <bwlimit|0>
#   remote-list <server>                 "<domain>/<name>/" lines
#   remote-manifest <server> <domain> <name>
#   remote-delete <server> <domain> <name>
#   download <server> <domain> <name>    then verify
#   restore-files <src_domain> <name> <domain> <site_user> <release> [persistent_dir...]
#       unpacks files.tar.zst AS THE SITE USER into releases/<release> and
#       replaces shared/; activation is hp-site-deploy.sh activate.
#   stage-db <domain> <name> <db> <staged.bak>   copy into the MSSQL volume
#   stage-upload <upload.bak> <staged.bak>       uploaded .bak into the MSSQL volume
#   unstage <staged.bak>
#
# rclone runs as root with /etc/hostpanel/rclone.conf (0600): backups are
# root-only and the Drive token never becomes readable by the panel user.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
check_db_dirs
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") create|delete|verify|read-config|rclone-install|remote-config|remote-test|upload|remote-list|remote-manifest|remote-delete|download|restore-files|stage-db|stage-upload|unstage …"
action=$1
shift

RCLONE_VERSION=v1.75.2
declare -A RCLONE_SHA256=(
  [amd64]=349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702
  [arm64]=7e1e8d69654941b7b7df84ee74c5f7fb09cce7d5496947fb7bf16b55ff427d10
)
MSSQL_UID=10001
LOW=(nice -n 10 ionice -c3)

rclone_() {
  [[ -x $RCLONE_BIN ]] || die "rclone kurulu değil"
  [[ -f $RCLONE_CONF ]] || die "uzak hedef yapılandırılmamış"
  root_log_file "$RCLONE_LOG"
  # stderr (rclone's log, "YYYY/MM/DD hh:mm:ss LEVEL : …") goes to the job log
  # and is mirrored to rclone.log; the exit status stays rclone's.
  "${LOW[@]}" "$RCLONE_BIN" --config "$RCLONE_CONF" "$@" 2> >(tee -a "$RCLONE_LOG" >&2)
}


case $action in
  create)
    [[ $# -ge 4 ]] || die "kullanım: create <domain> <name> <components> <release|-> [db...]"
    [[ $1 != _mail ]] || die "posta yedekleri hp-mail.sh backup ile alınır"
    out=$(backup_dir "$1" "$2")
    domain=$1 name=$2 comps=$3 release=$4
    shift 4
    validate_components "$comps"
    # db arguments: <name> (MSSQL .bak) or pg:<name> (PostgreSQL .dump)
    for db in "$@"; do validate_name "${db#pg:}" 63; done
    [[ ! -e $out ]] || die "yedek zaten var: ${out}"
    install -d -o root -g root -m 0700 "$BACKUP_ROOT" "$BACKUP_ROOT/$domain"
    install -d -o root -g root -m 0700 "$out"
    done_ok=0
    cleanup() {
      local db
      for db in "${dbs[@]}"; do
        if [[ $db == pg:* ]]; then rm -f -- "$PG_HOST_BACKUP/hpbk-$name-${db#pg:}.dump"; else rm -f -- "$MSSQL_HOST_BACKUP/hpbk-$name-$db.bak"; fi
      done
      ((done_ok)) || rm -rf --one-file-system -- "$out"
    }
    dbs=("$@")
    trap cleanup EXIT
    read_stdin_limited "$out/config.json" 205000
    chmod 0600 "$out/config.json"

    if [[ ,$comps, == *,files,* ]]; then
      [[ $release != - ]] || die "files bileşeni için sürüm gerekli"
      validate_release "$release"
      dir=$(site_dir "$domain")
      [[ -d $dir/releases/$release && ! -L $dir/releases/$release ]] || die "aktif sürüm bulunamadı: ${release}"
      paths=("releases/$release")
      if [[ -d $dir/shared && ! -L $dir/shared ]]; then paths+=(shared); fi
      command -v zstd >/dev/null || die "zstd kurulu değil"
      log "dosyalar paketleniyor (${release} + shared/)…"
      "${LOW[@]}" tar --zstd -cf "$out/files.tar.zst" -C "$dir" --transform "s,^releases/$release,release,S" "${paths[@]}"
    fi
    if [[ ,$comps, == *,db,* ]]; then
      for db in "${dbs[@]}"; do
        if [[ $db == pg:* ]]; then
          src=$PG_HOST_BACKUP/hpbk-$name-${db#pg:}.dump dst=$out/db-pg-${db#pg:}.dump
        else
          src=$MSSQL_HOST_BACKUP/hpbk-$name-$db.bak dst=$out/db-$db.bak
        fi
        [[ -f $src && ! -L $src ]] || die "veritabanı yedeği bulunamadı: ${src}"
        mv -f -- "$src" "$dst"
        chown root:root "$dst"
        chmod 0600 "$dst"
        log "veritabanı: ${db} ($(du -h "$dst" | cut -f1))"
      done
    fi
    if [[ ,$comps, == *,config,* ]]; then
      conf=/etc/nginx/sites-available/hp-$domain.conf
      if [[ -f $conf ]]; then install -o root -g root -m 0600 "$conf" "$out/nginx.conf"; fi
    fi
    if [[ ,$comps, == *,ssl,* ]]; then
      ssl=()
      for p in "etc/hostpanel/ssl/$domain" "etc/letsencrypt/live/$domain" "etc/letsencrypt/archive/$domain" "etc/letsencrypt/renewal/$domain.conf"; do
        if [[ -e /$p ]]; then ssl+=("$p"); fi
      done
      if ((${#ssl[@]})); then
        "${LOW[@]}" tar --zstd -cf "$out/ssl.tar.zst" -C / "${ssl[@]}"
        log "SSL dosyaları paketlendi"
      else
        log "SSL: sertifika dosyası yok, atlandı"
      fi
    fi
    chmod 0600 "$out"/*
    (cd "$out" && find . -mindepth 1 -maxdepth 1 -type f ! -name SHA256SUMS ! -name manifest.json -printf '%f\n' | sort |
      xargs -r sha256sum >SHA256SUMS)
    chmod 0600 "$out/SHA256SUMS"
    size=$(du -sb "$out" | cut -f1)
    {
      printf '{"version":1,"domain":"%s","name":"%s","components":[' "$domain" "$name"
      IFS=, read -ra cl <<<"$comps"
      first=1
      for c in "${cl[@]}"; do
        ((first)) || printf ','
        printf '"%s"' "$c"
        first=0
      done
      printf '],"size":%d,"created":"%s"}\n' "$size" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >"$out/manifest.json"
    chmod 0600 "$out/manifest.json"
    done_ok=1
    log "yedek hazır: ${out} ($(du -sh "$out" | cut -f1))"
    echo "size=$size"
    ;;

  delete)
    [[ $# -eq 2 ]] || die "kullanım: delete <domain> <name>"
    out=$(backup_dir "$1" "$2")
    rm -f -- "$MSSQL_HOST_BACKUP"/hpbk-"$2"-*.bak "$PG_HOST_BACKUP"/hpbk-"$2"-*.dump
    if [[ -e $out ]]; then
      [[ ! -L $out ]] || die "symlink olamaz"
      rm -rf --one-file-system -- "$out"
      log "silindi: ${out}"
    fi
    rmdir --ignore-fail-on-non-empty "$BACKUP_ROOT/$1" 2>/dev/null || true
    ;;

  verify)
    [[ $# -eq 2 ]] || die "kullanım: verify <domain> <name>"
    out=$(backup_dir "$1" "$2")
    [[ -d $out && ! -L $out ]] || die "yedek bulunamadı: ${out}"
    check_sums "$out"
    ;;

  read-config)
    [[ $# -eq 2 ]] || die "kullanım: read-config <domain> <name>"
    out=$(backup_dir "$1" "$2")
    [[ -f $out/config.json && ! -L $out/config.json ]] || die "config.json yok"
    cat -- "$out/config.json"
    ;;

  rclone-install)
    [[ $# -eq 0 ]] || die "kullanım: rclone-install"
    arch=$(dpkg --print-architecture)
    sum=${RCLONE_SHA256[$arch]:-}
    [[ -n $sum ]] || die "desteklenmeyen mimari: ${arch}"
    command -v unzip >/dev/null || die "unzip kurulu değil (apt install unzip)"
    command -v curl >/dev/null || die "curl kurulu değil"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    file=rclone-$RCLONE_VERSION-linux-$arch.zip
    log "indiriliyor: https://downloads.rclone.org/$RCLONE_VERSION/$file"
    curl -fsSL --proto '=https' --max-time 600 -o "$tmp/$file" "https://downloads.rclone.org/$RCLONE_VERSION/$file"
    echo "$sum  $tmp/$file" | sha256sum --quiet -c - || die "SHA-256 tutmuyor, kurulum iptal"
    log "SHA-256 doğrulandı"
    unzip -q "$tmp/$file" -d "$tmp/x"
    bin=$tmp/x/rclone-$RCLONE_VERSION-linux-$arch/rclone
    [[ -f $bin ]] || die "zip içinde rclone bulunamadı"
    install -o root -g root -m 0755 "$bin" "$RCLONE_BIN"
    log "kuruldu: $("$RCLONE_BIN" version | head -n1)"
    ;;

  remote-config)
    [[ $# -eq 4 ]] || die "kullanım: remote-config <drive-oauth|drive-sa> <root_folder> <crypt 0|1> <shared_id|->"
    mode=$1 root=$2 crypt=$3 shared=$4
    validate_oneof "$mode" drive-oauth drive-sa
    validate_folder "$root"
    validate_oneof "$crypt" 0 1
    validate_shared_id "$shared"
    [[ -x $RCLONE_BIN ]] || die "rclone kurulu değil"
    { IFS= read -r pw && IFS= read -r salt && IFS= read -r cid && IFS= read -r csec && IFS= read -r -n 32768 js; } ||
      die "stdin eksik"
    [[ -n $js && $js == "{"*"}" && $js != *[[:cntrl:]]* ]] || die "JSON tek satır olmalı"
    if [[ $crypt == 1 ]]; then
      [[ $pw =~ ^[A-Za-z0-9]{32}$ && $salt =~ ^[A-Za-z0-9]{32}$ ]] || die "geçersiz crypt anahtarı"
    fi
    [[ $cid == - || $cid =~ ^[A-Za-z0-9._-]{1,200}\.apps\.googleusercontent\.com$ ]] || die "geçersiz client_id"
    [[ $csec == - || $csec =~ ^[A-Za-z0-9_-]{10,100}$ ]] || die "geçersiz client_secret"
    ensure_etc_dir
    {
      echo "[hpdrive]"
      echo "type = drive"
      echo "scope = drive"
      if [[ $cid != - ]]; then echo "client_id = $cid"; fi
      if [[ $csec != - ]]; then echo "client_secret = $csec"; fi
      if [[ $shared != - ]]; then echo "team_drive = $shared"; fi
      if [[ $mode == drive-oauth ]]; then
        echo "token = $js"
      else
        echo "service_account_file = $RCLONE_SA"
      fi
      echo
      if [[ $crypt == 1 ]]; then
        echo "[hpcrypt]"
        echo "type = crypt"
        echo "remote = hpdrive:$root"
        echo "filename_encryption = standard"
        echo "directory_name_encryption = true"
        echo "password = $(printf '%s' "$pw" | "$RCLONE_BIN" obscure -)"
        echo "password2 = $(printf '%s' "$salt" | "$RCLONE_BIN" obscure -)"
        echo
        echo "[hp]"
        echo "type = alias"
        echo "remote = hpcrypt:"
      else
        echo "[hp]"
        echo "type = alias"
        echo "remote = hpdrive:$root"
      fi
    } | atomic_write "$RCLONE_CONF" 0600 root:root
    if [[ $mode == drive-sa ]]; then
      printf '%s\n' "$js" | atomic_write "$RCLONE_SA" 0600 root:root
    else
      rm -f -- "$RCLONE_SA"
    fi
    log "rclone yapılandırması yazıldı (${mode}, crypt=${crypt})"
    ;;

  remote-test)
    [[ $# -eq 1 ]] || die "kullanım: remote-test <server>"
    validate_server_name "$1"
    probe=hp:$1/.hp-test-$(date +%s)
    log "klasör oluşturuluyor: $1"
    rclone_ mkdir "hp:$1"
    echo "hostpanel $(date -u +%FT%TZ)" | rclone_ rcat "$probe"
    got=$(rclone_ cat "$probe")
    rclone_ deletefile "$probe"
    [[ $got == hostpanel* ]] || die "yazılan dosya geri okunamadı"
    log "yazma/okuma/silme başarılı"
    rclone_ about hpdrive: 2>/dev/null || true
    ;;

  upload)
    [[ $# -eq 4 ]] || die "kullanım: upload <server> <domain> <name> <bwlimit|0>"
    validate_server_name "$1"
    out=$(backup_dir "$2" "$3")
    validate_bwlimit "$4"
    [[ -d $out && ! -L $out ]] || die "yedek bulunamadı: ${out}"
    extra=()
    if [[ $4 != 0 ]]; then extra+=(--bwlimit "$4"); fi
    log "yükleniyor: hp:$1/$2/$3 ($(du -sh "$out" | cut -f1))"
    rclone_ copy "$out" "hp:$1/$2/$3" --stats 30s --stats-one-line -v "${extra[@]}"
    rclone_ check "$out" "hp:$1/$2/$3" --one-way --size-only
    log "yükleme tamam"
    ;;

  remote-list)
    [[ $# -eq 1 ]] || die "kullanım: remote-list <server>"
    validate_server_name "$1"
    rc=0
    rclone_ lsf --dirs-only -R --max-depth 2 "hp:$1" || rc=$?
    # 3 = directory not found: nothing uploaded from this server yet.
    ((rc == 0 || rc == 3)) || exit "$rc"
    ;;

  remote-manifest)
    [[ $# -eq 3 ]] || die "kullanım: remote-manifest <server> <domain> <name>"
    validate_server_name "$1"
    backup_dir "$2" "$3" >/dev/null
    rclone_ cat --head 65536 "hp:$1/$2/$3/manifest.json"
    ;;

  remote-delete)
    [[ $# -eq 3 ]] || die "kullanım: remote-delete <server> <domain> <name>"
    validate_server_name "$1"
    backup_dir "$2" "$3" >/dev/null
    rc=0
    rclone_ purge "hp:$1/$2/$3" || rc=$?
    ((rc == 0 || rc == 3)) || exit "$rc"
    log "Drive'dan silindi: $1/$2/$3"
    ;;

  download)
    [[ $# -eq 3 ]] || die "kullanım: download <server> <domain> <name>"
    validate_server_name "$1"
    out=$(backup_dir "$2" "$3")
    [[ ! -e $out ]] || die "yerel kopya zaten var"
    install -d -o root -g root -m 0700 "$BACKUP_ROOT" "$BACKUP_ROOT/$2"
    tmp=$BACKUP_ROOT/$2/.dl-$3
    rm -rf --one-file-system -- "$tmp"
    install -d -o root -g root -m 0700 "$tmp"
    trap 'rm -rf --one-file-system -- "$tmp"' EXIT
    log "indiriliyor: hp:$1/$2/$3"
    rclone_ copy "hp:$1/$2/$3" "$tmp" --max-depth 1 --stats 30s --stats-one-line -v
    check_sums "$tmp"
    chmod 0600 "$tmp"/*
    mv -T -- "$tmp" "$out"
    trap - EXIT
    log "indirildi: ${out}"
    ;;

  restore-files)
    [[ $# -ge 5 ]] || die "kullanım: restore-files <src_domain> <name> <domain> <site_user> <release> [dir...]"
    [[ $1 != _mail ]] || die "posta yedeği siteye geri yüklenemez"
    src=$(backup_dir "$1" "$2")
    dir=$(site_dir "$3")
    expected_user=$4 release=$5
    shift 5
    validate_site_user "$expected_user"
    validate_release "$release"
    for d in "$@"; do validate_reldir "$d"; done
    archive=$src/files.tar.zst
    [[ -f $archive && ! -L $archive ]] || die "yedekte dosya arşivi yok"
    [[ -d $dir ]] || die "site dizini yok: ${dir}"
    user=$(stat -c %U "$dir")
    [[ $user == "$expected_user" ]] || die "site dizini sahibi beklenen kullanıcı değil"
    rel=$dir/releases/$release
    [[ ! -e $rel ]] || die "sürüm zaten var: ${release}"
    stage=$dir/releases/.restore-$release
    rm -rf --one-file-system -- "$stage"
    install -d -o "$user" -g www-data -m 2750 "$stage"
    trap 'rm -rf --one-file-system -- "$stage"' EXIT
    as_user() { runuser -u "$user" -- "$@"; }

    log "arşiv açılıyor ($(du -h "$archive" | cut -f1))…"
    # root opens the file; tar itself runs as the site user.
    "${LOW[@]}" runuser -u "$user" -- tar --zstd -xf - -C "$stage" --no-same-owner --no-same-permissions <"$archive" ||
      die "arşiv açılamadı"
    [[ -d $stage/release && ! -L $stage/release ]] || die "arşivde release/ yok"
    as_user mv -T -- "$stage/release" "$rel"
    if [[ -d $stage/shared && ! -L $stage/shared ]]; then
      if [[ -e $dir/shared ]]; then
        as_user mv -T -- "$dir/shared" "$stage/shared.old"
      fi
      as_user mv -T -- "$stage/shared" "$dir/shared"
      log "shared/ yedektekiyle değiştirildi"
    fi
    for d in "$@"; do
      as_user mkdir -p -- "$dir/shared/$d"
      as_user rm -rf -- "${rel:?}/$d"
      as_user mkdir -p -- "$(dirname "$rel/$d")"
      as_user ln -s -- "$dir/shared/$d" "$rel/$d"
    done
    as_user chmod -R u+rwX,g+rX,g-w,o-rwx -- "$rel"
    log "sürüm hazır: ${release} ($(du -sh "$rel" | cut -f1))"
    ;;

  stage-db)
    [[ $# -eq 4 ]] || die "kullanım: stage-db <domain> <name> <db> <staged.bak>"
    src=$(backup_dir "$1" "$2")
    validate_name "$3" 63
    validate_staged_bak "$4"
    f=$src/db-$3.bak
    [[ -f $f && ! -L $f ]] || die "yedekte veritabanı yok: $3"
    [[ -d $MSSQL_HOST_BACKUP ]] || die "MSSQL yedek dizini yok"
    install -o "$MSSQL_UID" -g root -m 0600 "$f" "$MSSQL_HOST_BACKUP/$4"
    log "hazırlandı: $4"
    ;;

  stage-upload)
    [[ $# -eq 2 ]] || die "kullanım: stage-upload <upload.bak> <staged.bak>"
    f=$(validate_path_under "$1" "$UPLOAD_DIR")
    [[ $(basename "$f") =~ ^import-[0-9]+\.bak$ ]] || die "geçersiz yükleme dosyası"
    [[ -f $f && ! -L $f ]] || die "yükleme bulunamadı"
    validate_staged_bak "$2"
    [[ -d $MSSQL_HOST_BACKUP ]] || die "MSSQL yedek dizini yok"
    install -o "$MSSQL_UID" -g root -m 0600 "$f" "$MSSQL_HOST_BACKUP/$2"
    log "hazırlandı: $2 ($(du -h "$f" | cut -f1))"
    ;;

  unstage)
    [[ $# -eq 1 ]] || die "kullanım: unstage <staged.bak>"
    validate_staged_bak "$1"
    rm -f -- "$MSSQL_HOST_BACKUP/$1"
    ;;

  *)
    die "bilinmeyen işlem: ${action}"
    ;;
esac
