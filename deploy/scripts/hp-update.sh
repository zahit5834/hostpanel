#!/usr/bin/env bash
# hp-update.sh — update HostPanel itself from a GitHub release, with rollback.
#
#   hp-update.sh start <vX.Y.Z>    start the update in a transient unit and return
#                                  (the panel calls this; the panel gets restarted)
#   hp-update.sh run <vX.Y.Z>      same, but wait and stream the output (update.sh)
#   hp-update.sh apply <vX.Y.Z>    the update itself (only inside hostpanel-update.service)
#   hp-update.sh refresh-vhost     re-render the panel's nginx vhost from config.yaml
#
# Root downloads the release itself from the repository named in the root-owned
# config.yaml and verifies it against the release's SHA256SUMS: a compromised
# panel can only choose which published release gets installed.
#
# apply must not run inside hostpanel.service: "systemctl stop hostpanel" kills
# every process in that cgroup, sudo children included. Hence start/run hand it
# to systemd-run.
#
# Steps: download + sha256 → unpack + version check → copy of the current files
# → stop panel → copy of the DB (new migrations stay reversible) → install →
# start → health check (/healthz = "ok <version>" and still active 10 s later)
# → on failure: stop, restore files and DB, start the old version.
# Progress: /var/log/hostpanel-root/update.log; state: /var/lib/hostpanel-update/status.json.
{
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") start|run|apply <vX.Y.Z> | refresh-vhost"
action=$1
shift

SELF=$(readlink -f "$0")
UPDATE_LOG=${ROOT_LOG_DIR}/update.log
STATUS=${UPDATE_DIR}/status.json
UNIT=hostpanel-update

# write_status STATE STEP REASON — status.json for the panel (0644, no secrets).
write_status() {
  local clean=()
  local a
  for a in "$@"; do
    a=${a//[\"\\]/}
    clean+=("${a//[[:cntrl:]]/ }")
  done
  local finished=""
  [[ ${clean[0]} == running ]] || finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  install -d -o root -g root -m 0755 "$UPDATE_DIR"
  printf '{"id":"%s","from":"%s","to":"%s","state":"%s","step":"%s","reason":"%s","started_at":"%s","finished_at":"%s"}\n' \
    "$ID" "$FROM" "$TO" "${clean[0]}" "${clean[1]}" "${clean[2]}" "$STARTED" "$finished" |
    atomic_write "$STATUS" 0644 root:root
}

panel_listen() {
  local l
  l=$(config_value listen)
  [[ -n $l ]] || l=$PANEL_UPSTREAM
  [[ $l =~ ^127\.0\.0\.1:[0-9]{1,5}$ ]] || die "beklenmeyen listen adresi: ${l}"
  printf '%s\n' "$l"
}

data_dir() {
  local d
  d=$(config_value data_dir)
  [[ -n $d ]] || d=/var/lib/hostpanel
  [[ $d =~ ^/var/lib/[a-z0-9_-]+$ && ! -L $d ]] || die "beklenmeyen data_dir: ${d}"
  printf '%s\n' "$d"
}

# healthy VERSION — /healthz answers "ok VERSION" within 60 s and the service is
# still active 10 s later (a crash loop would otherwise pass the first probe).
healthy() {
  local want="ok $1" url i body
  url="http://$(panel_listen)/healthz"
  for ((i = 0; i < 60; i++)); do
    body=$(curl -fsS --max-time 3 "$url" 2>/dev/null || true)
    [[ $body == "$want" ]] && break
    sleep 1
  done
  [[ $body == "$want" ]] || {
    log "health check: beklenen '${want}', gelen '${body:-yanıt yok}'"
    return 1
  }
  sleep 10
  systemctl is-active --quiet hostpanel || {
    log "health check: servis 10 sn sonra aktif değil"
    return 1
  }
  body=$(curl -fsS --max-time 3 "$url" 2>/dev/null || true)
  [[ $body == "$want" ]]
}

save_rollback() {
  local rb=$UPDATE_DIR/rollback
  rm -rf -- "$rb"
  install -d -o root -g root -m 0700 "$rb" "$rb/db"
  cp -a -- "$HP_OPT/bin" "$HP_OPT/scripts" "$HP_OPT/templates" "$rb/"
  cp -a -- /etc/hostpanel/runtimes "$rb/runtimes"
  cp -a -- "$HP_SUDOERS" "$rb/sudoers"
  cp -a -- "$HP_UNIT" "$rb/hostpanel.service"
  log "mevcut dosyaların kopyası alındı (${rb})"
}

save_db() {
  local dd f
  dd=$(data_dir)
  for f in hostpanel.db hostpanel.db-wal hostpanel.db-shm; do
    [[ -f $dd/$f ]] && cp -a -- "$dd/$f" "$UPDATE_DIR/rollback/db/"
  done
  log "veritabanı kopyalandı ($(du -sh "$UPDATE_DIR/rollback/db" | cut -f1))"
}

restore_rollback() {
  local rb=$UPDATE_DIR/rollback dd f
  dd=$(data_dir)
  systemctl stop hostpanel || true
  install -o root -g root -m 0755 "$rb/bin/hostpanel" "$HP_OPT/bin/.hostpanel.new"
  mv -f -- "$HP_OPT/bin/.hostpanel.new" "$HP_OPT/bin/hostpanel"
  replace_tree "$rb/scripts" "$HP_OPT/scripts"
  replace_tree "$rb/templates" "$HP_OPT/templates"
  rm -rf -- /etc/hostpanel/runtimes.old
  mv -- /etc/hostpanel/runtimes /etc/hostpanel/runtimes.old
  cp -a -- "$rb/runtimes" /etc/hostpanel/runtimes
  rm -rf -- /etc/hostpanel/runtimes.old
  install -o root -g root -m 0440 "$rb/sudoers" "$HP_SUDOERS"
  install -o root -g root -m 0644 "$rb/hostpanel.service" "$HP_UNIT"
  systemctl daemon-reload
  rm -f -- "$dd/hostpanel.db" "$dd/hostpanel.db-wal" "$dd/hostpanel.db-shm"
  for f in "$rb"/db/*; do
    [[ -f $f ]] && cp -a -- "$f" "$dd/"
  done
  log "eski sürümün dosyaları ve veritabanı geri yüklendi"
  systemctl start hostpanel
}

apply() {
  TO=$1
  validate_version "$TO"
  if grep -q '/hostpanel\.service' /proc/self/cgroup; then
    die "apply panel servisinin içinden çalıştırılamaz (start kullanın)"
  fi
  exec 9>/run/hostpanel-update.lock
  flock -n 9 || die "başka bir güncelleme sürüyor"
  root_log_file "$UPDATE_LOG"
  exec > >(tee -a "$UPDATE_LOG") 2>&1

  local repo arch name stage url
  repo=$(config_value update_repo)
  [[ -n $repo ]] || repo=zahit5834/hostpanel
  validate_repo "$repo"
  arch=$(hp_arch)
  ID=$(date -u +%Y%m%dT%H%M%SZ)
  STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  FROM=$("$HP_OPT/bin/hostpanel" version 2>/dev/null || echo unknown)
  FROM=${FROM//[^A-Za-z0-9.+_-]/}
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) güncelleme ${FROM} → ${TO} (${repo}, ${arch})"
  write_status running download ""

  name=hostpanel-${TO}-linux-${arch}
  stage=$UPDATE_DIR/stage
  rm -rf -- "$stage"
  install -d -o root -g root -m 0700 "$stage"
  url=https://github.com/${repo}/releases/download/${TO}
  log "indiriliyor: ${url}/${name}.tar.gz"
  if ! curl -fsSL --proto '=https' --tlsv1.2 --max-time 900 -o "$stage/${name}.tar.gz" "${url}/${name}.tar.gz" ||
    ! curl -fsSL --proto '=https' --tlsv1.2 --max-time 60 -o "$stage/SHA256SUMS" "${url}/SHA256SUMS"; then
    write_status failed download "indirme başarısız"
    die "release indirilemedi"
  fi
  if ! (cd "$stage" && grep -E "^[0-9a-f]{64}  ${name//./\\.}\.tar\.gz$" SHA256SUMS | sha256sum -c --strict -); then
    write_status failed verify "SHA-256 doğrulanamadı"
    die "SHA-256 doğrulanamadı"
  fi
  log "SHA-256 doğrulandı"

  # Only plain files/dirs under the expected top directory.
  if ! archive_ok "$stage/${name}.tar.gz" "$name"; then
    write_status failed verify "arşiv beklenmeyen içerik taşıyor"
    die "arşivde beklenmeyen giriş (link, mutlak yol, ..)"
  fi
  tar -xzf "$stage/${name}.tar.gz" -C "$stage" --no-same-owner --no-same-permissions
  local got
  got=$("$stage/$name/bin/hostpanel" version 2>/dev/null || true)
  if [[ $got != "$TO" ]]; then
    write_status failed verify "paketteki binary sürümü '${got}'"
    die "paketteki binary ${got:-çalışmadı}, beklenen ${TO}"
  fi

  write_status running backup ""
  save_rollback
  log "panel durduruluyor"
  systemctl stop hostpanel
  save_db

  write_status running install ""
  if ! (install_release "$stage/$name"); then
    log "kurulum başarısız; geri dönülüyor"
    restore_rollback
    write_status rolled_back install "kurulum adımı başarısız"
    exit 1
  fi
  "$HP_OPT/scripts/hp-update.sh" refresh-vhost || log "uyarı: panel vhost yenilenemedi (eskisi duruyor)"
  log "yeni sürüm başlatılıyor"
  systemctl start hostpanel || true

  write_status running health ""
  if healthy "$TO"; then
    log "health check başarılı: ${TO} çalışıyor"
    write_status success "done" ""
    rm -rf -- "$stage"
    echo "=== güncelleme tamamlandı: ${FROM} → ${TO}"
    return 0
  fi
  log "health check başarısız; ${FROM} sürümüne geri dönülüyor"
  journalctl -u hostpanel -n 20 --no-pager 2>/dev/null || true
  restore_rollback
  if healthy "$FROM"; then
    write_status rolled_back health "yeni sürüm health check'i geçemedi; ${FROM} geri yüklendi"
    echo "=== geri dönüldü: ${FROM} çalışıyor"
  else
    write_status failed health "geri dönüş sonrası da panel yanıt vermiyor"
    echo "=== HATA: geri dönüş sonrası panel yanıt vermiyor (journalctl -u hostpanel)"
  fi
  exit 1
}

refresh_vhost() {
  [[ -f $HP_VHOST ]] || {
    log "panel vhost yok, atlandı"
    return 0
  }
  local domain port
  domain=$(config_value panel_domain)
  port=$(config_value panel_port)
  [[ -n $port ]] || port=8443
  if [[ -n $domain && -s /etc/letsencrypt/live/$PANEL_CERT_NAME/fullchain.pem ]]; then
    write_panel_vhost domain "$domain" "$port"
  else
    panel_self_signed
    write_panel_vhost ip "" "$port"
  fi
  log "panel vhost yenilendi"
}

case $action in
  start | run)
    [[ $# -eq 1 ]] || die "kullanım: ${action} <vX.Y.Z>"
    validate_version "$1"
    args=(--unit="$UNIT" --collect --quiet --description="HostPanel update to $1")
    [[ $action == run ]] && args+=(--wait --pipe)
    if systemctl is-active --quiet "${UNIT}.service"; then
      die "bir güncelleme zaten çalışıyor"
    fi
    systemd-run "${args[@]}" -- /bin/bash "$SELF" apply "$1"
    [[ $action == start ]] && log "güncelleme başlatıldı: $1 (ilerleme: ${UPDATE_LOG})"
    ;;
  apply)
    [[ $# -eq 1 ]] || die "kullanım: apply <vX.Y.Z>"
    apply "$1"
    ;;
  refresh-vhost)
    [[ $# -eq 0 ]] || die "refresh-vhost argüman almaz"
    refresh_vhost
    ;;
  *)
    die "bilinmeyen işlem: ${action}"
    ;;
esac
exit 0
}
