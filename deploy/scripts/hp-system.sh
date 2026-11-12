#!/usr/bin/env bash
# hp-system.sh — operating system maintenance (Faz 11).
#
#   hp-system.sh apt-refresh                      apt-get update
#   hp-system.sh apt-run <security|all> <hold|nohold>
#       security = unattended-upgrade (the distribution's security origin
#       only), all = "apt-get upgrade --with-new-pkgs" (never dist-upgrade,
#       never removes packages, keeps changed config files). hold keeps
#       docker.io/containerd/runc back for this run (a Docker upgrade restarts
#       every container). Runs in its own unit (hostpanel-apt) so that dpkg
#       is never cut by a panel restart; needrestart only lists (mode l).
#   hp-system.sh needrestart                      needrestart -b (services, kernel)
#   hp-system.sh unattended <on|off>              /etc/apt/apt.conf.d/20auto-upgrades
#   hp-system.sh reboot <at +N|HH:MM | cancel>    shutdown -r / shutdown -c
#   hp-system.sh swap-create <MB 1024-16384>      /swapfile, only when there is no swap
#   hp-system.sh service <reload|restart> <nginx|docker|named|fail2ban>
#   hp-system.sh nginx-test | nginx-dump          nginx -t / nginx -T (≤ 1 MB)
#   hp-system.sh sudoers-sum                      sha256 of /etc/sudoers.d/hostpanel (0440 root)
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") apt-refresh|apt-run|needrestart|unattended|reboot|swap-create|service|nginx-test|nginx-dump|sudoers-sum …"
action=$1
shift
SELF=$(readlink -f "$0")
APT_LOG=${ROOT_LOG_DIR}/apt.log
APT_UNIT=hostpanel-apt
AUTO_UPGRADES=/etc/apt/apt.conf.d/20auto-upgrades
HOLD_PKGS=(docker.io containerd runc)
SUDOERS_FILE=/etc/sudoers.d/hostpanel

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1

apt_lock() {
  install -d -o root -g root -m 0700 /run/hostpanel-apt
  exec 8>/run/hostpanel-apt/lock
  flock -n 8 || die "başka bir paket işlemi sürüyor"
}

apt_opts=(-o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

case $action in
  apt-refresh)
    [[ $# -eq 0 ]] || die "kullanım: apt-refresh"
    apt_lock
    apt-get -q "${apt_opts[@]}" update
    ;;

  apt-run)
    [[ $# -eq 2 ]] || die "kullanım: apt-run <security|all> <hold|nohold>"
    validate_oneof "$1" security all
    validate_oneof "$2" hold nohold
    if [[ ${HP_APT_UNIT:-} != 1 ]]; then
      # leave the panel's cgroup: a stop/restart of hostpanel.service must not kill dpkg
      if systemctl is-active --quiet "${APT_UNIT}.service"; then
        die "bir paket güncellemesi zaten çalışıyor"
      fi
      systemctl reset-failed "${APT_UNIT}.service" >/dev/null 2>&1 || true
      exec systemd-run --quiet --unit="$APT_UNIT" --wait --pipe --collect \
        --setenv=HP_APT_UNIT=1 -p KillMode=process -- /bin/bash "$SELF" apt-run "$1" "$2"
    fi
    apt_lock
    root_log_file "$APT_LOG"
    exec > >(tee -a "$APT_LOG") 2>&1
    echo "=== $(date -Is) apt-run $1 $2"
    held=()
    cleanup() {
      local p
      for p in "${held[@]}"; do apt-mark unhold "$p" >/dev/null 2>&1 || true; done
    }
    trap cleanup EXIT
    if [[ $2 == hold ]]; then
      for p in "${HOLD_PKGS[@]}"; do
        [[ $(dpkg-query -W -f='${Status}' "$p" 2>/dev/null) == "install ok installed" ]] || continue
        if [[ $(apt-mark showhold "$p") != "$p" ]]; then
          apt-mark hold "$p" >/dev/null
          held+=("$p")
        fi
      done
      ((${#held[@]} == 0)) || log "bu çalışmada beklemeye alındı: ${held[*]}"
    fi
    apt-get -q "${apt_opts[@]}" update
    if [[ $1 == security ]]; then
      command -v unattended-upgrade >/dev/null || die "unattended-upgrades kurulu değil (sudo apt install unattended-upgrades)"
      unattended-upgrade -v
    else
      apt-get -y -q "${apt_opts[@]}" --with-new-pkgs upgrade
    fi
    if command -v needrestart >/dev/null; then
      echo "--- needrestart"
      needrestart -b -r l 2>/dev/null || true
    fi
    [[ -f /var/run/reboot-required ]] && echo "REBOOT-REQUIRED: 1"
    echo "=== $(date -Is) bitti"
    ;;

  needrestart)
    [[ $# -eq 0 ]] || die "kullanım: needrestart"
    command -v needrestart >/dev/null || {
      echo "NEEDRESTART-MISSING: 1"
      exit 0
    }
    needrestart -b -r l 2>/dev/null || true
    ;;

  unattended)
    [[ $# -eq 1 ]] || die "kullanım: unattended <on|off>"
    validate_oneof "$1" on off
    v=0
    [[ $1 == on ]] && v=1
    [[ ! -L $AUTO_UPGRADES ]] || die "${AUTO_UPGRADES} symlink olamaz"
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "%s";\n' "$v" |
      atomic_write "$AUTO_UPGRADES" 0644 root:root
    log "otomatik güvenlik güncellemeleri: $1"
    ;;

  reboot)
    [[ $# -ge 1 ]] || die "kullanım: reboot <at +N|HH:MM | cancel>"
    case $1 in
      at)
        [[ $# -eq 2 ]] || die "kullanım: reboot at <+N|HH:MM>"
        when=$2
        if [[ $when =~ ^\+([0-9]{1,4})$ ]]; then
          ((BASH_REMATCH[1] >= 1 && BASH_REMATCH[1] <= 1440)) || die "1–1440 dakika"
        elif [[ $when =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
          :
        else
          die "geçersiz zaman: $when (+N dakika ya da SS:DD)"
        fi
        shutdown -r "$when" "HostPanel: planlı yeniden başlatma"
        log "yeniden başlatma planlandı: $when"
        ;;
      cancel)
        [[ $# -eq 1 ]] || die "kullanım: reboot cancel"
        shutdown -c "HostPanel: yeniden başlatma iptal edildi"
        log "planlı yeniden başlatma iptal edildi"
        ;;
      *) die "kullanım: reboot <at +N|HH:MM | cancel>" ;;
    esac
    ;;

  swap-create)
    [[ $# -eq 1 ]] || die "kullanım: swap-create <MB>"
    mb=$1
    [[ $mb =~ ^[0-9]{4,5}$ ]] && ((mb >= 1024 && mb <= 16384)) || die "boyut 1024–16384 MB olmalı"
    [[ -z $(swapon --show --noheadings 2>/dev/null) ]] || die "sunucuda zaten swap var"
    f=/swapfile
    [[ ! -e $f && ! -L $f ]] || die "${f} zaten var"
    avail=$(df --output=avail -k / | tail -n1 | tr -d ' ')
    ((avail / 1024 >= mb + 2048)) || die "diskte yer yok: ${mb} MB + 2048 MB boş alan gerekir"
    umask 077
    if ! fallocate -l "${mb}M" "$f" 2>/dev/null; then
      dd if=/dev/zero of="$f" bs=1M count="$mb" status=none
    fi
    chmod 0600 "$f"
    mkswap "$f" >/dev/null
    if ! swapon "$f"; then
      rm -f -- "$f"
      die "swapon başarısız"
    fi
    have=0
    while read -r dev _; do [[ $dev == "$f" ]] && have=1; done </etc/fstab
    if ((have == 0)); then
      { cat /etc/fstab; printf '%s none swap sw 0 0\n' "$f"; } | atomic_write /etc/fstab 0644 root:root
    fi
    log "swap oluşturuldu: ${f} ${mb} MB"
    ;;

  service)
    [[ $# -eq 2 ]] || die "kullanım: service <reload|restart> <nginx|docker|named|fail2ban>"
    validate_oneof "$1" reload restart
    validate_oneof "$2" nginx docker named fail2ban
    [[ $(systemctl show -p LoadState --value "$2.service" 2>/dev/null) == loaded ]] || die "$2 kurulu değil"
    if [[ $2 == nginx ]]; then
      nginx -t 2>&1 || die "nginx yapılandırması hatalı; ${1} yapılmadı"
    fi
    if [[ $2 == fail2ban && $1 == reload ]]; then
      fail2ban-client -t >/dev/null 2>&1 || die "fail2ban yapılandırması hatalı; reload yapılmadı"
    fi
    systemctl "$1" "$2.service"
    sleep 1
    systemctl is-active --quiet "$2.service" || die "$2 ${1} sonrası çalışmıyor"
    log "$2: $1 tamam"
    ;;

  nginx-test)
    [[ $# -eq 0 ]] || die "kullanım: nginx-test"
    command -v nginx >/dev/null || die "nginx kurulu değil"
    nginx -t 2>&1
    ;;

  nginx-dump)
    [[ $# -eq 0 ]] || die "kullanım: nginx-dump"
    command -v nginx >/dev/null || die "nginx kurulu değil"
    tmp=$(mktemp)
    trap 'rm -f -- "$tmp"' EXIT
    nginx -T >"$tmp" 2>/dev/null || true
    head -c 1048576 "$tmp"
    ;;

  sudoers-sum)
    [[ $# -eq 0 ]] || die "kullanım: sudoers-sum"
    if [[ -f $SUDOERS_FILE && ! -L $SUDOERS_FILE ]]; then
      sha256sum "$SUDOERS_FILE" | awk '{print $1}'
    else
      echo missing
    fi
    ;;

  *)
    die "bilinmeyen işlem: $action"
    ;;
esac
