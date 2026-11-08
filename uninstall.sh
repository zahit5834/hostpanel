#!/usr/bin/env bash
# HostPanel uninstaller.
#
# By default only the panel goes: service, unit, sudoers, /opt/hostpanel, the
# panel's nginx vhost, fail2ban jail and logrotate rule. Sites keep running,
# MSSQL/PostgreSQL keep running, backups stay, UFW rules are not touched, and the panel's
# config/database stay in /etc/hostpanel and /var/lib/hostpanel (re-running
# install.sh brings the panel back as it was).
#
# Each of these needs its own flag AND a typed confirmation:
#   --purge-config      panel database, config, master.key, logs, hostpanel user
#                       (site env/PHP files are kept while sites remain)
#   --delete-sites      all hp-* sites: services, nginx configs, site users, /var/www/sites
#   --delete-databases  the hostpanel-mssql and hostpanel-postgres containers and
#                       their data (all databases!)
#   --delete-backups    /var/backups/hostpanel (local backups; Drive copies are not touched)
set -euo pipefail

PURGE=0 SITES=0 DBS=0 BACKUPS=0

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mUYARI:\033[0m %s\n' "$*" >&2; }
fail() {
  printf '\033[1;31mHATA:\033[0m %s\n' "$*" >&2
  exit 1
}

for a in "$@"; do
  case $a in
    --purge-config) PURGE=1 ;;
    --delete-sites) SITES=1 ;;
    --delete-databases) DBS=1 ;;
    --delete-backups) BACKUPS=1 ;;
    -h | --help)
      sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) fail "bilinmeyen seçenek: $a" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "root olarak çalıştırın (sudo)"
[[ -r /dev/tty ]] || fail "onay için terminal gerekli"

# typed WORD QUESTION — the admin has to type WORD exactly.
typed() {
  local a
  read -r -p "$2 Onaylamak için '$1' yazın: " a </dev/tty
  [[ $a == "$1" ]]
}

typed kaldır "HostPanel paneli kaldırılacak (siteler, veritabanları ve yedekler varsayılan olarak korunur)." || fail "iptal edildi"
if ((SITES)); then
  typed SITELERI-SIL "TÜM siteler (servisler, nginx config'leri, site kullanıcıları, /var/www/sites) silinecek." || fail "iptal edildi"
fi
if ((DBS)); then
  typed VERITABANLARINI-SIL "MSSQL ve PostgreSQL container'ları ve TÜM veritabanları (/var/lib/hostpanel/{mssql,postgres,postgres-backup}) silinecek." || fail "iptal edildi"
fi
if ((BACKUPS)); then
  typed YEDEKLERI-SIL "Yerel yedekler (/var/backups/hostpanel) silinecek; Drive'dakiler kalır." || fail "iptal edildi"
fi
if ((PURGE)); then
  typed AYARLARI-SIL "Panel veritabanı, config, master.key ve loglar silinecek (geri dönüşü yok)." || fail "iptal edildi"
fi

reload_nginx() {
  if nginx -t -q 2>/dev/null; then
    systemctl reload nginx || true
  else
    warn "nginx -t başarısız; nginx yeniden yüklenmedi (nginx -t ile kontrol edin)"
  fi
}

say "Panel durduruluyor"
systemctl stop hostpanel-update.service 2>/dev/null || true
systemctl disable --now hostpanel 2>/dev/null || true
rm -f /etc/systemd/system/hostpanel.service /etc/sudoers.d/hostpanel /etc/logrotate.d/hostpanel
systemctl daemon-reload
rm -rf /opt/hostpanel /var/lib/hostpanel-update
if [[ -e /etc/nginx/sites-available/hostpanel.conf || -L /etc/nginx/sites-enabled/hostpanel.conf ]]; then
  rm -f /etc/nginx/sites-enabled/hostpanel.conf /etc/nginx/sites-available/hostpanel.conf
  reload_nginx
fi
if [[ -f /etc/fail2ban/jail.d/hostpanel.conf ]]; then
  rm -f /etc/fail2ban/jail.d/hostpanel.conf /etc/fail2ban/filter.d/hostpanel.conf
  systemctl restart fail2ban 2>/dev/null || true
fi

if ((SITES)); then
  say "Siteler siliniyor"
  for u in /etc/systemd/system/hp-site-*.service; do
    [[ -e $u ]] || continue
    systemctl disable --now "$(basename "$u")" 2>/dev/null || true
    rm -f "$u"
  done
  systemctl stop 'hp-cron-*' 'hp-build-*' 2>/dev/null || true
  systemctl daemon-reload
  rm -f /etc/nginx/sites-enabled/hp-*.conf /etc/nginx/sites-available/hp-*.conf /etc/nginx/conf.d/hostpanel-maps.conf
  reload_nginx
  while IFS=: read -r name _; do
    [[ $name =~ ^site_[a-z0-9_]+$ ]] && userdel "$name" 2>/dev/null || true
  done </etc/passwd
  rm -rf /var/www/sites /etc/hostpanel/env /etc/hostpanel/php /etc/hostpanel/git /run/hostpanel-git
  warn "Let's Encrypt sertifikaları silinmedi (certbot certificates / certbot delete --cert-name <domain>)"
fi

if ((DBS)); then
  say "MSSQL ve PostgreSQL siliniyor"
  if command -v docker >/dev/null; then
    docker rm -f hostpanel-mssql hostpanel-postgres >/dev/null 2>&1 || true
  fi
  rm -rf /var/lib/hostpanel/mssql /var/lib/hostpanel/postgres /var/lib/hostpanel/postgres-backup
fi

if ((BACKUPS)); then
  say "Yerel yedekler siliniyor"
  rm -rf /var/backups/hostpanel
fi

if ((PURGE)); then
  say "Panel verileri siliniyor"
  rm -f /etc/hostpanel/config.yaml /etc/hostpanel/master.key /etc/hostpanel/rclone.conf /etc/hostpanel/rclone-sa.json
  rm -rf /etc/hostpanel/runtimes /etc/hostpanel/panel-tls /var/log/hostpanel /var/log/hostpanel-root
  # /var/lib/hostpanel: keep the database data unless it was deleted above.
  if [[ -d /var/lib/hostpanel ]]; then
    find /var/lib/hostpanel -mindepth 1 -maxdepth 1 ! -name mssql ! -name postgres ! -name postgres-backup -exec rm -rf {} +
    rmdir /var/lib/hostpanel 2>/dev/null || true
  fi
  rmdir /etc/hostpanel/ssl 2>/dev/null || true
  rmdir /etc/hostpanel 2>/dev/null || true
  userdel hostpanel 2>/dev/null || true
fi

echo
say "HostPanel kaldırıldı."
((SITES)) || echo "    Siteler çalışmaya devam ediyor (hp-site-* servisleri, /var/www/sites)."
((DBS)) || echo "    MSSQL/PostgreSQL container'ları ve veritabanları duruyor."
[[ ! -f /etc/bind/.hostpanel ]] || echo "    DNS sunucusu (BIND) çalışmaya devam ediyor; zone'lar /var/lib/bind/hostpanel (apt purge bind9 ile kaldırılır)."
((BACKUPS)) || echo "    Yerel yedekler: /var/backups/hostpanel"
((PURGE)) || echo "    Panel ayarları: /etc/hostpanel, /var/lib/hostpanel (install.sh ile geri kurulur)."
echo "    UFW kurallarına dokunulmadı; paketler (nginx, certbot, fail2ban…) kaldırılmadı."
