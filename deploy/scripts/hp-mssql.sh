#!/usr/bin/env bash
# hp-mssql.sh — Docker + SQL Server container for HostPanel.
#
#   hp-mssql.sh install-docker
#       apt-get install docker.io (Ubuntu archive), enable the service.
#   hp-mssql.sh create <image> <memory_mb> <bind 127.0.0.1|0.0.0.0>
#       stdin line 1: sa password, line 2: MSSQL_PID (Express|Developer|product key).
#       Secrets reach docker through a 0600 --env-file (never argv / ps).
#   hp-mssql.sh remove-container      data directory is kept
#   hp-mssql.sh purge                 remove container, move data dir aside (failed installs)
#   hp-mssql.sh start|stop|restart
#   hp-mssql.sh status                key=value lines (docker, container, cpu, mem…)
#   hp-mssql.sh logs <n>
#   hp-mssql.sh firewall <ip|cidr>... UFW allow rules for 1433/tcp (refuses if UFW is inactive)
#   hp-mssql.sh firewall-clear        remove the panel's 1433 rules (no-op without UFW)
#
# The container uses --network host: ports published with -p go through
# Docker's own iptables chain and bypass UFW entirely. With host networking
# SQL Server binds directly on the host (MSSQL_IP_ADDRESS, default 127.0.0.1)
# and UFW rules apply as for any other service.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
check_db_dirs
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") install-docker|create|remove-container|purge|start|stop|restart|status|logs|firewall|firewall-clear …"
action=$1
shift

NAME=hostpanel-mssql
DATA=/var/lib/hostpanel/mssql
MSSQL_UID=10001 # "mssql" user inside the official images
UFW_TAG=hostpanel-mssql

need_docker() { command -v docker >/dev/null || die "Docker kurulu değil"; }
exists() { docker inspect --type container "$NAME" >/dev/null 2>&1; }

ufw_active() { command -v ufw >/dev/null && [[ $(ufw status 2>/dev/null | head -n1) == "Status: active" ]]; }

# Delete the panel's rules one at a time (rule numbers shift after each delete).
ufw_clear() {
  local n
  while n=$(ufw status numbered | grep -F "# ${UFW_TAG}" | head -n1 | sed -E 's/^\[ *([0-9]+)\].*/\1/') && [[ -n $n ]]; do
    [[ $n =~ ^[0-9]+$ ]] || die "ufw çıktısı çözümlenemedi"
    ufw --force delete "$n" >/dev/null
  done
}

case "$action" in
install-docker)
  [[ $# -eq 0 ]] || die "kullanım: install-docker"
  export DEBIAN_FRONTEND=noninteractive
  log "apt-get update"
  apt-get update -q
  log "apt-get install docker.io"
  apt-get install -y -q --no-install-recommends docker.io
  systemctl enable --now docker
  docker version --format 'Docker {{.Server.Version}}'
  ;;

create)
  [[ $# -eq 3 ]] || die "kullanım: create <image> <memory_mb> <bind>"
  image=$1 mem=$2 bind=$3
  validate_mssql_image "$image"
  [[ $mem =~ ^[0-9]{4,5}$ ]] && ((mem >= 2048 && mem <= 65536)) || die "geçersiz bellek: $mem"
  validate_oneof "$bind" 127.0.0.1 0.0.0.0
  IFS= read -r sa_pw || die "stdin: sa şifresi yok"
  IFS= read -r pid || die "stdin: MSSQL_PID yok"
  [[ $sa_pw =~ ^[A-Za-z0-9]{16,64}$ ]] || die "geçersiz sa şifresi biçimi"
  validate_mssql_pid "$pid"
  need_docker
  ! exists || die "container zaten var: $NAME"
  if [[ -n $(ss -Hltn "sport = :1433") ]]; then die "1433 portu başka bir süreç tarafından kullanılıyor"; fi

  [[ -d /var/lib/hostpanel ]] || die "/var/lib/hostpanel yok (panel kurulu mu?)"
  install -d -m 0700 -o "$MSSQL_UID" "$DATA"
  install -d -m 0700 -o "$MSSQL_UID" "$DATA/backup"

  log "docker pull $image"
  docker pull -q "$image"

  envf=$(mktemp /run/hp-mssql-env.XXXXXX)
  trap 'rm -f "$envf"' EXIT
  chmod 600 "$envf"
  {
    echo "ACCEPT_EULA=Y"
    echo "MSSQL_SA_PASSWORD=$sa_pw"
    echo "MSSQL_PID=$pid"
    echo "MSSQL_MEMORY_LIMIT_MB=$mem"
    echo "MSSQL_IP_ADDRESS=$bind"
    echo "MSSQL_TCP_PORT=1433"
    echo "MSSQL_BACKUP_DIR=/var/opt/mssql/backup"
  } >"$envf"
  # Container limit = SQL Server's own limit + headroom for the image's other
  # processes; swap is not allowed (memory-swap = memory).
  cmem=$((mem + 256))
  log "docker run $NAME (network host, ${bind}:1433, memory ${cmem}m)"
  docker run -d --name "$NAME" \
    --network host \
    --restart unless-stopped \
    --memory "${cmem}m" --memory-swap "${cmem}m" \
    --env-file "$envf" \
    -v "$DATA:/var/opt/mssql" \
    --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
    "$image" >/dev/null
  rm -f "$envf"
  log "container başlatıldı"
  ;;

remove-container)
  [[ $# -eq 0 ]] || die "kullanım: remove-container"
  need_docker
  if exists; then
    docker stop -t 30 "$NAME" >/dev/null 2>&1 || true
    docker rm -f "$NAME" >/dev/null
    log "container kaldırıldı (veri korunuyor: $DATA)"
  fi
  ;;

purge)
  [[ $# -eq 0 ]] || die "kullanım: purge"
  if command -v docker >/dev/null && exists; then docker rm -f "$NAME" >/dev/null; fi
  if [[ -d $DATA ]]; then
    dest="$DATA.removed-$(date +%Y%m%d-%H%M%S)"
    mv "$DATA" "$dest"
    log "veri dizini kenara alındı: $dest"
  fi
  ;;

start | restart)
  [[ $# -eq 0 ]] || die "kullanım: $action"
  need_docker
  exists || die "container yok"
  if [[ $action == start ]]; then docker start "$NAME" >/dev/null; else docker restart -t 30 "$NAME" >/dev/null; fi
  log "$action tamam"
  ;;

stop)
  [[ $# -eq 0 ]] || die "kullanım: stop"
  need_docker
  exists || die "container yok"
  docker stop -t 30 "$NAME" >/dev/null
  log "durduruldu"
  ;;

status)
  [[ $# -eq 0 ]] || die "kullanım: status"
  if ! command -v docker >/dev/null; then
    echo "docker=absent"
    exit 0
  fi
  if ! systemctl is-active --quiet docker; then
    echo "docker=inactive"
    exit 0
  fi
  echo "docker=active"
  if ! exists; then
    echo "container=absent"
    exit 0
  fi
  docker inspect --type container -f 'container={{.State.Status}}
started_at={{.State.StartedAt}}
restarts={{.RestartCount}}
oom={{.State.OOMKilled}}
image={{.Config.Image}}' "$NAME"
  if [[ $(docker inspect --type container -f '{{.State.Running}}' "$NAME") == true ]]; then
    docker stats --no-stream --format 'cpu={{.CPUPerc}}
mem={{.MemUsage}}
mem_pct={{.MemPerc}}' "$NAME"
  fi
  ;;

logs)
  [[ $# -eq 1 && $1 =~ ^[0-9]{1,4}$ ]] && (($1 >= 1)) || die "kullanım: logs <1-9999>"
  need_docker
  exists || die "container yok"
  docker logs --tail "$1" --timestamps "$NAME" 2>&1
  ;;

firewall)
  [[ $# -ge 1 && $# -le 50 ]] || die "kullanım: firewall <ip|cidr>... (1-50)"
  for ip in "$@"; do validate_ip_or_cidr "$ip"; done
  command -v ufw >/dev/null || die "ufw kurulu değil"
  # The panel never enables UFW itself: doing so without an SSH rule would
  # cut the admin off. Enabling UFW is the admin's (tested) decision.
  ufw_active || die "UFW etkin değil; dış erişim yalnızca UFW etkinken açılabilir (1433 aksi halde tüm internete açık olurdu)"
  ufw_clear
  for ip in "$@"; do
    ufw allow proto tcp from "$ip" to any port 1433 comment "$UFW_TAG" >/dev/null
    log "izin: $ip → 1433/tcp"
  done
  ;;

firewall-clear)
  [[ $# -eq 0 ]] || die "kullanım: firewall-clear"
  if ufw_active; then
    ufw_clear
    log "1433 kuralları kaldırıldı"
  fi
  ;;

*)
  die "bilinmeyen işlem: $action"
  ;;
esac
