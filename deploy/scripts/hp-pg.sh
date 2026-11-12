#!/usr/bin/env bash
# hp-pg.sh — PostgreSQL container for HostPanel (official postgres image).
#
#   hp-pg.sh create <image> <memory_mb> <bind 127.0.0.1|*>
#       docker run + wait + pg_hba + superuser password removed. The init
#       password is generated here and never leaves root.
#   hp-pg.sh remove-container          data directory is kept
#   hp-pg.sh purge                     remove container, move data dir aside (failed installs)
#   hp-pg.sh start|stop|restart
#   hp-pg.sh status                    key=value lines (docker, container, cpu, mem…)
#   hp-pg.sh logs <n>
#   hp-pg.sh hba [ip|cidr...]          rewrite pg_hba.conf (127.0.0.1 + the given addresses), reload
#   hp-pg.sh firewall <ip|cidr>...     UFW allow rules for 5432/tcp (refuses if UFW is inactive)
#   hp-pg.sh firewall-clear
#   hp-pg.sh ready                     wait (≤120 s) until the server accepts connections
#   hp-pg.sh version
#   hp-pg.sh role-create <role>        stdin: password (also resets attributes of an existing role)
#   hp-pg.sh role-password <role>      stdin: password
#   hp-pg.sh role-enable <role> 0|1
#   hp-pg.sh role-drop <role>
#   hp-pg.sh db-create <db> <owner>
#   hp-pg.sh db-drop <db> [backup]     "backup": pg_dump -Fc to $PG_HOST_BACKUP/pre-drop-<db>-<ts>.dump first
#   hp-pg.sh sizes                     <db>=<bytes> lines
#   hp-pg.sh relocate to-new|to-old    (no container) move postgres/ + postgres-backup/ between
#                                      /var/lib/hostpanel and the root-owned /var/lib/hostpanel-db
#   hp-pg.sh dump <db> <file>          pg_dump -Fc → $PG_HOST_BACKUP/<file>.dump (file: hpbk-…)
#   hp-pg.sh restore <db> <owner> backup <domain> <name> <srcdb>
#   hp-pg.sh restore <db> <owner> upload <path>
#       stdin: owner's password. Custom-format dumps only (PGDMP); restored as
#       the owner over TCP (never as superuser) into a temporary database
#       inside one transaction, then swapped in.
#   hp-pg.sh check-dump <path>         uploaded file is a readable custom-format dump
#   hp-pg.sh isolation-test
#
# SQL is written here, never received from the panel: names are validated and
# reach psql as -v variables (:"ident" / :'literal' quoting by psql itself);
# passwords come on stdin and are [A-Za-z0-9] only.
#
# --network host for the same reason as hp-mssql.sh: ports published with -p
# bypass UFW. listen_addresses keeps the server on 127.0.0.1 unless external
# access is enabled (then pg_hba + UFW limit who can connect).
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
check_db_dirs
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") create|remove-container|purge|start|stop|restart|status|logs|hba|firewall|firewall-clear|relocate|ready|version|role-*|db-*|sizes|dump|restore|check-dump|isolation-test …"
action=$1
shift

NAME=hostpanel-postgres
DATA=$(db_path postgres) # mounted at /var/lib/postgresql
STAGE=$DATA/hp-stage             # inside the volume: readable by the container
PG_UID=999                       # "postgres" user of the official image
UFW_TAG=hostpanel-pg
PW_RE='^[A-Za-z0-9]{16,64}$'

need_docker() { command -v docker >/dev/null || die "Docker kurulu değil"; }
exists() { docker inspect --type container "$NAME" >/dev/null 2>&1; }
running() { [[ $(docker inspect --type container -f '{{.State.Running}}' "$NAME" 2>/dev/null) == true ]]; }
need_running() {
  need_docker
  exists || die "PostgreSQL container'ı yok"
  running || die "PostgreSQL container'ı çalışmıyor"
}
ufw_active() { command -v ufw >/dev/null && [[ $(ufw status 2>/dev/null | head -n1) == "Status: active" ]]; }

ufw_clear() {
  local n
  while n=$(ufw status numbered | grep -F "# ${UFW_TAG}" | head -n1 | sed -E 's/^\[ *([0-9]+)\].*/\1/') && [[ -n $n ]]; do
    [[ $n =~ ^[0-9]+$ ]] || die "ufw çıktısı çözümlenemedi"
    ufw --force delete "$n" >/dev/null
  done
}

# psql as the superuser over the container's unix socket (peer auth).
# SQL comes on stdin; extra arguments are -v name=value pairs.
pg_sql() {
  local db=$1
  shift
  docker exec -i -u postgres "$NAME" psql -X -q -At -v ON_ERROR_STOP=1 -d "$db" "$@"
}

read_pw() {
  local pw
  IFS= read -r pw || die "stdin: şifre yok"
  [[ $pw =~ $PW_RE ]] || die "geçersiz şifre biçimi"
  printf '%s' "$pw"
}

rand_pw() { head -c 48 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9' | head -c 32; }

# pgdata_host — the data directory on the host (PGDATA differs per major).
pgdata_host() {
  local p
  p=$(docker exec "$NAME" printenv PGDATA) || die "PGDATA okunamadı"
  [[ $p =~ ^/var/lib/postgresql/[0-9]{2}/docker$ ]] || die "beklenmeyen PGDATA: $p"
  printf '%s\n' "$DATA${p#/var/lib/postgresql}"
}

wait_ready() {
  local i
  for ((i = 0; i < 60; i++)); do
    if running && docker exec -u postgres "$NAME" pg_isready -q -h /var/run/postgresql 2>/dev/null; then
      # The image's first start runs initdb on a temporary server, then
      # restarts; wait for the final one (it listens on TCP).
      if docker exec -u postgres "$NAME" pg_isready -q -h 127.0.0.1 2>/dev/null; then return 0; fi
    fi
    sleep 2
  done
  return 1
}

# write_hba [cidr...] — the superuser only through the socket (peer); every
# other role with scram over TCP from loopback (+ allowed addresses).
write_hba() {
  local dir f ip
  dir=$(pgdata_host)
  f=$dir/pg_hba.conf
  [[ -f $f && ! -L $f ]] || die "pg_hba.conf bulunamadı"
  cp -p -- "$f" "$f.hp-prev"
  {
    echo "# Managed by HostPanel (hp-pg.sh) — do not edit."
    echo "local   all   postgres                 peer"
    echo "local   all   all                      reject"
    echo "host    all   postgres   0.0.0.0/0     reject"
    echo "host    all   postgres   ::/0          reject"
    echo "host    all   all        127.0.0.1/32  scram-sha-256"
    echo "host    all   all        ::1/128       scram-sha-256"
    for ip in "$@"; do
      if [[ $ip != */* ]]; then
        if [[ $ip == *:* ]]; then ip=$ip/128; else ip=$ip/32; fi
      fi
      echo "host    all   all        $ip   scram-sha-256"
    done
  } | atomic_write "$f" 0600 "$PG_UID:$PG_UID"
  local errs
  errs=$(pg_sql postgres <<<"SELECT pg_reload_conf(); SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL;" | tail -n1)
  if [[ $errs != 0 ]]; then
    mv -f -- "$f.hp-prev" "$f"
    pg_sql postgres <<<"SELECT pg_reload_conf();" >/dev/null
    die "pg_hba.conf reddedildi; önceki dosya geri yüklendi"
  fi
  rm -f -- "$f.hp-prev"
  log "pg_hba.conf yazıldı ($(($# + 2)) TCP kuralı)"
}

db_owner() { pg_sql postgres -v db="$1" <<<"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = :'db';"; }
role_exists() { [[ $(pg_sql postgres -v r="$1" <<<"SELECT count(*) FROM pg_roles WHERE rolname = :'r';") == 1 ]]; }

# with_pgpass VAR ROLE PW — a 0600 pgpass inside the container for TCP logins
# as ROLE; its path goes to VAR (the password never appears in argv or the
# environment).
PGPASS_FILES=()
with_pgpass() {
  local f
  f=/tmp/hp-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n').pgpass
  printf '127.0.0.1:5432:*:%s:%s\n' "$2" "$3" | docker exec -i -u postgres "$NAME" sh -c 'umask 077 && cat >"$1"' sh "$f"
  PGPASS_FILES+=("$f")
  printf -v "$1" '%s' "$f"
}

# set_pw PW — a psql "\set pw" line for stdin (never -v on argv: visible in ps).
set_pw() { printf "\\set pw '%s'\n" "$1"; }
pgpass_cleanup() {
  local f
  for f in "${PGPASS_FILES[@]}"; do docker exec -u postgres "$NAME" rm -f -- "$f" >/dev/null 2>&1 || true; done
  PGPASS_FILES=()
}

# as_role PGPASS ROLE DB [psql args] — psql as ROLE over TCP; SQL on stdin.
as_role() {
  local pf=$1 role=$2 db=$3
  shift 3
  docker exec -i -u postgres -e PGPASSFILE="$pf" -e PGCONNECT_TIMEOUT=10 "$NAME" \
    psql -X -q -At -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$role" -d "$db" "$@"
}

check_magic() {
  [[ -f $1 && ! -L $1 ]] || die "döküm dosyası bulunamadı"
  [[ $(head -c 5 -- "$1") == PGDMP ]] || die "dosya pg_dump custom formatında değil (pg_dump -Fc ile alın; düz .sql kabul edilmez)"
}

stage_file() { # SRC → path inside the container
  local base
  install -d -o "$PG_UID" -g "$PG_UID" -m 0700 "$STAGE"
  base=hprs-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n').dump
  install -o "$PG_UID" -g "$PG_UID" -m 0600 -- "$1" "$STAGE/$base"
  printf '/var/lib/postgresql/hp-stage/%s\n' "$base"
}
unstage() { rm -f -- "$STAGE/${1##*/}" "$STAGE/${1##*/}.list"; }

case "$action" in
create)
  [[ $# -eq 3 ]] || die "kullanım: create <image> <memory_mb> <bind>"
  image=$1 mem=$2 bind=$3
  validate_pg_image "$image"
  [[ $mem =~ ^[0-9]{3,5}$ ]] && ((mem >= 512 && mem <= 65536)) || die "geçersiz bellek: $mem"
  validate_oneof "$bind" 127.0.0.1 '*'
  need_docker
  ! exists || die "container zaten var: $NAME"
  if [[ -n $(ss -Hltn "sport = :5432") ]]; then die "5432 portu başka bir süreç tarafından kullanılıyor"; fi
  [[ -d /var/lib/hostpanel ]] || die "/var/lib/hostpanel yok (panel kurulu mu?)"
  if db_moved postgres; then ensure_db_root; fi
  install -d -m 0700 -o "$PG_UID" -g "$PG_UID" "$DATA"
  ensure_pg_backup_dir

  log "docker pull $image"
  docker pull -q "$image"

  # The init password exists only because the image's entrypoint requires one
  # for initdb; the superuser gets "PASSWORD NULL" right after (socket only).
  envf=$(mktemp /run/hp-pg-env.XXXXXX)
  trap 'rm -f "$envf"' EXIT
  chmod 600 "$envf"
  {
    echo "POSTGRES_PASSWORD=$(rand_pw)"
    # The image's default pg_hba trusts 127.0.0.1 (with --network host: every
    # local process) until write_hba runs; peer/scram from initdb on closes that.
    echo "POSTGRES_INITDB_ARGS=--encoding=UTF8 --locale=C.UTF-8 --auth-local=peer --auth-host=scram-sha-256"
  } >"$envf"

  # Memory: container limit = setting + headroom; server parameters scale with it.
  cmem=$((mem + 256))
  sb=$((mem / 4)) ecs=$((mem * 3 / 4)) mwm=$((mem / 20))
  ((mwm >= 64)) || mwm=64
  ((mwm <= 2048)) || mwm=2048
  log "docker run $NAME (network host, ${bind}:5432, memory ${cmem}m, shared_buffers ${sb}MB)"
  docker run -d --name "$NAME" \
    --network host \
    --restart unless-stopped \
    --memory "${cmem}m" --memory-swap "${cmem}m" \
    --shm-size 256m \
    --env-file "$envf" \
    -v "$DATA:/var/lib/postgresql" \
    --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
    "$image" postgres \
    -c listen_addresses="$bind" -c port=5432 \
    -c shared_buffers="${sb}MB" -c effective_cache_size="${ecs}MB" \
    -c maintenance_work_mem="${mwm}MB" -c work_mem=8MB -c max_connections=100 \
    -c password_encryption=scram-sha-256 >/dev/null
  log "container başlatıldı, hazır olması bekleniyor"
  if ! wait_ready; then
    docker logs --tail 30 "$NAME" 2>&1 || true
    die "PostgreSQL zamanında hazır olmadı"
  fi
  rm -f "$envf"
  # The init password stays in the container's config (docker inspect, root
  # only) but stops working here: no password, no TCP for the superuser.
  write_hba
  pg_sql postgres <<<"ALTER ROLE postgres PASSWORD NULL;" >/dev/null
  log "süper kullanıcı yalnızca container içinden (soket) erişilebilir; şifresi yok"
  pg_sql postgres <<<"SELECT version();"
  ;;

remove-container)
  [[ $# -eq 0 ]] || die "kullanım: remove-container"
  need_docker
  if exists; then
    docker stop -t 60 "$NAME" >/dev/null 2>&1 || true
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
  if [[ $action == start ]]; then docker start "$NAME" >/dev/null; else docker restart -t 60 "$NAME" >/dev/null; fi
  wait_ready || die "PostgreSQL hazır olmadı"
  log "$action tamam"
  ;;

stop)
  [[ $# -eq 0 ]] || die "kullanım: stop"
  need_docker
  exists || die "container yok"
  docker stop -t 60 "$NAME" >/dev/null
  log "durduruldu"
  ;;

status)
  [[ $# -eq 0 ]] || die "kullanım: status"
  echo "data_dir=$DATA"
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
  if running; then
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

ready)
  [[ $# -eq 0 ]] || die "kullanım: ready"
  need_docker
  exists || die "container yok"
  wait_ready || die "PostgreSQL hazır olmadı"
  ;;

version)
  [[ $# -eq 0 ]] || die "kullanım: version"
  need_running
  pg_sql postgres <<<"SHOW server_version;"
  ;;

hba)
  [[ $# -le 50 ]] || die "en fazla 50 adres"
  for ip in "$@"; do validate_ip_or_cidr "$ip"; done
  need_running
  write_hba "$@"
  ;;

firewall)
  [[ $# -ge 1 && $# -le 50 ]] || die "kullanım: firewall <ip|cidr>... (1-50)"
  for ip in "$@"; do validate_ip_or_cidr "$ip"; done
  command -v ufw >/dev/null || die "ufw kurulu değil"
  ufw_active || die "UFW etkin değil; dış erişim yalnızca UFW etkinken açılabilir (5432 aksi halde tüm internete açık olurdu)"
  ufw_clear
  for ip in "$@"; do
    ufw allow proto tcp from "$ip" to any port 5432 comment "$UFW_TAG" >/dev/null
    log "izin: $ip → 5432/tcp"
  done
  ;;

relocate)
  [[ $# -eq 1 ]] || die "kullanım: relocate to-new|to-old"
  need_docker
  ! exists || die "önce container kaldırılmalı"
  db_relocate "$1" postgres postgres-backup
  ;;

firewall-clear)
  [[ $# -eq 0 ]] || die "kullanım: firewall-clear"
  if ufw_active; then
    ufw_clear
    log "5432 kuralları kaldırıldı"
  fi
  ;;

role-create)
  [[ $# -eq 1 ]] || die "kullanım: role-create <role>"
  validate_pg_name "$1"
  pw=$(read_pw)
  need_running
  if role_exists "$1"; then
    [[ $(pg_sql postgres -v r="$1" <<<"SELECT rolsuper OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname = :'r';") == f ]] ||
      die "$1 ayrıcalıklı bir rol; panel bu rolü devralamaz"
  else
    pg_sql postgres -v r="$1" <<<'CREATE ROLE :"r";' >/dev/null
  fi
  {
    set_pw "$pw"
    echo "ALTER ROLE :\"r\" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 50 PASSWORD :'pw';"
  } | pg_sql postgres -v r="$1" >/dev/null
  log "rol hazır: $1"
  ;;

role-password)
  [[ $# -eq 1 ]] || die "kullanım: role-password <role>"
  validate_pg_name "$1"
  pw=$(read_pw)
  need_running
  role_exists "$1" || die "rol yok: $1"
  { set_pw "$pw"; echo "ALTER ROLE :\"r\" PASSWORD :'pw';"; } | pg_sql postgres -v r="$1" >/dev/null
  log "şifre değişti: $1"
  ;;

role-enable)
  [[ $# -eq 2 ]] || die "kullanım: role-enable <role> 0|1"
  validate_pg_name "$1"
  validate_oneof "$2" 0 1
  need_running
  role_exists "$1" || die "rol yok: $1"
  if [[ $2 == 1 ]]; then
    pg_sql postgres -v r="$1" <<<'ALTER ROLE :"r" LOGIN;' >/dev/null
  else
    pg_sql postgres -v r="$1" >/dev/null <<'SQL'
ALTER ROLE :"r" NOLOGIN;
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = :'r';
SQL
  fi
  log "rol $([[ $2 == 1 ]] && echo etkin || echo 'devre dışı'): $1"
  ;;

role-drop)
  [[ $# -eq 1 ]] || die "kullanım: role-drop <role>"
  validate_pg_name "$1"
  need_running
  if ! role_exists "$1"; then
    log "rol zaten yok: $1"
    exit 0
  fi
  n=$(pg_sql postgres -v r="$1" <<<"SELECT count(*) FROM pg_database WHERE datdba = (SELECT oid FROM pg_roles WHERE rolname = :'r');")
  [[ $n == 0 ]] || die "$1 rolünün veritabanları var"
  pg_sql postgres -v r="$1" >/dev/null <<'SQL'
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = :'r';
DROP ROLE :"r";
SQL
  log "rol silindi: $1"
  ;;

db-create)
  [[ $# -eq 2 ]] || die "kullanım: db-create <db> <owner>"
  validate_pg_name "$1"
  validate_pg_name "$2"
  need_running
  role_exists "$2" || die "sahip rol yok: $2"
  cur=$(db_owner "$1")
  if [[ -n $cur ]]; then
    [[ $cur == "$2" ]] || die "$1 veritabanı başka bir role ait ($cur); devralınmaz"
    log "veritabanı zaten var: $1"
  else
    pg_sql postgres -v db="$1" -v o="$2" >/dev/null <<'SQL'
CREATE DATABASE :"db" OWNER :"o" TEMPLATE template0 ENCODING 'UTF8' LOCALE 'C.UTF-8';
SQL
    log "veritabanı oluşturuldu: $1 (sahip $2)"
  fi
  pg_sql postgres -v db="$1" <<<'REVOKE ALL ON DATABASE :"db" FROM PUBLIC;' >/dev/null
  ;;

db-drop)
  [[ $# -ge 1 && $# -le 2 ]] || die "kullanım: db-drop <db> [backup]"
  validate_pg_name "$1"
  [[ $# -eq 1 ]] || validate_oneof "$2" backup
  need_running
  if [[ -z $(db_owner "$1") ]]; then
    log "veritabanı zaten yok: $1"
    exit 0
  fi
  if [[ ${2:-} == backup ]]; then
    ensure_pg_backup_dir
    out=$PG_HOST_BACKUP/pre-drop-$1-$(date +%Y%m%d-%H%M%S).dump
    umask 077
    docker exec -u postgres "$NAME" pg_dump -Fc -d "$1" >"$out" || {
      rm -f -- "$out"
      die "yedek alınamadı; silinmedi"
    }
    log "son yedek: $out ($(du -h "$out" | cut -f1))"
  fi
  pg_sql postgres -v db="$1" <<<'DROP DATABASE :"db" WITH (FORCE);' >/dev/null
  log "veritabanı silindi: $1"
  ;;

sizes)
  [[ $# -eq 0 ]] || die "kullanım: sizes"
  need_running
  pg_sql postgres <<<"SELECT datname || '=' || pg_database_size(datname) FROM pg_database WHERE NOT datistemplate AND datname <> 'postgres' ORDER BY 1;"
  ;;

dump)
  [[ $# -eq 2 ]] || die "kullanım: dump <db> <file>"
  validate_pg_name "$1"
  [[ $2 =~ ^hpbk-[A-Za-z0-9_-]{1,140}$ ]] || die "geçersiz dosya adı"
  need_running
  [[ -n $(db_owner "$1") ]] || die "veritabanı yok: $1"
  ensure_pg_backup_dir
  out=$PG_HOST_BACKUP/$2.dump
  umask 077
  docker exec -u postgres "$NAME" nice -n 10 pg_dump -Fc -d "$1" >"$out" || {
    rm -f -- "$out"
    die "pg_dump başarısız: $1"
  }
  log "döküm: $1 ($(du -h "$out" | cut -f1))"
  ;;

check-dump)
  [[ $# -eq 1 ]] || die "kullanım: check-dump <path>"
  f=$(validate_path_under "$1" "$UPLOAD_DIR")
  [[ $(basename "$f") =~ ^pgimport-[0-9]+\.dump$ ]] || die "geçersiz yükleme dosyası"
  check_magic "$f"
  need_running
  staged=$(stage_file "$f")
  trap 'unstage "$staged"' EXIT
  docker exec -u postgres "$NAME" pg_restore -l "$staged" >/dev/null || die "döküm okunamadı (bozuk ya da daha yeni bir PostgreSQL sürümünden)"
  n=$(docker exec -u postgres "$NAME" pg_restore -l "$staged" | grep -c '^[0-9]' || true)
  log "döküm geçerli: ${n} nesne"
  ;;

restore)
  [[ $# -ge 4 ]] || die "kullanım: restore <db> <owner> backup <domain> <name> <srcdb> | upload <path>"
  db=$1 owner=$2 kind=$3
  validate_pg_name "$db"
  validate_pg_name "$owner"
  case $kind in
    backup)
      [[ $# -eq 6 ]] || die "kullanım: restore <db> <owner> backup <domain> <name> <srcdb>"
      validate_domain "$4"
      validate_backup_name "$5"
      validate_name "$6" 63
      src=$BACKUP_ROOT/$4/$5/db-pg-$6.dump
      ;;
    upload)
      [[ $# -eq 4 ]] || die "kullanım: restore <db> <owner> upload <path>"
      src=$(validate_path_under "$4" "$UPLOAD_DIR")
      [[ $(basename "$src") =~ ^pgimport-[0-9]+\.dump$ ]] || die "geçersiz yükleme dosyası"
      ;;
    *) die "geçersiz kaynak: $kind" ;;
  esac
  pw=$(read_pw)
  check_magic "$src"
  need_running
  role_exists "$owner" || die "sahip rol yok: $owner"
  cur=$(db_owner "$db")
  [[ -z $cur || $cur == "$owner" ]] || die "$db veritabanı başka bir role ait ($cur)"

  tmpdb=hprs_$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')
  staged=$(stage_file "$src")
  cleanup() {
    pgpass_cleanup
    unstage "$staged"
    if [[ -n ${tmpdb:-} ]]; then pg_sql postgres -v db="$tmpdb" <<<'DROP DATABASE IF EXISTS :"db" WITH (FORCE);' >/dev/null 2>&1 || true; fi
  }
  trap cleanup EXIT

  # Leave out what a database owner can't (and shouldn't) restore: plpgsql's
  # own entries, comments on extensions, publications/subscriptions.
  docker exec -u postgres "$NAME" pg_restore -l "$staged" >/dev/null || die "döküm okunamadı (bozuk ya da daha yeni bir PostgreSQL sürümünden)"
  # The list is filtered inside the container (fixed script, path as $1).
  # shellcheck disable=SC2016
  docker exec -u postgres "$NAME" sh -c \
    'pg_restore -l "$1" | grep -vE "^[0-9]+; [0-9]+ [0-9]+ (EXTENSION - plpgsql|COMMENT - EXTENSION )" >"$1.list"; exit 0' sh "$staged"

  pg_sql postgres -v db="$tmpdb" -v o="$owner" >/dev/null <<'SQL'
CREATE DATABASE :"db" OWNER :"o" TEMPLATE template0 ENCODING 'UTF8' LOCALE 'C.UTF-8';
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
SQL
  pf=""
  with_pgpass pf "$owner" "$pw"
  log "geri yükleniyor (rol: $owner, tek işlem)…"
  if ! docker exec -u postgres -e PGPASSFILE="$pf" "$NAME" nice -n 10 pg_restore \
    -h 127.0.0.1 -U "$owner" -d "$tmpdb" \
    --no-owner --no-privileges --no-tablespaces --no-publications --no-subscriptions --no-security-labels \
    --single-transaction --exit-on-error -L "${staged}.list" "$staged"; then
    die "geri yükleme başarısız; mevcut veritabanına dokunulmadı"
  fi
  # Swap in: the old database (if any) goes, the restored one takes its name.
  pg_sql postgres -v db="$db" -v t="$tmpdb" >/dev/null <<'SQL'
SET client_min_messages = warning;
DROP DATABASE IF EXISTS :"db" WITH (FORCE);
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :'t';
ALTER DATABASE :"t" RENAME TO :"db";
SQL
  tmpdb=""
  pg_sql postgres -v db="$db" <<<'REVOKE ALL ON DATABASE :"db" FROM PUBLIC;' >/dev/null
  log "geri yüklendi: $db (sahip $owner)"
  ;;

isolation-test)
  [[ $# -eq 0 ]] || die "kullanım: isolation-test"
  need_running
  A=hpiso_a B=hpiso_b
  pwa=$(rand_pw) pwb=$(rand_pw)
  iso_cleanup() {
    pgpass_cleanup
    pg_sql postgres >/dev/null 2>&1 <<'SQL' || true
DROP DATABASE IF EXISTS hpiso_a_db WITH (FORCE);
DROP DATABASE IF EXISTS hpiso_b_db WITH (FORCE);
DROP ROLE IF EXISTS hpiso_a;
DROP ROLE IF EXISTS hpiso_b;
SQL
  }
  trap iso_cleanup EXIT
  iso_cleanup
  for r in "$A:$pwa" "$B:$pwb"; do
    {
      set_pw "${r#*:}"
      echo "CREATE ROLE :\"r\" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'pw';"
    } | pg_sql postgres -v r="${r%%:*}" >/dev/null
    pg_sql postgres -v db="${r%%:*}_db" -v o="${r%%:*}" >/dev/null <<'SQL'
CREATE DATABASE :"db" OWNER :"o" TEMPLATE template0;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
SQL
  done
  pfa="" pfb="" bad=""
  with_pgpass pfa "$A" "$pwa"
  with_pgpass pfb "$B" "$pwb"
  with_pgpass bad "$A" "WrongPassword0000000"
  fails=0
  pass() { echo "✓ $1"; }
  fail() {
    echo "✗ $1"
    fails=$((fails + 1))
  }
  # expect_ok / expect_err DESC PGPASS ROLE DB SQL
  expect_ok() { if as_role "$2" "$3" "$4" <<<"$5" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi; }
  expect_err() { if as_role "$2" "$3" "$4" <<<"$5" >/dev/null 2>&1; then fail "$1"; else pass "$1"; fi; }
  for pair in "$A:$B:$pfa" "$B:$A:$pfb"; do
    me=${pair%%:*} rest=${pair#*:}
    other=${rest%%:*} pf=${rest#*:}
    echo "— $me"
    expect_ok "$me kendi veritabanında tablo oluşturup okuyabiliyor" "$pf" "$me" "${me}_db" \
      "CREATE TABLE t(x int); INSERT INTO t VALUES (1); SELECT x FROM t; DROP TABLE t;"
    expect_err "$me, ${other}_db veritabanına bağlanamıyor" "$pf" "$me" "${other}_db" "SELECT 1;"
    expect_err "$me süper kullanıcı değil" "$pf" "$me" "${me}_db" \
      "DO \$\$BEGIN IF (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN RETURN; END IF; RAISE EXCEPTION 'not superuser'; END\$\$;"
    expect_err "$me yeni veritabanı oluşturamıyor" "$pf" "$me" "${me}_db" "CREATE DATABASE hpiso_x;"
    expect_err "$me postgres rolüne geçemiyor" "$pf" "$me" "${me}_db" "SET ROLE postgres;"
    expect_err "$me güvenilmeyen uzantı kuramıyor (dblink)" "$pf" "$me" "${me}_db" "CREATE EXTENSION dblink;"
    expect_err "$me sunucuda program çalıştıramıyor (COPY PROGRAM)" "$pf" "$me" "${me}_db" "COPY (SELECT 1) TO PROGRAM 'id';"
    expect_err "$me sunucu dosyası okuyamıyor" "$pf" "$me" "${me}_db" "SELECT pg_read_file('/etc/passwd');"
  done
  expect_err "yanlış şifre reddediliyor" "$bad" "$A" "${A}_db" "SELECT 1;"
  if docker exec -u postgres -e PGCONNECT_TIMEOUT=5 "$NAME" psql -X -h 127.0.0.1 -U postgres -d postgres -c 'SELECT 1' </dev/null >/dev/null 2>&1; then
    fail "süper kullanıcı TCP ile bağlanamıyor"
  else
    pass "süper kullanıcı TCP ile bağlanamıyor"
  fi
  echo
  if ((fails)); then die "izolasyon testi başarısız: ${fails} kontrol"; fi
  log "izolasyon testi başarılı"
  ;;

*)
  die "bilinmeyen işlem: $action"
  ;;
esac
