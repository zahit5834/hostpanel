#!/usr/bin/env bash
# hp-ssh.sh — SSH login settings, admin keys and the host fail2ban jails (Faz 11).
#
#   hp-ssh.sh status
#       effective sshd settings (sshd -T), admin users and their keys, the
#       pending revert, as key=value lines (see the Go parser hostsec.ParseSSHStatus).
#   hp-ssh.sh apply <password yes|no> <root no|prohibit-password|yes>
#       write sshd_config.d/00-hostpanel.conf, sshd -t, check the effective
#       values, reload; then a revert timer: unless "confirm" follows within
#       180 s (the admin logged in again in a NEW session), "revert" restores
#       the previous file by itself. Open sessions are never cut.
#   hp-ssh.sh confirm | revert
#   hp-ssh.sh key-add <user>            public key on stdin (one plain line, no options)
#   hp-ssh.sh key-del <user> <SHA256:…>
#   hp-ssh.sh f2b-status
#   hp-ssh.sh f2b-unban <sshd|hostpanel|recidive> <ip>
#   hp-ssh.sh f2b-config <maxretry> <findtime_min> <bantime_min> <recidive 0|1>
#       extra ignoreip entries (IP/CIDR) on stdin, one per line; loopback is
#       always ignored. fail2ban-client -t must pass, otherwise the old file stays.
#
# Users are limited to root and members of the "sudo" group; keys only go to
# ~/.ssh/authorized_keys (a custom AuthorizedKeysFile makes the keys read-only).
# Password login can only be turned off while at least one admin key exists.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root
[[ $# -ge 1 ]] || die "kullanım: $(basename "$0") status|apply|confirm|revert|key-add|key-del|f2b-status|f2b-unban|f2b-config …"
action=$1
shift
SELF=$(readlink -f "$0")

lock() {
  install -d -o root -g root -m 0700 "$SSH_STATE_DIR"
  [[ ! -L $SSH_STATE_DIR ]] || die "${SSH_STATE_DIR} symlink olamaz"
  exec 9>"$SSH_STATE_DIR/.lock"
  flock -w 60 9 || die "başka bir SSH işlemi sürüyor"
}

# admin_users — root and members of the sudo group that exist, one per line.
admin_users() {
  {
    echo root
    getent group sudo | cut -d: -f4 | tr ',' '\n'
  } | awk 'NF && !seen[$0]++' | while read -r u; do
    getent passwd "$u" >/dev/null && echo "$u"
  done
}

is_admin() {
  local u
  while read -r u; do [[ $u == "$1" ]] && return 0; done < <(admin_users)
  return 1
}

home_of() { getent passwd "$1" | cut -d: -f6; }
akf_default() {
  local v
  v=$(sshd -T 2>/dev/null | awk '$1 == "authorizedkeysfile" {$1=""; sub(/^ /, ""); print}')
  [[ $v == ".ssh/authorized_keys" || $v == ".ssh/authorized_keys .ssh/authorized_keys2" ]]
}
keys_file() { printf '%s/.ssh/authorized_keys' "$(home_of "$1")"; }

# admin_key_count — keys across all admin users' authorized_keys.
admin_key_count() {
  local u f n=0
  while read -r u; do
    f=$(keys_file "$u")
    [[ -f $f && ! -L $f ]] || continue
    n=$((n + $(ssh-keygen -lf "$f" 2>/dev/null | grep -c . || true)))
  done < <(admin_users)
  echo "$n"
}

sshd_reload() {
  # Ubuntu 24.04 starts ssh.service from ssh.socket: an inactive service reads
  # the new file on the next connection by itself.
  if systemctl is-active --quiet ssh.service; then
    systemctl reload ssh.service
  fi
}

# effective_ok PASSWORD ROOT — sshd -T reports the requested values.
effective_ok() {
  local want_root=$2 eff
  [[ $want_root == prohibit-password ]] && want_root=without-password
  eff=$(sshd -T 2>/dev/null) || return 1
  [[ $(awk '$1 == "passwordauthentication" {print $2}' <<<"$eff") == "$1" ]] &&
    [[ $(awk '$1 == "permitrootlogin" {print $2}' <<<"$eff") == "$want_root" ]]
}

restore_prev() {
  if [[ -f $SSH_STATE_DIR/prev.conf ]]; then
    install -o root -g root -m 0644 "$SSH_STATE_DIR/prev.conf" "$SSH_DROPIN"
  elif [[ -f $SSH_STATE_DIR/prev.none ]]; then
    rm -f -- "$SSH_DROPIN"
  fi
  if ! sshd -t 2>/dev/null; then
    # the earlier file passed when it was written; if it no longer does, the
    # distribution defaults are the safe fallback
    rm -f -- "$SSH_DROPIN"
  fi
  rm -f -- "$SSH_STATE_DIR/prev.conf" "$SSH_STATE_DIR/prev.none"
}

# timer_pending — the revert timer is still counting down (an elapsed one-shot
# timer reports "active" with sub-state "elapsed").
timer_pending() {
  [[ $(systemctl show -p SubState --value "${SSH_REVERT_UNIT}.timer" 2>/dev/null) == waiting ]]
}

stop_timer() {
  systemctl stop "${SSH_REVERT_UNIT}.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "${SSH_REVERT_UNIT}.timer" "${SSH_REVERT_UNIT}.service" >/dev/null 2>&1 || true
}

set_state() { printf 'state=%s at=%s%s\n' "$1" "$(date +%s)" "${2:+ $2}" | atomic_write "$SSH_STATE_DIR/state" 0600 root:root; }

case $action in
  status)
    [[ $# -eq 0 ]] || die "kullanım: status"
    command -v sshd >/dev/null || die "openssh-server kurulu değil"
    eff=$(sshd -T 2>/dev/null) || die "sshd -T çalışmadı (yapılandırma hatalı olabilir: sshd -t)"
    for k in passwordauthentication kbdinteractiveauthentication permitrootlogin pubkeyauthentication; do
      printf '%s=%s\n' "$k" "$(awk -v k="$k" '$1 == k {print $2}' <<<"$eff")"
    done
    printf 'authorizedkeysfile=%s\n' "$(awk '$1 == "authorizedkeysfile" {$1=""; sub(/^ /, ""); print}' <<<"$eff")"
    awk '$1 == "port" {print "port=" $2}' <<<"$eff"
    [[ -f $SSH_DROPIN ]] && echo "managed=1" || echo "managed=0"
    if [[ -f $SSH_STATE_DIR/state && ! -L $SSH_STATE_DIR/state ]]; then
      cat -- "$SSH_STATE_DIR/state"
    fi
    if timer_pending; then echo "pending=1"; else echo "pending=0"; fi
    while read -r u; do
      f=$(keys_file "$u")
      echo "user=${u}"
      [[ -f $f && ! -L $f ]] || continue
      ssh-keygen -lf "$f" 2>/dev/null | sed "s/^/key=${u} /" || true
    done < <(admin_users)
    ;;

  apply)
    [[ $# -eq 2 ]] || die "kullanım: apply <password yes|no> <root no|prohibit-password|yes>"
    pw=$1 root=$2
    validate_oneof "$pw" yes no
    validate_oneof "$root" no prohibit-password yes
    command -v sshd >/dev/null || die "openssh-server kurulu değil"
    lock
    if timer_pending; then
      die "önceki SSH değişikliği onay bekliyor; önce onaylayın ya da geri alın"
    fi
    if [[ $pw == no ]] && (($(admin_key_count) == 0)); then
      die "hiç SSH anahtarı yok: parola girişi kapatılırsa sunucuya girilemez"
    fi
    rm -f -- "$SSH_STATE_DIR/prev.conf" "$SSH_STATE_DIR/prev.none"
    if [[ -f $SSH_DROPIN ]]; then
      cp -p -- "$SSH_DROPIN" "$SSH_STATE_DIR/prev.conf"
    else
      : >"$SSH_STATE_DIR/prev.none"
    fi
    install -d -m 0755 "$(dirname "$SSH_DROPIN")"
    render_sshd_dropin "$pw" "$root" | atomic_write "$SSH_DROPIN" 0644 root:root
    if ! sshd -t; then
      restore_prev
      die "sshd yeni yapılandırmayı reddetti; önceki hali geri yüklendi"
    fi
    if ! effective_ok "$pw" "$root"; then
      restore_prev
      die "etkin değerler istenenle aynı değil (başka bir yapılandırma satırı önce geliyor olabilir); önceki hali geri yüklendi"
    fi
    sshd_reload
    stop_timer
    systemd-run --quiet --unit="$SSH_REVERT_UNIT" --on-active="$SSH_REVERT_SECS" --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no \
      "$SELF" revert 9>&-
    deadline=$(($(date +%s) + SSH_REVERT_SECS))
    set_state applied "deadline=${deadline} password=${pw} root=${root}"
    log "uygulandı: PasswordAuthentication ${pw}, PermitRootLogin ${root}; ${SSH_REVERT_SECS} sn içinde onaylanmazsa geri alınacak"
    echo "deadline=${deadline}"
    ;;

  confirm)
    [[ $# -eq 0 ]] || die "kullanım: confirm"
    lock
    timer_pending || die "onay bekleyen SSH değişikliği yok (süre dolduysa geri alınmıştır)"
    stop_timer
    rm -f -- "$SSH_STATE_DIR/prev.conf" "$SSH_STATE_DIR/prev.none"
    set_state confirmed
    log "SSH değişikliği onaylandı"
    ;;

  revert)
    [[ $# -eq 0 ]] || die "kullanım: revert"
    lock
    if [[ ! -f $SSH_STATE_DIR/prev.conf && ! -f $SSH_STATE_DIR/prev.none ]]; then
      stop_timer
      log "geri alınacak değişiklik yok"
      exit 0
    fi
    restore_prev
    sshd_reload
    set_state reverted
    # the timer fired (this runs as its service) or the admin asked: either way it is done
    systemctl stop "${SSH_REVERT_UNIT}.timer" >/dev/null 2>&1 || true
    log "SSH ayarları önceki haline döndürüldü"
    ;;

  key-add)
    [[ $# -eq 1 ]] || die "kullanım: key-add <user> (anahtar stdin'den)"
    user=$1
    validate_sys_user "$user"
    is_admin "$user" || die "yalnızca root ve sudo grubundaki kullanıcılar: $user"
    akf_default || die "AuthorizedKeysFile özelleştirilmiş; anahtarlar panelden yönetilemez"
    tmp=$(mktemp)
    trap 'rm -f -- "$tmp"' EXIT
    read_stdin_limited "$tmp" 16384
    line=$(head -n1 "$tmp")
    key=$(validate_pubkey "$line")
    fp=$(key_fingerprint "$key")
    [[ -n $fp ]] || die "anahtar okunamadı"
    lock
    home=$(home_of "$user")
    [[ -d $home && ! -L $home ]] || die "kullanıcının home dizini yok: $user"
    grp=$(id -gn "$user")
    [[ ! -L $home/.ssh ]] || die "${home}/.ssh symlink olamaz"
    [[ -d $home/.ssh ]] || install -d -o "$user" -g "$grp" -m 0700 "$home/.ssh"
    f=$home/.ssh/authorized_keys
    [[ ! -L $f ]] || die "${f} symlink olamaz"
    if [[ -f $f ]] && ssh-keygen -lf "$f" 2>/dev/null | awk '{print $2}' | grep -qxF -- "$fp"; then
      die "bu anahtar zaten ekli: $fp"
    fi
    { [[ -f $f ]] && cat -- "$f"; printf '%s\n' "$key"; } | atomic_write "$f" 0600 "$user:$grp"
    log "anahtar eklendi: ${user} ${fp}"
    echo "fingerprint=${fp}"
    ;;

  key-del)
    [[ $# -eq 2 ]] || die "kullanım: key-del <user> <SHA256:…>"
    user=$1 fp=$2
    validate_sys_user "$user"
    validate_fingerprint "$fp"
    is_admin "$user" || die "yalnızca root ve sudo grubundaki kullanıcılar: $user"
    akf_default || die "AuthorizedKeysFile özelleştirilmiş; anahtarlar panelden yönetilemez"
    lock
    f=$(keys_file "$user")
    [[ -f $f && ! -L $f ]] || die "anahtar dosyası yok: $user"
    out=$(mktemp)
    trap 'rm -f -- "$out"' EXIT
    found=0
    while IFS= read -r l || [[ -n $l ]]; do
      if [[ -n $l && $l != \#* && $(key_fingerprint "$l") == "$fp" ]]; then
        found=1
        continue
      fi
      printf '%s\n' "$l" >>"$out"
    done <"$f"
    ((found)) || die "anahtar bulunamadı: $fp"
    pw=$(sshd -T 2>/dev/null | awk '$1 == "passwordauthentication" {print $2}')
    if [[ $pw == no ]] && (($(admin_key_count) <= 1)); then
      die "son SSH anahtarı silinemez: parola girişi kapalı"
    fi
    atomic_write "$f" 0600 "$user:$(id -gn "$user")" <"$out"
    log "anahtar silindi: ${user} ${fp}"
    ;;

  f2b-status)
    [[ $# -eq 0 ]] || die "kullanım: f2b-status"
    command -v fail2ban-client >/dev/null || {
      echo "installed=0"
      exit 0
    }
    echo "installed=1"
    if systemctl is-active --quiet fail2ban; then echo "active=1"; else echo "active=0"; fi
    read -r r f b c <<<"$(f2b_current)"
    echo "config=${r} ${f} ${b} ${c}"
    while read -r x; do [[ -n $x ]] && echo "ignore=${x}"; done < <(f2b_ignored)
    if systemctl is-active --quiet fail2ban; then
      jails=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' ' ')
      for j in $jails; do
        [[ $j =~ ^[A-Za-z0-9_-]{1,40}$ ]] || continue
        echo "--- jail ${j}"
        fail2ban-client status "$j" 2>/dev/null || true
      done
    fi
    ;;

  f2b-unban)
    [[ $# -eq 2 ]] || die "kullanım: f2b-unban <jail> <ip>"
    validate_oneof "$1" sshd hostpanel recidive
    [[ ${#2} -le 45 && $2 =~ ^[0-9A-Fa-f:.]+$ && $2 == *[.:]* ]] || die "geçersiz IP: $2"
    fail2ban-client set "$1" unbanip "$2"
    log "engel kaldırıldı: $1 $2"
    ;;

  f2b-config)
    [[ $# -eq 4 ]] || die "kullanım: f2b-config <maxretry> <findtime_dk> <bantime_dk> <recidive 0|1> (muaf IP'ler stdin'den)"
    command -v fail2ban-client >/dev/null || die "fail2ban kurulu değil"
    tmp=$(mktemp)
    new=$(mktemp)
    backup=$(mktemp)
    trap 'rm -f -- "$tmp" "$new" "$backup"' EXIT
    read_stdin_limited "$tmp" 4096
    ign=()
    while IFS= read -r x || [[ -n $x ]]; do
      x=${x//[[:space:]]/}
      [[ -n $x ]] || continue
      validate_ip_or_cidr "$x"
      ign+=("$x")
    done <"$tmp"
    ((${#ign[@]} <= 50)) || die "en fazla 50 muaf adres"
    on=$(write_f2b_filter)
    # fail2ban -t fails on a jail without its log file; the panel's auth.log is
    # created by install.sh (root does not create files in the panel's log dir)
    [[ -f /var/log/hostpanel/auth.log ]] || on=false
    [[ $4 == 0 || -f /var/log/fail2ban.log ]] || install -o root -g adm -m 0640 /dev/null /var/log/fail2ban.log
    render_f2b_jail "$on" "$1" "$2" "$3" "$4" "$(f2b_ports)" "${ign[@]}" >"$new"
    had=0
    if [[ -f $F2B_JAIL ]]; then
      cp -p -- "$F2B_JAIL" "$backup"
      had=1
    fi
    install -o root -g root -m 0644 "$new" "$F2B_JAIL"
    if ! fail2ban-client -t >/dev/null 2>&1; then
      if ((had)); then install -o root -g root -m 0644 "$backup" "$F2B_JAIL"; else rm -f -- "$F2B_JAIL"; fi
      fail2ban-client -t 2>&1 | tail -n 5 >&2 || true
      die "fail2ban yeni yapılandırmayı reddetti; önceki hali geri yüklendi"
    fi
    if systemctl is-active --quiet fail2ban; then
      fail2ban-client reload >/dev/null
    fi
    log "fail2ban ayarları uygulandı: deneme ${1}, süre ${2} dk, ban ${3} dk, tekrar edenler ${4}, muaf ${#ign[@]} adres"
    ;;

  *)
    die "bilinmeyen işlem: $action"
    ;;
esac
