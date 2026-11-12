package hostsec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
)

// RevertAfter is how long an SSH change waits for confirmation (hp-ssh.sh
// SSH_REVERT_SECS) before it undoes itself.
const RevertAfter = 180 * time.Second

// SSHKey is one line of an admin's authorized_keys.
type SSHKey struct {
	User    string
	Bits    int
	FP      string // SHA256:…
	Comment string
	Type    string // ED25519, RSA, ECDSA …
}

// SSHUser is root or a member of the sudo group.
type SSHUser struct {
	Name string
	Keys []SSHKey
}

// SSHStatus is the parsed output of "hp-ssh.sh status".
type SSHStatus struct {
	Password       string // sshd -T values: yes|no
	KbdInteractive string
	RootLogin      string // yes|no|without-password|forced-commands-only
	Pubkey         string
	AKF            string
	Ports          []string
	Managed        bool // 00-hostpanel.conf exists

	State           string // applied|confirmed|reverted|""
	StateAt         time.Time
	Deadline        time.Time
	Pending         bool
	PendingPassword string
	PendingRoot     string

	Users []SSHUser
}

// PasswordOff is true when no password-like login method is left.
func (s SSHStatus) PasswordOff() bool { return s.Password == "no" && s.KbdInteractive == "no" }

// AKFDefault reports the stock AuthorizedKeysFile (the panel manages only ~/.ssh/authorized_keys).
func (s SSHStatus) AKFDefault() bool {
	return s.AKF == ".ssh/authorized_keys" || s.AKF == ".ssh/authorized_keys .ssh/authorized_keys2"
}

// KeyCount counts the keys of all admin users.
func (s SSHStatus) KeyCount() int {
	n := 0
	for _, u := range s.Users {
		n += len(u.Keys)
	}
	return n
}

// HasUser reports whether name is one of the admin users.
func (s SSHStatus) HasUser(name string) bool {
	for _, u := range s.Users {
		if u.Name == name {
			return true
		}
	}
	return false
}

// RootMode maps sshd -T's spelling back to the form value.
func (s SSHStatus) RootMode() string {
	if s.RootLogin == "without-password" {
		return "prohibit-password"
	}
	return s.RootLogin
}

// RootLabel is the Turkish description of a PermitRootLogin value.
func RootLabel(v string) string {
	switch v {
	case "no":
		return "kapalı"
	case "prohibit-password", "without-password":
		return "yalnızca anahtarla"
	case "yes":
		return "açık (şifreyle de)"
	case "forced-commands-only":
		return "yalnızca zorunlu komutlarla"
	}
	return v
}

// ParseSSHStatus reads the key=value lines of hp-ssh.sh status.
func ParseSSHStatus(out string) SSHStatus {
	var st SSHStatus
	users := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "passwordauthentication":
			st.Password = v
		case "kbdinteractiveauthentication":
			st.KbdInteractive = v
		case "permitrootlogin":
			st.RootLogin = v
		case "pubkeyauthentication":
			st.Pubkey = v
		case "authorizedkeysfile":
			st.AKF = v
		case "port":
			st.Ports = append(st.Ports, v)
		case "managed":
			st.Managed = v == "1"
		case "pending":
			st.Pending = v == "1"
		case "state":
			// "state=applied at=… deadline=… password=no root=no"
			f := strings.Fields(line)
			for _, kv := range f {
				a, b, _ := strings.Cut(kv, "=")
				switch a {
				case "state":
					st.State = b
				case "at":
					st.StateAt = unixTime(b)
				case "deadline":
					st.Deadline = unixTime(b)
				case "password":
					st.PendingPassword = b
				case "root":
					st.PendingRoot = b
				}
			}
		case "user":
			if _, ok := users[v]; !ok {
				users[v] = len(st.Users)
				st.Users = append(st.Users, SSHUser{Name: v})
			}
		case "key":
			if key, ok := parseKeyLine(v); ok {
				i, seen := users[key.User]
				if !seen {
					i = len(st.Users)
					users[key.User] = i
					st.Users = append(st.Users, SSHUser{Name: key.User})
				}
				st.Users[i].Keys = append(st.Users[i].Keys, key)
			}
		}
	}
	if !st.Pending {
		st.PendingPassword, st.PendingRoot = "", ""
	}
	return st
}

func unixTime(s string) time.Time {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// parseKeyLine reads "<user> <bits> SHA256:… <comment…> (TYPE)" (ssh-keygen -lf).
func parseKeyLine(v string) (SSHKey, bool) {
	f := strings.Fields(v)
	if len(f) < 4 || !strings.HasPrefix(f[2], "SHA256:") {
		return SSHKey{}, false
	}
	bits, err := strconv.Atoi(f[1])
	if err != nil {
		return SSHKey{}, false
	}
	k := SSHKey{User: f[0], Bits: bits, FP: f[2]}
	last := f[len(f)-1]
	if strings.HasPrefix(last, "(") && strings.HasSuffix(last, ")") {
		k.Type = strings.Trim(last, "()")
		f = f[:len(f)-1]
	}
	k.Comment = strings.Join(f[3:], " ")
	if k.Comment == "no comment" {
		k.Comment = ""
	}
	return k, true
}

// --- input validation (mirrors lib.sh) ---

var (
	sysUserRe     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]+$`)
	keyDataRe     = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,3}$`)
	keyCommentRe  = regexp.MustCompile(`^[A-Za-z0-9@._ -]+$`)
)

var keyTypes = map[string]bool{
	"ssh-ed25519": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"ssh-rsa": true, "sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// ValidatePubKey checks one public key line ("type base64 [comment]") and
// returns it normalised. Lines with options (command=, from=) are refused;
// the root helper checks it again with ssh-keygen (key size, encoding).
func ValidatePubKey(line string) (string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", errors.New("anahtar boş")
	}
	if len(line) > 16384 || strings.ContainsAny(line, "\r\n") {
		return "", errors.New("tek satırlık bir açık anahtar girin (id_ed25519.pub içeriği)")
	}
	f := strings.Fields(line)
	if !keyTypes[f[0]] {
		if strings.Contains(f[0], "PRIVATE") || strings.HasPrefix(line, "-----BEGIN") {
			return "", errors.New("bu bir özel anahtar; yalnızca .pub dosyasının içeriğini girin")
		}
		return "", errors.New("desteklenmeyen anahtar türü (ssh-ed25519, ecdsa-sha2-*, ssh-rsa; seçenekli satırlar kabul edilmez)")
	}
	if len(f) < 2 || len(f[1]) < 60 || !keyDataRe.MatchString(f[1]) {
		return "", errors.New("anahtar verisi bozuk")
	}
	out := f[0] + " " + f[1]
	if len(f) > 2 {
		c := strings.Join(f[2:], " ")
		if len(c) > 100 || !keyCommentRe.MatchString(c) {
			return "", errors.New("anahtar açıklaması yalnızca harf, rakam, @ . _ - ve boşluk içerebilir (en fazla 100)")
		}
		out += " " + c
	}
	return out, nil
}

// --- auth.log: who logged in how ---

// SSHLogin is one "Accepted …" line of /var/log/auth.log.
type SSHLogin struct {
	Time   time.Time
	User   string
	IP     string
	Method string // publickey, password, keyboard-interactive/pam
	FP     string // for publickey
}

// ParseAccepted extracts sshd's successful logins from auth.log lines
// ("<RFC3339> host sshd[pid]: Accepted publickey for u from 1.2.3.4 port 5 ssh2: ED25519 SHA256:…").
func ParseAccepted(lines []string) []SSHLogin {
	var out []SSHLogin
	for _, l := range lines {
		i := strings.Index(l, "]: Accepted ")
		if i < 0 || !strings.Contains(l[:i], " sshd") {
			continue
		}
		f := strings.Fields(l[i+len("]: Accepted "):])
		// method for user from ip port n ssh2[: TYPE FP]
		if len(f) < 7 || f[1] != "for" || f[3] != "from" || f[5] != "port" {
			continue
		}
		lg := SSHLogin{Method: f[0], User: f[2], IP: f[4]}
		ts, _, _ := strings.Cut(l, " ")
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			lg.Time = t
		}
		if lg.Method == "publickey" && len(f) >= 10 && strings.HasPrefix(f[9], "SHA256:") {
			lg.FP = f[9]
		}
		out = append(out, lg)
	}
	return out
}

// ReadAccepted reads the logins from the current and the previous auth.log
// (the panel is in the adm group). Oldest first.
func ReadAccepted(path string) []SSHLogin {
	var lines []string
	for _, p := range []string{path + ".1", path} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 4096), 64*1024)
		for sc.Scan() {
			if t := sc.Text(); strings.Contains(t, "]: Accepted ") {
				lines = append(lines, t)
			}
		}
		f.Close()
	}
	return ParseAccepted(lines)
}

// --- service ---

// SSH runs hp-ssh.sh. In dry-run it keeps an in-memory server so the pages
// (apply → countdown → confirm/revert, keys) can be developed and tested.
type SSH struct {
	Runner     exec.Runner
	ScriptsDir string
	DryRun     bool
	AuthLog    string // default /var/log/auth.log

	mu   sync.Mutex
	fake *fakeSSH
}

func (s *SSH) authLog() string {
	if s.AuthLog != "" {
		return s.AuthLog
	}
	return "/var/log/auth.log"
}

// Logins returns the recent successful SSH logins (newest last).
func (s *SSH) Logins() []SSHLogin {
	if s.DryRun {
		s.mu.Lock()
		defer s.mu.Unlock()
		return append([]SSHLogin(nil), s.fakeState().logins...)
	}
	return ReadAccepted(s.authLog())
}

func (s *SSH) run(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := exec.Helper(s.ScriptsDir, "hp-ssh.sh", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Timeout = 90 * time.Second
	res, err := s.Runner.Run(ctx, cmd)
	return res.Stdout, err
}

// Status reads the effective settings and keys.
func (s *SSH) Status(ctx context.Context) (SSHStatus, error) {
	if s.DryRun {
		s.mu.Lock()
		defer s.mu.Unlock()
		return ParseSSHStatus(s.fakeState().status()), nil
	}
	out, err := s.run(ctx, "", "status")
	if err != nil {
		return SSHStatus{}, err
	}
	return ParseSSHStatus(out), nil
}

// ApplyInput is the SSH form.
type ApplyInput struct {
	Password bool   // allow password login
	Root     string // no|prohibit-password|yes
	// KeyTested: the admin ticked "I can log in with a key" (required when no
	// publickey login is visible in auth.log).
	KeyTested bool
}

// CheckApply returns why a change would be unsafe ("" = fine).
func CheckApply(st SSHStatus, in ApplyInput, logins []SSHLogin) error {
	switch in.Root {
	case "no", "prohibit-password", "yes":
	default:
		return errors.New("geçersiz root girişi seçeneği")
	}
	if st.Pending {
		return errors.New("önceki değişiklik onay bekliyor; önce onaylayın ya da geri alın")
	}
	if !in.Password {
		if st.KeyCount() == 0 {
			return errors.New("hiç SSH anahtarı yok: parola girişi kapatılırsa sunucuya girilemez. Önce anahtar ekleyin")
		}
		if !keyLoginSeen(st, logins) && !in.KeyTested {
			return errors.New("bu anahtarlardan biriyle yapılmış bir SSH girişi görülmedi; anahtarla girebildiğinizi doğrulayıp kutuyu işaretleyin")
		}
		if in.Root == "yes" {
			return errors.New("parola girişi kapalıyken root için \"açık (şifreyle de)\" seçilemez")
		}
	}
	return nil
}

// keyLoginSeen: some admin logged in with one of the current keys.
func keyLoginSeen(st SSHStatus, logins []SSHLogin) bool {
	fps := map[string]bool{}
	for _, u := range st.Users {
		for _, k := range u.Keys {
			fps[k.FP] = true
		}
	}
	for _, l := range logins {
		if l.Method == "publickey" && fps[l.FP] {
			return true
		}
	}
	return false
}

// LastKeyLogin returns the newest publickey login (zero when none).
func LastKeyLogin(logins []SSHLogin) SSHLogin {
	for i := len(logins) - 1; i >= 0; i-- {
		if logins[i].Method == "publickey" {
			return logins[i]
		}
	}
	return SSHLogin{}
}

// LoginSince reports a publickey login at or after t (a new session after apply).
func LoginSince(logins []SSHLogin, t time.Time) (SSHLogin, bool) {
	for i := len(logins) - 1; i >= 0; i-- {
		if !logins[i].Time.Before(t) && logins[i].Method == "publickey" {
			return logins[i], true
		}
	}
	return SSHLogin{}, false
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// Apply writes the drop-in and starts the revert timer; returns the deadline.
func (s *SSH) Apply(ctx context.Context, in ApplyInput) (time.Time, error) {
	if s.DryRun {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.fakeState().apply(yesNo(in.Password), in.Root)
	}
	out, err := s.run(ctx, "", "apply", yesNo(in.Password), in.Root)
	if err != nil {
		return time.Time{}, err
	}
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "deadline="); ok {
			return unixTime(v), nil
		}
	}
	return time.Now().Add(RevertAfter), nil
}

// Confirm keeps the pending change.
func (s *SSH) Confirm(ctx context.Context) error {
	if s.DryRun {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.fakeState().confirm()
	}
	_, err := s.run(ctx, "", "confirm")
	return err
}

// Revert restores the previous settings now.
func (s *SSH) Revert(ctx context.Context) error {
	if s.DryRun {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.fakeState().revert()
		return nil
	}
	_, err := s.run(ctx, "", "revert")
	return err
}

// AddKey validates line and adds it for user; returns the fingerprint.
func (s *SSH) AddKey(ctx context.Context, user, line string) (string, error) {
	if !sysUserRe.MatchString(user) {
		return "", errors.New("geçersiz kullanıcı")
	}
	key, err := ValidatePubKey(line)
	if err != nil {
		return "", err
	}
	if s.DryRun {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.fakeState().addKey(user, key)
	}
	out, err := s.run(ctx, key+"\n", "key-add", user)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "fingerprint="); ok {
			return v, nil
		}
	}
	return "", nil
}

// CheckDeleteKey refuses deleting the last key while password login is off,
// and the key of the newest SSH login (most likely the admin's own).
func CheckDeleteKey(st SSHStatus, user, fp string, logins []SSHLogin, force bool) error {
	found := false
	for _, u := range st.Users {
		for _, k := range u.Keys {
			if u.Name == user && k.FP == fp {
				found = true
			}
		}
	}
	if !found {
		return errors.New("anahtar bulunamadı (liste değişmiş olabilir)")
	}
	if st.PasswordOff() && st.KeyCount() <= 1 {
		return errors.New("son SSH anahtarı silinemez: parola girişi kapalı")
	}
	if last := LastKeyLogin(logins); last.FP == fp && !force {
		return fmt.Errorf("bu anahtar son SSH girişinde kullanıldı (%s, %s); büyük olasılıkla sizin anahtarınız. Yine de silmek için onay kutusunu işaretleyin", last.User, last.IP)
	}
	return nil
}

// DeleteKey removes a key by fingerprint.
func (s *SSH) DeleteKey(ctx context.Context, user, fp string) error {
	if !sysUserRe.MatchString(user) || !fingerprintRe.MatchString(fp) || len(fp) != 50 {
		return errors.New("geçersiz anahtar")
	}
	if s.DryRun {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.fakeState().delKey(user, fp)
	}
	_, err := s.run(ctx, "", "key-del", user, fp)
	return err
}
