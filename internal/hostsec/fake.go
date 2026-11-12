package hostsec

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// fakeSSH mimics hp-ssh.sh for dry-run: same rules, state in memory, the
// revert timer is evaluated lazily (an expired pending change reads as reverted).
type fakeSSH struct {
	password, root       string
	prevPassword, prevRo string
	pending              bool
	deadline             time.Time
	state                string
	stateAt              time.Time
	keys                 map[string][]string // user → lines
	logins               []SSHLogin
}

// Sample key so the dry-run page has something to show.
const fakeKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKlEk+Xrz/i41WqjQPxzg3PwrmFRoDaBHz6Vo6g0TAzL admin@laptop"

func (s *SSH) fakeState() *fakeSSH {
	if s.fake == nil {
		fp, _ := FakeFingerprint(fakeKey)
		s.fake = &fakeSSH{password: "yes", root: "yes", keys: map[string][]string{"root": nil, "ubuntu": {fakeKey}},
			logins: []SSHLogin{{Time: time.Now().Add(-2 * time.Hour), User: "ubuntu", IP: "203.0.113.10", Method: "publickey", FP: fp}}}
	}
	f := s.fake
	if f.pending && time.Now().After(f.deadline) {
		f.revert()
	}
	return f
}

// FakeFingerprint computes the OpenSSH SHA256 fingerprint of a key line.
func FakeFingerprint(line string) (string, error) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return "", errors.New("anahtar okunamadı")
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return "", errors.New("anahtar okunamadı")
	}
	h := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:]), nil
}

func (f *fakeSSH) status() string {
	var b strings.Builder
	root := f.root
	if root == "prohibit-password" {
		root = "without-password"
	}
	fmt.Fprintf(&b, "passwordauthentication=%s\nkbdinteractiveauthentication=no\npermitrootlogin=%s\npubkeyauthentication=yes\n", f.password, root)
	b.WriteString("authorizedkeysfile=.ssh/authorized_keys .ssh/authorized_keys2\nport=22\n")
	if f.state != "" {
		b.WriteString("managed=1\n")
		fmt.Fprintf(&b, "state=%s at=%d", f.state, f.stateAt.Unix())
		if f.pending {
			fmt.Fprintf(&b, " deadline=%d password=%s root=%s", f.deadline.Unix(), f.password, f.root)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("managed=0\n")
	}
	if f.pending {
		b.WriteString("pending=1\n")
	} else {
		b.WriteString("pending=0\n")
	}
	for _, u := range []string{"root", "ubuntu"} {
		fmt.Fprintf(&b, "user=%s\n", u)
		for _, k := range f.keys[u] {
			fp, _ := FakeFingerprint(k)
			fl := strings.Fields(k)
			c := "no comment"
			if len(fl) > 2 {
				c = strings.Join(fl[2:], " ")
			}
			typ, bits := "RSA", 3072
			switch {
			case strings.HasPrefix(fl[0], "ssh-ed25519"), strings.HasPrefix(fl[0], "sk-ssh-ed25519"):
				typ, bits = "ED25519", 256
			case strings.Contains(fl[0], "ecdsa"):
				typ, bits = "ECDSA", 256
			}
			fmt.Fprintf(&b, "key=%s %d %s %s (%s)\n", u, bits, fp, c, typ)
		}
	}
	return b.String()
}

func (f *fakeSSH) keyCount() int {
	n := 0
	for _, k := range f.keys {
		n += len(k)
	}
	return n
}

func (f *fakeSSH) apply(pw, root string) (time.Time, error) {
	if f.pending {
		return time.Time{}, errors.New("önceki SSH değişikliği onay bekliyor; önce onaylayın ya da geri alın")
	}
	if pw == "no" && f.keyCount() == 0 {
		return time.Time{}, errors.New("hiç SSH anahtarı yok: parola girişi kapatılırsa sunucuya girilemez")
	}
	f.prevPassword, f.prevRo = f.password, f.root
	f.password, f.root = pw, root
	f.pending, f.deadline = true, time.Now().Add(RevertAfter)
	f.state, f.stateAt = "applied", time.Now()
	return f.deadline, nil
}

func (f *fakeSSH) confirm() error {
	if !f.pending {
		return errors.New("onay bekleyen SSH değişikliği yok (süre dolduysa geri alınmıştır)")
	}
	f.pending = false
	f.state, f.stateAt = "confirmed", time.Now()
	return nil
}

func (f *fakeSSH) revert() {
	if !f.pending {
		return
	}
	f.password, f.root = f.prevPassword, f.prevRo
	f.pending = false
	f.state, f.stateAt = "reverted", time.Now()
}

func (f *fakeSSH) addKey(user, key string) (string, error) {
	if _, ok := f.keys[user]; !ok {
		return "", errors.New("yalnızca root ve sudo grubundaki kullanıcılar: " + user)
	}
	fp, err := FakeFingerprint(key)
	if err != nil {
		return "", err
	}
	for _, k := range f.keys[user] {
		if g, _ := FakeFingerprint(k); g == fp {
			return "", errors.New("bu anahtar zaten ekli: " + fp)
		}
	}
	f.keys[user] = append(f.keys[user], key)
	return fp, nil
}

func (f *fakeSSH) delKey(user, fp string) error {
	keys := f.keys[user]
	for i, k := range keys {
		if g, _ := FakeFingerprint(k); g == fp {
			if f.password == "no" && f.keyCount() <= 1 {
				return errors.New("son SSH anahtarı silinemez: parola girişi kapalı")
			}
			f.keys[user] = append(keys[:i:i], keys[i+1:]...)
			return nil
		}
	}
	return errors.New("anahtar bulunamadı: " + fp)
}
