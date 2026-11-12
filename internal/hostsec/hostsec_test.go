package hostsec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const edKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKlEk+Xrz/i41WqjQPxzg3PwrmFRoDaBHz6Vo6g0TAzL admin@laptop"
const edFP = "SHA256:rIluIzwe7w2LyE+GlxoH+lQ/j5w20deUMvTz+8oZq9I"

// Output shape of hp-ssh.sh status as seen in the ubuntu:24.04 container test.
const statusOut = `passwordauthentication=no
kbdinteractiveauthentication=no
permitrootlogin=without-password
pubkeyauthentication=yes
authorizedkeysfile=.ssh/authorized_keys .ssh/authorized_keys2
port=22
port=2222
managed=1
state=applied at=1794460000 deadline=1794460180 password=no root=prohibit-password
pending=1
user=root
user=admin
key=admin 256 SHA256:rIluIzwe7w2LyE+GlxoH+lQ/j5w20deUMvTz+8oZq9I admin@laptop (ED25519)
key=admin 3072 SHA256:aP1dnyO8XwsEOr0sHZBdxpzELQ1XjhaU8z98pJAcn+k rsa key (RSA)
key=admin 256 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA no comment (ED25519)
`

func TestParseSSHStatus(t *testing.T) {
	st := ParseSSHStatus(statusOut)
	if !st.PasswordOff() || st.RootMode() != "prohibit-password" || !st.Managed || !st.Pending || !st.AKFDefault() {
		t.Fatalf("settings: %+v", st)
	}
	if st.Deadline.Unix() != 1794460180 || st.PendingPassword != "no" || st.PendingRoot != "prohibit-password" || st.State != "applied" {
		t.Fatalf("state: %+v", st)
	}
	if len(st.Ports) != 2 || len(st.Users) != 2 || st.Users[0].Name != "root" || len(st.Users[0].Keys) != 0 {
		t.Fatalf("users: %+v", st.Users)
	}
	k := st.Users[1].Keys
	if st.KeyCount() != 3 || k[0].FP != edFP || k[0].Comment != "admin@laptop" || k[0].Type != "ED25519" || k[0].Bits != 256 ||
		k[1].Comment != "rsa key" || k[1].Bits != 3072 || k[2].Comment != "" {
		t.Fatalf("keys: %+v", k)
	}
	if ParseSSHStatus("pending=0\nstate=applied at=1 deadline=2 password=no root=no\n").PendingPassword != "" {
		t.Fatal("pending values without a pending timer")
	}
}

func TestValidatePubKey(t *testing.T) {
	if got, err := ValidatePubKey("  " + edKey + "  "); err != nil || got != edKey {
		t.Fatalf("good key: %q %v", got, err)
	}
	for _, bad := range []string{
		"", `command="/bin/sh" ` + edKey, `from="1.2.3.4" ` + edKey, "ssh-dss AAAAB3NzaC1kc3MAAACBAP" + strings.Repeat("A", 80),
		"ssh-ed25519 short", edKey + " $(id)", edKey + "\n" + edKey, "-----BEGIN OPENSSH PRIVATE KEY-----",
		"ssh-ed25519 " + strings.Repeat("A", 60) + "!!",
	} {
		if _, err := ValidatePubKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if fp, _ := FakeFingerprint(edKey); fp != edFP {
		t.Fatalf("fingerprint %s (ssh-keygen: %s)", fp, edFP)
	}
}

func TestParseAccepted(t *testing.T) {
	lines := []string{
		"2026-11-07T09:39:05.598139+00:00 ubuntu sshd[78686]: Accepted publickey for ubuntu from 203.0.113.10 port 31682 ssh2: ED25519 " + edFP,
		"2026-11-07T10:00:00.000000+00:00 ubuntu sshd[1]: Accepted password for root from 198.51.100.5 port 2 ssh2",
		"2026-11-12T05:06:52.311933+00:00 ubuntu sshd[258957]: Failed password for root from 203.205.18.230 port 37933 ssh2",
		"2026-11-12T05:06:53+00:00 ubuntu CRON[1]: Accepted publickey for x from 1.2.3.4 port 1 ssh2: ED25519 SHA256:x",
	}
	got := ParseAccepted(lines)
	if len(got) != 2 || got[0].FP != edFP || got[0].User != "ubuntu" || got[0].IP != "203.0.113.10" || got[0].Time.Year() != 2026 ||
		got[1].Method != "password" || got[1].FP != "" {
		t.Fatalf("%+v", got)
	}
	if l := LastKeyLogin(got); l.FP != edFP {
		t.Fatalf("last key login %+v", l)
	}
	if _, ok := LoginSince(got, got[0].Time.Add(time.Second)); ok {
		t.Fatal("password login counted as a new key session")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "auth.log.1"), []byte(lines[0]+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "auth.log"), []byte(lines[2]+"\n"+lines[1]+"\n"), 0o600)
	if r := ReadAccepted(filepath.Join(dir, "auth.log")); len(r) != 2 || r[0].Method != "publickey" {
		t.Fatalf("read: %+v", r)
	}
}

func TestCheckApplyAndDelete(t *testing.T) {
	none := ParseSSHStatus("passwordauthentication=yes\nkbdinteractiveauthentication=no\npermitrootlogin=yes\npending=0\nuser=root\nuser=ubuntu\n")
	if err := CheckApply(none, ApplyInput{Password: false, Root: "no", KeyTested: true}, nil); err == nil {
		t.Fatal("password off without any key")
	}
	if err := CheckApply(none, ApplyInput{Password: true, Root: "no"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckApply(none, ApplyInput{Password: true, Root: "maybe"}, nil); err == nil {
		t.Fatal("bad root mode")
	}
	withKey := ParseSSHStatus("passwordauthentication=yes\nkbdinteractiveauthentication=no\npermitrootlogin=yes\npending=0\nuser=ubuntu\nkey=ubuntu 256 " + edFP + " a (ED25519)\n")
	if err := CheckApply(withKey, ApplyInput{Root: "no"}, nil); err == nil || !strings.Contains(err.Error(), "kutuyu") {
		t.Fatalf("no key login seen: %v", err)
	}
	if err := CheckApply(withKey, ApplyInput{Root: "no", KeyTested: true}, nil); err != nil {
		t.Fatal(err)
	}
	logins := []SSHLogin{{Method: "publickey", FP: edFP, User: "ubuntu", IP: "203.0.113.10"}}
	if err := CheckApply(withKey, ApplyInput{Root: "no"}, logins); err != nil {
		t.Fatal(err)
	}
	if err := CheckApply(withKey, ApplyInput{Root: "yes"}, logins); err == nil {
		t.Fatal("root password login while password login is off")
	}
	pending := ParseSSHStatus(statusOut)
	if err := CheckApply(pending, ApplyInput{Password: true, Root: "no"}, nil); err == nil {
		t.Fatal("apply while pending")
	}

	// delete rules
	off := ParseSSHStatus("passwordauthentication=no\nkbdinteractiveauthentication=no\nuser=ubuntu\nkey=ubuntu 256 " + edFP + " a (ED25519)\n")
	if err := CheckDeleteKey(off, "ubuntu", edFP, nil, true); err == nil {
		t.Fatal("deleted the last key while password login is off")
	}
	if err := CheckDeleteKey(withKey, "ubuntu", edFP, logins, false); err == nil || !strings.Contains(err.Error(), "son SSH girişinde") {
		t.Fatalf("own key: %v", err)
	}
	if err := CheckDeleteKey(withKey, "ubuntu", edFP, logins, true); err != nil {
		t.Fatal(err)
	}
	if err := CheckDeleteKey(withKey, "root", edFP, nil, true); err == nil {
		t.Fatal("key of another user")
	}
}

func TestFakeSSHFlow(t *testing.T) {
	ctx := context.Background()
	s := &SSH{DryRun: true}
	st, _ := s.Status(ctx)
	if st.Password != "yes" || st.KeyCount() != 1 || st.Pending {
		t.Fatalf("initial %+v", st)
	}
	if _, err := s.Apply(ctx, ApplyInput{Password: false, Root: "prohibit-password"}); err != nil {
		t.Fatal(err)
	}
	st, _ = s.Status(ctx)
	if !st.Pending || !st.PasswordOff() || st.RootMode() != "prohibit-password" || time.Until(st.Deadline) < 170*time.Second {
		t.Fatalf("applied %+v", st)
	}
	// deadline passes → reverted on the next read
	s.mu.Lock()
	s.fake.deadline = time.Now().Add(-time.Second)
	s.mu.Unlock()
	st, _ = s.Status(ctx)
	if st.Pending || st.Password != "yes" || st.State != "reverted" {
		t.Fatalf("auto revert %+v", st)
	}
	s.Apply(ctx, ApplyInput{Password: false, Root: "no"})
	if err := s.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(ctx); err == nil {
		t.Fatal("double confirm")
	}
	if err := s.DeleteKey(ctx, "ubuntu", edFP); err == nil {
		t.Fatal("deleted the last key")
	}
	if _, err := s.AddKey(ctx, "ubuntu", edKey); err == nil {
		t.Fatal("duplicate key")
	}
	if _, err := s.AddKey(ctx, "bob", edKey); err == nil {
		t.Fatal("non-admin user")
	}
}

func TestParseF2BStatus(t *testing.T) {
	raw, err := os.ReadFile("testdata/f2b-status.txt")
	if err != nil {
		t.Fatal(err)
	}
	st := ParseF2BStatus(string(raw))
	if !st.Installed || !st.Active || st.Config != (F2BConfig{5, 15, 60, true}) || len(st.Ignore) != 1 || len(st.Jails) != 3 {
		t.Fatalf("%+v", st)
	}
	hp := st.Jail("hostpanel")
	if hp == nil || hp.CurBanned != 2 || len(hp.Banned) != 2 || hp.Banned[0] != "2001:db8::5" || hp.Files != "/var/log/hostpanel/auth.log" {
		t.Fatalf("hostpanel %+v", hp)
	}
	if r := st.Jail("recidive"); r == nil || r.CurFailed != 3 || len(r.Banned) != 0 {
		t.Fatalf("recidive %+v", r)
	}
	if st.TotalBanned() != 3 {
		t.Fatal(st.TotalBanned())
	}
}

func TestIgnoreList(t *testing.T) {
	got, err := ParseIgnoreList("203.0.113.5\n10.1.2.3/16, 127.0.0.1 ::1\n203.0.113.5\n2001:db8::/48")
	if err != nil || strings.Join(got, " ") != "203.0.113.5 10.1.0.0/16 2001:db8::/48" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "1.2.3", "0.0.0.0", "a.b.c.d"} {
		if _, err := ParseIgnoreList(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if !Covers(got, "10.1.200.4") || !Covers(got, "::ffff:203.0.113.5") || !Covers(nil, "127.0.0.1") || Covers(got, "198.51.100.1") {
		t.Fatal("Covers")
	}
	f := &Fail2ban{DryRun: true}
	ctx := context.Background()
	if err := f.Configure(ctx, F2BConfig{5, 15, 60, false}, got, "198.51.100.1"); err == nil {
		t.Fatal("own IP missing from the ignore list")
	}
	if err := f.Configure(ctx, F2BConfig{2, 15, 60, false}, got, "127.0.0.1"); err == nil {
		t.Fatal("range")
	}
	if err := f.Configure(ctx, F2BConfig{5, 15, 60, true}, got, "10.1.0.9"); err != nil {
		t.Fatal(err)
	}
	if err := f.Unban(ctx, "sshd", "185.48.180.8"); err != nil {
		t.Fatal(err)
	}
	if err := f.Unban(ctx, "apache", "185.48.180.8"); err == nil {
		t.Fatal("bad jail")
	}
	st, _ := f.Status(ctx)
	if !st.Config.Recidive || st.Jail("sshd").CurBanned != 1 {
		t.Fatalf("%+v", st)
	}
}

// ss -ltnuH on this server (2026-11-12).
const ssOut = `udp UNCONN 0      0         127.0.0.54:53    0.0.0.0:*
udp UNCONN 0      0      127.0.0.53%lo:53    0.0.0.0:*
tcp LISTEN 0      4096      127.0.0.54:53    0.0.0.0:*
tcp LISTEN 0      128          0.0.0.0:135   0.0.0.0:*
tcp LISTEN 0      511          0.0.0.0:8443  0.0.0.0:*
tcp LISTEN 0      4096         0.0.0.0:22    0.0.0.0:*
tcp LISTEN 0      511          0.0.0.0:80    0.0.0.0:*
tcp LISTEN 0      128        127.0.0.1:1433  0.0.0.0:*
tcp LISTEN 0      4096       127.0.0.1:8090  0.0.0.0:*
tcp LISTEN 0      128                *:135         *:*
tcp LISTEN 0      511             [::]:8443     [::]:*
tcp LISTEN 0      4096            [::]:22       [::]:*
tcp LISTEN 0      128            [::1]:1431     [::]:*
udp UNCONN 0      0      0.0.0.0:51820    0.0.0.0:*
`

func TestParseSSAndUnexpected(t *testing.T) {
	ls := ParseSS(ssOut)
	if len(ls) != 13 {
		t.Fatalf("%d listeners: %+v", len(ls), ls)
	}
	exp := []PortInfo{{"tcp", 22, "SSH"}, {"tcp", 80, "HTTP"}, {"tcp", 443, "HTTPS"}, {"tcp", 8443, "panel"}}
	if got := UnexpectedPorts(ls, exp); strings.Join(got, ",") != "tcp/135,udp/51820" {
		t.Fatalf("%v", got)
	}
}

func TestAudit(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	on := true
	ssh := ParseSSHStatus("passwordauthentication=yes\nkbdinteractiveauthentication=no\npermitrootlogin=yes\n")
	f2b := ParseF2BStatus("installed=1\nactive=1\n--- jail sshd\n")
	in := AuditInput{Now: now, SSH: &ssh, UFWInstalled: true, UFWActive: false, Listeners: ParseSS(ssOut),
		Expected: []PortInfo{{"tcp", 22, ""}, {"tcp", 80, ""}, {"tcp", 8443, ""}}, F2B: &f2b, UnattendedOn: &on,
		TOTP: false, BackupsPlanned: true, LastBackupOK: now.Add(-time.Hour), IntegrityChecked: true,
		Integrity: []IntegrityIssue{{"scripts/hp-ssh.sh", "changed"}}}
	fs := Audit(in)
	lvl := map[string]string{}
	for _, f := range fs {
		lvl[f.ID] = f.Level
	}
	want := map[string]string{"ssh.password": LevelBad, "ssh.root": LevelBad, "ufw": LevelBad, "ports": LevelBad,
		"fail2ban": LevelWarn, "updates.auto": LevelOK, "panel.2fa": LevelBad, "panel.export": LevelWarn,
		"backups": LevelOK, "integrity": LevelBad}
	for id, l := range want {
		if lvl[id] != l {
			t.Errorf("%s = %s, want %s", id, lvl[id], l)
		}
	}
	bad := BadIDs(fs)
	if n := NewBad(fs, bad); len(n) != 0 {
		t.Fatalf("same state reported again: %v", n)
	}
	if n := NewBad(fs, "ssh.password"); len(n) == 0 || n[0].ID == "ssh.password" {
		t.Fatalf("new findings %v", n)
	}
}

func TestIntegrity(t *testing.T) {
	dir := t.TempDir()
	dep := filepath.Join(dir, "deploy")
	for p, c := range map[string]string{
		"scripts/hp-a.sh": "a", "scripts/lib.sh": "lib", "scripts/test_lib.sh": "t", "scripts/runtimes/x.sh": "x",
		"templates/nginx/s.tpl": "s", "sudoers/hostpanel": "sudo", "systemd/hostpanel.service": "unit",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(dep, p)), 0o755)
		os.WriteFile(filepath.Join(dep, p), []byte(c), 0o644)
	}
	m, err := BuildManifest(dep)
	if err != nil || len(m) != 6 || m["scripts/test_lib.sh"] != "" {
		t.Fatalf("%v %v", m, err)
	}
	p := IntegrityPaths{ScriptsDir: filepath.Join(dep, "scripts"), TemplatesDir: filepath.Join(dep, "templates"),
		Unit: filepath.Join(dep, "systemd/hostpanel.service")}
	if is := CheckIntegrity(m, p); len(is) != 0 {
		t.Fatalf("clean tree: %v", is)
	}
	os.WriteFile(filepath.Join(dep, "scripts/hp-a.sh"), []byte("a; curl evil"), 0o644)
	os.Remove(filepath.Join(dep, "templates/nginx/s.tpl"))
	os.WriteFile(filepath.Join(dep, "scripts/hp-new.sh"), []byte("n"), 0o644)
	p.SudoersSum = "deadbeef"
	is := CheckIntegrity(m, p)
	got := []string{}
	for _, i := range is {
		got = append(got, i.Path+":"+i.Kind)
	}
	if strings.Join(got, " ") != "scripts/hp-a.sh:changed scripts/hp-new.sh:extra sudoers:changed templates/nginx/s.tpl:missing" {
		t.Fatalf("%v", got)
	}
	if IssuesKey(is) == "" || IssuesKey(is) != IssuesKey(CheckIntegrity(m, p)) || IssuesKey(nil) != "" {
		t.Fatal("IssuesKey")
	}
	p.CheckOwner = true // test files belong to the test user, not root
	if is := CheckIntegrity(m, p); len(is) <= len(got) {
		t.Fatalf("owner check found nothing: %v", is)
	}
}

// TestManifestFresh fails when deploy/ changed without "make manifest".
func TestManifestFresh(t *testing.T) {
	m, err := BuildManifest("../../deploy")
	if err != nil {
		t.Fatal(err)
	}
	rel := ReleaseManifest()
	for k, v := range m {
		if rel[k] != v {
			t.Errorf("manifest_gen.go is stale for %s: run make manifest", k)
		}
	}
	for k := range rel {
		if _, ok := m[k]; !ok {
			t.Errorf("manifest_gen.go lists removed file %s: run make manifest", k)
		}
	}
}
