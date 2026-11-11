package mail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/store"
)

func TestAddresses(t *testing.T) {
	for _, a := range []string{"info@ornek.com", "ali.veli_1@sub.ornek.com.tr", "0x@ornek.com"} {
		if !ValidAddress(a) {
			t.Errorf("rejected %q", a)
		}
	}
	for _, a := range []string{"Info@ornek.com", "a|b@ornek.com", "a b@ornek.com", "a+b@ornek.com", "a..b@ornek.com",
		"a.@ornek.com", ".a@ornek.com", "a@b@ornek.com", "a:1@ornek.com", "a,b@ornek.com", "ornek.com", "a@ornek",
		"a@ornek.com\n", strings.Repeat("a", 65) + "@ornek.com"} {
		if ValidAddress(a) {
			t.Errorf("accepted %q", a)
		}
	}
	if !ValidTarget("a+tag@gmail.com") || ValidTarget("a,b@gmail.com") || ValidTarget("x@y") {
		t.Fatal("ValidTarget")
	}
	if NormalizeAddress(" Ali@Ornek.COM ") != "ali@ornek.com" || DomainOf("a@b.com") != "b.com" || DomainOf("x") != "" {
		t.Fatal("normalize/domain")
	}
	if !ValidImage(DefaultImage) || ValidImage("mailserver/docker-mailserver:latest") || ValidImage("x/docker-mailserver:17.0.0") {
		t.Fatal("image")
	}
}

func TestPasswords(t *testing.T) {
	for _, pw := range []string{"short", "with space1234", "tab\tsecret12", "ünicode12345", strings.Repeat("x", 129)} {
		if CheckPassword(pw) == nil {
			t.Errorf("accepted %q", pw)
		}
	}
	if err := CheckPassword(`Abc!def"ghi$|:\`); err != nil {
		t.Fatal(err)
	}
	a, b := GeneratePassword(), GeneratePassword()
	if len(a) != 20 || a == b || CheckPassword(a) != nil || strings.ContainsAny(a, "0O1lI") {
		t.Fatalf("generated %q %q", a, b)
	}
}

func TestParsers(t *testing.T) {
	l := ParseList("account b@ornek.com 0\naccount a@ornek.com 250\naccount bad|x@ornek.com 1\n" +
		"alias info@ornek.com a@ornek.com,dis@gmail.com,bad,x\nalias x@ornek.com\njunk\n")
	if len(l.Mailboxes) != 2 || l.Mailboxes[0].Address != "a@ornek.com" || l.Mailboxes[0].QuotaMB != 250 {
		t.Fatalf("%+v", l.Mailboxes)
	}
	if len(l.Aliases) != 1 || strings.Join(l.Aliases[0].Targets, ",") != "a@ornek.com,dis@gmail.com" {
		t.Fatalf("%+v", l.Aliases)
	}
	if !l.HasMailbox("b@ornek.com") || l.HasMailbox("info@ornek.com") {
		t.Fatal("HasMailbox")
	}
	if d := l.Domains(); len(d) != 1 || d[0] != "ornek.com" {
		t.Fatal(d)
	}
	u := ParseUsage("a@ornek.com 2048 256000\nb@ornek.com 10 -\nbad line\n")
	if u["a@ornek.com"] != 2048 || u["b@ornek.com"] != 10 || len(u) != 2 {
		t.Fatal(u)
	}
	m := Mailbox{QuotaMB: 4, UsedKiB: 2048, HasUsage: true}
	if m.UsedPct() != 50 || m.UsedMB() != 2 {
		t.Fatal(m.UsedPct(), m.UsedMB())
	}
	if ParseDKIM("[hp-mail.sh] x\ntxt="+fakeDKIM("ornek.com")+"\n") != fakeDKIM("ornek.com") {
		t.Fatal("dkim")
	}
	if ParseDKIM("txt=v=DKIM1; k=rsa; p=abc\"; include") != "" {
		t.Fatal("dkim accepted junk")
	}
	if ParseQueue("count=7\n") != 7 || ParseQueue("") != 0 {
		t.Fatal("queue")
	}
	b := ParseBans("dovecot 203.0.113.5\npostfix 2001:db8::1\ncustom not-an-ip\nBad 1.2.3.4\n")
	if len(b) != 2 || b[1].Jail != "postfix" {
		t.Fatalf("%+v", b)
	}
	st := ParseStatus("docker=active\ncontainer=running\nhealth=healthy\ncert_until=4102444800\n")
	if !st.Running() || st.Health != "healthy" || st.CertUntil.Year() != 2100 {
		t.Fatalf("%+v", st)
	}
}

func TestRecords(t *testing.T) {
	d := Domain{Name: "ornek.com", DKIMSelector: "mail", DKIMTXT: fakeDKIM("ornek.com")}
	rs := Records(d, "mail.ornek.com")
	if len(rs) != 4 || rs[0].Value != "10 mail.ornek.com." || rs[2].Name != "mail._domainkey.ornek.com" || rs[3].Name != "_dmarc.ornek.com" {
		t.Fatalf("%+v", rs)
	}
	d.DKIMTXT = ""
	if len(Records(d, "mail.ornek.com")) != 3 {
		t.Fatal("dkim without key")
	}
}

// recRunner records helper calls like exec.DryRun (empty output, success).
type recRunner struct {
	mu     sync.Mutex
	calls  []call
	failOn map[string]int // subcommand → failures left
}

type call struct {
	args    []string
	stdin   string
	secrets []string
}

func (r *recRunner) Run(ctx context.Context, c exec.Cmd) (exec.Result, error) {
	var in string
	if c.Stdin != nil {
		b, _ := io.ReadAll(c.Stdin)
		in = string(b)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call{args: c.Args, stdin: in, secrets: c.Secrets})
	if len(c.Args) > 2 && r.failOn[c.Args[2]] > 0 {
		r.failOn[c.Args[2]]--
		return exec.Result{}, errors.New(c.Args[2] + " failed")
	}
	return exec.Result{DryRun: true}, nil
}

func (r *recRunner) find(sub string) []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []call
	for _, c := range r.calls {
		if len(c.args) > 2 && c.args[2] == sub { // sudo -n <script> <sub> …
			c.args = c.args[2:]
			out = append(out, c)
		}
	}
	return out
}

func testService(t *testing.T) (*Service, *recRunner, *[]string) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	act := logs.NewActivity(db)
	jm := jobs.NewManager(db, t.TempDir(), act, jobs.NewBroker(), log)
	rr := &recRunner{}
	var mu sync.Mutex
	changed := &[]string{}
	s := &Service{Store: NewStore(db), DB: db, Runner: rr, Jobs: jm, Activity: act, Log: log,
		ScriptsDir: "/opt/hostpanel/scripts", DryRun: true, MemTotalMB: 8000, Fake: NewFake(),
		Changed: func(_ context.Context, names []string) {
			mu.Lock()
			*changed = append(*changed, names...)
			mu.Unlock()
		}}
	s.Register()
	jctx, cancel := context.WithCancel(ctx)
	t.Cleanup(func() { cancel(); jm.Wait() })
	if err := jm.Start(jctx, 2); err != nil {
		t.Fatal(err)
	}
	return s, rr, changed
}

func waitJob(t *testing.T, s *Service, id int64) jobs.Job {
	t.Helper()
	for i := 0; i < 500; i++ {
		j, err := s.Jobs.Get(context.Background(), id)
		if err == nil && (j.Status == jobs.StatusSuccess || j.Status == jobs.StatusFailed) {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return jobs.Job{}
}

func TestServiceFlow(t *testing.T) {
	ctx := context.Background()
	s, rr, changed := testService(t)

	in := InstallInput{Hostname: "mail.ornek.com", Domain: "ornek.com", LEEmail: "admin@ornek.com", MemoryMB: 1024}
	if _, err := s.StartInstall(ctx, in); err == nil || !strings.Contains(err.Error(), "Docker") {
		t.Fatalf("install without docker: %v", err)
	}
	store.SetSetting(ctx, s.DB, settingDockerInstalled, "1")
	for _, bad := range []InstallInput{
		{Hostname: "ornek.com", Domain: "ornek.com", LEEmail: "a@ornek.com", MemoryMB: 1024}, // not a full host name
		{Hostname: "mail.ornek.com", Domain: "mail.ornek.com", LEEmail: "a@ornek.com", MemoryMB: 1024},
		{Hostname: "mail.ornek.com", Domain: "ornek.com", LEEmail: "x", MemoryMB: 1024},
		{Hostname: "mail.ornek.com", Domain: "ornek.com", LEEmail: "a@ornek.com", MemoryMB: 512},
		{Hostname: "mail.ornek.com", Domain: "ornek.com", LEEmail: "a@ornek.com", MemoryMB: 7800}, // > total-512
	} {
		if _, err := s.StartInstall(ctx, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	s.NameTaken = func(_ context.Context, host string) error {
		if host == "site.ornek.com" {
			return io.EOF
		}
		return nil
	}
	if _, err := s.StartInstall(ctx, InstallInput{Hostname: "site.ornek.com", Domain: "ornek.com", LEEmail: "a@ornek.com", MemoryMB: 1024}); err == nil {
		t.Fatal("site name accepted as mail host")
	}
	id, err := s.StartInstall(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if j := waitJob(t, s, id); j.Status != jobs.StatusSuccess {
		t.Fatalf("install: %+v", j)
	}
	if _, err := s.StartInstall(ctx, in); err == nil {
		t.Fatal("second install accepted")
	}
	if !s.Installed(ctx) || !s.LiveStatus(ctx).Running() {
		t.Fatal("not running after install")
	}
	for _, sub := range []string{"precheck", "prepare", "vhost", "cert", "create", "wait", "dkim"} {
		if len(rr.find(sub)) == 0 {
			t.Errorf("helper %s not called", sub)
		}
	}
	if c := rr.find("create")[0]; strings.Join(c.args, " ") != "create "+DefaultImage+" mail.ornek.com 1024 0 25 ornek.com" {
		t.Fatalf("create args %v", c.args)
	}
	d0, err := s.Store.DomainByName(ctx, "ornek.com")
	if err != nil || d0.DKIMTXT != fakeDKIM("ornek.com") {
		t.Fatalf("domain %+v %v", d0, err)
	}
	if !strings.Contains(strings.Join(*changed, " "), "mail.ornek.com") {
		t.Fatalf("changed %v", *changed)
	}
	l, _ := s.Listing(ctx)
	if !l.HasMailbox("postmaster@ornek.com") {
		t.Fatalf("%+v", l)
	}

	// Domains.
	if _, err := s.AddDomain(ctx, "mail.ornek.com", 0); err == nil {
		t.Fatal("mail host accepted as domain")
	}
	d, err := s.AddDomain(ctx, "Baska.NET", 0)
	if err != nil || d.Name != "baska.net" || d.DKIMTXT == "" {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := s.AddDomain(ctx, "baska.net", 0); err == nil {
		t.Fatal("duplicate domain")
	}

	// Mailboxes: the password goes on stdin only (and is masked).
	addr, pw, err := s.CreateMailbox(ctx, d.ID, " Ali ", "", 500)
	if err != nil || addr != "ali@baska.net" || len(pw) != 20 {
		t.Fatalf("%q %q %v", addr, pw, err)
	}
	c := rr.find("account-set")
	last := c[len(c)-1]
	if last.stdin != pw+"\n" || len(last.secrets) != 1 || last.secrets[0] != pw || strings.Contains(strings.Join(last.args, " "), pw) {
		t.Fatalf("password handling %+v", last)
	}
	if _, _, err := s.CreateMailbox(ctx, d.ID, "ali", "", 0); err == nil {
		t.Fatal("duplicate mailbox")
	}
	if _, _, err := s.CreateMailbox(ctx, d.ID, "x|y", "", 0); err == nil {
		t.Fatal("bad local part")
	}
	if _, _, err := s.CreateMailbox(ctx, d.ID, "veli", "short", 0); err == nil {
		t.Fatal("short password")
	}
	l, _ = s.Listing(ctx)
	if l.Mailboxes[0].Address != "ali@baska.net" || l.Mailboxes[0].QuotaMB != 500 {
		t.Fatalf("%+v", l.Mailboxes)
	}
	if pw2, err := s.ResetPassword(ctx, addr, "Yeni-Sifre-123"); err != nil || pw2 != "Yeni-Sifre-123" {
		t.Fatal(err)
	}
	if _, err := s.ResetPassword(ctx, "yok@baska.net", ""); err == nil {
		t.Fatal("reset of a missing mailbox")
	}
	if _, err := s.ResetPassword(ctx, "ali@yabanci.com", ""); err == nil {
		t.Fatal("reset outside the mail domains")
	}
	if err := s.SetQuota(ctx, addr, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetQuota(ctx, addr, -1); err == nil {
		t.Fatal("negative quota")
	}

	// Aliases.
	if _, err := s.AddAlias(ctx, d.ID, "ali", "dis@gmail.com"); err == nil {
		t.Fatal("alias on a mailbox address")
	}
	if _, err := s.AddAlias(ctx, d.ID, "info", "info@baska.net"); err == nil {
		t.Fatal("alias to itself")
	}
	al, err := s.AddAlias(ctx, d.ID, "info", "Dis+tag@Gmail.com")
	if err != nil || al != "info@baska.net" {
		t.Fatal(al, err)
	}
	if _, err := s.AddAlias(ctx, d.ID, "info", "dis+tag@gmail.com"); err == nil {
		t.Fatal("duplicate alias target")
	}
	s.AddAlias(ctx, d.ID, "info", "ali@baska.net")
	if _, _, err := s.CreateMailbox(ctx, d.ID, "info", "", 0); err == nil {
		t.Fatal("mailbox on an alias address")
	}
	if _, err := s.DeleteDomain(ctx, d.ID); err == nil {
		t.Fatal("domain with mailboxes deleted")
	}

	// Mailbox delete is a job; its alias targets go with it.
	jid, err := s.StartDeleteMailbox(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	if j := waitJob(t, s, jid); j.Status != jobs.StatusSuccess || strings.Contains(j.Params, pw) {
		t.Fatalf("%+v", j)
	}
	l, _ = s.Listing(ctx)
	if l.HasMailbox(addr) {
		t.Fatal("mailbox still listed")
	}
	if a, ok := l.Alias("info@baska.net"); !ok || len(a.Targets) != 1 {
		t.Fatalf("%+v", l.Aliases)
	}
	if err := s.DeleteAlias(ctx, "info@baska.net", "dis+tag@gmail.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteDomain(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	// The last mailbox stays.
	if _, err := s.StartDeleteMailbox(ctx, "postmaster@ornek.com"); err == nil {
		t.Fatal("last mailbox deleted")
	}

	// Settings.
	if _, _, err := s.StartSettings(ctx, SettingsInput{MemoryMB: 1024, ClamAV: true, MsgLimitMB: 25}); err == nil {
		t.Fatal("ClamAV with 1 GB")
	}
	if _, _, err := s.StartSettings(ctx, SettingsInput{MemoryMB: 1024, MsgLimitMB: 25}); err == nil {
		t.Fatal("no change accepted")
	}
	jid, diff, err := s.StartSettings(ctx, SettingsInput{MemoryMB: 3072, ClamAV: true, MsgLimitMB: 50})
	if err != nil || !strings.Contains(diff, "ClamAV") {
		t.Fatal(diff, err)
	}
	if j := waitJob(t, s, jid); j.Status != jobs.StatusSuccess {
		t.Fatalf("%+v", j)
	}
	cs := rr.find("create")
	if got := strings.Join(cs[len(cs)-1].args, " "); got != "create "+DefaultImage+" mail.ornek.com 3072 1 50 ornek.com" {
		t.Fatal(got)
	}
	if err := s.Operate(ctx, "rm"); err == nil {
		t.Fatal("bad op")
	}
	if err := s.Operate(ctx, "stop"); err != nil || s.LiveStatus(ctx).Running() {
		t.Fatal("stop", err)
	}
	if err := s.Flush(ctx); err == nil {
		t.Fatal("flush while stopped")
	}
	if err := s.RemoveFailed(ctx, io.Discard); err == nil {
		t.Fatal("removed a working server")
	}
	if err := s.Unban(ctx, "1.2.3"); err == nil {
		t.Fatal("bad ip")
	}

	// No helper call carried a password on argv.
	for _, c := range rr.calls {
		for _, a := range c.args {
			if a == pw || a == "Yeni-Sifre-123" {
				t.Fatalf("password on argv: %v", c.args)
			}
		}
	}
	var n int
	s.DB.QueryRow(`SELECT count(*) FROM activity_log WHERE params LIKE ? OR summary LIKE ?`, "%"+pw+"%", "%"+pw+"%").Scan(&n)
	if n != 0 {
		t.Fatal("password in activity log")
	}
}

func TestFailedInstallRemoved(t *testing.T) {
	ctx := context.Background()
	s, _, _ := testService(t)
	store.SetSetting(ctx, s.DB, settingDockerInstalled, "1")
	srv := Server{Image: DefaultImage, Hostname: "mail.ornek.com", MemoryMB: 1024, MsgLimitMB: 25, Status: StatusError}
	s.Store.InsertServer(ctx, &srv)
	d := Domain{Name: "ornek.com"}
	s.Store.InsertDomain(ctx, &d)
	if _, err := s.AddDomain(ctx, "baska.net", 0); err == nil {
		t.Fatal("domain added to a failed server")
	}
	if err := s.RemoveFailed(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.Server(ctx); err == nil {
		t.Fatal("server row kept")
	}
	if ds, _ := s.Store.Domains(ctx, 0); len(ds) != 0 {
		t.Fatal("domains kept")
	}
}

func TestLengthChecks(t *testing.T) {
	long := strings.Repeat("a", 64)
	if !ValidLocal(long) || ValidLocal(long+"a") {
		t.Error("local part limit is 64")
	}
	for s, want := range map[string]bool{
		"admin@ornek.com":                        true,
		long + "@ornek.com":                      true,
		long + "a@ornek.com":                     false,
		"a@" + strings.Repeat("b", 253) + ".com": true,
		"a@" + strings.Repeat("b", 254) + ".com": false,
		"a@ornek." + strings.Repeat("c", 63):     true,
		"a@ornek." + strings.Repeat("c", 64):     false,
		"a@ornek.c":                              false,
		"a@ornek":                                false,
		"a b@ornek.com":                          false,
	} {
		if validLEEmail(s) != want {
			t.Errorf("validLEEmail(%.20q…) = %v", s, !want)
		}
	}
	key := func(n int) string { return "txt=" + dkimPrefix + strings.Repeat("A", n) }
	if ParseDKIM(key(100)) == "" || ParseDKIM(key(1002)) == "" || ParseDKIM(key(99)) != "" || ParseDKIM(key(1003)) != "" {
		t.Error("DKIM key length bounds")
	}
}

func TestImageUpdate(t *testing.T) {
	ctx := context.Background()
	s, rr, _ := testService(t)
	store.SetSetting(ctx, s.DB, settingDockerInstalled, "1")
	id, err := s.StartInstall(ctx, InstallInput{Hostname: "mail.ornek.com", Domain: "ornek.com", LEEmail: "a@ornek.com", MemoryMB: 1024})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, s, id)
	for _, bad := range []string{DefaultImage, "mailserver/docker-mailserver:16.0.1-r2", "mailserver/docker-mailserver:18.0.0-r1", "evil/x:17.0.1-r1", "mailserver/docker-mailserver:17.0.1"} {
		if _, err := s.StartImageUpdate(ctx, bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	next := "mailserver/docker-mailserver:17.0.1-r1"
	if id, err = s.StartImageUpdate(ctx, next); err != nil {
		t.Fatal(err)
	}
	if j := waitJob(t, s, id); j.Status != jobs.StatusSuccess {
		t.Fatalf("%+v", j)
	}
	srv, _ := s.Store.Server(ctx)
	if srv.Image != next || srv.Status != StatusRunning {
		t.Fatalf("%+v", srv)
	}
	if p := rr.find("pull"); len(p) != 1 || p[0].args[1] != next {
		t.Fatalf("pull %+v", p)
	}
	if c := rr.find("create"); c[len(c)-1].args[1] != next {
		t.Fatalf("create %+v", c)
	}
	// the new version does not become healthy → back to the old image
	rr.mu.Lock()
	rr.failOn = map[string]int{"wait": 1}
	rr.mu.Unlock()
	creates := len(rr.find("create"))
	if id, err = s.StartImageUpdate(ctx, "mailserver/docker-mailserver:17.1.0-r1"); err != nil {
		t.Fatal(err)
	}
	j := waitJob(t, s, id)
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "eski sürüme dönüldü") {
		t.Fatalf("%+v", j)
	}
	srv, _ = s.Store.Server(ctx)
	c := rr.find("create")
	if srv.Image != next || srv.Status != StatusRunning || len(c) != creates+2 || c[len(c)-1].args[1] != next {
		t.Fatalf("after rollback: %+v, creates %d", srv, len(c)-creates)
	}
	// a failed pull leaves the server alone
	rr.mu.Lock()
	rr.failOn = map[string]int{"pull": 1}
	rr.mu.Unlock()
	removes := len(rr.find("remove"))
	id, _ = s.StartImageUpdate(ctx, "mailserver/docker-mailserver:17.1.0-r1")
	if j := waitJob(t, s, id); j.Status != jobs.StatusFailed || len(rr.find("remove")) != removes {
		t.Fatalf("pull failure touched the container: %+v", j)
	}
}

func TestEnsureVhost(t *testing.T) {
	ctx := context.Background()
	s, rr, _ := testService(t)
	s.EnsureVhost(ctx) // not installed: nothing to do
	if len(rr.find("vhost")) != 0 {
		t.Fatal("vhost without a server")
	}
	store.SetSetting(ctx, s.DB, settingDockerInstalled, "1")
	id, err := s.StartInstall(ctx, InstallInput{Hostname: "mail.ornek.com", Domain: "ornek.com", LEEmail: "a@ornek.com", MemoryMB: 1024})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, s, id)
	n := len(rr.find("vhost"))
	s.EnsureVhost(ctx)
	s.EnsureVhost(ctx) // once per revision
	v := rr.find("vhost")
	if len(v) != n+1 || v[len(v)-1].args[1] != "mail.ornek.com" {
		t.Fatalf("vhost calls %+v", v)
	}
}
