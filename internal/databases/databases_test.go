package databases

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	cases := map[string]string{
		"Şahin Yazılım A.Ş.":    "c_sahin_yazilim_a_s",
		"İĞÜŞÖÇ ığüşöç":         "c_igusoc_igusoc",
		"  --  ":                "c_musteri",
		"Acme; DROP LOGIN sa":   "c_acme_drop_login_sa",
		"123 Ltd":               "c_123_ltd",
		strings.Repeat("a", 90): "c_" + strings.Repeat("a", 40),
	}
	for in, want := range cases {
		if got := LoginBase(in); got != want {
			t.Errorf("LoginBase(%q) = %q, want %q", in, got, want)
		}
		if !ValidName(LoginBase(in)) {
			t.Errorf("LoginBase(%q) not a valid name", in)
		}
	}
	for in, want := range map[string]string{"ornek_com": "ornek_com", "1site": "db_1site", "sysx": "db_sysx", "": "db", "Çay-Bahçesi": "cay_bahcesi"} {
		if got := DBBase(in); got != want || !ValidName(got) {
			t.Errorf("DBBase(%q) = %q (valid=%v), want %q", in, got, ValidName(got), want)
		}
	}
	for _, bad := range []string{"", "a", "A_b", "1abc", "a-b", "a b", "master", "tempdb", "sa", "hpiso_x", "sysdb", "a]; DROP", strings.Repeat("a", 64)} {
		if ValidName(bad) {
			t.Errorf("ValidName(%q) = true", bad)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw := GeneratePassword()
		if len(pw) != 24 || !ValidPassword(pw) {
			t.Fatalf("bad password %q", pw)
		}
		if !strings.ContainsAny(pw, pwLower) || !strings.ContainsAny(pw, pwUpper) || !strings.ContainsAny(pw, pwDigits) {
			t.Fatalf("password %q misses a class", pw)
		}
		if seen[pw] {
			t.Fatal("duplicate password")
		}
		seen[pw] = true
	}
}

func TestConnStrings(t *testing.T) {
	c := ConnInfo{Host: "127.0.0.1", Port: 1433, Database: "shop_db", User: "c_acme", Password: "Abc123def456GHI789jkl012"}
	if got, want := c.ADONET(), "Server=127.0.0.1,1433;Database=shop_db;User Id=c_acme;Password=Abc123def456GHI789jkl012;Encrypt=True;TrustServerCertificate=True;"; got != want {
		t.Errorf("ADONET = %q", got)
	}
	if got, want := c.URL(), "mssql://c_acme:Abc123def456GHI789jkl012@127.0.0.1:1433/shop_db?encrypt=true&trustServerCertificate=true"; got != want {
		t.Errorf("URL = %q", got)
	}
	if c.ForRuntime("dotnet") != c.ADONET() || c.ForRuntime("node") != c.URL() {
		t.Error("ForRuntime picks the wrong format")
	}
	if DefaultEnvKey("dotnet") != "ConnectionStrings__DefaultConnection" || DefaultEnvKey("node") != "DATABASE_URL" {
		t.Error("DefaultEnvKey")
	}
}

type capture struct {
	q    string
	args []sql.NamedArg
}

// TestSQLUsesParameters checks that user data never ends up in the SQL text:
// names and passwords must travel as named parameters only.
func TestSQLUsesParameters(t *testing.T) {
	var got []capture
	m := &MSSQL{exec: func(_ context.Context, q string, args []sql.NamedArg) error {
		got = append(got, capture{q, args})
		return nil
	}}
	ctx := context.Background()
	const login, db, pw = "c_acme_x", "acme_shop", "Zz9Zz9Zz9Zz9Zz9Zz9Zz9Zz9"
	calls := []func() error{
		func() error { return m.CreateLogin(ctx, login, pw) },
		func() error { return m.SetPassword(ctx, login, pw) },
		func() error { return m.SetLoginEnabled(ctx, login, false) },
		func() error { return m.SetLoginEnabled(ctx, login, true) },
		func() error { return m.DropLogin(ctx, login) },
		func() error { return m.CreateDatabase(ctx, db, login) },
		func() error { return m.Drop(ctx, db, BackupDir+"/pre-drop-acme_shop-20261105-120000.bak") },
		func() error { return m.Backup(ctx, db, BackupDir+"/x.bak") },
		func() error { return m.ChangeSA(ctx, pw) },
		func() error { return m.TryAccess(ctx, db) },
	}
	for i, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if len(got) != len(calls) {
		t.Fatalf("got %d statements", len(got))
	}
	for _, c := range got {
		for _, secret := range []string{login, db, pw, "pre-drop"} {
			if strings.Contains(c.q, secret) {
				t.Errorf("value %q embedded in SQL text:\n%s", secret, c.q)
			}
		}
		if len(c.args) == 0 {
			t.Errorf("statement without parameters:\n%s", c.q)
		}
		if strings.Contains(c.q, "EXEC (@sql)") && !strings.Contains(c.q, "QUOTENAME(") {
			t.Errorf("dynamic SQL without QUOTENAME:\n%s", c.q)
		}
	}
	if !strings.Contains(got[0].q, "DENY VIEW ANY DATABASE") || !strings.Contains(got[0].q, "CHECK_POLICY = ON") {
		t.Error("CreateLogin must deny VIEW ANY DATABASE and enforce the password policy")
	}
	if !strings.Contains(got[5].q, "ALTER AUTHORIZATION ON DATABASE::") {
		t.Error("CreateDatabase must transfer ownership")
	}
	if !strings.Contains(got[6].q, "BACKUP DATABASE @db") {
		t.Error("Drop must back up first")
	}

	// Invalid input is rejected before anything is sent.
	got = nil
	for _, err := range []error{
		m.CreateLogin(ctx, "x]; DROP LOGIN sa;--", pw),
		m.CreateLogin(ctx, login, "short"),
		m.CreateLogin(ctx, login, "pw'; DROP LOGIN sa;--aaaaaaaa"),
		m.CreateDatabase(ctx, "master", login),
		m.Drop(ctx, db, "/etc/shadow"),
		m.Drop(ctx, db, BackupDir+"/../../../etc/x.bak"),
	} {
		if err == nil {
			t.Error("invalid input accepted")
		}
	}
	if len(got) != 0 {
		t.Errorf("%d statements sent for invalid input", len(got))
	}
}

func TestParseAllowIPs(t *testing.T) {
	got, err := ParseAllowIPs("203.0.113.7, 198.51.100.17/24\n2001:db8::1 203.0.113.7 ::ffff:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	want := "203.0.113.7,198.51.100.0/24,2001:db8::1,192.0.2.1"
	if strings.Join(got, ",") != want {
		t.Errorf("got %v", got)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "0.0.0.0", "::", "0.0.0.0/8", "127.0.0.1", "224.0.0.1", "1.2.3", "any", "1.2.3.4; ufw disable"} {
		if _, err := ParseAllowIPs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseStatus(t *testing.T) {
	st := ParseStatus("docker=active\ncontainer=running\nstarted_at=2026-11-05T10:00:00Z\nrestarts=0\noom=false\nimage=x\ncpu=0.52%\nmem=800MiB / 2.25GiB\nmem_pct=34.7%\n")
	if !st.DockerInstalled() || !st.Running() || st.CPU != "0.52%" || st.Mem != "800MiB / 2.25GiB" || st.OOM {
		t.Errorf("%+v", st)
	}
	if st := ParseStatus("docker=absent\n"); st.DockerInstalled() || st.Running() {
		t.Errorf("%+v", st)
	}
}

func TestIsolationFake(t *testing.T) {
	f := NewFakeServer("")
	admin := f.Admin(nil, "SaSaSaSaSaSaSaSaSaSaSa11")
	if err := admin.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	connect := func(_ context.Context, login, pw, db string) (LoginSession, error) { return f.Session(login, pw, db) }
	if err := IsolationTest(context.Background(), &out, admin, connect); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "✗") || !strings.Contains(out.String(), "İzolasyon testi başarılı") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
	if len(f.Databases()) != 0 {
		t.Errorf("cleanup left databases: %v", f.Databases())
	}
	if wrong := f.Admin(nil, "WrongWrongWrong123"); wrong.Ping(context.Background()) == nil {
		t.Error("wrong sa password accepted")
	}
}

// leakySession sees every database: the test must catch it.
type leakySession struct{ LoginSession }

func (leakySession) VisibleDatabases(context.Context) ([]string, error) {
	return []string{"master", "hpiso_x_adb", "hpiso_x_bdb"}, nil
}
func (leakySession) TryAccess(context.Context, string) error { return nil }

func TestIsolationDetectsLeak(t *testing.T) {
	f := NewFakeServer("")
	admin := f.Admin(nil, "SaSaSaSaSaSaSaSaSaSaSa11")
	connect := func(_ context.Context, login, pw, db string) (LoginSession, error) {
		s, err := f.Session(login, pw, "")
		if err != nil {
			return nil, err
		}
		return leakySession{s}, nil
	}
	var out bytes.Buffer
	if err := IsolationTest(context.Background(), &out, admin, connect); err == nil {
		t.Fatalf("leak not detected:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "✗ diğer veritabanının kataloğunu okuyamıyor") {
		t.Errorf("output:\n%s", out.String())
	}
}

// TestIsolationMSSQL runs against a real SQL Server:
//
//	HOSTPANEL_TEST_MSSQL=<sa password> [HOSTPANEL_TEST_MSSQL_ADDR=127.0.0.1:1433] go test ./internal/databases -run IsolationMSSQL -v
func TestIsolationMSSQL(t *testing.T) {
	pw := os.Getenv("HOSTPANEL_TEST_MSSQL")
	if pw == "" {
		t.Skip("HOSTPANEL_TEST_MSSQL (sa şifresi) tanımlı değil")
	}
	addr := os.Getenv("HOSTPANEL_TEST_MSSQL_ADDR")
	if addr == "" {
		addr = "127.0.0.1:1433"
	}
	admin := &MSSQL{Addr: addr, User: "sa", Password: pw}
	ctx := context.Background()
	if err := admin.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	connect := func(ctx context.Context, login, lpw, db string) (LoginSession, error) {
		m := &MSSQL{Addr: addr, User: login, Password: lpw, Database: db}
		if err := m.Ping(ctx); err != nil {
			return nil, err
		}
		return m, nil
	}
	var out bytes.Buffer
	err := IsolationTest(ctx, &out, admin, connect)
	t.Log("\n" + out.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.GetSize(ctx); err != nil {
		t.Errorf("GetSize: %v", err)
	}
}

func TestRestoreSQL(t *testing.T) {
	var got []capture
	m := &MSSQL{
		exec: func(_ context.Context, q string, args []sql.NamedArg) error {
			got = append(got, capture{q, args})
			return nil
		},
		files: func(string) ([]restoreFile, error) {
			return []restoreFile{{"OldShop", "D"}, {"OldShop_2", "D"}, {"OldShop_log", "L"}}, nil
		},
	}
	ctx := context.Background()
	path := BackupDir + "/hprs-20261105-120000-a1b2-acme_shop.bak"
	if err := m.Restore(ctx, "acme_shop", path, "c_acme"); err != nil {
		t.Fatal(err)
	}
	q := got[0].q
	for _, v := range []string{"acme_shop", "c_acme", "OldShop", "hprs-", ".mdf"} {
		if strings.Contains(q, v) {
			t.Errorf("value %q embedded in SQL text", v)
		}
	}
	for _, want := range []string{"RESTORE DATABASE @db FROM DISK = @path WITH REPLACE", "MOVE @l3 TO @p3",
		"REVOKE CONNECT FROM guest", "ALTER AUTHORIZATION ON DATABASE::", "TRUSTWORTHY OFF", "RECOVERY SIMPLE", "SINGLE_USER"} {
		if !strings.Contains(q, want) {
			t.Errorf("restore SQL lacks %q", want)
		}
	}
	args := map[string]any{}
	for _, a := range got[0].args {
		args[a.Name] = a.Value
	}
	if args["p1"] != ServerDataDir+"/acme_shop.mdf" || args["p2"] != ServerDataDir+"/acme_shop_2.ndf" ||
		args["p3"] != ServerDataDir+"/acme_shop_log.ldf" || args["l2"] != "OldShop_2" {
		t.Errorf("file mapping: %v", args)
	}

	// Bad input never reaches the server; FILESTREAM is refused.
	got = nil
	for _, err := range []error{
		m.Restore(ctx, "master", path, "c_acme"),
		m.Restore(ctx, "acme_shop", "/etc/shadow", "c_acme"),
		m.Restore(ctx, "acme_shop", path, "sa]; --"),
	} {
		if err == nil {
			t.Error("invalid input accepted")
		}
	}
	m.files = func(string) ([]restoreFile, error) { return []restoreFile{{"x", "D"}, {"fs", "S"}}, nil }
	if err := m.Restore(ctx, "acme_shop", path, "c_acme"); err == nil {
		t.Error("FILESTREAM backup accepted")
	}
	if len(got) != 0 {
		t.Errorf("%d statements sent for invalid input", len(got))
	}
}
